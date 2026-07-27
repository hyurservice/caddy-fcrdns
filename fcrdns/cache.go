package fcrdns

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/dgraph-io/ristretto"
	"golang.org/x/sync/singleflight"
)

// estimatedEntryOverheadBytes is a conservative per-entry estimate covering
// map bucket bookkeeping, pointers, and GC overhead beyond the raw key
// string content itself. It's an approximation, not an exact accounting -
// good enough for bounding memory to the right order of magnitude.
const estimatedEntryOverheadBytes = 64

// estimatedEntryDefaultBytes is used to translate a byte budget into a
// NumCounters hint (Ristretto's admission sketch wants roughly 10x the
// number of items you expect to hold, not a byte count) when we don't yet
// know the real average key length.
const estimatedEntryDefaultBytes = 100

// DefaultMaxCacheBytes is a generous default cache memory budget: even at
// a conservative ~150 bytes/entry, this holds on the order of tens of
// thousands of entries.
const DefaultMaxCacheBytes = 10 * 1024 * 1024 // 10 MiB

// CacheConfig configures a Cache's memory bound and per-outcome TTLs.
type CacheConfig struct {
	// MaxBytes bounds the cache's estimated memory usage (see
	// estimatedEntryOverheadBytes for how per-entry cost is estimated).
	// Ristretto evicts using a cost-aware admission policy (TinyLFU) once
	// this is reached, rather than plain least-recently-used, which gives
	// some resistance to cache pollution from a flood of one-off keys -
	// relevant here since this cache's keys are derived from request
	// source IPs, which are attacker-influenceable.
	MaxBytes int64
	// VerifiedTTL, RejectedTTL, and UnknownTTL set how long a cached
	// Outcome of each kind is trusted before Verify is attempted again.
	// UnknownTTL should be short: a DNS timeout is often transient, and a
	// long TTL would keep a legitimate crawler being treated as unverified
	// for that whole duration.
	VerifiedTTL time.Duration
	RejectedTTL time.Duration
	UnknownTTL  time.Duration
}

// DefaultCacheConfig returns reasonable defaults.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		MaxBytes:    DefaultMaxCacheBytes,
		VerifiedTTL: 24 * time.Hour,
		RejectedTTL: time.Hour,
		UnknownTTL:  time.Minute,
	}
}

// Cache wraps Verify with caching and concurrency-safe deduplication.
//
// Entries are keyed by (ip, hostname pattern, forward policy) - deliberately
// not including any UnknownPolicy, since UnknownPolicy is applied afterward
// by the caller (via Outcome.Allowed) and the same cached Outcome must be
// usable regardless of which UnknownPolicy a given caller applies. This
// matters for the "call Verify twice with opposite UnknownPolicy values to
// distinguish a confirmed rejection from an unknown result" pattern: both
// calls must hit the same cache entry rather than triggering two lookups.
type Cache struct {
	resolver Resolver
	store    *ristretto.Cache
	group    singleflight.Group
	config   CacheConfig
}

// NewCache creates a Cache that uses resolver for lookups not already
// cached.
func NewCache(resolver Resolver, config CacheConfig) (*Cache, error) {
	if config.MaxBytes <= 0 {
		config.MaxBytes = DefaultCacheConfig().MaxBytes
	}

	expectedEntries := config.MaxBytes / estimatedEntryDefaultBytes
	if expectedEntries < 1000 {
		expectedEntries = 1000
	}

	store, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: expectedEntries * 10,
		MaxCost:     config.MaxBytes,
		BufferItems: 64,
		Metrics:     true,
		// We estimate and supply our own per-entry byte cost (see
		// entryCost), so Ristretto must not additionally add its own
		// internal per-item storage-overhead guess on top of that -
		// otherwise the effective budget would be a mix of our explicit
		// estimate and an opaque one we don't control.
		IgnoreInternalCost: true,
	})
	if err != nil {
		return nil, fmt.Errorf("creating ristretto cache: %w", err)
	}
	return &Cache{resolver: resolver, store: store, config: config}, nil
}

func cacheKey(ip string, hostnamePattern *regexp.Regexp, forwardPolicy ForwardConfirmPolicy) string {
	return ip + "|" + hostnamePattern.String() + "|" + forwardPolicy.String()
}

// entryCost estimates the memory cost, in bytes, of caching the given key.
func entryCost(key string) int64 {
	return int64(len(key)) + estimatedEntryOverheadBytes
}

// Verify behaves like the package-level Verify function, but consults the
// cache first and stores the result afterward. Concurrent calls for the
// same (ip, hostnamePattern, forwardPolicy) are deduplicated: only one
// actual DNS lookup sequence runs at a time per key, and other callers for
// that same key wait for its result rather than each performing their own
// lookup.
func (c *Cache) Verify(ctx context.Context, ip string, hostnamePattern *regexp.Regexp, forwardPolicy ForwardConfirmPolicy) Outcome {
	key := cacheKey(ip, hostnamePattern, forwardPolicy)

	if v, ok := c.store.Get(key); ok {
		if outcome, ok := v.(Outcome); ok {
			return outcome
		}
	}

	v, _, _ := c.group.Do(key, func() (interface{}, error) {
		// Re-check: another goroutine may have populated the cache between
		// our Get above and singleflight scheduling this function.
		if v, ok := c.store.Get(key); ok {
			if outcome, ok := v.(Outcome); ok {
				return outcome, nil
			}
		}

		outcome := Verify(ctx, c.resolver, ip, hostnamePattern, forwardPolicy)
		c.store.SetWithTTL(key, outcome, entryCost(key), c.ttlFor(outcome))
		c.store.Wait()
		return outcome, nil
	})

	return v.(Outcome)
}

func (c *Cache) ttlFor(outcome Outcome) time.Duration {
	switch outcome {
	case OutcomeVerified:
		return c.config.VerifiedTTL
	case OutcomeRejected:
		return c.config.RejectedTTL
	default:
		return c.config.UnknownTTL
	}
}

// Close releases the cache's background resources. Call this when the
// Cache is no longer needed (e.g. on Caddy module cleanup/reprovision).
func (c *Cache) Close() {
	c.store.Close()
}

// Metrics exposes the underlying cache's hit/miss/eviction counters, for
// monitoring and for tests that need to confirm the size bound is enforced.
func (c *Cache) Metrics() *ristretto.Metrics {
	return c.store.Metrics
}
