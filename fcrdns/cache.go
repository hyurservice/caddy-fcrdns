package fcrdns

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/dgraph-io/ristretto"
	"golang.org/x/sync/singleflight"
)

// CacheConfig configures a Cache's size bound and per-outcome TTLs.
type CacheConfig struct {
	// MaxEntries bounds the number of cached outcomes. Ristretto evicts
	// using a cost-aware admission policy (TinyLFU) once this is reached,
	// rather than plain least-recently-used, which gives some resistance
	// to cache pollution from a flood of one-off keys - relevant here since
	// this cache's keys are derived from request source IPs, which are
	// attacker-influenceable.
	MaxEntries int64
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
		MaxEntries:  50_000,
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
	if config.MaxEntries <= 0 {
		config.MaxEntries = DefaultCacheConfig().MaxEntries
	}
	store, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: config.MaxEntries * 10,
		MaxCost:     config.MaxEntries,
		BufferItems: 64,
	})
	if err != nil {
		return nil, fmt.Errorf("creating ristretto cache: %w", err)
	}
	return &Cache{resolver: resolver, store: store, config: config}, nil
}

func cacheKey(ip string, hostnamePattern *regexp.Regexp, forwardPolicy ForwardConfirmPolicy) string {
	return ip + "|" + hostnamePattern.String() + "|" + forwardPolicy.String()
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
		c.store.SetWithTTL(key, outcome, 1, c.ttlFor(outcome))
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
