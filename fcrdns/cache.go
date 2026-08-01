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
	index    *index
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

	idx := newIndex()
	// Ristretto's OnEvict/OnReject only expose the item's hashed uint64 key
	// and its Value, never the original string key we passed to Set - so
	// cachedResult carries its own key along for the ride, purely so these
	// callbacks can tell the index which entry just stopped being cached.
	forgetFromIndex := func(item *ristretto.Item) {
		if cr, ok := item.Value.(cachedResult); ok {
			idx.remove(cr.key)
		}
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
		OnEvict:            forgetFromIndex,
		OnReject:           forgetFromIndex,
	})
	if err != nil {
		return nil, fmt.Errorf("creating ristretto cache: %w", err)
	}
	return &Cache{resolver: resolver, store: store, config: config, index: idx}, nil
}

func cacheKey(ip string, hostnamePattern *regexp.Regexp, forwardPolicy ForwardConfirmPolicy) string {
	return ip + "|" + hostnamePattern.String() + "|" + forwardPolicy.String()
}

// entryCost estimates the memory cost, in bytes, of caching the given key.
func entryCost(key string) int64 {
	return int64(len(key)) + estimatedEntryOverheadBytes
}

// cachedResult is what's actually stored in the cache - the Outcome (which
// drives the TTL and Allowed()) and the Detail (kept around so a cache hit
// can still be logged with the same information a fresh lookup would have
// provided). key is included so Ristretto's OnEvict/OnReject callbacks -
// which only see this Value, not the original string key - can tell the
// side index which entry to forget.
type cachedResult struct {
	key     string
	outcome Outcome
	detail  Detail
}

// groupResult additionally tracks whether this particular call performed a
// fresh lookup or found (or waited for) an already-cached value, so Verify
// can report cacheHit accurately even when multiple concurrent callers are
// deduplicated by singleflight.
type groupResult struct {
	cachedResult
	fresh bool
}

// Verify behaves like the package-level Verify function, but consults the
// cache first and stores the result afterward. Concurrent calls for the
// same (ip, hostnamePattern, forwardPolicy) are deduplicated: only one
// actual DNS lookup sequence runs at a time per key, and other callers for
// that same key wait for its result rather than each performing their own
// lookup.
//
// The returned bool is true if this call's answer came from an entry that
// was already cached before this call started. It's false both for the
// call that actually performs a fresh lookup and for any other concurrent
// calls deduplicated alongside it by singleflight (none of them found a
// pre-existing entry, even though only one of them did the real work) -
// useful for logging, but not a precise "did I personally do a lookup"
// signal.
func (c *Cache) Verify(ctx context.Context, ip string, hostnamePattern *regexp.Regexp, forwardPolicy ForwardConfirmPolicy) (Outcome, Detail, bool) {
	key := cacheKey(ip, hostnamePattern, forwardPolicy)

	// Exactly one hit per external call, regardless of which return path
	// below is taken - see index.hit's doc comment for why this can't be
	// done per-branch instead without over- or under-counting concurrent,
	// singleflight-deduplicated callers.
	defer c.index.hit(key)

	if v, ok := c.store.Get(key); ok {
		if cached, ok := v.(cachedResult); ok {
			return cached.outcome, cached.detail, true
		}
	}

	v, _, _ := c.group.Do(key, func() (interface{}, error) {
		// Re-check: another goroutine may have populated the cache between
		// our Get above and singleflight scheduling this function.
		if v, ok := c.store.Get(key); ok {
			if cached, ok := v.(cachedResult); ok {
				return groupResult{cachedResult: cached, fresh: false}, nil
			}
		}

		outcome, detail := Verify(ctx, c.resolver, ip, hostnamePattern, forwardPolicy)
		result := cachedResult{key: key, outcome: outcome, detail: detail}
		ttl := c.ttlFor(outcome)
		// Must run before SetWithTTL/Wait: see index.observe's doc comment.
		c.index.observe(key, ip, hostnamePattern.String(), forwardPolicy.String(), outcome, detail, time.Now().Add(ttl))
		c.store.SetWithTTL(key, result, entryCost(key), ttl)
		c.store.Wait()
		return groupResult{cachedResult: result, fresh: true}, nil
	})

	gr := v.(groupResult)
	return gr.outcome, gr.detail, !gr.fresh
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

// Top returns up to limit currently-cached entries ordered by descending
// hit count (ties broken by soonest expiry), along with the total number of
// entries tracked (which may exceed what's returned). Intended for
// debugging/observability (e.g. an admin API listing), not for anything on
// Verify's own path.
func (c *Cache) Top(limit int) (total int, entries []IndexEntry) {
	return c.index.top(limit)
}
