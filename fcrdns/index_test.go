package fcrdns

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCache_Top_HitsCountEveryCall(t *testing.T) {
	resolver := &countingResolver{names: []string{"host.crawl.baidu.com."}}
	cache, err := NewCache(resolver, testCacheConfig())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer cache.Close()

	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)
	ctx := context.Background()

	const calls = 5
	for i := 0; i < calls; i++ {
		cache.Verify(ctx, "1.2.3.4", pattern, AllowForwardFailure)
	}

	total, entries := cache.Top(10)
	if total != 1 {
		t.Fatalf("total = %d, want 1", total)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if entries[0].Hits != calls {
		t.Errorf("Hits = %d, want %d (one per Verify call, cached or not)", entries[0].Hits, calls)
	}
	if entries[0].IP != "1.2.3.4" {
		t.Errorf("IP = %q, want 1.2.3.4", entries[0].IP)
	}
	if entries[0].Outcome != OutcomeVerified {
		t.Errorf("Outcome = %v, want %v", entries[0].Outcome, OutcomeVerified)
	}
}

func TestCache_Top_ConcurrentDedupedCallsAllCount(t *testing.T) {
	// Regression test for the leader/waiter double- or under-counting trap:
	// singleflight.Do returns the *same* result value to every deduplicated
	// caller, so a naive "only count when this call did the fresh lookup"
	// check can't tell a waiter apart from the leader - see Cache.Verify's
	// deferred index.hit call, which counts every external call exactly
	// once regardless of which branch it took.
	release := make(chan struct{})
	resolver := &countingResolver{names: []string{"host.crawl.baidu.com."}, release: release}
	cache, err := NewCache(resolver, testCacheConfig())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer cache.Close()

	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)
	ctx := context.Background()

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			cache.Verify(ctx, "1.2.3.4", pattern, AllowForwardFailure)
		}()
	}

	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	// One more call, now safely served from cache, to also exercise the
	// early-Get hit path alongside the dedup path above.
	cache.Verify(ctx, "1.2.3.4", pattern, AllowForwardFailure)

	_, entries := cache.Top(10)
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if entries[0].Hits != goroutines+1 {
		t.Errorf("Hits = %d, want %d (%d deduplicated concurrent calls + 1 later cache hit)",
			entries[0].Hits, goroutines+1, goroutines)
	}
}

func TestCache_Top_OrderedByHitsDescending(t *testing.T) {
	resolver := &countingResolver{names: []string{"host.crawl.baidu.com."}}
	cache, err := NewCache(resolver, testCacheConfig())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer cache.Close()

	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)
	ctx := context.Background()

	hitCounts := map[string]int{
		"1.1.1.1": 1,
		"2.2.2.2": 5,
		"3.3.3.3": 3,
	}
	for ip, n := range hitCounts {
		for i := 0; i < n; i++ {
			cache.Verify(ctx, ip, pattern, AllowForwardFailure)
		}
	}

	total, entries := cache.Top(10)
	if total != 3 {
		t.Fatalf("total = %d, want 3", total)
	}
	wantOrder := []string{"2.2.2.2", "3.3.3.3", "1.1.1.1"}
	if len(entries) != len(wantOrder) {
		t.Fatalf("len(entries) = %d, want %d", len(entries), len(wantOrder))
	}
	for i, ip := range wantOrder {
		if entries[i].IP != ip {
			t.Errorf("entries[%d].IP = %q, want %q (order: %v)", i, entries[i].IP, ip, entries)
		}
	}
}

func TestCache_Top_LimitTruncatesButTotalReflectsEverything(t *testing.T) {
	resolver := &countingResolver{names: []string{"host.crawl.baidu.com."}}
	cache, err := NewCache(resolver, testCacheConfig())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer cache.Close()

	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)
	ctx := context.Background()

	const distinctIPs = 10
	for i := 0; i < distinctIPs; i++ {
		cache.Verify(ctx, fmt.Sprintf("10.0.0.%d", i), pattern, AllowForwardFailure)
	}

	total, entries := cache.Top(3)
	if total != distinctIPs {
		t.Errorf("total = %d, want %d", total, distinctIPs)
	}
	if len(entries) != 3 {
		t.Errorf("len(entries) = %d, want 3", len(entries))
	}

	total, entries = cache.Top(0)
	if total != distinctIPs {
		t.Errorf("total = %d, want %d", total, distinctIPs)
	}
	if len(entries) != 0 {
		t.Errorf("len(entries) = %d, want 0 for limit=0", len(entries))
	}
}

func TestCache_Top_EvictedEntriesDisappear(t *testing.T) {
	// Same premise as TestCache_SizeIsBoundedByMaxBytes: with a tiny
	// MaxBytes, most inserted keys get evicted or never admitted at all.
	// The index must track this - not just report every key ever inserted -
	// otherwise a "top cache entries" view would show long-gone keys.
	const maxBytes = 5000
	const distinctKeys = 2000

	resolver := &countingResolver{names: []string{"host.crawl.baidu.com."}}
	cache, err := NewCache(resolver, CacheConfig{
		MaxBytes:    maxBytes,
		VerifiedTTL: time.Hour,
		RejectedTTL: time.Hour,
		UnknownTTL:  time.Hour,
	})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer cache.Close()

	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)
	ctx := context.Background()

	for i := 0; i < distinctKeys; i++ {
		cache.Verify(ctx, fmt.Sprintf("10.0.%d.%d", i/256, i%256), pattern, AllowForwardFailure)
	}

	total, _ := cache.Top(distinctKeys)
	if total >= distinctKeys {
		t.Errorf("index total = %d, want well under %d (evicted/rejected keys must not linger in the index)",
			total, distinctKeys)
	}
}

func TestCache_Top_TTLExpiryRemovesEntry(t *testing.T) {
	resolver := &countingResolver{names: []string{"host.crawl.baidu.com."}}
	cache, err := NewCache(resolver, CacheConfig{
		MaxBytes:    1_000_000,
		VerifiedTTL: 20 * time.Millisecond,
		RejectedTTL: time.Hour,
		UnknownTTL:  time.Hour,
	})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer cache.Close()

	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)
	ctx := context.Background()

	cache.Verify(ctx, "1.2.3.4", pattern, AllowForwardFailure)
	if total, _ := cache.Top(10); total != 1 {
		t.Fatalf("total = %d, want 1 right after insert", total)
	}

	// Ristretto's cleanup ticker sweeps expired entries in 5-second buckets
	// (bucketDurationSecs in its ttl.go, not configurable via the public
	// Config), checked every TtlTickerDurationInSec/2 = 2.5s - so a very
	// short TTL like this test's can still take close to 10s to actually be
	// swept and trigger OnEvict, even though Get already stops returning it
	// immediately (Ristretto's own expiration check, independent of the
	// sweep). Give it generous room rather than asserting on a tight bound.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if total, _ := cache.Top(10); total == 0 {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Errorf("index still reports the expired entry after 15s, want it swept by Ristretto's cleanup ticker")
}
