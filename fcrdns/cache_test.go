package fcrdns

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingResolver counts LookupAddr calls (LookupHost isn't needed for
// these tests since all cases use AllowForwardFailure) and can optionally
// block until released, to test concurrent-call deduplication.
type countingResolver struct {
	calls   int32
	release chan struct{} // if non-nil, LookupAddr blocks on this before returning
	names   []string
	err     error
}

func (r *countingResolver) LookupAddr(ctx context.Context, ip string) ([]string, error) {
	atomic.AddInt32(&r.calls, 1)
	if r.release != nil {
		<-r.release
	}
	return r.names, r.err
}

func (r *countingResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return nil, notFoundErr()
}

func (r *countingResolver) callCount() int {
	return int(atomic.LoadInt32(&r.calls))
}

func testCacheConfig() CacheConfig {
	return CacheConfig{
		MaxEntries:  1000,
		VerifiedTTL: time.Hour,
		RejectedTTL: time.Hour,
		UnknownTTL:  time.Hour,
	}
}

func TestCache_HitAvoidsSecondLookup(t *testing.T) {
	resolver := &countingResolver{names: []string{"host.crawl.baidu.com."}}
	cache, err := NewCache(resolver, testCacheConfig())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer cache.Close()

	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)
	ctx := context.Background()

	first := cache.Verify(ctx, "1.2.3.4", pattern, AllowForwardFailure)
	second := cache.Verify(ctx, "1.2.3.4", pattern, AllowForwardFailure)

	if first != OutcomeVerified || second != OutcomeVerified {
		t.Fatalf("got first=%v second=%v, want both %v", first, second, OutcomeVerified)
	}
	if got := resolver.callCount(); got != 1 {
		t.Errorf("resolver called %d times, want 1 (second call should be a cache hit)", got)
	}
}

func TestCache_DifferentIPsAreNotConflated(t *testing.T) {
	resolver := &countingResolver{names: []string{"host.crawl.baidu.com."}}
	cache, err := NewCache(resolver, testCacheConfig())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer cache.Close()

	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)
	ctx := context.Background()

	cache.Verify(ctx, "1.2.3.4", pattern, AllowForwardFailure)
	cache.Verify(ctx, "5.6.7.8", pattern, AllowForwardFailure)

	if got := resolver.callCount(); got != 2 {
		t.Errorf("resolver called %d times, want 2 (different IPs must not share a cache entry)", got)
	}
}

func TestCache_ForwardPolicyIsPartOfCacheKey(t *testing.T) {
	resolver := &countingResolver{names: []string{"host.crawl.baidu.com."}}
	cache, err := NewCache(resolver, testCacheConfig())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer cache.Close()

	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)
	ctx := context.Background()

	cache.Verify(ctx, "1.2.3.4", pattern, AllowForwardFailure)
	cache.Verify(ctx, "1.2.3.4", pattern, RequireForwardConfirm)

	if got := resolver.callCount(); got != 2 {
		t.Errorf("resolver called %d times, want 2 (different forward policies must not share a cache entry)", got)
	}
}

func TestCache_UnknownPolicyIsNotPartOfCacheKey(t *testing.T) {
	// Cache.Verify doesn't take an UnknownPolicy at all - this test just
	// documents/confirms that a single cached Outcome serves both possible
	// downstream interpretations (Allowed(RejectUnknown) and
	// Allowed(AcceptUnknown)) without re-querying, which is what makes the
	// "call twice with opposite UnknownPolicy to distinguish confirmed
	// rejection from unknown" pattern cheap.
	resolver := &countingResolver{err: timeoutErr()}
	cache, err := NewCache(resolver, testCacheConfig())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer cache.Close()

	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)
	ctx := context.Background()

	outcome := cache.Verify(ctx, "1.2.3.4", pattern, AllowForwardFailure)
	if outcome != OutcomeUnknown {
		t.Fatalf("got %v, want %v", outcome, OutcomeUnknown)
	}

	if outcome.Allowed(RejectUnknown) {
		t.Errorf("Allowed(RejectUnknown) = true, want false")
	}
	if !outcome.Allowed(AcceptUnknown) {
		t.Errorf("Allowed(AcceptUnknown) = false, want true")
	}
	if got := resolver.callCount(); got != 1 {
		t.Errorf("resolver called %d times, want 1", got)
	}
}

func TestCache_TTLExpiry(t *testing.T) {
	resolver := &countingResolver{names: []string{"host.crawl.baidu.com."}}
	cache, err := NewCache(resolver, CacheConfig{
		MaxEntries:  1000,
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
	if got := resolver.callCount(); got != 1 {
		t.Fatalf("resolver called %d times after first Verify, want 1", got)
	}

	time.Sleep(200 * time.Millisecond)

	cache.Verify(ctx, "1.2.3.4", pattern, AllowForwardFailure)
	if got := resolver.callCount(); got != 2 {
		t.Errorf("resolver called %d times after TTL expiry, want 2 (entry should have expired)", got)
	}
}

func TestCache_ConcurrentIdenticalCallsAreDeduplicated(t *testing.T) {
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
	results := make([]Outcome, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			results[i] = cache.Verify(ctx, "1.2.3.4", pattern, AllowForwardFailure)
		}(i)
	}

	// Give the goroutines a moment to all reach the blocked LookupAddr call
	// (or pile up behind singleflight waiting on the one in flight) before
	// releasing it.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	for i, r := range results {
		if r != OutcomeVerified {
			t.Errorf("goroutine %d got %v, want %v", i, r, OutcomeVerified)
		}
	}
	if got := resolver.callCount(); got != 1 {
		t.Errorf("resolver called %d times for %d concurrent identical requests, want 1", got, goroutines)
	}
}

func TestCache_ConcurrentDifferentKeysAreNotSerialized(t *testing.T) {
	// Two distinct IPs, both blocked on the same release channel. If the
	// cache serialized unrelated keys behind one lock held across the
	// lookup, this would deadlock (both goroutines waiting for a release
	// that only happens after both have started).
	release := make(chan struct{})
	resolver := &countingResolver{names: []string{"host.crawl.baidu.com."}, release: release}
	cache, err := NewCache(resolver, testCacheConfig())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	defer cache.Close()

	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)
	ctx := context.Background()

	done := make(chan struct{}, 2)
	go func() {
		cache.Verify(ctx, "1.2.3.4", pattern, AllowForwardFailure)
		done <- struct{}{}
	}()
	go func() {
		cache.Verify(ctx, "5.6.7.8", pattern, AllowForwardFailure)
		done <- struct{}{}
	}()

	// Both should reach the blocked LookupAddr call independently; release
	// once, which unblocks both since they're reading from the same closed
	// channel.
	time.Sleep(50 * time.Millisecond)
	close(release)

	timeout := time.After(2 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-timeout:
			t.Fatal("timed out waiting for concurrent lookups on different keys - they may be incorrectly serialized")
		}
	}

	if got := resolver.callCount(); got != 2 {
		t.Errorf("resolver called %d times, want 2 (one per distinct IP)", got)
	}
}
