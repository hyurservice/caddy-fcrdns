package fcrdns

import (
	"container/heap"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// IndexEntry is a point-in-time snapshot of one cached verification result,
// for observability (e.g. Caddy's admin API). It plays no role in Verify's
// own caching decisions - see index below for why it exists at all.
type IndexEntry struct {
	IP              string
	HostnamePattern string
	ForwardPolicy   string
	Outcome         Outcome
	MatchedHostname string
	ForwardChecked  bool
	Err             error
	Hits            uint64
	ExpiresAt       time.Time
}

// index is a side-table mirroring Cache's contents, kept eventually
// consistent with it via Ristretto's OnEvict/OnReject hooks (see NewCache).
// It exists only because Ristretto itself has no iteration API - by design,
// it's built purely for O(1) get/set/del throughput and does not support
// enumerating what it currently holds. Nothing in Verify's actual caching
// path reads from this index; it is purely for tools like the admin API
// cache-listing endpoint.
type index struct {
	mu      sync.Mutex
	entries map[string]*indexEntry
}

type indexEntry struct {
	IndexEntry
	hits atomic.Uint64
}

func newIndex() *index {
	return &index{entries: make(map[string]*indexEntry)}
}

// observe upserts the metadata for a freshly-computed result, without
// touching its hit count. It must be called before the corresponding
// Ristretto Set is given a chance to run its admission policy (see the
// call site in Cache.Verify) - if the item is rejected, the synchronous
// OnReject callback removes what observe just added, and if observe ran
// afterward instead, a rejected item would leave a phantom entry that
// nothing would ever clean up.
func (idx *index) observe(key, ip, hostnamePattern, forwardPolicy string, outcome Outcome, detail Detail, expiresAt time.Time) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	e, ok := idx.entries[key]
	if !ok {
		e = &indexEntry{}
		idx.entries[key] = e
	}
	e.IP = ip
	e.HostnamePattern = hostnamePattern
	e.ForwardPolicy = forwardPolicy
	e.Outcome = outcome
	e.MatchedHostname = detail.MatchedHostname
	e.ForwardChecked = detail.ForwardChecked
	e.Err = detail.Err
	e.ExpiresAt = expiresAt
}

// hit increments key's hit count. Called exactly once per external
// Cache.Verify call (see its deferred call), whether that call found an
// existing cache entry, performed a fresh lookup, or waited for another
// goroutine's in-flight lookup of the same key - so Hits reflects total
// query volume for that key, not just cache-hit volume. A no-op if key
// isn't tracked (e.g. it was rejected/evicted between observe and here).
func (idx *index) hit(key string) {
	idx.mu.Lock()
	e, ok := idx.entries[key]
	idx.mu.Unlock()
	if !ok {
		return
	}
	e.hits.Add(1)
}

// remove drops key from the index. Called from Ristretto's OnEvict/OnReject
// hooks, so the index doesn't grow stale entries for keys that are no
// longer actually cached.
func (idx *index) remove(key string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	delete(idx.entries, key)
}

// len returns the number of entries currently tracked.
func (idx *index) len() int {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	return len(idx.entries)
}

// snapshot returns a copy of every tracked entry, in no particular order.
func (idx *index) snapshot() []IndexEntry {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	out := make([]IndexEntry, 0, len(idx.entries))
	for _, e := range idx.entries {
		entry := e.IndexEntry
		entry.Hits = e.hits.Load()
		out = append(out, entry)
	}
	return out
}

// rank reports whether a is strictly more "important" than b for the
// purposes of a top-N listing: higher hit count first, ties broken by
// whichever expires sooner (the more time-sensitive of the two).
func rank(a, b IndexEntry) bool {
	if a.Hits != b.Hits {
		return a.Hits > b.Hits
	}
	return a.ExpiresAt.Before(b.ExpiresAt)
}

// topHeap is a min-heap ordered by ascending rank (so its root - Len()-1 in
// heap terms, i.e. index 0 - is always the *least* important entry
// currently held), letting top() maintain a bounded window of the N most
// important entries in O(log N) per candidate rather than sorting
// everything.
type topHeap []IndexEntry

func (h topHeap) Len() int            { return len(h) }
func (h topHeap) Less(i, j int) bool  { return rank(h[j], h[i]) } // reversed: root is the smallest/worst
func (h topHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *topHeap) Push(x interface{}) { *h = append(*h, x.(IndexEntry)) }
func (h *topHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

// top returns up to limit entries ranked by rank (descending importance),
// and the total number of entries currently tracked (which may be larger
// than what's returned). Cost is O(n log limit) rather than O(n log n),
// which matters since the cache's total size is caller-configurable and
// could be large.
func (idx *index) top(limit int) (total int, entries []IndexEntry) {
	all := idx.snapshot()
	total = len(all)

	if limit <= 0 {
		return total, nil
	}
	if limit >= total {
		entries = all
	} else {
		h := make(topHeap, 0, limit)
		for _, e := range all {
			if h.Len() < limit {
				heap.Push(&h, e)
				continue
			}
			if rank(e, h[0]) {
				heap.Pop(&h)
				heap.Push(&h, e)
			}
		}
		entries = []IndexEntry(h)
	}

	// The heap only guarantees the *set* of top entries, not their order.
	sort.Slice(entries, func(i, j int) bool { return rank(entries[i], entries[j]) })
	return total, entries
}
