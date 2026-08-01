# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

A standalone Caddy module (`github.com/hyurservice/caddy-fcrdns`) implementing
FCrDNS (forward-confirmed reverse DNS) verification, as a `verify_fcrdns` HTTP
request matcher. See README.md for usage/configuration - this file is about
non-obvious decisions and conventions, not the public interface.

**Origin and intended use**: this was built to solve a false-positive problem
in the sibling `../containers` repo (`hyurservice`'s Caddy setup): crawlers
like Baidu, Yahoo Slurp, and Amazonbot don't publish static IP ranges, so
`hyurservice`'s existing IP-allowlist mechanism (`allowed-ips.caddy`, built
from vendors that *do* publish ranges) can't cover them. This module is meant
to eventually be wired into `../containers/hyurservice/caddy/Dockerfile`'s
`xcaddy build` and referenced from its Caddyfile, but that integration hasn't
happened yet - right now this repo is developed and tested standalone. Don't
assume the two repos are wired together unless you've checked.

## Architecture: core vs. glue, and why

- `fcrdns/` is pure Go with **zero** dependency on Caddy, HTTP, User-Agents,
  or the concept of a "crawler." It's a general-purpose "verify this IP
  against this hostname pattern" primitive, reusable outside Caddy entirely
  (e.g. verifying a webhook sender, or SMTP anti-spam - FCrDNS is a generic
  technique, not crawler-specific).
- `app.go` / `matcher.go` / `caddyfile.go` / `adminapi.go` (root package
  `caddyfcrdns`) are the *only* place Caddy-specific concerns belong: request
  handling, the User-Agent pre-filter, Caddyfile syntax, logging, the admin
  API.
- **Deliberately not in the module at all**: which crawlers to check, and
  their User-Agent strings. That's expressed in the *caller's* Caddyfile via
  the built-in `header_regexp` matcher, combined with `verify_fcrdns` in the
  same named matcher block. This works because Caddy's `MatcherSet.Match`
  (in caddy's own `modules/caddyhttp/routes.go`) short-circuits on the first
  failing matcher in the set - confirmed by reading Caddy's source, not
  assumed - so a cheap `header_regexp` placed before `verify_fcrdns` means
  the DNS check only runs for requests actually claiming to be that crawler.
  Do not add User-Agent awareness to this module; if a future need seems to
  require it, that's a sign the matcher composition is being done wrong at
  the call site, not a gap in this module.

## Distinguishing confirmed-rejection from unknown, without a third return value

`Match()` returns a plain bool, but three outcomes exist internally
(verified/rejected/unknown). Rather than exposing a side channel, the
Caddyfile composes two calls with opposite `unknown_policy` and `not`:
`accept_unknown` collapses verified-or-unknown to true, so `not (...)` is
true exactly on a confirmed mismatch. The second call is a cache hit, not a
second lookup - see below for why that specifically requires excluding
`unknown_policy` from the cache key. See README.md's "Distinguishing a
confirmed spoof" section for the actual Caddyfile pattern.

## Cache design gotchas

- **Cache key is `(ip, hostname_pattern, forward_policy)` - deliberately not
  `unknown_policy`.** The two-call composition pattern above depends on both
  calls hitting the same cache entry. Adding `unknown_policy` to the key
  would silently break that into two real DNS lookups.
- **Ristretto's `IgnoreInternalCost: true` is load-bearing, not cosmetic.**
  Without it, Ristretto silently adds its own per-item byte-size estimate
  (`itemSize`, based on its internal struct's `unsafe.Sizeof`) on top of
  whatever cost you supply - with a small budget, that overhead alone can
  exceed the entire budget and cause *every* entry to be rejected with zero
  errors surfaced anywhere (`KeysAdded` stays 0 forever). This was found by
  writing `TestCache_SizeIsBoundedByMaxBytes` and diagnosing why it reported
  `resident=0` no matter how many entries were inserted - don't remove that
  flag without re-running that test.
- Cost is estimated ourselves (key length + a fixed overhead constant), not
  left to Ristretto's internal accounting, specifically so the budget is one
  transparent number instead of partly-opaque.
- `Cache.Verify`'s `cacheHit` return value is `false` for *every* member of a
  singleflight-deduplicated batch that misses the cache, not just the one
  that actually performed the lookup - see the doc comment on `Cache.Verify`
  before changing this; it's intentional, not a bug to "fix."

## Admin API design gotchas (`fcrdns/index.go`, `adminapi.go`)

`GET /verify_fcrdns/cache` (see README.md "Admin API") lists the cache's
contents ranked by hit count, for live debugging. Getting this right
surfaced several non-obvious Ristretto/Caddy/singleflight interactions:

- **Ristretto has no enumeration API, by design** - it's built purely for
  O(1) get/set/del throughput, not for "what's currently in here." The side
  index in `fcrdns/index.go` exists solely to answer that question; nothing
  on `Cache.Verify`'s actual path reads from it.
- **`OnEvict`/`OnReject` only expose the *hashed* `uint64` key on `Item`, not
  the original string key** you passed to `Set`. That's why `cachedResult`
  (the value Ristretto stores) carries its own `key` field - it's the only
  way those callbacks can tell the index which entry to forget.
- **`index.observe` must run *before* `store.SetWithTTL`/`Wait`, not after -
  ordering that looks backwards at first glance.** Ristretto's admission
  policy can reject a fresh `Set` (rare, but real under memory pressure), and
  `OnReject` fires *synchronously inside `Wait()`* - confirmed by reading
  `processItems` in ristretto's own `cache.go`: `Wait()` enqueues a marker
  onto the same single-consumer channel `Set` used, so by the time `Wait()`
  returns, any rejection for the item enqueued just before it has already
  been processed, in FIFO order, on that same goroutine. If `observe` ran
  *after* `SetWithTTL`/`Wait` instead, a rejected item's `OnReject` would fire
  and find nothing to remove (the index entry wouldn't exist yet), then
  `observe` would add a phantom entry immediately afterward that nothing
  would ever clean up. Running `observe` first means a same-key `OnReject`
  correctly removes what was just optimistically added.
- **`singleflight.Do` returns the *identical* result value to every
  deduplicated caller**, including the `fresh`/leader-vs-waiter distinction -
  there is no way to tell, from inside the shared closure or its result,
  "was I the goroutine that actually ran this, or one that waited for it."
  Concretely: incrementing a hit counter *inside* the `group.Do` closure only
  counts the leader once, no matter how many goroutines were deduplicated
  alongside it. `Cache.Verify` resolves this with a single `defer
  c.index.hit(key)` at the top of the function, outside `group.Do` entirely -
  it fires exactly once per external call regardless of which branch (early
  cache hit, fresh lookup, or deduplicated wait) was taken. Don't move hit
  counting back inside the closure or split it across branches; both are easy
  ways to reintroduce double- or under-counting. `TestCache_Top_ConcurrentDedupedCallsAllCount`
  is the regression test for this specifically.
- **Ristretto's cleanup ticker sweeps expired entries in 5-second buckets**
  (`bucketDurationSecs` in its own `ttl.go`, not exposed via `Config`), ticked
  every `TtlTickerDurationInSec/2` (2.5s default) - so an entry with a very
  short TTL can take close to 10s of wall-clock time to actually trigger
  `OnEvict` and disappear from the index, even though `Get` already stops
  returning it immediately via its own independent expiration check. This
  cost a flaky-looking test failure once (`TestCache_Top_TTLExpiryRemovesEntry`
  originally polled for only 3s) - give tests around this generous margin
  (15s+), not a tight bound, and don't read a few seconds of "the index still
  shows an already-expired entry" as a bug to fix.
- **Admin API modules (`admin.api.*`) are provisioned *before* regular apps
  during config load** - confirmed by reading caddy's own `caddy.go`:
  `provisionContext` calls `replaceLocalAdminServer` (which provisions every
  registered `admin.api.*` module, including this one) strictly before the
  loop that calls `ctx.App(appName)` for each app in the config. This means
  `AdminAPI.Provision` cannot use `ctx.App("verify_fcrdns")` the way
  `matcher.go` does - at that point in startup, the real app isn't loaded
  yet, so `ctx.App` would silently instantiate a brand-new, separately-
  configured `App` with its own disconnected cache instead of erroring.
  Fixed via `currentApp` (`atomic.Pointer[App]` in `app.go`), set at the end
  of `App.Provision` and cleared (via `CompareAndSwap`, so a reload's new
  instance can't be clobbered by the old instance's later `Stop`) in
  `App.Stop`. `adminapi.go`'s handler reads it lazily at *request* time,
  long after startup ordering stops mattering.

## Policy defaults

Both `forward_policy` and `unknown_policy` default (empty string) to their
*stricter* option (`require_forward_confirm`, `reject_unknown`) - see
`parseForwardPolicy`/`parseUnknownPolicy` in matcher.go. This means
`verify_fcrdns <hostname_pattern>` alone is a complete, safe matcher. Keep
defaulting to the stricter option if more policy dimensions are ever added.

## Real-world DNS validation

`allow_forward_failure` exists because of a concrete finding, not
speculation: querying real Baidu infrastructure directly (`host <ip>`, no
crawler traffic needed - PTR/forward lookups are outbound queries under our
control) showed `220.181.108.108` forward-confirms cleanly via its PTR
hostname `baiduspider-220-181-108-108.crawl.baidu.com`, but
`180.76.15.15`'s PTR hostname (`baiduspider-180-76-15-15.crawl.baidu.com`)
has no forward A record at all (NXDOMAIN), despite both being real Baidu
crawler IPs. Both cases are captured as tests in `fcrdns/verify_test.go`
(`TestVerify_StrictPass`, `TestVerify_LenientPassDespiteForwardFailure`).

Googlebot has also been validated this way (used in README.md as the primary
example, since Baidu isn't a great first impression for a public README):
`66.249.66.1`, `66.249.66.10`, and `66.249.79.35` all reverse-resolve to
`crawl-<ip>.googlebot.com` and all forward-confirm cleanly - no
`allow_forward_failure` gap like Baidu's, so Googlebot doesn't illustrate
that particular policy well, which is why the Baidu data stays in README.md
specifically for that callout.

**Amazonbot: tried to validate, and it revealed a different problem worth
knowing about.** A community-sourced IP list (`rezmoss/cloud-provider-ip-
addresses`) claims to list Amazonbot IPs, but querying several of them
(`3.81.194.188`, `3.81.253.151`, `3.82.29.30`, etc.) shows generic
`ec2-<ip>.compute-1.amazonaws.com` reverse DNS - not Amazon's documented
`crawl.amazonbot.amazon` pattern at all. AWS's IP space churns constantly, so
a scraped/community list for an AWS-hosted crawler is likely picking up
stale or reassigned generic EC2 instances rather than genuine current
Amazonbot traffic. **Don't trust a third-party Amazonbot IP list as a source
of real example IPs** - if Amazonbot support is ever added, it needs IPs
obtained some other way (e.g. from actual observed request logs of a site
Amazonbot is known to crawl) to validate against.

**Yahoo Slurp: tried to validate, came back inconclusive - not the same as
"not yet tried."** Yahoo's documented verification method is a PTR hostname
ending in `.crawl.yahoo.net`. Sampled ~15 IPs across two independent
historical/community sources (a 2008 news article's example IP, and the
2020 `bienthuy/Search-Engine-IP-Range` list's `74.6.0.0/16` and
`8.12.144.0/24` ranges, plus a broader manual spread within `74.6.0.0/16`)
and found zero matches for `.crawl.yahoo.net`. What showed up instead:
`unknown.yahoo.com` (a generic placeholder, across multiple unrelated
ranges) and what's clearly Yahoo's internal network/corporate
infrastructure (e.g. `vl-120.tor5-6-pda.gq1.yahoo.com`, and one explicitly
under `corp.gq1.yahoo.com`). Directly resolving `crawl.yahoo.net` itself
just points to an AWS Global Accelerator endpoint, not any individual
crawler host. Best interpretation: the historical/community "Yahoo IP
ranges" floating around are Yahoo's general corporate netblock, not a
crawler-specific one, and actual Slurp crawl volume may now be small enough
(Yahoo Search runs on Bing's index today) that a live example is genuinely
hard to find by guessing ranges. **Don't add a Yahoo Slurp config entry
without first finding a real, currently-active source of example IPs** (e.g.
observed request logs from a site Slurp is known to still crawl) - guessing
from any of the sources above didn't work, so trying more of the same kind
of source isn't likely to either.

## Testing conventions

- `fcrdns` package tests use a fake `Resolver` (function fields), never real
  DNS - see `fakeResolver`/`countingResolver` in the test files.
- **`go build`/`go test` passing does not mean the Caddy-facing config
  works.** This is a Caddy module; the only way to validate the Caddyfile
  syntax, matcher wiring, and app lookup actually work is to build a real
  Caddy binary with xcaddy (pointing `--with` at a local copy of this repo
  via a plain path, not a `replace` directive in this repo's own go.mod) and
  exercise it with real HTTP requests. Every non-trivial change in this
  repo's history was validated that way before being trusted - see README.md
  "Development" for the exact commands.
- Caddy buffers log writes for a few seconds. If debug/info logs don't show
  up in `docker logs` immediately after a request, wait ~5-10s before
  concluding something's broken - this cost real debugging time once
  already (temporarily added raw `os.Stderr.WriteString` calls to confirm
  `Provision`/`Match` were actually being reached before realizing it was
  just a flush delay).
- `go.mod`'s Go version has been bumped a few times as transitive
  dependencies (`golang.org/x/sync`, then `caddyserver/caddy/v2`) required
  it. Don't fight this by re-pinning older versions unless there's a
  concrete reason to support an older Go - it's cost time before for no
  lasting benefit.

## Not yet done

- Yahoo Slurp and Amazonbot both need a real (non-community-sourced,
  non-historical) source of example IPs before they can be validated at all
  - guessing from IP ranges circulating online didn't work for either (see
  above).
- Wired into `../containers/hyurservice/caddy/Dockerfile` and its Caddyfile
  on the `caddy-fcrdns-integration` branch of that repo - not yet merged to
  its `master`.
- No CI configured.
