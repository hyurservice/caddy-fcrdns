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
  their User-Agent strings. That's expressed in the *caller's* Caddyfile,
  composed with a cheap `header_regexp` pre-filter via `expression`/CEL's
  `&&` (**not** by putting both in the same named matcher block - see
  "The matcher-set ordering bug" below; an earlier version of this note
  claimed the latter was safe, and it was wrong). Do not add User-Agent
  awareness to this module; if a future need seems to require it, that's a
  sign the matcher composition is being done wrong at the call site, not a
  gap in this module.

## The matcher-set ordering bug (found live in production, 2026-08-01)

**Caddy does not guarantee that conditions within a single `@name { }`
matcher block evaluate in the order they're written**, when that block
combines more than one matcher *type* (e.g. `header_regexp` +
`verify_fcrdns`). This was the original, incorrect assumption this module's
whole "compose a UA pre-filter with verify_fcrdns" design rested on - it was
live in `../containers/hyurservice`'s Caddyfile and caused every distinct
visitor IP to trigger DNS lookups against Baidu/Bing/Yandex's patterns
*regardless of User-Agent*, silently defeating the entire point of the
pre-filter.

**Root cause**, traced through `caddyserver/caddy/v2@v2.11.4`'s own source,
not assumed:
- A named matcher block combining multiple matcher types compiles to one
  JSON object keyed by matcher name (e.g.
  `{"header_regexp": {...}, "verify_fcrdns": {...}}`).
- Loading that at config-provision time goes through
  `Context.loadModuleMap` (`context.go`), which returns a **`map[string]any`**.
- `MatcherSets.FromInterface` (`modules/caddyhttp/routes.go`) then builds
  the final ordered `MatcherSet []any` slice via `for _, matcher := range
  matcherSetIfaces` - iterating that map. **Go map iteration order is
  intentionally randomized by the runtime.** `MatchNot`'s own `Provision`
  (used by the Caddyfile `not { }` block) has the identical pattern, so
  wrapping in `not { }` doesn't help either - it's not a workaround.
- `MatcherSet.Match`/`MatchWithError` genuinely do short-circuit on the
  first *failing* matcher, in whatever order ended up in the slice - that
  part of the original assumption was correct. But which matcher lands
  first is decided arbitrarily, once, at each config load/reload - not by
  Caddyfile source order. If `verify_fcrdns` happens to land first, it runs
  unconditionally, before `header_regexp` ever gets a chance to short-circuit
  it.
- Confirmed empirically, not just via source reading: replayed real
  production requests (genuine Android Chrome UAs, no crawler keyword
  anywhere in them) against a local instance running the real
  `(allowed_crawlers)` Caddyfile snippet, and a `verify_fcrdns` cache entry
  was created anyway. A plain `curl/8.5.0` UA reproduced it too.

**The fix**: don't combine matcher types in one `@name { }` block for this
purpose. Two options were considered:
1. Nested `handle` blocks (nest the DNS check inside a `handle
   @cheap_ua_matcher { }`) - the *outer* route/handle list, unlike a single
   route's own matcher-set, genuinely is an ordered slice (routes get
   appended one per `handle` directive in Caddyfile source order, not
   loaded from a map) - this was the originally-proposed fix and would have
   worked, at the cost of restructuring every call site's Caddyfile.
2. **What was actually implemented**: give this module a `CELLibrary`
   (`celmatcher.go`), so callers use `expression header_regexp(...) &&
   verify_fcrdns(...)` instead. CEL's `&&` is guaranteed left-to-right
   short-circuit by language spec, independent of Caddy's matcher-set
   loading entirely. Chosen over (1) because it fixes the hazard at the
   module level for every caller, not just this one Caddyfile, and doesn't
   require restructuring existing route trees into nested handles.

See README.md's usage section (marked with a prominent warning) for the
correct, current Caddyfile pattern - **do not** re-introduce
`@name { header_regexp ...; verify_fcrdns ... }` as a documented example
even though it's shorter to write; it silently reverts to this bug.

## Distinguishing confirmed-rejection from unknown, without a third return value

`Match()`/`MatchWithError()` return a plain bool (plus, now, an error - see
"Adopting RequestMatcherWithError" below), but three outcomes exist
internally (verified/rejected/unknown). Rather than exposing a side
channel, callers compose two calls with opposite `unknown_policy` and CEL's
`!`: `accept_unknown` collapses verified-or-unknown to true, so `!(...)` is
true exactly on a confirmed mismatch. The second call is a cache hit, not a
second lookup - see below for why that specifically requires excluding
`unknown_policy` from the cache key. See README.md's "Distinguishing a
confirmed spoof" section for the actual pattern.

## Adopting RequestMatcherWithError, and adding CELLibrary support

`matcher.go`'s `Match` is now a thin wrapper around a real
`MatchWithError(r) (bool, error)`, mirroring the convention Caddy's own
core matchers use (they all implement both, with `Match` just discarding
`MatchWithError`'s error - confirmed by reading `matchers.go`, e.g.
`MatchQuery`/`MatchHeader`). This was motivated by, and is a prerequisite
for, `celmatcher.go`'s `CELLibrary` implementation (`CELMatcherDecorator`
prefers a `CELMatcherWithErrorFactory` over the deprecated
`CELMatcherFactory`, which needs `RequestMatcherWithError`).

The error is used narrowly: only for "no client IP available" (a genuine
server misconfiguration, e.g. `trusted_proxies` not set up correctly) -
**not** for any DNS outcome. A DNS timeout/failure is deliberately not a Go
error; it's the `Unknown` outcome, resolved via `unknown_policy` like any
other outcome. Surfacing it as an error instead would abort the request
into Caddy's error-handling middleware chain regardless of
`unknown_policy`, defeating the entire point of that setting. Don't expand
what counts as an "error" here without re-checking this reasoning.

`celmatcher.go`'s `CELLibrary` registers three overloads (1/2/3 string
args, matching the Caddyfile matcher's own optional-arg shape), mirroring
`MatchPathRE.CELLibrary`'s unnamed/named-pattern dual registration pattern
extended to three arities. Each factory just constructs a `VerifyFCrDNS`
and calls its normal `Provision(ctx)` - the same `ctx` the `CELLibrary`
method itself received - so all the real provisioning logic (app lookup,
regex compilation, policy parsing) is reused unchanged, not duplicated.

One easy-to-get-wrong detail: `Provision` has a pointer receiver and
mutates the matcher in place, so `return m, m.Provision(ctx)` as a single
expression is riskier than it looks (evaluation order of the two return
values isn't obviously guaranteed to run `Provision`'s mutation before `m`
is copied for return). Followed `MatchPathRE`'s proven pattern instead:
assign the error to a local first (`err := m.Provision(ctx)`), *then*
`return m, err` as a separate statement.

Validated the actual fix (not just that the code compiles) against a real
xcaddy build: replayed the same non-crawler requests that revealed the bug
against an `expression header_regexp(...) && verify_fcrdns(...)` matcher -
confirmed the cache stayed empty for both a real captured Android Chrome UA
and a plain `curl` UA, and only got an entry once a UA actually claiming
`Baiduspider` was sent.

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

**Bing: officially documented, and validated clean - no forward-confirmation
gap like Baidu's.** Bing's own docs (`bing.com/webmasters/help/how-to-verify-
bingbot-3905dc26`, and the 2012 Bing Webmaster Blog post "How to Verify that
Bingbot is Bingbot," which is still what gets cited as current guidance)
state the method explicitly: reverse DNS must resolve to a hostname ending
in `search.msn.com`, forward-confirmed back to the same IP - and explicitly
warn *against* relying on a static IP list instead, since ranges "can change
any time." Pulled 4 IPs directly from Bing's own currently-published
`bingbot.json` (the file `../containers/hyurservice/cron/scripts/update-
allowed-ips.sh` already fetches for the static allowlist) across different
prefixes - `157.55.39.1`, `40.77.202.1`, `40.77.167.10`, `207.46.13.5` - and
all four reverse-resolve to `msnbot-<ip-with-dashes>.search.msn.com` and
forward-confirm cleanly. One caveat: a Microsoft Community Hub thread
(Oct 2023) reported that IPs in `40.77.202.0/24` specifically didn't
reverse-resolve as documented; testing an IP from that exact prefix today
showed it resolving fine, so either it's been fixed since or was a
narrower/transient issue - not a systemic gap worth an `allow_forward_
failure` policy the way Baidu needed. Since Bing already has a working,
actively-used official static IP list, FCrDNS here is a supplementary/
fallback check (catches a UA claiming Bingbot from an IP the static list
hasn't caught up on yet, and - the part the static list can't do at all -
lets a confirmed-spoof check run), not a gap-filler like it is for Baidu.

**Facebook/Meta: checked, and it's a real negative finding - Meta does not
officially recommend FCrDNS at all.** Fetched Meta's two current official
pages directly (`developers.facebook.com/docs/sharing/webmasters/crawler/`
and `developers.facebook.com/documentation/sharing/webmasters/web-
crawlers`) rather than trust aggregated/third-party summaries (which - same
lesson as Amazonbot - confidently asserted a `*.fb.com`/`*.facebook.com`
reverse-DNS pattern that appears nowhere in Meta's actual pages). Neither
official page mentions reverse DNS, PTR records, or hostname verification
at all. The only guidance given, verbatim: "Add to your allow list either
the user agent strings or the IP addresses used by the crawler." Neither
page publishes actual IP ranges either - the lists floating around online
(GitHub gists, third-party blogs) are unofficial, same category of risk as
the Amazonbot list that turned out to be wrong. **Don't add a Facebook/Meta
verify_fcrdns entry based on a third-party-claimed hostname pattern** -
there is no official pattern to validate against, and unlike Yahoo/Amazonbot
(where an official pattern exists but real example IPs are hard to find),
here the "official pattern" itself would have to be invented from
unofficial sources first.

**Facebook/Meta ASN check: works, but not worth implementing right now.**
Since Meta doesn't document FCrDNS, checked whether ASN membership could
serve as an alternative signal instead. Queried `whois.cymru.com` for real
Facebook/Meta IP ranges spanning all four RIRs (ARIN, RIPE NCC, LACNIC,
AFRINIC), IPv4 and IPv6, and both the classic `facebookexternalhit`
link-preview crawler's ranges and the newer `Meta-ExternalAgent` AI-training
crawler's ranges (e.g. `57.141.0.0/24`) - every single one sits under the
same dedicated `AS32934` ("FACEBOOK - Facebook, Inc., US"). This is
structurally different from Amazonbot: Amazon's crawler runs on shared AWS
EC2 space (a generic cloud ASN with millions of unrelated tenants, so ASN
membership proves nothing crawler-specific), while Meta owns and announces
its own dedicated IP space, so ASN membership is a genuinely strong,
Meta-specific signal. Also confirmed this isn't something Meta documents
either - checked their two official crawler pages again specifically for
ASN/AS32934 and found nothing.

Decided not to pursue it further, for two concrete reasons: (1) it would
require new infrastructure this stack doesn't have -
`../containers/hyurservice`'s existing `shift72/caddy-geo-ip` module only
does country-level MaxMind lookups, so ASN matching would need a different
module (e.g. `lum8rjack/caddy-maxmind-asn` or `porech/caddy-maxmind-
geolocation`) plus MaxMind's separate `GeoLite2-ASN.mmdb`, neither in place
today; (2) unlike Amazonbot, there's already a working static list to fall
back on - `../containers/hyurservice/caddy/ip-blocklists/allowed-ips.caddy`
has a `FacebookBot (via sefinek/trusted-ips-whitelist)` section with 1053
CIDR entries that substantially match the real AS32934 footprint found
here (e.g. `157.240.0.0/16`, `173.252.64.0/19`, `129.134.0.0/17`,
`2a03:2880::/32`) - unlike the Amazonbot community list, which turned out
to be bogus, this one holds up under spot-checking against real WHOIS data.

**Yandex: officially documented, validated live, and actually implemented
- but with a narrower hostname pattern than the docs literally state.**
Yandex's own page (`yandex.com/support/webmaster/en/robot-workings/check-
yandex-robots`) states the method explicitly: "All Yandex robots have names
ending in yandex.ru, yandex.net or yandex.com," forward-confirmed, and
recommends it *over* IP-based allowlisting specifically because "Bots use
an offline network: AS13238, AS208722 and AS212066... their list is not
disclosed" and changes frequently - same situation as Baidu (FCrDNS is the
only official method, not a supplement to a maintained static list).

Guessing the network address (`.1`) inside the project's existing
community-sourced YandexBot CIDR blocks (`../containers/hyurservice/caddy/
ip-blocklists/allowed-ips.caddy`, via `sefinek/trusted-ips-whitelist`) mostly
produced NXDOMAIN or resolved to hostnames that are real Yandex domains but
don't look crawler-specific - `213.180.192.1` -> `sas-1lb19b-kni0.yndx.net`,
`77.88.0.1` -> `s257klg.storage.yandex.net`. Same lesson as Yahoo: a `.1`
address in a broad company CIDR block is usually just infrastructure, not
the crawler. A real reported crawler IP instead: `5.45.207.124` and
`5.45.207.1` both reverse-resolve to `5-45-207-124.spider.yandex.com` /
`5-45-207-1.spider.yandex.com` and forward-confirm cleanly - no Baidu-style
gap.

The hostname_pattern actually configured is `\.spider\.yandex\.com$`, not
the broader `\.yandex\.(ru|net|com)$` the official docs describe - real
crawler traffic specifically lives under a `spider.` subdomain, distinct
from `yndx.net`/`storage.yandex.net` company infrastructure that also
technically matches the docs' broader suffix. Trusting the wider pattern
would risk treating non-crawler Yandex traffic as a verified bot. Only the
`.com` variant is configured since that's the only one actually observed -
`spider.yandex.ru`/`spider.yandex.net` haven't been validated against real
IPs, so don't assume they exist or follow the same convention without
checking first.

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
- **When validating from a *consuming* repo (e.g.
  `../containers/hyurservice`) right after pushing a fix here, pin the exact
  commit** - `xcaddy build --with github.com/hyurservice/caddy-fcrdns` (no
  version) resolves through Go's module proxy (`proxy.golang.org` by
  default), which can keep serving an already-cached "latest" for a bit
  after a fresh push, especially if an earlier build in the same session
  already resolved a lookup against this module. This produced a real,
  confusing failure once: a build appeared to use the just-pushed
  `CELLibrary` code but actually linked a commit from before it existed
  (`go version -m ./caddy | grep caddy-fcrdns` showed the wrong hash),
  which read exactly like `expression verify_fcrdns(...)` being broken when
  the module itself was fine. Use `--with
  github.com/hyurservice/caddy-fcrdns@<full-commit-hash>` to force fetching
  that exact commit and sidestep the ambiguity entirely - `go version -m` on
  the built binary is the way to confirm which commit actually got linked,
  not just trusting the build succeeded.

## Not yet done

- Yahoo Slurp and Amazonbot both need a real (non-community-sourced,
  non-historical) source of example IPs before they can be validated at all
  - guessing from IP ranges circulating online didn't work for either (see
  above).
- Facebook/Meta isn't addable at all right now, not just unvalidated - see
  above; there's no official pattern to implement against, unlike Yahoo/
  Amazonbot where the gap is just finding real example IPs.
- Wired into `../containers/hyurservice/caddy/Dockerfile` and its Caddyfile,
  merged to that repo's `master` (Baidu, Bing, and Yandex) - but that
  Caddyfile's `(allowed_crawlers)` snippet still uses the buggy
  `@name { header_regexp ...; verify_fcrdns ... }` pattern (see "The
  matcher-set ordering bug" above) and is currently **disabled** in that
  repo's live config while this fix lands. Needs to be rewritten to use
  `expression` and re-enabled - not done yet as of this module's CEL
  support landing.
- No CI configured.
