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
- `app.go` / `matcher.go` / `caddyfile.go` (root package `caddyfcrdns`) are
  the *only* place Caddy-specific concerns belong: request handling, the
  User-Agent pre-filter, Caddyfile syntax, logging.
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

Yahoo Slurp (`crawl.yahoo.net`) has a documented pattern but hasn't been
checked against live DNS data yet (Yahoo's own site is gated behind a
CAPTCHA when queried directly, which may complicate finding real IPs to test
against) - do that before treating its config as validated, and add the
findings as tests the same way.

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

- Yahoo Slurp isn't validated against live data yet (see above).
- Amazonbot needs a real (non-community-sourced) source of example IPs
  before it can be validated at all (see above).
- Not wired into `../containers/hyurservice/caddy/Dockerfile` or its
  Caddyfile yet.
- No CI configured.
