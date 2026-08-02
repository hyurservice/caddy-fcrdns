# caddy-fcrdns

A [Caddy](https://caddyserver.com) module that verifies a request's claimed
identity using forward-confirmed reverse DNS (FCrDNS) - the same technique
Google, Bing, Yahoo, and Baidu document for verifying their own crawlers.

## Why

Some crawlers (Google, Bing, Anthropic, OpenAI, and others) publish a static
list of their IP ranges, so verifying them is just an IP-list membership
check. Others - Baidu, Yahoo Slurp, Amazonbot - don't publish one at all, and
instead document reverse-DNS verification: check that the request's source
IP has a PTR record ending in a known suffix (e.g. `.crawl.yahoo.net`), and
optionally confirm that hostname's forward (A/AAAA) lookup resolves back to
the same IP.

This module implements that check as a Caddy HTTP request matcher, so it can
be composed into ordinary Caddyfile logic (allow verified crawlers to skip a
WAF/rate-limit/bot-challenge pipeline; treat a *failed* verification as a
stronger signal than an unverified one; etc).

## Installation

Build with [xcaddy](https://github.com/caddyserver/xcaddy), pinned to a
[tagged release](https://github.com/hyurservice/caddy-fcrdns/tags) rather
than left unversioned:

```shell
xcaddy build --with github.com/hyurservice/caddy-fcrdns@v0.1.0
```

An unversioned `--with` resolves "latest" through Go's module proxy on
every build, which can lag behind a just-pushed commit for a while - and
in a Docker build, a floating version string also gives the build-layer
cache no signal that a rebuild should actually pick up a new release.
Pinning avoids both.

## Usage

Configure the shared cache/timeout settings once, globally:

```caddyfile
{
    verify_fcrdns {
        cache_max_bytes 10000000
        verified_ttl 24h
        rejected_ttl 1h
        unknown_ttl 1m
        dns_timeout 2s
    }
}
```

All of the above are optional; see [Global options](#global-options) for
defaults. Then use the `verify_fcrdns` matcher, gated behind a cheap
User-Agent pre-filter so the DNS check only runs for traffic actually
claiming to be the crawler in question - via `expression`, combining both
conditions with `&&`, **not** by putting `header_regexp` and `verify_fcrdns`
in the same `@name { }` block (see the warning below for why that matters):

```caddyfile
example.com {
    @googlebot_verified {
        expression `header_regexp('User-Agent', '(?i)googlebot') && verify_fcrdns('\.googlebot\.com$')`
    }

    handle @googlebot_verified {
        # skip your WAF/rate-limit/challenge pipeline for confirmed crawlers
    }
    handle {
        # everyone else, including UAs that claim to be Googlebot but
        # don't verify
    }
}
```

(Google and Bing both publish static IP ranges too, which is a simpler
alternative when available - see the ["Why"](#why) section. Googlebot is
used here purely as a widely-recognized illustration of the technique.)

> [!WARNING]
> **Don't write `@name { header_regexp ...; verify_fcrdns ... }`** (multiple
> matcher *types* combined in one Caddyfile matcher block) expecting
> `header_regexp` to always run first and short-circuit the DNS lookup for
> non-matching traffic. Caddy loads a matcher block's conditions from a Go
> map internally, and Go map iteration order is randomized - so which
> condition runs first is decided arbitrarily once, at config load/reload
> time, and can just as easily put `verify_fcrdns` first. When that happens,
> *every* request triggers a DNS lookup regardless of User-Agent, not just
> ones claiming to be the crawler - silently defeating the entire point of
> the pre-filter. This isn't hypothetical: it was found in a real production
> deployment, where two IPs whose requests never claimed to be a crawler at
> all still showed up in the `verify_fcrdns` cache as rejected. `expression`
> with CEL's `&&` doesn't have this problem - CEL guarantees left-to-right
> short-circuit evaluation by language spec, unlike Caddy's matcher-set
> loading. See CLAUDE.md for the full writeup, including how this was
> diagnosed. (A bare `verify_fcrdns <pattern>` with nothing else in its
> matcher block is unaffected either way - the hazard is specifically about
> *combining* it with another matcher type for a pre-filter.)

### Distinguishing a confirmed spoof from an inconclusive check

`verify_fcrdns` collapses to a single boolean, so by itself it can't tell you
*why* a request didn't match - a hostname that definitively doesn't match
the expected pattern, and a DNS lookup that merely timed out, both come back
`false` if `unknown_policy` is `reject_unknown`. If you want to treat a
confirmed spoof more aggressively (e.g. an outright `abort`) while treating
an inconclusive lookup like ordinary unverified traffic, call the matcher
twice with opposite `unknown_policy` values and compose with `!` (again via
`expression`, for the same short-circuit-ordering reason as above):

```caddyfile
@googlebot_confirmed_spoof {
    expression `header_regexp('User-Agent', '(?i)googlebot') && !verify_fcrdns('\.googlebot\.com$', 'require_forward_confirm', 'accept_unknown')`
}

handle @googlebot_confirmed_spoof {
    abort
}
```

With `accept_unknown`, the matcher returns `true` for both a confirmed pass
*and* an inconclusive result - the only way it returns `false` is a
confirmed mismatch. So `!(...)` is true precisely on a confirmed spoof.
The second call is a cache hit rather than a second DNS round-trip (see
[Caching](#caching)).

## Matcher syntax

```caddyfile
verify_fcrdns <hostname_pattern> [<forward_policy>] [<unknown_policy>]
```

| Argument | Values | Default | Meaning |
|---|---|---|---|
| `hostname_pattern` | a regular expression | *(required)* | Checked against the client IP's PTR hostname(s) |
| `forward_policy` | `require_forward_confirm` \| `allow_forward_failure` | `require_forward_confirm` | Whether a successful forward (A/AAAA) lookup resolving back to the original IP is mandatory, or whether a PTR hostname match is sufficient on its own |
| `unknown_policy` | `reject_unknown` \| `accept_unknown` | `reject_unknown` | Whether a DNS timeout/transient error is treated as not-allowed or allowed |

Both policy arguments default to the stricter option, so
`verify_fcrdns <hostname_pattern>` alone is a safe, complete matcher.

`verify_fcrdns` is also usable from `expression` (CEL) matchers, as
`verify_fcrdns(pattern)`, `verify_fcrdns(pattern, forward_policy)`, or
`verify_fcrdns(pattern, forward_policy, unknown_policy)` - see the warning
above for why this, not a combined `@name { header_regexp ...; verify_fcrdns
... }` block, is the right way to pair it with a User-Agent pre-filter.

`allow_forward_failure` exists because some real crawlers don't maintain a
forward record for every dynamically-generated PTR hostname - confirmed
against live Baidu infrastructure: `220.181.108.108`'s PTR hostname forward-
confirms cleanly, but `180.76.15.15`'s PTR hostname has no forward record at
all (NXDOMAIN), despite both being real Baidu crawler IPs.

## Global options

Configured once, in a `verify_fcrdns { }` block at the top of the Caddyfile:

| Option | Default | Meaning |
|---|---|---|
| `cache_max_bytes` | 10 MiB | Estimated memory bound for the shared result cache |
| `verified_ttl` | `24h` | How long a confirmed pass is cached |
| `rejected_ttl` | `1h` | How long a confirmed mismatch is cached |
| `unknown_ttl` | `1m` | How long an inconclusive (timeout/error) result is cached - kept short so a transient DNS blip doesn't stick |
| `dns_timeout` | `2s` | Bound on a single verification's DNS lookups (PTR, and forward if applicable) |

## Caching

Every verification is cached, keyed by `(ip, hostname_pattern,
forward_policy)` - deliberately *not* including `unknown_policy`, so the
two-call composition pattern above shares one cache entry instead of
triggering two lookups. Concurrent requests for the same key are
deduplicated (only one actual DNS lookup runs; others wait for its result),
and the cache is bounded by estimated memory (`cache_max_bytes`), evicting
via a cost-aware admission policy - relevant because this cache's keys are
derived from request source IPs, which are attacker-influenceable.

## Admin API

While Caddy is running, `GET /verify_fcrdns/cache` on the [admin
API](https://caddyserver.com/docs/api) lists the shared cache's contents -
similar in spirit to CrowdSec's `cscli decisions list` - ordered by
descending hit count, so you can see at a glance which IPs/patterns are
actually being checked repeatedly:

```shell
curl 'http://localhost:2019/verify_fcrdns/cache?limit=5'
```

```json
{
  "total_entries": 4821,
  "returned": 2,
  "entries": [
    {
      "ip": "66.249.66.1",
      "hostname_pattern": "\\.googlebot\\.com$",
      "forward_policy": "require_forward_confirm",
      "outcome": "verified",
      "matched_hostname": "crawl-66-249-66-1.googlebot.com",
      "forward_checked": true,
      "hits": 1842,
      "expires_in": "18h32m10s"
    },
    {
      "ip": "203.0.113.42",
      "hostname_pattern": "\\.crawl\\.baidu\\.com$",
      "forward_policy": "allow_forward_failure",
      "outcome": "unknown",
      "forward_checked": false,
      "error": "context deadline exceeded",
      "hits": 47,
      "expires_in": "38s"
    }
  ]
}
```

Add `&format=table` for a human-readable rendering instead:

```shell
curl 'http://localhost:2019/verify_fcrdns/cache?limit=5&format=table'
```

```
┌─────────────────┬──────────────────────┬─────────────────────────┬──────────┬──────────────────────────────────────────┬─────┬──────┬─────────┬────────────────────────────────────┐
│       IP        │       PATTERN        │         POLICY          │ OUTCOME  │                 HOSTNAME                 │ FWD │ HITS │ EXPIRES │               ERROR                │
├─────────────────┼──────────────────────┼─────────────────────────┼──────────┼──────────────────────────────────────────┼─────┼──────┼─────────┼────────────────────────────────────┤
│ 66.249.66.1     │ \.googlebot\.com$    │ require_forward_confirm │ verified │ crawl-66-249-66-1.googlebot.com.         │ yes │ 1842 │ 24h0m0s │ -                                  │
│ 220.181.108.108 │ \.crawl\.baidu\.com$ │ allow_forward_failure   │ verified │ baiduspider-220-181-108-108.crawl.bai... │ no  │ 903  │ 24h0m0s │ -                                  │
│ 198.51.100.7    │ \.crawl\.baidu\.com$ │ allow_forward_failure   │ rejected │ -                                        │ no  │ 210  │ 1h0m0s  │ -                                  │
│ 203.0.113.42    │ \.crawl\.baidu\.com$ │ allow_forward_failure   │ unknown  │ -                                        │ no  │ 47   │ 1m0s    │ lookup : context deadline exceeded │
└─────────────────┴──────────────────────┴─────────────────────────┴──────────┴──────────────────────────────────────────┴─────┴──────┴─────────┴────────────────────────────────────┘

showing 4 of 4 entries
```

In an actual terminal, `rejected` renders in yellow and `unknown` (plus its
`ERROR` text) in red, so a confirmed mismatch and an inconclusive DNS result
stand out from `verified` at a glance - colors are forced on regardless of
whether Caddy's own process is attached to a terminal, since that has no
bearing on whether the `curl` caller viewing this wants color. Pass
`&colors=no` to get plain text instead (e.g. for a client/terminal that
doesn't interpret ANSI codes, which would otherwise show the raw escape
bytes rather than an absence of color).

`limit` defaults to 20; there's no server-side cap, and `&limit=inf` returns
every currently-cached entry. `total_entries` always reflects the full cache
regardless of `limit`, so you can tell "am I seeing everything, or just the
top few". `hits` counts every `Verify` call for that key - cache hits and
fresh lookups alike, including concurrent requests deduplicated against an
in-flight lookup - not just cache hits. This is a read-only view; nothing on
the actual `Verify` path reads from it.

## Logging

Provisioning logs the resolved configuration at `info` level. Each
`verify_fcrdns` match logs at `debug` level: client IP, both policies, the
outcome, whether it was a cache hit, the matched PTR hostname (if any), and
the underlying DNS error (if any) - enough to answer "why did this specific
request get this outcome" without adding instrumentation. Debug logging is
off by default (per Caddy's usual logging config) since this fires on every
request that passes the User-Agent pre-filter.

## Package layout

- `fcrdns/` - the actual FCrDNS verification logic, its cache, and the
  cache's observability index (`index.go`). Pure Go, no dependency on
  Caddy, HTTP, User-Agents, or crawlers - a general-purpose verification
  primitive usable outside Caddy entirely.
- `app.go`, `matcher.go`, `caddyfile.go` - the Caddy-specific glue: the
  global app (shared cache/config), the HTTP request matcher, and Caddyfile
  parsing for both.
- `adminapi.go` - the `GET /verify_fcrdns/cache` admin API endpoint (see
  [Admin API](#admin-api)).

## Development

```shell
go test ./...          # unit tests (fcrdns package uses a fake resolver; no network access needed)
go vet ./...
gofmt -l .
```

Since this is a Caddy module, `go build`/`go test` only prove the Go code is
valid - they don't prove the Caddyfile-facing configuration actually works.
Validate that by building a real Caddy binary with xcaddy against a local
copy of this repo and exercising it with real requests:

```shell
xcaddy build --with github.com/hyurservice/caddy-fcrdns=/path/to/local/checkout
./caddy adapt --config Caddyfile --adapter caddyfile   # confirms the config parses
./caddy run --config Caddyfile --adapter caddyfile     # then curl it
```

Caddy buffers log writes for a few seconds before flushing - if debug logs
don't appear immediately, wait a little before concluding logging is broken.
