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

Build with [xcaddy](https://github.com/caddyserver/xcaddy):

```shell
xcaddy build --with github.com/hyurservice/caddy-fcrdns
```

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
claiming to be the crawler in question:

```caddyfile
example.com {
    @googlebot_verified {
        header_regexp User-Agent `(?i)googlebot`
        verify_fcrdns `\.googlebot\.com$`
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

### Distinguishing a confirmed spoof from an inconclusive check

`verify_fcrdns` collapses to a single boolean, so by itself it can't tell you
*why* a request didn't match - a hostname that definitively doesn't match
the expected pattern, and a DNS lookup that merely timed out, both come back
`false` if `unknown_policy` is `reject_unknown`. If you want to treat a
confirmed spoof more aggressively (e.g. an outright `abort`) while treating
an inconclusive lookup like ordinary unverified traffic, call the matcher
twice with opposite `unknown_policy` values and compose with `not`:

```caddyfile
@googlebot_confirmed_spoof {
    header_regexp User-Agent `(?i)googlebot`
    not verify_fcrdns `\.googlebot\.com$` require_forward_confirm accept_unknown
}

handle @googlebot_confirmed_spoof {
    abort
}
```

With `accept_unknown`, the matcher returns `true` for both a confirmed pass
*and* an inconclusive result - the only way it returns `false` is a
confirmed mismatch. So `not (...)` is true precisely on a confirmed spoof.
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

## Logging

Provisioning logs the resolved configuration at `info` level. Each
`verify_fcrdns` match logs at `debug` level: client IP, both policies, the
outcome, whether it was a cache hit, the matched PTR hostname (if any), and
the underlying DNS error (if any) - enough to answer "why did this specific
request get this outcome" without adding instrumentation. Debug logging is
off by default (per Caddy's usual logging config) since this fires on every
request that passes the User-Agent pre-filter.

## Package layout

- `fcrdns/` - the actual FCrDNS verification logic and its cache. Pure Go,
  no dependency on Caddy, HTTP, User-Agents, or crawlers - a general-purpose
  verification primitive usable outside Caddy entirely.
- `app.go`, `matcher.go`, `caddyfile.go` - the Caddy-specific glue: the
  global app (shared cache/config), the HTTP request matcher, and Caddyfile
  parsing for both.

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
