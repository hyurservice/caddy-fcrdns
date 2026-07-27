package caddyfcrdns

import (
	"strconv"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("verify_fcrdns", parseApp)
}

// UnmarshalCaddyfile parses:
//
//	verify_fcrdns <hostname_pattern> [<forward_policy>] [<unknown_policy>]
func (m *VerifyFCrDNS) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume the directive name

	if !d.NextArg() {
		return d.ArgErr()
	}
	m.HostnamePattern = d.Val()

	if d.NextArg() {
		m.ForwardPolicy = d.Val()
	}
	if d.NextArg() {
		m.UnknownPolicy = d.Val()
	}
	if d.NextArg() {
		return d.ArgErr()
	}

	return nil
}

// parseApp parses the global option block:
//
//	verify_fcrdns {
//	    cache_max_bytes <bytes>
//	    verified_ttl <duration>
//	    rejected_ttl <duration>
//	    unknown_ttl <duration>
//	    dns_timeout <duration>
//	}
func parseApp(d *caddyfile.Dispenser, _ any) (any, error) {
	app := &App{}

	if !d.Next() {
		return nil, d.Err("expected tokens")
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "cache_max_bytes":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			bytes, err := strconv.ParseInt(d.Val(), 10, 64)
			if err != nil {
				return nil, d.Errf("invalid cache_max_bytes %q: %v", d.Val(), err)
			}
			app.CacheMaxBytes = bytes
		case "verified_ttl":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.VerifiedTTL = d.Val()
		case "rejected_ttl":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.RejectedTTL = d.Val()
		case "unknown_ttl":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.UnknownTTL = d.Val()
		case "dns_timeout":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.DNSTimeout = d.Val()
		default:
			return nil, d.Errf("unrecognized verify_fcrdns option %q", d.Val())
		}
	}

	return httpcaddyfile.App{
		Name:  "verify_fcrdns",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}
