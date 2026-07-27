// Package caddyfcrdns wires the fcrdns package into Caddy: a global app
// holding shared configuration (DNS timeout, result cache) and an HTTP
// request matcher (verify_fcrdns) that uses it.
//
// This is deliberately thin. All FCrDNS logic lives in the fcrdns package
// and has no knowledge of Caddy, HTTP, User-Agents, or crawlers.
package caddyfcrdns

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/hyurservice/caddy-fcrdns/fcrdns"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(App{})
}

// App holds configuration shared by every verify_fcrdns matcher instance:
// the DNS resolver, per-lookup timeout, and result cache. Configure exactly
// one instance globally (see caddyfile.go for the `verify_fcrdns { }`
// global option block).
type App struct {
	// CacheMaxBytes bounds the shared result cache's estimated memory
	// usage. Defaults to fcrdns.DefaultMaxCacheBytes.
	CacheMaxBytes int64 `json:"cache_max_bytes,omitempty"`
	// VerifiedTTL, RejectedTTL, and UnknownTTL are Go duration strings
	// (e.g. "24h") controlling how long a cached outcome of each kind is
	// trusted. See fcrdns.CacheConfig for defaults and rationale.
	VerifiedTTL string `json:"verified_ttl,omitempty"`
	RejectedTTL string `json:"rejected_ttl,omitempty"`
	UnknownTTL  string `json:"unknown_ttl,omitempty"`
	// DNSTimeout bounds how long a single Verify call (PTR lookup plus, if
	// applicable, forward lookup) may take before being treated as
	// OutcomeUnknown. Defaults to 2s.
	DNSTimeout string `json:"dns_timeout,omitempty"`

	cache      *fcrdns.Cache
	dnsTimeout time.Duration
	logger     *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "verify_fcrdns",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision sets up the shared cache and resolver.
func (a *App) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger()

	cfg := fcrdns.DefaultCacheConfig()

	if a.CacheMaxBytes > 0 {
		cfg.MaxBytes = a.CacheMaxBytes
	}

	var err error
	if cfg.VerifiedTTL, err = parseDurationOrDefault(a.VerifiedTTL, cfg.VerifiedTTL); err != nil {
		return fmt.Errorf("invalid verified_ttl: %w", err)
	}
	if cfg.RejectedTTL, err = parseDurationOrDefault(a.RejectedTTL, cfg.RejectedTTL); err != nil {
		return fmt.Errorf("invalid rejected_ttl: %w", err)
	}
	if cfg.UnknownTTL, err = parseDurationOrDefault(a.UnknownTTL, cfg.UnknownTTL); err != nil {
		return fmt.Errorf("invalid unknown_ttl: %w", err)
	}

	a.dnsTimeout = 2 * time.Second
	if a.DNSTimeout != "" {
		d, err := time.ParseDuration(a.DNSTimeout)
		if err != nil {
			return fmt.Errorf("invalid dns_timeout %q: %w", a.DNSTimeout, err)
		}
		a.dnsTimeout = d
	}

	cache, err := fcrdns.NewCache(fcrdns.NetResolver{}, cfg)
	if err != nil {
		return fmt.Errorf("provisioning verify_fcrdns cache: %w", err)
	}
	a.cache = cache

	a.logger.Info("provisioned verify_fcrdns",
		zap.Int64("cache_max_bytes", cfg.MaxBytes),
		zap.Duration("verified_ttl", cfg.VerifiedTTL),
		zap.Duration("rejected_ttl", cfg.RejectedTTL),
		zap.Duration("unknown_ttl", cfg.UnknownTTL),
		zap.Duration("dns_timeout", a.dnsTimeout),
	)

	return nil
}

// Start implements caddy.App. There is no background work to start; the
// cache and resolver are ready as soon as Provision returns.
func (a *App) Start() error { return nil }

// Stop implements caddy.App, releasing the cache's background resources.
func (a *App) Stop() error {
	if a.cache != nil {
		a.cache.Close()
	}
	return nil
}

// Verify runs a cached FCrDNS check against ip, bounded by this app's
// configured DNS timeout. The returned bool is true if this call was
// served from the cache - see fcrdns.Cache.Verify for exactly what that
// means under concurrent, deduplicated calls.
func (a *App) Verify(ip string, hostnamePattern *regexp.Regexp, forwardPolicy fcrdns.ForwardConfirmPolicy) (fcrdns.Outcome, fcrdns.Detail, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), a.dnsTimeout)
	defer cancel()
	return a.cache.Verify(ctx, ip, hostnamePattern, forwardPolicy)
}

// parseDurationOrDefault parses s as a duration, returning def if s is empty.
func parseDurationOrDefault(s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	return time.ParseDuration(s)
}

var (
	_ caddy.Module      = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
	_ caddy.App         = (*App)(nil)
)
