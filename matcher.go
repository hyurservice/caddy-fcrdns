package caddyfcrdns

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/hyurservice/caddy-fcrdns/fcrdns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func init() {
	caddy.RegisterModule(VerifyFCrDNS{})
}

// VerifyFCrDNS is an HTTP request matcher that performs a forward-confirmed
// reverse DNS (FCrDNS) check on the request's client IP: it looks up the
// IP's PTR record(s), checks whether any hostname matches HostnamePattern,
// and (depending on ForwardPolicy) confirms that hostname's forward lookup
// resolves back to the IP.
//
// Caddyfile syntax:
//
//	verify_fcrdns <hostname_pattern> [<forward_policy>] [<unknown_policy>]
//
// forward_policy is "require_forward_confirm" (default) or
// "allow_forward_failure". unknown_policy is "reject_unknown" (default) or
// "accept_unknown". A global `verify_fcrdns { }` app block must be
// configured (see caddyfile.go) - that's where the shared cache, DNS
// timeout, and per-outcome TTLs live.
type VerifyFCrDNS struct {
	HostnamePattern string `json:"hostname_pattern,omitempty"`
	ForwardPolicy   string `json:"forward_policy,omitempty"`
	UnknownPolicy   string `json:"unknown_policy,omitempty"`

	hostnameRe    *regexp.Regexp
	forwardPolicy fcrdns.ForwardConfirmPolicy
	unknownPolicy fcrdns.UnknownPolicy
	app           *App
	logger        *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (VerifyFCrDNS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.verify_fcrdns",
		New: func() caddy.Module { return new(VerifyFCrDNS) },
	}
}

// Provision compiles the hostname pattern, validates the policy strings,
// and loads the shared verify_fcrdns app.
func (m *VerifyFCrDNS) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	re, err := regexp.Compile(m.HostnamePattern)
	if err != nil {
		return fmt.Errorf("invalid hostname_pattern %q: %w", m.HostnamePattern, err)
	}
	m.hostnameRe = re

	switch m.ForwardPolicy {
	case "", "require_forward_confirm":
		m.forwardPolicy = fcrdns.RequireForwardConfirm
	case "allow_forward_failure":
		m.forwardPolicy = fcrdns.AllowForwardFailure
	default:
		return fmt.Errorf("invalid forward_policy %q: must be require_forward_confirm or allow_forward_failure", m.ForwardPolicy)
	}

	switch m.UnknownPolicy {
	case "", "reject_unknown":
		m.unknownPolicy = fcrdns.RejectUnknown
	case "accept_unknown":
		m.unknownPolicy = fcrdns.AcceptUnknown
	default:
		return fmt.Errorf("invalid unknown_policy %q: must be reject_unknown or accept_unknown", m.UnknownPolicy)
	}

	appIface, err := ctx.App("verify_fcrdns")
	if err != nil {
		return fmt.Errorf("loading verify_fcrdns app (add a global `verify_fcrdns { }` block to the Caddyfile): %w", err)
	}
	app, ok := appIface.(*App)
	if !ok {
		return fmt.Errorf("verify_fcrdns app has unexpected type %T", appIface)
	}
	m.app = app

	return nil
}

// Match satisfies caddyhttp.RequestMatcher.
func (m VerifyFCrDNS) Match(r *http.Request) bool {
	ip, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	if !ok || ip == "" {
		if ce := m.logger.Check(zapcore.DebugLevel, "verify_fcrdns: no client IP available"); ce != nil {
			ce.Write()
		}
		return false
	}

	outcome, detail, cacheHit := m.app.Verify(ip, m.hostnameRe, m.forwardPolicy)
	allowed := outcome.Allowed(m.unknownPolicy)

	if ce := m.logger.Check(zapcore.DebugLevel, "verify_fcrdns"); ce != nil {
		fields := []zap.Field{
			zap.String("client_ip", ip),
			zap.String("hostname_pattern", m.HostnamePattern),
			zap.String("forward_policy", m.forwardPolicy.String()),
			zap.String("unknown_policy", m.unknownPolicy.String()),
			zap.String("outcome", outcome.String()),
			zap.Bool("allowed", allowed),
			zap.Bool("cache_hit", cacheHit),
			zap.Bool("forward_checked", detail.ForwardChecked),
		}
		if detail.MatchedHostname != "" {
			fields = append(fields, zap.String("matched_hostname", detail.MatchedHostname))
		}
		if detail.Err != nil {
			fields = append(fields, zap.Error(detail.Err))
		}
		ce.Write(fields...)
	}

	return allowed
}

var (
	_ caddy.Module             = (*VerifyFCrDNS)(nil)
	_ caddy.Provisioner        = (*VerifyFCrDNS)(nil)
	_ caddyhttp.RequestMatcher = (*VerifyFCrDNS)(nil)
)
