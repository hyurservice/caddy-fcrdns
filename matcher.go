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

	forwardPolicy, err := parseForwardPolicy(m.ForwardPolicy)
	if err != nil {
		return err
	}
	m.forwardPolicy = forwardPolicy

	unknownPolicy, err := parseUnknownPolicy(m.UnknownPolicy)
	if err != nil {
		return err
	}
	m.unknownPolicy = unknownPolicy

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

// Match satisfies caddyhttp.RequestMatcher. It's a thin wrapper around
// MatchWithError that discards the error, kept only so VerifyFCrDNS also
// satisfies the plain RequestMatcher interface - MatchWithError is what
// Caddy actually calls at runtime when both are implemented.
func (m VerifyFCrDNS) Match(r *http.Request) bool {
	match, _ := m.MatchWithError(r)
	return match
}

// MatchWithError satisfies caddyhttp.RequestMatcherWithError. An error here
// aborts the request into Caddy's error-handling middleware chain, so it's
// used narrowly: only for "no client IP available," a genuine server
// misconfiguration (e.g. trusted_proxies not set up correctly), not for any
// DNS outcome. A DNS timeout/failure is deliberately NOT an error - it's
// the Unknown outcome, resolved via unknown_policy like any other outcome;
// surfacing it as a Go error instead would abort the request regardless of
// unknown_policy, defeating the point of that setting.
func (m VerifyFCrDNS) MatchWithError(r *http.Request) (bool, error) {
	ip, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	if !ok || ip == "" {
		return false, fmt.Errorf("verify_fcrdns: no client IP available")
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

	return allowed, nil
}

// parseForwardPolicy maps a Caddyfile forward_policy token to its enum
// value. An empty string (the argument was omitted) defaults to
// RequireForwardConfirm - the stricter of the two - so that a bare
// `verify_fcrdns <hostname_pattern>` with no further arguments is safe by
// default rather than silently lenient.
func parseForwardPolicy(s string) (fcrdns.ForwardConfirmPolicy, error) {
	switch s {
	case "", "require_forward_confirm":
		return fcrdns.RequireForwardConfirm, nil
	case "allow_forward_failure":
		return fcrdns.AllowForwardFailure, nil
	default:
		return 0, fmt.Errorf("invalid forward_policy %q: must be require_forward_confirm or allow_forward_failure", s)
	}
}

// parseUnknownPolicy maps a Caddyfile unknown_policy token to its enum
// value. An empty string (the argument was omitted) defaults to
// RejectUnknown - the stricter of the two - for the same reason as
// parseForwardPolicy.
func parseUnknownPolicy(s string) (fcrdns.UnknownPolicy, error) {
	switch s {
	case "", "reject_unknown":
		return fcrdns.RejectUnknown, nil
	case "accept_unknown":
		return fcrdns.AcceptUnknown, nil
	default:
		return 0, fmt.Errorf("invalid unknown_policy %q: must be reject_unknown or accept_unknown", s)
	}
}

var (
	_ caddy.Module                      = (*VerifyFCrDNS)(nil)
	_ caddy.Provisioner                 = (*VerifyFCrDNS)(nil)
	_ caddyhttp.RequestMatcher          = (*VerifyFCrDNS)(nil)
	_ caddyhttp.RequestMatcherWithError = (*VerifyFCrDNS)(nil)
)
