package caddyfcrdns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/hyurservice/caddy-fcrdns/fcrdns"
	"go.uber.org/zap"
)

func TestParseForwardPolicy(t *testing.T) {
	tests := []struct {
		in      string
		want    fcrdns.ForwardConfirmPolicy
		wantErr bool
	}{
		{"", fcrdns.RequireForwardConfirm, false}, // default: the stricter option
		{"require_forward_confirm", fcrdns.RequireForwardConfirm, false},
		{"allow_forward_failure", fcrdns.AllowForwardFailure, false},
		{"bogus", 0, true},
	}
	for _, tt := range tests {
		got, err := parseForwardPolicy(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseForwardPolicy(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err == nil && got != tt.want {
			t.Errorf("parseForwardPolicy(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseUnknownPolicy(t *testing.T) {
	tests := []struct {
		in      string
		want    fcrdns.UnknownPolicy
		wantErr bool
	}{
		{"", fcrdns.RejectUnknown, false}, // default: the stricter option
		{"reject_unknown", fcrdns.RejectUnknown, false},
		{"accept_unknown", fcrdns.AcceptUnknown, false},
		{"bogus", 0, true},
	}
	for _, tt := range tests {
		got, err := parseUnknownPolicy(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseUnknownPolicy(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err == nil && got != tt.want {
			t.Errorf("parseUnknownPolicy(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestUnmarshalCaddyfile_OnlyHostnamePatternRequired(t *testing.T) {
	d := caddyfile.NewTestDispenser(`verify_fcrdns \.crawl\.baidu\.com$`)
	var m VerifyFCrDNS
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if m.HostnamePattern != `\.crawl\.baidu\.com$` {
		t.Errorf("HostnamePattern = %q, want the pattern", m.HostnamePattern)
	}
	if m.ForwardPolicy != "" {
		t.Errorf("ForwardPolicy = %q, want empty (so Provision applies the require_forward_confirm default)", m.ForwardPolicy)
	}
	if m.UnknownPolicy != "" {
		t.Errorf("UnknownPolicy = %q, want empty (so Provision applies the reject_unknown default)", m.UnknownPolicy)
	}
}

func TestUnmarshalCaddyfile_AllThreeArgs(t *testing.T) {
	d := caddyfile.NewTestDispenser(`verify_fcrdns \.crawl\.baidu\.com$ allow_forward_failure accept_unknown`)
	var m VerifyFCrDNS
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if m.ForwardPolicy != "allow_forward_failure" {
		t.Errorf("ForwardPolicy = %q, want %q", m.ForwardPolicy, "allow_forward_failure")
	}
	if m.UnknownPolicy != "accept_unknown" {
		t.Errorf("UnknownPolicy = %q, want %q", m.UnknownPolicy, "accept_unknown")
	}
}

func TestUnmarshalCaddyfile_TooManyArgsIsAnError(t *testing.T) {
	d := caddyfile.NewTestDispenser(`verify_fcrdns pattern require_forward_confirm reject_unknown extra`)
	var m VerifyFCrDNS
	if err := m.UnmarshalCaddyfile(d); err == nil {
		t.Error("expected an error for a fourth positional argument, got nil")
	}
}

func TestUnmarshalCaddyfile_MissingHostnamePatternIsAnError(t *testing.T) {
	d := caddyfile.NewTestDispenser(`verify_fcrdns`)
	var m VerifyFCrDNS
	if err := m.UnmarshalCaddyfile(d); err == nil {
		t.Error("expected an error when hostname_pattern is missing, got nil")
	}
}

func TestMatchWithError_NoClientIPIsAnError(t *testing.T) {
	app := newTestApp(t, fakeResolver{names: []string{"host.crawl.baidu.com."}})
	m := VerifyFCrDNS{
		HostnamePattern: `\.crawl\.baidu\.com$`,
		hostnameRe:      mustPattern(t, `\.crawl\.baidu\.com$`),
		forwardPolicy:   fcrdns.AllowForwardFailure,
		app:             app,
		logger:          zap.NewNop(),
	}

	// No VarsCtxKey in context at all, so GetVar(ClientIPVarKey) can't find
	// an IP - matches what a real request looks like if trusted_proxies (or
	// the vars middleware generally) isn't set up correctly.
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	allowed, err := m.MatchWithError(req)
	if err == nil {
		t.Fatal("expected an error when no client IP is available, got nil")
	}
	if allowed {
		t.Error("allowed = true, want false alongside the error")
	}

	// Match (the plain-bool wrapper) must not panic on this same input -
	// it should just discard the error and report false.
	if m.Match(req) {
		t.Error("Match() = true, want false")
	}
}

func TestMatchWithError_WithClientIP(t *testing.T) {
	app := newTestApp(t, fakeResolver{names: []string{"host.crawl.baidu.com."}})
	m := VerifyFCrDNS{
		HostnamePattern: `\.crawl\.baidu\.com$`,
		hostnameRe:      mustPattern(t, `\.crawl\.baidu\.com$`),
		forwardPolicy:   fcrdns.AllowForwardFailure,
		unknownPolicy:   fcrdns.RejectUnknown,
		app:             app,
		logger:          zap.NewNop(),
	}

	vars := map[string]any{caddyhttp.ClientIPVarKey: "1.2.3.4"}
	ctx := context.WithValue(context.Background(), caddyhttp.VarsCtxKey, vars)
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)

	allowed, err := m.MatchWithError(req)
	if err != nil {
		t.Fatalf("MatchWithError: %v", err)
	}
	if !allowed {
		t.Error("allowed = false, want true (fakeResolver's PTR name matches the pattern)")
	}
}
