package fcrdns

import (
	"context"
	"errors"
	"net"
	"regexp"
	"testing"
)

// fakeResolver lets each test script exactly what LookupAddr/LookupHost
// should return, without any real network access.
type fakeResolver struct {
	lookupAddr func(ctx context.Context, ip string) ([]string, error)
	lookupHost func(ctx context.Context, host string) ([]string, error)
}

func (f fakeResolver) LookupAddr(ctx context.Context, ip string) ([]string, error) {
	return f.lookupAddr(ctx, ip)
}

func (f fakeResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return f.lookupHost(ctx, host)
}

func notFoundErr() error {
	return &net.DNSError{Err: "no such host", IsNotFound: true}
}

func timeoutErr() error {
	return &net.DNSError{Err: "i/o timeout", IsTimeout: true}
}

func mustPattern(t *testing.T, expr string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(expr)
	if err != nil {
		t.Fatalf("invalid pattern %q: %v", expr, err)
	}
	return re
}

func TestVerify_StrictPass(t *testing.T) {
	// Real-world example: 220.181.108.108 -> baiduspider-220-181-108-108.crawl.baidu.com,
	// which forward-confirms back to 220.181.108.108.
	resolver := fakeResolver{
		lookupAddr: func(ctx context.Context, ip string) ([]string, error) {
			return []string{"baiduspider-220-181-108-108.crawl.baidu.com."}, nil
		},
		lookupHost: func(ctx context.Context, host string) ([]string, error) {
			return []string{"220.181.108.108"}, nil
		},
	}
	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)

	got := Verify(context.Background(), resolver, "220.181.108.108", pattern, RequireForwardConfirm)
	if got != OutcomeVerified {
		t.Errorf("got %v, want %v", got, OutcomeVerified)
	}
}

func TestVerify_LenientPassDespiteForwardFailure(t *testing.T) {
	// Real-world example: 180.76.15.15 -> baiduspider-180-76-15-15.crawl.baidu.com,
	// but that hostname has no forward A record (NXDOMAIN). Confirmed by
	// live `host` lookups against Baidu's actual infrastructure.
	forwardLookupCalled := false
	resolver := fakeResolver{
		lookupAddr: func(ctx context.Context, ip string) ([]string, error) {
			return []string{"baiduspider-180-76-15-15.crawl.baidu.com."}, nil
		},
		lookupHost: func(ctx context.Context, host string) ([]string, error) {
			forwardLookupCalled = true
			return nil, notFoundErr()
		},
	}
	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)

	got := Verify(context.Background(), resolver, "180.76.15.15", pattern, AllowForwardFailure)
	if got != OutcomeVerified {
		t.Errorf("got %v, want %v", got, OutcomeVerified)
	}
	if forwardLookupCalled {
		t.Errorf("AllowForwardFailure should skip the forward lookup entirely, but it was called")
	}
}

func TestVerify_StrictRejectsSameHostnameWithoutForwardConfirm(t *testing.T) {
	// Same PTR data as above, but under the strict policy this must fail,
	// since there is no forward confirmation.
	resolver := fakeResolver{
		lookupAddr: func(ctx context.Context, ip string) ([]string, error) {
			return []string{"baiduspider-180-76-15-15.crawl.baidu.com."}, nil
		},
		lookupHost: func(ctx context.Context, host string) ([]string, error) {
			return nil, notFoundErr()
		},
	}
	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)

	got := Verify(context.Background(), resolver, "180.76.15.15", pattern, RequireForwardConfirm)
	if got != OutcomeRejected {
		t.Errorf("got %v, want %v", got, OutcomeRejected)
	}
}

func TestVerify_RejectedHostnameDoesNotMatchPattern(t *testing.T) {
	resolver := fakeResolver{
		lookupAddr: func(ctx context.Context, ip string) ([]string, error) {
			return []string{"some-host.evil-example.com."}, nil
		},
		lookupHost: func(ctx context.Context, host string) ([]string, error) {
			t.Fatalf("forward lookup should not be attempted when no PTR name matches")
			return nil, nil
		},
	}
	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)

	got := Verify(context.Background(), resolver, "1.2.3.4", pattern, AllowForwardFailure)
	if got != OutcomeRejected {
		t.Errorf("got %v, want %v", got, OutcomeRejected)
	}
}

func TestVerify_RejectedNoPTRRecord(t *testing.T) {
	resolver := fakeResolver{
		lookupAddr: func(ctx context.Context, ip string) ([]string, error) {
			return nil, notFoundErr()
		},
		lookupHost: func(ctx context.Context, host string) ([]string, error) {
			t.Fatalf("forward lookup should not be attempted when PTR lookup fails")
			return nil, nil
		},
	}
	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)

	got := Verify(context.Background(), resolver, "1.2.3.4", pattern, AllowForwardFailure)
	if got != OutcomeRejected {
		t.Errorf("got %v, want %v", got, OutcomeRejected)
	}
}

func TestVerify_RejectedForwardResolvesToDifferentIP(t *testing.T) {
	resolver := fakeResolver{
		lookupAddr: func(ctx context.Context, ip string) ([]string, error) {
			return []string{"spoofed.crawl.baidu.com."}, nil
		},
		lookupHost: func(ctx context.Context, host string) ([]string, error) {
			return []string{"9.9.9.9"}, nil
		},
	}
	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)

	got := Verify(context.Background(), resolver, "1.2.3.4", pattern, RequireForwardConfirm)
	if got != OutcomeRejected {
		t.Errorf("got %v, want %v", got, OutcomeRejected)
	}
}

func TestVerify_ForwardConfirmIPv6Equivalence(t *testing.T) {
	// Same address, different textual representation - must compare as
	// parsed IPs, not raw strings.
	resolver := fakeResolver{
		lookupAddr: func(ctx context.Context, ip string) ([]string, error) {
			return []string{"host.crawl.baidu.com."}, nil
		},
		lookupHost: func(ctx context.Context, host string) ([]string, error) {
			return []string{"2001:0db8:0000:0000:0000:0000:0000:0001"}, nil
		},
	}
	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)

	got := Verify(context.Background(), resolver, "2001:db8::1", pattern, RequireForwardConfirm)
	if got != OutcomeVerified {
		t.Errorf("got %v, want %v", got, OutcomeVerified)
	}
}

func TestVerify_UnknownOnPTRTimeout(t *testing.T) {
	resolver := fakeResolver{
		lookupAddr: func(ctx context.Context, ip string) ([]string, error) {
			return nil, timeoutErr()
		},
		lookupHost: func(ctx context.Context, host string) ([]string, error) {
			t.Fatalf("forward lookup should not be attempted when PTR lookup times out")
			return nil, nil
		},
	}
	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)

	got := Verify(context.Background(), resolver, "1.2.3.4", pattern, AllowForwardFailure)
	if got != OutcomeUnknown {
		t.Errorf("got %v, want %v", got, OutcomeUnknown)
	}
}

func TestVerify_UnknownOnForwardTimeout(t *testing.T) {
	resolver := fakeResolver{
		lookupAddr: func(ctx context.Context, ip string) ([]string, error) {
			return []string{"host.crawl.baidu.com."}, nil
		},
		lookupHost: func(ctx context.Context, host string) ([]string, error) {
			return nil, timeoutErr()
		},
	}
	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)

	got := Verify(context.Background(), resolver, "1.2.3.4", pattern, RequireForwardConfirm)
	if got != OutcomeUnknown {
		t.Errorf("got %v, want %v", got, OutcomeUnknown)
	}
}

func TestVerify_UnknownWhenContextDeadlineExceeded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	resolver := fakeResolver{
		lookupAddr: func(ctx context.Context, ip string) ([]string, error) {
			return nil, errors.New("some generic resolver error")
		},
		lookupHost: func(ctx context.Context, host string) ([]string, error) {
			return nil, nil
		},
	}
	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)

	got := Verify(ctx, resolver, "1.2.3.4", pattern, AllowForwardFailure)
	if got != OutcomeUnknown {
		t.Errorf("got %v, want %v", got, OutcomeUnknown)
	}
}

func TestVerify_UnknownOnUnrecognizedErrorType(t *testing.T) {
	// A generic (non-*net.DNSError) error, with no context deadline
	// involved, should default to Unknown rather than being confidently
	// treated as Rejected.
	resolver := fakeResolver{
		lookupAddr: func(ctx context.Context, ip string) ([]string, error) {
			return nil, errors.New("something unexpected happened")
		},
		lookupHost: func(ctx context.Context, host string) ([]string, error) {
			return nil, nil
		},
	}
	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)

	got := Verify(context.Background(), resolver, "1.2.3.4", pattern, AllowForwardFailure)
	if got != OutcomeUnknown {
		t.Errorf("got %v, want %v", got, OutcomeUnknown)
	}
}

func TestVerify_TrailingDotInPTRNameIsNormalized(t *testing.T) {
	resolver := fakeResolver{
		lookupAddr: func(ctx context.Context, ip string) ([]string, error) {
			return []string{"host.crawl.baidu.com."}, nil
		},
		lookupHost: func(ctx context.Context, host string) ([]string, error) {
			return []string{"1.2.3.4"}, nil
		},
	}
	// Pattern anchored at end-of-string; would fail to match if the
	// trailing "." from the PTR record weren't stripped first.
	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)

	got := Verify(context.Background(), resolver, "1.2.3.4", pattern, RequireForwardConfirm)
	if got != OutcomeVerified {
		t.Errorf("got %v, want %v", got, OutcomeVerified)
	}
}

func TestOutcome_Allowed(t *testing.T) {
	tests := []struct {
		outcome Outcome
		policy  UnknownPolicy
		want    bool
	}{
		{OutcomeVerified, RejectUnknown, true},
		{OutcomeVerified, AcceptUnknown, true},
		{OutcomeRejected, RejectUnknown, false},
		{OutcomeRejected, AcceptUnknown, false},
		{OutcomeUnknown, RejectUnknown, false},
		{OutcomeUnknown, AcceptUnknown, true},
	}
	for _, tt := range tests {
		got := tt.outcome.Allowed(tt.policy)
		if got != tt.want {
			t.Errorf("Outcome(%v).Allowed(%v) = %v, want %v", tt.outcome, tt.policy, got, tt.want)
		}
	}
}
