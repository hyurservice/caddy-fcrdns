// Package fcrdns implements forward-confirmed reverse DNS (FCrDNS)
// verification: given a source IP and an expected hostname pattern, it
// checks whether the IP's PTR record matches that pattern and, optionally,
// whether the matched hostname's forward (A/AAAA) lookup resolves back to
// the original IP.
//
// This package has no knowledge of HTTP, Caddy, User-Agents, or crawlers -
// it is a general-purpose verification primitive. Anything crawler-specific
// (which requests to check, which hostname pattern applies to which
// service) belongs in the caller.
package fcrdns

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
)

// Resolver abstracts the DNS operations Verify needs, so callers can supply
// a custom resolver (e.g. pointed at a specific DNS server) and so tests can
// substitute a fake implementation without making real network calls.
type Resolver interface {
	// LookupAddr returns the PTR names for the given IP address.
	LookupAddr(ctx context.Context, ip string) (names []string, err error)
	// LookupHost returns the A/AAAA addresses for the given hostname.
	LookupHost(ctx context.Context, host string) (addrs []string, err error)
}

// NetResolver adapts *net.Resolver to the Resolver interface. The zero value
// uses net.DefaultResolver.
type NetResolver struct {
	Resolver *net.Resolver
}

func (r NetResolver) resolver() *net.Resolver {
	if r.Resolver != nil {
		return r.Resolver
	}
	return net.DefaultResolver
}

func (r NetResolver) LookupAddr(ctx context.Context, ip string) ([]string, error) {
	return r.resolver().LookupAddr(ctx, ip)
}

func (r NetResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return r.resolver().LookupHost(ctx, host)
}

// ForwardConfirmPolicy controls whether Verify requires a successful forward
// (A/AAAA) lookup that resolves back to the original IP, or tolerates that
// step failing/being absent.
type ForwardConfirmPolicy int

const (
	// RequireForwardConfirm requires the matched hostname's forward lookup
	// to resolve back to the original IP for the outcome to be Verified.
	RequireForwardConfirm ForwardConfirmPolicy = iota
	// AllowForwardFailure accepts a PTR hostname match as sufficient on its
	// own, even if the forward lookup fails, is absent (NXDOMAIN), or
	// resolves to a different address. Some legitimate crawlers don't
	// maintain a forward record for every dynamically-generated PTR
	// hostname - see the package-level tests for a real example.
	AllowForwardFailure
)

func (p ForwardConfirmPolicy) String() string {
	if p == AllowForwardFailure {
		return "allow_forward_failure"
	}
	return "require_forward_confirm"
}

// UnknownPolicy controls how Outcome.Allowed treats an inconclusive lookup
// (DNS timeout or transient error) - as opposed to a confirmed match or
// confirmed mismatch, which are unaffected by this policy.
type UnknownPolicy int

const (
	// RejectUnknown treats an inconclusive lookup as not allowed.
	RejectUnknown UnknownPolicy = iota
	// AcceptUnknown treats an inconclusive lookup as allowed.
	AcceptUnknown
)

func (p UnknownPolicy) String() string {
	if p == AcceptUnknown {
		return "accept_unknown"
	}
	return "reject_unknown"
}

// Outcome is the result of a verification attempt, independent of any
// policy about how to treat it.
type Outcome int

const (
	// OutcomeVerified means the PTR hostname matched the expected pattern,
	// and (if required) the forward lookup confirmed it.
	OutcomeVerified Outcome = iota
	// OutcomeRejected means the lookups completed but did not confirm a
	// match - the PTR hostname didn't match the pattern, there was no PTR
	// record at all, or (under RequireForwardConfirm) the forward lookup
	// didn't resolve back to the original IP.
	OutcomeRejected
	// OutcomeUnknown means a lookup timed out or hit a transient error, so
	// no confident pass/fail determination could be made.
	OutcomeUnknown
)

func (o Outcome) String() string {
	switch o {
	case OutcomeVerified:
		return "verified"
	case OutcomeRejected:
		return "rejected"
	case OutcomeUnknown:
		return "unknown"
	default:
		return "invalid"
	}
}

// Allowed collapses an Outcome to a boolean using unknownPolicy to decide
// how OutcomeUnknown is treated. OutcomeVerified is always allowed;
// OutcomeRejected is never allowed.
func (o Outcome) Allowed(unknownPolicy UnknownPolicy) bool {
	switch o {
	case OutcomeVerified:
		return true
	case OutcomeUnknown:
		return unknownPolicy == AcceptUnknown
	default:
		return false
	}
}

// Detail carries additional information about a Verify call, useful for
// logging/debugging. It plays no role in Outcome or Allowed's decisions.
type Detail struct {
	// MatchedHostname is the PTR hostname that matched hostnamePattern, if
	// any.
	MatchedHostname string
	// ForwardChecked is true if a forward lookup was attempted (i.e. a PTR
	// hostname matched, and forwardPolicy was RequireForwardConfirm).
	ForwardChecked bool
	// Err is the underlying error from whichever lookup produced a
	// non-Verified outcome, if any.
	Err error
}

// Verify performs a forward-confirmed reverse DNS check on ip: it looks up
// ip's PTR record(s), checks whether any of the returned hostnames match
// hostnamePattern, and - depending on forwardPolicy - confirms that
// hostname's forward lookup resolves back to ip.
//
// ctx should carry a deadline; Verify does not impose its own timeout.
func Verify(ctx context.Context, resolver Resolver, ip string, hostnamePattern *regexp.Regexp, forwardPolicy ForwardConfirmPolicy) (Outcome, Detail) {
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil {
		return outcomeForLookupError(ctx, err), Detail{Err: err}
	}

	matched := ""
	for _, name := range names {
		if hostnamePattern.MatchString(strings.TrimSuffix(name, ".")) {
			matched = name
			break
		}
	}
	if matched == "" {
		return OutcomeRejected, Detail{}
	}

	if forwardPolicy == AllowForwardFailure {
		return OutcomeVerified, Detail{MatchedHostname: matched}
	}

	addrs, err := resolver.LookupHost(ctx, matched)
	if err != nil {
		return outcomeForLookupError(ctx, err), Detail{MatchedHostname: matched, ForwardChecked: true, Err: err}
	}

	target := net.ParseIP(ip)
	for _, addr := range addrs {
		if parsed := net.ParseIP(addr); parsed != nil && target != nil && parsed.Equal(target) {
			return OutcomeVerified, Detail{MatchedHostname: matched, ForwardChecked: true}
		}
	}
	return OutcomeRejected, Detail{MatchedHostname: matched, ForwardChecked: true}
}

// outcomeForLookupError classifies a DNS lookup error as either a confirmed
// rejection (e.g. NXDOMAIN - there's a definitive answer, and it's "no
// record") or an inconclusive/unknown result (timeout or other transient
// condition). Unrecognized error shapes are treated as unknown rather than
// rejected, since we can't be confident it's a definitive "no" rather than
// some other resolver hiccup.
func outcomeForLookupError(ctx context.Context, err error) Outcome {
	if ctx.Err() != nil {
		// Our own deadline fired.
		return OutcomeUnknown
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout || dnsErr.IsTemporary {
			return OutcomeUnknown
		}
		if dnsErr.IsNotFound {
			return OutcomeRejected
		}
	}
	return OutcomeUnknown
}
