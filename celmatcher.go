package caddyfcrdns

import (
	"fmt"
	"reflect"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// stringSliceType mirrors caddyhttp's own (unexported) helper of the same
// name, used to convert a CEL string-list value into a Go []string.
var stringSliceType = reflect.TypeFor[[]string]()

// CELLibrary exposes verify_fcrdns for use in `expression` matchers, e.g.:
//
//	expression verify_fcrdns('\\.googlebot\\.com$')
//	expression verify_fcrdns('\\.googlebot\\.com$', 'allow_forward_failure')
//	expression verify_fcrdns('\\.googlebot\\.com$', 'allow_forward_failure', 'accept_unknown')
//
// Unlike a Caddyfile `@name { header_regexp ...; verify_fcrdns ... }` block
// (whose matchers are AND'ed via Caddy's own matcher-set loading, which
// provides no ordering guarantee between matcher types - see CLAUDE.md),
// CEL's `&&` operator short-circuits left-to-right by language spec, so
// `expression header_regexp(...) && verify_fcrdns(...)` reliably skips the
// DNS lookup when the cheap check already failed.
//
// Each arity is registered as its own overload (mirroring MatchPathRE's
// unnamed/named pattern split, extended to three arities here) since CEL
// overloads have fixed arity; their compiled options are then combined into
// one library. Each factory just constructs a VerifyFCrDNS and calls its
// normal Provision - the same pattern MatchPathRE uses - so this reuses all
// the Caddyfile-path's provisioning logic (app lookup, regex compilation,
// policy parsing) unchanged.
func (VerifyFCrDNS) CELLibrary(ctx caddy.Context) (cel.Library, error) {
	oneArg, err := caddyhttp.CELMatcherImpl(
		"verify_fcrdns",
		"verify_fcrdns_request_string",
		[]*cel.Type{cel.StringType},
		func(data ref.Val) (caddyhttp.RequestMatcherWithError, error) {
			pattern := data.(types.String)
			m := VerifyFCrDNS{HostnamePattern: string(pattern)}
			err := m.Provision(ctx)
			return m, err
		},
	)
	if err != nil {
		return nil, err
	}

	twoArg, err := caddyhttp.CELMatcherImpl(
		"verify_fcrdns",
		"verify_fcrdns_request_string_string",
		[]*cel.Type{cel.StringType, cel.StringType},
		func(data ref.Val) (caddyhttp.RequestMatcherWithError, error) {
			args, err := celStringArgs(data, 2)
			if err != nil {
				return nil, err
			}
			m := VerifyFCrDNS{HostnamePattern: args[0], ForwardPolicy: args[1]}
			err = m.Provision(ctx)
			return m, err
		},
	)
	if err != nil {
		return nil, err
	}

	threeArg, err := caddyhttp.CELMatcherImpl(
		"verify_fcrdns",
		"verify_fcrdns_request_string_string_string",
		[]*cel.Type{cel.StringType, cel.StringType, cel.StringType},
		func(data ref.Val) (caddyhttp.RequestMatcherWithError, error) {
			args, err := celStringArgs(data, 3)
			if err != nil {
				return nil, err
			}
			m := VerifyFCrDNS{HostnamePattern: args[0], ForwardPolicy: args[1], UnknownPolicy: args[2]}
			err = m.Provision(ctx)
			return m, err
		},
	)
	if err != nil {
		return nil, err
	}

	envOpts := append(oneArg.CompileOptions(), twoArg.CompileOptions()...)
	envOpts = append(envOpts, threeArg.CompileOptions()...)
	prgOpts := append(oneArg.ProgramOptions(), twoArg.ProgramOptions()...)
	prgOpts = append(prgOpts, threeArg.ProgramOptions()...)
	return caddyhttp.NewMatcherCELLibrary(envOpts, prgOpts), nil
}

// celStringArgs converts the string-list CEL value CELMatcherImpl produces
// for a multi-string overload into a plain []string, checked against the
// expected arg count as a sanity check against the overload registration
// itself changing shape.
func celStringArgs(data ref.Val, want int) ([]string, error) {
	converted, err := data.ConvertToNative(stringSliceType)
	if err != nil {
		return nil, err
	}
	args := converted.([]string)
	if len(args) != want {
		return nil, fmt.Errorf("verify_fcrdns: expected %d CEL arguments, got %d", want, len(args))
	}
	return args, nil
}
