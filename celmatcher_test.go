package caddyfcrdns

import (
	"context"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// TestCELLibrary_RegistersWithoutError confirms the three overloads (1/2/3
// string args) register successfully. This only exercises CELMatcherImpl's
// declarative registration, not the factories themselves - those only run
// later, when a real CEL program compiling a constant verify_fcrdns(...)
// call is built (see CELMatcherDecorator), which needs a fully configured
// app the way Provision does. That deeper path (does the registered
// function actually work, and does && actually short-circuit before it)
// is validated against a real xcaddy build instead - see CLAUDE.md.
func TestCELLibrary_RegistersWithoutError(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	lib, err := VerifyFCrDNS{}.CELLibrary(ctx)
	if err != nil {
		t.Fatalf("CELLibrary: %v", err)
	}
	if lib == nil {
		t.Fatal("CELLibrary returned a nil library")
	}
	if len(lib.CompileOptions()) == 0 {
		t.Error("CompileOptions() is empty, want options from all three overloads")
	}
	if len(lib.ProgramOptions()) == 0 {
		t.Error("ProgramOptions() is empty, want options from all three overloads")
	}
}
