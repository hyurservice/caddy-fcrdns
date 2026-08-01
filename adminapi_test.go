package caddyfcrdns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/hyurservice/caddy-fcrdns/fcrdns"
	"go.uber.org/zap"
)

// fakeResolver always reports names as the PTR result for any IP, so tests
// can control verification outcomes without making real DNS calls. Forward
// lookups always fail - fine since these tests only use AllowForwardFailure.
type fakeResolver struct {
	names []string
}

func (r fakeResolver) LookupAddr(ctx context.Context, ip string) ([]string, error) {
	return r.names, nil
}

func (r fakeResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return nil, errors.New("forward lookup not implemented in fakeResolver")
}

// newTestApp builds an App backed by a fake resolver, bypassing
// Provision's hardcoded fcrdns.NetResolver - these are same-package tests,
// so setting the unexported cache field directly is the simplest way to get
// deterministic outcomes without real DNS. It also registers the app as
// currentApp (what Provision would normally do), restored to nil on
// cleanup.
func newTestApp(t *testing.T, resolver fcrdns.Resolver) *App {
	t.Helper()
	cache, err := fcrdns.NewCache(resolver, fcrdns.DefaultCacheConfig())
	if err != nil {
		t.Fatalf("fcrdns.NewCache: %v", err)
	}
	t.Cleanup(cache.Close)

	app := &App{cache: cache, logger: zap.NewNop(), dnsTimeout: time.Second}
	currentApp.Store(app)
	t.Cleanup(func() { currentApp.CompareAndSwap(app, nil) })
	return app
}

func mustAPIError(t *testing.T, err error) caddy.APIError {
	t.Helper()
	apiErr, ok := err.(caddy.APIError)
	if !ok {
		t.Fatalf("error is %T (%v), want caddy.APIError", err, err)
	}
	return apiErr
}

func TestHandleCacheList_NoAppConfigured(t *testing.T) {
	currentApp.Store(nil)

	req := httptest.NewRequest(http.MethodGet, "/verify_fcrdns/cache", nil)
	rec := httptest.NewRecorder()
	err := handleCacheList(rec, req)
	if err == nil {
		t.Fatal("expected an error when no verify_fcrdns app is configured, got nil")
	}
	if apiErr := mustAPIError(t, err); apiErr.HTTPStatus != http.StatusServiceUnavailable {
		t.Errorf("HTTPStatus = %d, want %d", apiErr.HTTPStatus, http.StatusServiceUnavailable)
	}
}

func TestHandleCacheList_MethodNotAllowed(t *testing.T) {
	newTestApp(t, fakeResolver{names: []string{"host.crawl.baidu.com."}})

	req := httptest.NewRequest(http.MethodPost, "/verify_fcrdns/cache", nil)
	rec := httptest.NewRecorder()
	apiErr := mustAPIError(t, handleCacheList(rec, req))
	if apiErr.HTTPStatus != http.StatusMethodNotAllowed {
		t.Errorf("HTTPStatus = %d, want %d", apiErr.HTTPStatus, http.StatusMethodNotAllowed)
	}
}

func TestHandleCacheList_InvalidLimitAndFormat(t *testing.T) {
	newTestApp(t, fakeResolver{names: []string{"host.crawl.baidu.com."}})

	targets := []string{
		"/verify_fcrdns/cache?limit=0",
		"/verify_fcrdns/cache?limit=-1",
		"/verify_fcrdns/cache?limit=notanumber",
		"/verify_fcrdns/cache?format=xml",
		"/verify_fcrdns/cache?colors=maybe",
	}
	for _, target := range targets {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		err := handleCacheList(rec, req)
		if err == nil {
			t.Errorf("%s: expected an error, got nil", target)
			continue
		}
		if apiErr := mustAPIError(t, err); apiErr.HTTPStatus != http.StatusBadRequest {
			t.Errorf("%s: HTTPStatus = %d, want %d", target, apiErr.HTTPStatus, http.StatusBadRequest)
		}
	}
}

func mustPattern(t *testing.T, expr string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(expr)
	if err != nil {
		t.Fatalf("regexp.Compile(%q): %v", expr, err)
	}
	return re
}

// populateEntries verifies 1.2.3.1 three times and 1.2.3.2 once, against a
// pattern that always matches the fakeResolver's PTR name - giving distinct,
// known hit counts to assert on.
func populateEntries(t *testing.T, app *App) {
	t.Helper()
	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)
	ctx := context.Background()
	app.cache.Verify(ctx, "1.2.3.1", pattern, fcrdns.AllowForwardFailure)
	app.cache.Verify(ctx, "1.2.3.1", pattern, fcrdns.AllowForwardFailure)
	app.cache.Verify(ctx, "1.2.3.1", pattern, fcrdns.AllowForwardFailure)
	app.cache.Verify(ctx, "1.2.3.2", pattern, fcrdns.AllowForwardFailure)
}

func TestHandleCacheList_JSONDefault(t *testing.T) {
	app := newTestApp(t, fakeResolver{names: []string{"host.crawl.baidu.com."}})
	populateEntries(t, app)

	req := httptest.NewRequest(http.MethodGet, "/verify_fcrdns/cache", nil)
	rec := httptest.NewRecorder()
	if err := handleCacheList(rec, req); err != nil {
		t.Fatalf("handleCacheList: %v", err)
	}

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var out cacheListJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("json.Unmarshal: %v (body: %s)", err, rec.Body.String())
	}
	if out.TotalEntries != 2 {
		t.Errorf("TotalEntries = %d, want 2", out.TotalEntries)
	}
	if out.Returned != 2 {
		t.Errorf("Returned = %d, want 2", out.Returned)
	}
	if len(out.Entries) != 2 {
		t.Fatalf("len(Entries) = %d, want 2", len(out.Entries))
	}
	// Ordered by descending hits: 1.2.3.1 (3 hits) before 1.2.3.2 (1 hit).
	if out.Entries[0].IP != "1.2.3.1" || out.Entries[0].Hits != 3 {
		t.Errorf("Entries[0] = %+v, want ip=1.2.3.1 hits=3", out.Entries[0])
	}
	if out.Entries[1].IP != "1.2.3.2" || out.Entries[1].Hits != 1 {
		t.Errorf("Entries[1] = %+v, want ip=1.2.3.2 hits=1", out.Entries[1])
	}
	if out.Entries[0].Outcome != "verified" {
		t.Errorf("Entries[0].Outcome = %q, want verified", out.Entries[0].Outcome)
	}
}

func TestHandleCacheList_LimitIsRespected(t *testing.T) {
	app := newTestApp(t, fakeResolver{names: []string{"host.crawl.baidu.com."}})
	populateEntries(t, app)

	req := httptest.NewRequest(http.MethodGet, "/verify_fcrdns/cache?limit=1", nil)
	rec := httptest.NewRecorder()
	if err := handleCacheList(rec, req); err != nil {
		t.Fatalf("handleCacheList: %v", err)
	}

	var out cacheListJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if out.TotalEntries != 2 {
		t.Errorf("TotalEntries = %d, want 2 (unaffected by limit)", out.TotalEntries)
	}
	if out.Returned != 1 || len(out.Entries) != 1 {
		t.Errorf("Returned = %d, len(Entries) = %d, want 1", out.Returned, len(out.Entries))
	}
}

func TestHandleCacheList_LimitInfReturnsEverything(t *testing.T) {
	app := newTestApp(t, fakeResolver{names: []string{"host.crawl.baidu.com."}})
	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)
	ctx := context.Background()
	// More than the old hard cap would have allowed, to prove there's no
	// server-side ceiling being silently applied.
	const distinctIPs = 25
	for i := 0; i < distinctIPs; i++ {
		app.cache.Verify(ctx, fmt.Sprintf("10.0.0.%d", i), pattern, fcrdns.AllowForwardFailure)
	}

	req := httptest.NewRequest(http.MethodGet, "/verify_fcrdns/cache?limit=inf", nil)
	rec := httptest.NewRecorder()
	if err := handleCacheList(rec, req); err != nil {
		t.Fatalf("handleCacheList: %v", err)
	}

	var out cacheListJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if out.TotalEntries != distinctIPs {
		t.Errorf("TotalEntries = %d, want %d", out.TotalEntries, distinctIPs)
	}
	if out.Returned != distinctIPs || len(out.Entries) != distinctIPs {
		t.Errorf("Returned = %d, len(Entries) = %d, want %d", out.Returned, len(out.Entries), distinctIPs)
	}
}

func TestHandleCacheList_TableFormat(t *testing.T) {
	app := newTestApp(t, fakeResolver{names: []string{"host.crawl.baidu.com."}})
	populateEntries(t, app)

	req := httptest.NewRequest(http.MethodGet, "/verify_fcrdns/cache?format=table", nil)
	rec := httptest.NewRecorder()
	if err := handleCacheList(rec, req); err != nil {
		t.Fatalf("handleCacheList: %v", err)
	}

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain prefix", ct)
	}

	body := rec.Body.String()
	for _, want := range []string{"1.2.3.1", "1.2.3.2", "IP", "HITS", "showing 2 of 2"} {
		if !strings.Contains(body, want) {
			t.Errorf("table output missing %q; got:\n%s", want, body)
		}
	}
}

func TestHandleCacheList_TableColors(t *testing.T) {
	// A PTR name that doesn't match the pattern, so the outcome is
	// "rejected" - the case colorizeOutcome actually colors, unlike the
	// "verified" entries populateEntries produces.
	app := newTestApp(t, fakeResolver{names: []string{"not-a-match.example.com."}})
	pattern := mustPattern(t, `\.crawl\.baidu\.com$`)
	app.cache.Verify(context.Background(), "1.2.3.1", pattern, fcrdns.AllowForwardFailure)

	const ansiPrefix = "\x1b["

	req := httptest.NewRequest(http.MethodGet, "/verify_fcrdns/cache?format=table", nil)
	rec := httptest.NewRecorder()
	if err := handleCacheList(rec, req); err != nil {
		t.Fatalf("handleCacheList: %v", err)
	}
	if body := rec.Body.String(); !strings.Contains(body, ansiPrefix) {
		t.Errorf("default (colors enabled) table output has no ANSI escape codes; got:\n%s", body)
	} else if !strings.Contains(body, "rejected") {
		t.Errorf("table output missing %q; got:\n%s", "rejected", body)
	}

	req = httptest.NewRequest(http.MethodGet, "/verify_fcrdns/cache?format=table&colors=no", nil)
	rec = httptest.NewRecorder()
	if err := handleCacheList(rec, req); err != nil {
		t.Fatalf("handleCacheList: %v", err)
	}
	body := rec.Body.String()
	if strings.Contains(body, ansiPrefix) {
		t.Errorf("colors=no table output still has ANSI escape codes; got:\n%s", body)
	}
	if !strings.Contains(body, "rejected") {
		t.Errorf("colors=no table output missing plain %q; got:\n%s", "rejected", body)
	}
}
