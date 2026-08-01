package caddyfcrdns

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/hyurservice/caddy-fcrdns/fcrdns"
	"github.com/olekukonko/tablewriter"
)

func init() {
	caddy.RegisterModule(AdminAPI{})
}

const (
	defaultCacheListLimit = 20
	maxCacheListLimit     = 1000
	maxTableColumnWidth   = 40
)

// AdminAPI exposes the shared verify_fcrdns cache's contents over Caddy's
// admin API - GET /verify_fcrdns/cache?limit=N&format=json|table - for live
// debugging, similar in spirit to `cscli decisions list`.
//
// It reads the shared App lazily, at request time, via currentApp (see
// app.go) rather than through ctx.App("verify_fcrdns") in Provision - admin
// API modules are provisioned before regular apps during config load, so
// ctx.App would not yet find the real one; see currentApp's doc comment.
type AdminAPI struct{}

// CaddyModule returns the Caddy module information.
func (AdminAPI) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.verify_fcrdns",
		New: func() caddy.Module { return new(AdminAPI) },
	}
}

// Routes implements caddy.AdminRouter.
func (AdminAPI) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: "/verify_fcrdns/cache",
			Handler: caddy.AdminHandlerFunc(handleCacheList),
		},
	}
}

func handleCacheList(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddy.APIError{HTTPStatus: http.StatusMethodNotAllowed, Err: fmt.Errorf("method not allowed")}
	}

	app := currentApp.Load()
	if app == nil {
		return caddy.APIError{
			HTTPStatus: http.StatusServiceUnavailable,
			Err:        fmt.Errorf("verify_fcrdns is not configured (no global `verify_fcrdns { }` block)"),
		}
	}

	limit := defaultCacheListLimit
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return caddy.APIError{HTTPStatus: http.StatusBadRequest, Err: fmt.Errorf("invalid limit %q: must be a positive integer", s)}
		}
		limit = n
	}
	if limit > maxCacheListLimit {
		limit = maxCacheListLimit
	}

	total, entries := app.Top(limit)

	switch format := r.URL.Query().Get("format"); format {
	case "", "json":
		return writeCacheListJSON(w, total, entries)
	case "table":
		return writeCacheListTable(w, total, entries)
	default:
		return caddy.APIError{HTTPStatus: http.StatusBadRequest, Err: fmt.Errorf("invalid format %q: must be json or table", format)}
	}
}

type cacheEntryJSON struct {
	IP              string `json:"ip"`
	HostnamePattern string `json:"hostname_pattern"`
	ForwardPolicy   string `json:"forward_policy"`
	Outcome         string `json:"outcome"`
	MatchedHostname string `json:"matched_hostname,omitempty"`
	ForwardChecked  bool   `json:"forward_checked"`
	Error           string `json:"error,omitempty"`
	Hits            uint64 `json:"hits"`
	ExpiresIn       string `json:"expires_in"`
}

type cacheListJSON struct {
	TotalEntries int              `json:"total_entries"`
	Returned     int              `json:"returned"`
	Entries      []cacheEntryJSON `json:"entries"`
}

func toCacheEntryJSON(e fcrdns.IndexEntry) cacheEntryJSON {
	var errStr string
	if e.Err != nil {
		errStr = e.Err.Error()
	}
	return cacheEntryJSON{
		IP:              e.IP,
		HostnamePattern: e.HostnamePattern,
		ForwardPolicy:   e.ForwardPolicy,
		Outcome:         e.Outcome.String(),
		MatchedHostname: e.MatchedHostname,
		ForwardChecked:  e.ForwardChecked,
		Error:           errStr,
		Hits:            e.Hits,
		ExpiresIn:       expiresIn(e.ExpiresAt),
	}
}

// expiresIn formats the time remaining until t as a Go duration string
// (e.g. "18h32m10s"), clamped to zero if t has already passed - which can
// happen since ExpiresAt is set once at insertion and this cache doesn't
// use sliding expiration, so a listing taken right at expiry could
// otherwise show a small negative duration.
func expiresIn(t time.Time) string {
	d := time.Until(t)
	if d < 0 {
		d = 0
	}
	return d.Round(time.Second).String()
}

func writeCacheListJSON(w http.ResponseWriter, total int, entries []fcrdns.IndexEntry) error {
	out := cacheListJSON{
		TotalEntries: total,
		Returned:     len(entries),
		Entries:      make([]cacheEntryJSON, len(entries)),
	}
	for i, e := range entries {
		out.Entries[i] = toCacheEntryJSON(e)
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(out)
}

func writeCacheListTable(w http.ResponseWriter, total int, entries []fcrdns.IndexEntry) error {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "showing %d of %d entries\n\n", len(entries), total)

	tw := tablewriter.NewWriter(w)
	tw.Header("IP", "PATTERN", "POLICY", "OUTCOME", "HOSTNAME", "FWD", "HITS", "EXPIRES", "ERROR")
	for _, e := range entries {
		tw.Append(
			e.IP,
			e.HostnamePattern,
			e.ForwardPolicy,
			e.Outcome.String(),
			truncate(dashIfEmpty(e.MatchedHostname), maxTableColumnWidth),
			yesNo(e.ForwardChecked),
			strconv.FormatUint(e.Hits, 10),
			expiresIn(e.ExpiresAt),
			truncate(dashIfEmpty(errString(e.Err)), maxTableColumnWidth),
		)
	}
	return tw.Render()
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// truncate shortens s to at most max characters, replacing the tail with
// "..." if it was longer, so one long hostname or DNS error message can't
// blow out the whole table's column widths.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

var (
	_ caddy.Module      = (*AdminAPI)(nil)
	_ caddy.AdminRouter = (*AdminAPI)(nil)
)
