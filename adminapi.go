package caddyfcrdns

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/fatih/color"
	"github.com/hyurservice/caddy-fcrdns/fcrdns"
	"github.com/olekukonko/tablewriter"
)

func init() {
	caddy.RegisterModule(AdminAPI{})
}

const (
	defaultCacheListLimit = 20
	maxTableColumnWidth   = 40
)

// tableYellow/tableRed highlight non-verified outcomes in the table format.
// EnableColor() forces ANSI codes on regardless of fatih/color's
// auto-detected NoColor: that detection is based on whether *this Caddy
// process's* os.Stdout is a terminal, which has nothing to do with whether
// the HTTP client requesting format=table is a human at a terminal - so
// left alone, it would silently strip colors whenever Caddy runs under
// systemd/docker (i.e. almost always in production), regardless of what the
// curl caller actually wants.
var (
	tableYellow = newTableColor(color.FgYellow)
	tableRed    = newTableColor(color.FgRed)
)

func newTableColor(attrs ...color.Attribute) *color.Color {
	c := color.New(attrs...)
	c.EnableColor()
	return c
}

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
		if s == "inf" {
			// No server-side hard cap - "inf" means "give me everything
			// currently tracked," however large that turns out to be.
			limit = math.MaxInt
		} else {
			n, err := strconv.Atoi(s)
			if err != nil || n < 1 {
				return caddy.APIError{HTTPStatus: http.StatusBadRequest, Err: fmt.Errorf(`invalid limit %q: must be a positive integer or "inf"`, s)}
			}
			limit = n
		}
	}

	colorsEnabled := true
	if s := r.URL.Query().Get("colors"); s != "" {
		switch s {
		case "yes":
			colorsEnabled = true
		case "no":
			colorsEnabled = false
		default:
			return caddy.APIError{HTTPStatus: http.StatusBadRequest, Err: fmt.Errorf("invalid colors %q: must be yes or no", s)}
		}
	}

	total, entries := app.Top(limit)

	switch format := r.URL.Query().Get("format"); format {
	case "", "json":
		return writeCacheListJSON(w, total, entries)
	case "table":
		return writeCacheListTable(w, total, entries, colorsEnabled)
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

func writeCacheListTable(w http.ResponseWriter, total int, entries []fcrdns.IndexEntry, colorsEnabled bool) error {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	tw := tablewriter.NewWriter(w)
	tw.Header("IP", "PATTERN", "POLICY", "OUTCOME", "HOSTNAME", "FWD", "HITS", "EXPIRES", "ERROR")
	for _, e := range entries {
		tw.Append(
			e.IP,
			e.HostnamePattern,
			e.ForwardPolicy,
			colorizeOutcome(e.Outcome, colorsEnabled),
			truncate(dashIfEmpty(e.MatchedHostname), maxTableColumnWidth),
			yesNo(e.ForwardChecked),
			strconv.FormatUint(e.Hits, 10),
			expiresIn(e.ExpiresAt),
			colorizeError(e.Err, colorsEnabled),
		)
	}
	if err := tw.Render(); err != nil {
		return err
	}

	_, err := fmt.Fprintf(w, "\nshowing %d of %d entries\n", len(entries), total)
	return err
}

// colorizeOutcome highlights non-verified outcomes so they stand out in a
// terminal: rejected (a confirmed mismatch) in yellow, unknown (inconclusive
// - DNS timeout/error) in red, matching the error column's color since
// they're usually the same underlying condition. If colorsEnabled is false
// (?colors=no), returns the plain string instead - a dumb terminal or a
// script parsing this output would otherwise see raw ANSI escape bytes
// rather than an absence of color.
func colorizeOutcome(o fcrdns.Outcome, colorsEnabled bool) string {
	if !colorsEnabled {
		return o.String()
	}
	switch o {
	case fcrdns.OutcomeRejected:
		return tableYellow.Sprint(o.String())
	case fcrdns.OutcomeUnknown:
		return tableRed.Sprint(o.String())
	default:
		return o.String()
	}
}

// colorizeError truncates and, if colorsEnabled, colors err's message in
// red; returns "-" if there's no error. Truncation happens before coloring,
// not after, so it can never cut through the middle of an ANSI escape
// sequence.
func colorizeError(err error, colorsEnabled bool) string {
	if err == nil {
		return "-"
	}
	text := truncate(err.Error(), maxTableColumnWidth)
	if !colorsEnabled {
		return text
	}
	return tableRed.Sprint(text)
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
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
