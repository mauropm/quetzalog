package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"quetzalog/internal/spl/ast"
	"quetzalog/internal/spl/executor"
	"quetzalog/internal/spl/parser"
	"quetzalog/internal/spl/planner"
	"quetzalog/internal/spl/serializer"
	"quetzalog/pkg/api"
	"quetzalog/pkg/event"
)

// ─────────────────────────────────────────────
// SPL Builder endpoints. The AST is the contract: the browser never builds SPL
// text, it only edits the wire AST and asks the server to (de)serialize and run
// it through the SAME pipeline used by /api/v1/search.
// ─────────────────────────────────────────────

type splQueryReq struct {
	Query    string          `json:"query"`
	Ast      json.RawMessage `json:"ast"`
	Limit    int             `json:"limit"`
	Offset   int             `json:"offset"`
	Earliest string          `json:"earliest"`
	Latest   string          `json:"latest"`
}

type splError struct {
	Message  string `json:"message"`
	Near     string `json:"near,omitempty"`
	Expected string `json:"expected,omitempty"`
}

// resolveSPL turns a request (which carries either raw SPL or a wire AST) into a
// canonical SPL string plus the parsed tree.
func resolveSPL(req splQueryReq) (string, *ast.Query, error) {
	if len(req.Ast) > 0 {
		var q ast.Query
		if err := json.Unmarshal(req.Ast, &q); err != nil {
			return "", nil, err
		}
		q.EnsureSearchFirst()
		return serializer.Serialize(&q), &q, nil
	}
	q, err := parseSPL(req.Query)
	if err != nil {
		return "", nil, err
	}
	q.EnsureSearchFirst()
	return serializer.Serialize(q), q, nil
}

// parseSPL runs the tokenizer + parser and returns the AST.
func parseSPL(input string) (*ast.Query, error) {
	p, err := parser.New(input)
	if err != nil {
		return nil, err
	}
	return p.Parse()
}

// SplParse converts SPL into the wire AST and reports which commands the builder
// can represent.
func (h *Handler) SplParse(w http.ResponseWriter, r *http.Request) {
	var req splQueryReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}
	if strings.TrimSpace(req.Query) == "" {
		writeSPL(w, map[string]any{
			"ok": false, "spl": "", "supported": false,
			"unsupported_commands": []string{}, "ast": nil,
			"error": splError{Message: "query is required"},
		})
		return
	}
	q, err := parseSPL(req.Query)
	if err != nil {
		writeSPL(w, map[string]any{
			"ok": false, "spl": "", "supported": false,
			"unsupported_commands": []string{}, "ast": nil,
			"error": splError{Message: err.Error()},
		})
		return
	}
	q.EnsureSearchFirst()
	spl := serializer.Serialize(q)
	unsupported := q.UnsupportedCommands()
	if unsupported == nil {
		unsupported = []string{}
	}
	rawAST, _ := json.Marshal(q)
	writeSPL(w, map[string]any{
		"ok":                 true,
		"spl":                spl,
		"supported":          len(unsupported) == 0,
		"unsupported_commands": unsupported,
		"ast":                json.RawMessage(rawAST),
		"error":              nil,
	})
}

// SplBuild converts a wire AST into canonical SPL.
func (h *Handler) SplBuild(w http.ResponseWriter, r *http.Request) {
	var req splQueryReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}
	spl, _, err := resolveSPL(req)
	if err != nil {
		writeSPL(w, map[string]any{"ok": false, "spl": "", "error": splError{Message: err.Error()}})
		return
	}
	writeSPL(w, map[string]any{"ok": true, "spl": spl, "error": nil})
}

// SplValidate structurally validates a wire AST (or raw SPL) and returns
// component-tagged errors the UI can highlight.
func (h *Handler) SplValidate(w http.ResponseWriter, r *http.Request) {
	var req splQueryReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}
	_, q, err := resolveSPL(req)
	if err != nil {
		writeSPL(w, map[string]any{"ok": false, "errors": []ast.ValidationError{{Component: "query", Message: err.Error()}}})
		return
	}
	errs := q.Validate()
	if errs == nil {
		errs = []ast.ValidationError{}
	}
	writeSPL(w, map[string]any{"ok": len(errs) == 0, "errors": errs})
}

// SplPreview runs a bounded preview through the shared executor and returns the
// columns, rows and timing.
func (h *Handler) SplPreview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req splQueryReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteJSON(w, http.StatusBadRequest, api.BadRequest("invalid request body"))
		return
	}
	spl, _, err := resolveSPL(req)
	if err != nil {
		writeSPL(w, map[string]any{"ok": false, "error": splError{Message: err.Error()},
			"query": req.Query, "fields": []string{}, "results": []any{}, "count": 0, "execution_ms": 0})
		return
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 1000 {
		limit = 1000
	}
	earliest := parseTimeRange(req.Earliest, false)
	latest := parseTimeRange(req.Latest, true)

	res, err := executor.Run(ctx, h.store.DB(), spl, executor.RunOptions{
		Limit:    limit,
		Offset:   maxInt(req.Offset, 0),
		Earliest: earliest,
		Latest:   latest,
	})
	if err != nil {
		// Preview is a best-effort, non-fatal surface: report every problem inline
		// (ok:false + error) so the builder can render it, rather than surfacing a
		// hard HTTP error the generic api() helper would throw on.
		h.logger.Warn("spl preview failed", "query", spl, "error", err)
		writeSPL(w, map[string]any{
			"ok": false, "error": splError{Message: err.Error()},
			"query": spl, "fields": []string{}, "results": []any{}, "count": 0, "execution_ms": 0,
		})
		return
	}
	cols := res.Columns
	if cols == nil {
		cols = []string{}
	}
	rows := res.Rows
	if rows == nil {
		rows = []map[string]any{}
	}
	writeSPL(w, map[string]any{
		"ok":           true,
		"query":        spl,
		"fields":       cols,
		"results":      rows,
		"count":        res.Count,
		"execution_ms": res.ExecutionMS,
		"error":        nil,
	})
}

// ───────────────────────── metadata / autocomplete ─────────────────────────

// SplIndexes returns distinct logical index values (source_type ∪ attribute
// "index"). Nothing is hard-coded.
func (h *Handler) SplIndexes(w http.ResponseWriter, r *http.Request) {
	const q = `SELECT DISTINCT source_type AS v FROM events WHERE source_type IS NOT NULL AND source_type <> ''
UNION
SELECT DISTINCT CAST(json_extract(attributes, '$."index"') AS TEXT) AS v FROM events
WHERE json_extract(attributes, '$."index"') IS NOT NULL AND CAST(json_extract(attributes, '$."index"') AS TEXT) <> ''
ORDER BY v LIMIT 500`
	vals := h.distinctStrings(r.Context(), q)
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"indexes": vals}))
}

// SplSourceTypes returns distinct source_type values.
func (h *Handler) SplSourceTypes(w http.ResponseWriter, r *http.Request) {
	vals := h.distinctStrings(r.Context(),
		`SELECT DISTINCT source_type AS v FROM events WHERE source_type IS NOT NULL AND source_type <> '' ORDER BY v LIMIT 500`)
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"sourcetypes": vals}))
}

// SplSources returns distinct source values.
func (h *Handler) SplSources(w http.ResponseWriter, r *http.Request) {
	vals := h.distinctStrings(r.Context(),
		`SELECT DISTINCT source AS v FROM events WHERE source IS NOT NULL AND source <> '' ORDER BY v LIMIT 500`)
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"sources": vals}))
}

// SplHosts returns distinct host values.
func (h *Handler) SplHosts(w http.ResponseWriter, r *http.Request) {
	vals := h.distinctStrings(r.Context(),
		`SELECT DISTINCT host AS v FROM events WHERE host IS NOT NULL AND host <> '' ORDER BY v LIMIT 500`)
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"hosts": vals}))
}

// SplFields returns the union of canonical event columns and the distinct set of
// attribute keys currently present, plus the "index" pseudo-field.
func (h *Handler) SplFields(w http.ResponseWriter, r *http.Request) {
	set := map[string]bool{"index": true}
	for _, c := range planner.CanonicalColumns() {
		set[c] = true
	}
	// Attribute keys currently in use.
	rows, err := h.store.DB().QueryContext(r.Context(),
		`SELECT DISTINCT j.key AS k FROM events, json_each(events.attributes) j WHERE events.attributes IS NOT NULL AND events.attributes <> '' LIMIT 1000`)
	if err == nil {
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err == nil {
				if k != "" && k != "index" {
					set[k] = true
				}
			}
		}
		rows.Close()
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"fields": out}))
}

// SplValues returns distinct values for a field (used for value pickers). An
// unknown field returns a 200 with an empty list rather than an error.
func (h *Handler) SplValues(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	field := q.Get("field")
	if strings.TrimSpace(field) == "" {
		api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"field": field, "values": []string{}}))
		return
	}
	limit := 50
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 && l <= 500 {
		limit = l
	}

	ctx := r.Context()

	// Optional scope narrowing (index/sourcetype/source/host).
	var scope []string
	var args []any
	for key, col := range map[string]string{"index": "index", "sourcetype": "source_type", "source": "source", "host": "host"} {
		val := q.Get(key)
		if val == "" {
			continue
		}
		expr, bound, err := planner.ColumnSQL(col, "=", val)
		if err != nil {
			continue
		}
		scope = append(scope, expr)
		args = append(args, bound...)
	}
	scopeSQL := ""
	if len(scope) > 0 {
		scopeSQL = " WHERE " + strings.Join(scope, " AND ")
	}

	var vals []string
	if strings.EqualFold(field, "index") {
		vals = h.distinctStringsArgs(ctx,
			`SELECT DISTINCT source_type AS v FROM events WHERE source_type IS NOT NULL AND source_type <> ''
UNION SELECT DISTINCT CAST(json_extract(attributes, '$."index"') AS TEXT) AS v FROM events WHERE json_extract(attributes, '$."index"') IS NOT NULL LIMIT ?`,
			limit)
		api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"field": field, "values": nz(vals)}))
		return
	}

	expr, _, ok := planner.DistinctExpr(field)
	if !ok {
		api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"field": field, "values": []string{}}))
		return
	}
	sqlStr := "SELECT DISTINCT " + expr + " AS v FROM events" + scopeSQL + " ORDER BY v LIMIT ?"
	args = append(args, limit)
	vals = h.distinctStringsArgs(ctx, sqlStr, args...)
	api.WriteJSON(w, http.StatusOK, api.Success(map[string]any{"field": field, "values": nz(vals)}))
}

// ───────────────────────── helpers ─────────────────────────

func writeSPL(w http.ResponseWriter, data any) {
	api.WriteJSON(w, http.StatusOK, api.Success(data))
}

func (h *Handler) distinctStrings(ctx context.Context, q string) []string {
	return h.distinctStringsArgs(ctx, q)
}

func (h *Handler) distinctStringsArgs(ctx context.Context, q string, args ...any) []string {
	rows, err := h.store.DB().QueryContext(ctx, q, args...)
	if err != nil {
		return []string{}
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s sql.NullString
		if err := rows.Scan(&s); err != nil {
			continue
		}
		if s.Valid && s.String != "" {
			out = append(out, s.String)
		}
	}
	return out
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// parseTimeRange resolves an absolute or relative ("24h", "15m", "7d", "now")
// time bound. For a latest bound, relative values are subtracted from now.
func parseTimeRange(s string, isLatest bool) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if strings.EqualFold(s, "now") {
		return time.Now()
	}
	if t := event.ParseTimestamp(s); !t.IsZero() {
		return t
	}
	dur := parseRelativeDuration(s)
	if dur > 0 {
		return time.Now().Add(-dur)
	}
	return time.Time{}
}

// parseRelativeDuration parses Splunk-style ranges: "24h", "90m", "7d", "2w",
// optionally with a leading "-". Returns 0 when unparseable.
func parseRelativeDuration(s string) time.Duration {
	s = strings.TrimSpace(strings.TrimPrefix(s, "-"))
	if s == "" {
		return 0
	}
	if strings.EqualFold(s, "all") {
		return 0
	}
	// Split trailing unit from numeric prefix.
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	numPart, unit := s[:i], strings.ToLower(s[i:])
	if numPart == "" {
		return 0
	}
	n, err := strconv.ParseFloat(numPart, 64)
	if err != nil {
		return 0
	}
	switch unit {
	case "s", "sec", "seconds":
		return time.Duration(n * float64(time.Second))
	case "m", "min", "mins", "minutes":
		return time.Duration(n * float64(time.Minute))
	case "h", "hr", "hrs", "hours":
		return time.Duration(n * float64(time.Hour))
	case "d", "day", "days":
		return time.Duration(n * 24 * float64(time.Hour))
	case "w", "week", "weeks":
		return time.Duration(n * 7 * 24 * float64(time.Hour))
	case "":
		// Bare number → try Go duration (e.g. "2h30m").
		if d, err := time.ParseDuration(s); err == nil {
			return d
		}
	}
	return 0
}

