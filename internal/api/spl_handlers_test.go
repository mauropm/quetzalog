package api_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"quetzalog/internal/events"
	"quetzalog/pkg/event"
)

func seedSPL(t *testing.T, e *env) {
	t.Helper()
	store := events.NewStore(e.db)
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	seedOne := func(src, stype, user, status string, rt int) {
		ev := event.NewEvent()
		ev.Source = src
		ev.SourceType = stype
		ev.Host = "web-01"
		ev.Severity = "err"
		ev.EventType = "auth"
		ev.Message = "login for " + user + " status=" + status
		ev.Timestamp = base.Add(time.Duration(len(user)) * time.Minute)
		ev.Attributes["user"] = user
		ev.Attributes["status"] = status
		ev.Attributes["response_time"] = rt
		ev.Attributes["index"] = stype
		if err := store.Create(context.Background(), ev); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	seedOne("auth", "audit", "mauro", "failed", 120)
	seedOne("auth", "audit", "ana", "success", 15)
	seedOne("web", "access", "ana", "failed", 90)
}

func TestSPLParseSupportsKnownCommands(t *testing.T) {
	e := newEnv(t)
	seedSPL(t, e)

	w, _ := do(e, "POST", "/api/v1/spl/parse", map[string]any{
		"query": `index=auth | where status="failed" | stats count by user | sort -count | head 10`,
	}, nil)
	if w.Code != 200 {
		t.Fatalf("status %d body=%s", w.Code, w.Body.String())
	}
	data := decodeBody(t, w)["data"].(map[string]any)
	if data["ok"] != true {
		t.Fatalf("expected ok, got %v", data)
	}
	if data["supported"] != true {
		t.Fatalf("expected supported, got %v", data["unsupported_commands"])
	}
	if data["ast"] == nil {
		t.Fatal("expected an ast in the response")
	}
	spl, _ := data["spl"].(string)
	if spl == "" {
		t.Fatal("expected non-empty canonical spl")
	}
}

func TestSPLParseFlagsUnsupportedCommand(t *testing.T) {
	e := newEnv(t)
	seedSPL(t, e)
	w, _ := do(e, "POST", "/api/v1/spl/parse", map[string]any{
		"query": `index=auth | transaction user`,
	}, nil)
	data := decodeBody(t, w)["data"].(map[string]any)
	if data["supported"] != false {
		t.Fatalf("expected supported=false, got %v", data)
	}
	list, _ := data["unsupported_commands"].([]any)
	found := false
	for _, v := range list {
		if s, _ := v.(string); s == "transaction" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected transaction flagged unsupported, got %v", list)
	}
}

func TestSPLBuildAndPreviewRoundTrip(t *testing.T) {
	e := newEnv(t)
	seedSPL(t, e)

	ast := map[string]any{
		"version": 1,
		"commands": []any{
			map[string]any{"type": "stats", "aggs": []any{map[string]any{"func": "count", "alias": "events"}}, "groupby": []any{"source"}},
			map[string]any{"type": "sort", "sort": []any{map[string]any{"field": "events", "desc": true}}},
			map[string]any{"type": "head", "n": 5},
		},
	}
	w, _ := do(e, "POST", "/api/v1/spl/build", map[string]any{"ast": ast}, nil)
	if w.Code != 200 {
		t.Fatalf("build status %d body=%s", w.Code, w.Body.String())
	}
	built := decodeBody(t, w)["data"].(map[string]any)
	spl, _ := built["spl"].(string)
	if spl == "" || !strings.Contains(strings.ToLower(spl), "search") || !strings.Contains(strings.ToLower(spl), "stats") {
		t.Fatalf("unexpected built spl: %q", spl)
	}

	w2, _ := do(e, "POST", "/api/v1/spl/preview", map[string]any{"ast": ast, "limit": 10}, nil)
	if w2.Code != 200 {
		t.Fatalf("preview status %d body=%s", w2.Code, w2.Body.String())
	}
	pv := decodeBody(t, w2)["data"].(map[string]any)
	if pv["ok"] != true {
		t.Fatalf("preview not ok: %v", pv)
	}
	results, _ := pv["results"].([]any)
	if len(results) == 0 {
		t.Fatalf("expected preview results, got %v", pv)
	}
	first, _ := results[0].(map[string]any)
	if _, ok := first["events"]; !ok {
		t.Fatalf("expected an 'events' aggregate column, row=%v", first)
	}
}

func TestSPLValidateFlagsBadCommand(t *testing.T) {
	e := newEnv(t)
	ast := map[string]any{
		"version":  1,
		"commands": []any{map[string]any{"type": "dedup", "field": ""}},
	}
	w, _ := do(e, "POST", "/api/v1/spl/validate", map[string]any{"ast": ast}, nil)
	pv := decodeBody(t, w)["data"].(map[string]any)
	if pv["ok"] == true {
		t.Fatalf("expected validation to fail for empty dedup field, got %v", pv)
	}
}

func TestSPLPreviewReportsBadQueryInline(t *testing.T) {
	e := newEnv(t)
	w, _ := do(e, "POST", "/api/v1/spl/preview", map[string]any{
		"query": `search ]`, "limit": 5,
	}, nil)
	if w.Code != 200 {
		t.Fatalf("expected 200 with inline error, got %d body=%s", w.Code, w.Body.String())
	}
	pv := decodeBody(t, w)["data"].(map[string]any)
	if pv["ok"] != false {
		t.Fatalf("expected ok=false for malformed query, got %v", pv)
	}
	if pv["error"] == nil {
		t.Fatalf("expected an error object, got %v", pv)
	}
}

func TestSPLMetadataEndpoints(t *testing.T) {
	e := newEnv(t)
	seedSPL(t, e)

	for path, key := range map[string]string{
		"/api/v1/spl/indexes":     "indexes",
		"/api/v1/spl/sourcetypes": "sourcetypes",
		"/api/v1/spl/sources":     "sources",
		"/api/v1/spl/hosts":       "hosts",
	} {
		w, _ := do(e, "GET", path, nil, nil)
		if w.Code != 200 {
			t.Fatalf("%s status %d", path, w.Code)
		}
		data := decodeBody(t, w)["data"].(map[string]any)
		list, ok := data[key].([]any)
		if !ok || len(list) == 0 {
			t.Fatalf("%s expected non-empty %s, got %v", path, key, data)
		}
	}

	w, _ := do(e, "GET", "/api/v1/spl/fields", nil, nil)
	fields := toStrings(decodeBody(t, w)["data"].(map[string]any)["fields"])
	want := map[string]bool{"user": false, "status": false, "source": false, "index": false}
	for _, f := range fields {
		if _, ok := want[f]; ok {
			want[f] = true
		}
	}
	for f, seen := range want {
		if !seen {
			t.Errorf("fields endpoint missing %q", f)
		}
	}

	wv, _ := do(e, "GET", "/api/v1/spl/values?field=status&limit=20", nil, nil)
	vals := toStrings(decodeBody(t, wv)["data"].(map[string]any)["values"])
	found := false
	for _, v := range vals {
		if v == "failed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected value 'failed' for field=status, got %v", vals)
	}

	wu, _ := do(e, "GET", "/api/v1/spl/values?field=definitely_not_a_field", nil, nil)
	if wu.Code != 200 {
		t.Fatalf("unknown field status %d", wu.Code)
	}
	ulist := decodeBody(t, wu)["data"].(map[string]any)["values"]
	if ul, ok := ulist.([]any); !ok || len(ul) != 0 {
		t.Fatalf("expected empty values for unknown field, got %v", ulist)
	}
}

func toStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Search must translate user-facing SPL failures into 400, never 5xx.
func TestSPLSearchInvalidQueryIs400(t *testing.T) {
	e := newEnv(t)
	seedSPL(t, e)
	cases := []string{
		`search ]`,                // unbalanced / unexpected character
		`index=auth | sort`,       // sort with no fields
		`index=auth | where (`,    // unbalanced paren
		`index=auth | eval x =`,   // eval with empty expression
	}
	for _, q := range cases {
		w, _ := do(e, "POST", "/api/v1/search", map[string]any{"query": q}, nil)
		if w.Code >= 500 {
			t.Errorf("query %q returned %d (want 4xx), body: %s", q, w.Code, w.Body.String())
		}
		if w.Code != 400 {
			t.Errorf("query %q returned %d, want 400", q, w.Code)
		}
	}

	// A valid SPL pipeline still returns 200 through the same endpoint.
	w, _ := do(e, "POST", "/api/v1/search", map[string]any{"query": `index=audit | stats count by user | head 5`}, nil)
	if w.Code != 200 {
		t.Fatalf("valid SPL pipeline returned %d: %s", w.Code, w.Body.String())
	}
}
