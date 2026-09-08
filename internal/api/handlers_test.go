package api_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"net/http"
	"net/url"
	"net/http/httptest"
	"strings"
	"testing"

	"quetzalog/internal/alerts"
	"quetzalog/internal/api"
	"quetzalog/internal/auth"
	"quetzalog/internal/config"
	"quetzalog/internal/database"
	"quetzalog/internal/detections"
	"quetzalog/internal/events"
	"quetzalog/internal/incidents"
	"quetzalog/internal/query"
)

type env struct {
	handler http.Handler
	db      *sql.DB
	dbName  string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := database.Migrate(db); err != nil {
		db.Close()
		t.Fatalf("migrate: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := config.DefaultConfig()
	// The management API is fail-closed by default; the test fixture supplies
	// a static operator token and a deterministic (env-pinned) admin bootstrap.
	cfg.Auth.APIToken = "test-api-token"
	if err := os.Setenv("QUETZALOG_ADMIN_PASSWORD", "changeme"); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() { _ = os.Unsetenv("QUETZALOG_ADMIN_PASSWORD") })
	h, err := api.SetupRouter(cfg,
		events.NewStore(db),
		query.NewService(db),
		alerts.NewStore(db),
		incidents.NewStore(db),
		detections.NewStore(db),
		auth.NewStore(db),
		logger,
	)
	if err != nil {
		db.Close()
		t.Fatalf("setup router: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return &env{handler: h, db: db}
}

func do(e *env, method, path string, body any, headers map[string]string) (*httptest.ResponseRecorder, *http.Request) {
	var rdr io.Reader = strings.NewReader("")
	if body != nil {
		switch v := body.(type) {
		case string:
			rdr = strings.NewReader(v)
		default:
			b, _ := json.Marshal(v)
			rdr = bytes.NewReader(b)
		}
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer test-api-token")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, req)
	return w, req
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("json decode %q: %v", w.Body.String(), err)
	}
	return out
}

func TestHealth(t *testing.T) {
	e := newEnv(t)
	w, _ := do(e, "GET", "/api/v1/health", nil, nil)
	if w.Code != 200 {
		t.Fatalf("health %d", w.Code)
	}
}

func TestCreateEventAttributeRoundTrip(t *testing.T) {
	e := newEnv(t)
	body := map[string]any{
		"id":        "evt-attr-1",
		"message":   "hello world",
		"source":    "unit",
		"severity":  "err",
		"attributes": map[string]any{"tenant": "acme", "count": 7},
	}
	w, _ := do(e, "POST", "/api/v1/events", body, nil)
	if w.Code != 201 {
		t.Fatalf("create event %d %s", w.Code, w.Body.String())
	}

	w, _ = do(e, "GET", "/api/v1/events/evt-attr-1", nil, nil)
	if w.Code != 200 {
		t.Fatalf("get event %d %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	attrs, _ := data["attributes"].(map[string]any)
	if attrs == nil || attrs["tenant"] != "acme" {
		t.Errorf("attributes did not round-trip through storage: %#v", data["attributes"])
	}
}

func TestListEventsWithAttrFilter(t *testing.T) {
	e := newEnv(t)
	mk := func(id, tenant string) map[string]any {
		return map[string]any{
			"id": id, "message": "x", "source": "unit",
			"attributes": map[string]any{"tenant": tenant},
		}
	}
	do(e, "POST", "/api/v1/events", mk("e1", "acme"), nil)
	do(e, "POST", "/api/v1/events", mk("e2", "globex"), nil)

	w, _ := do(e, "GET", "/api/v1/events?attr.tenant=acme", nil, nil)
	if w.Code != 200 {
		t.Fatalf("list with attr filter returned %d: %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	evs, _ := data["events"].([]any)
	if len(evs) != 1 {
		t.Errorf("attr filter returned %d events, want 1", len(evs))
	}
}

func TestListEventsSortInjectionSafe(t *testing.T) {
	e := newEnv(t)
	do(e, "POST", "/api/v1/events", map[string]any{"id": "s1", "message": "m", "source": "u"}, nil)
	payload := "timestamp,(SELECT id FROM events)"
	w, _ := do(e, "GET", "/api/v1/events?sort_by="+urlEscape(payload), nil, nil)
	if w.Code >= 500 {
		t.Errorf("sort_by injection payload produced %d; must be validated/rejected", w.Code)
	}
	// Table must remain usable.
	w, _ = do(e, "GET", "/api/v1/events", nil, nil)
	if w.Code != 200 {
		t.Fatalf("events unreadable after injection attempt: %d", w.Code)
	}
}

func urlEscape(s string) string {
	return url.QueryEscape(s)
}

func TestSearchEndpoint(t *testing.T) {
	e := newEnv(t)
	do(e, "POST", "/api/v1/events", map[string]any{"id": "q1", "message": "disk full", "source": "mon", "severity": "err"}, nil)

	w, _ := do(e, "POST", "/api/v1/search", map[string]any{"query": "source=mon", "limit": 10}, nil)
	if w.Code != 200 {
		t.Fatalf("search %d %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	res, _ := data["results"].([]any)
	if len(res) != 1 {
		t.Errorf("search results %d", len(res))
	}

	// head -1 must not crash the handler.
	w, _ = do(e, "POST", "/api/v1/search", map[string]any{"query": "source=mon | head -1", "limit": 10}, nil)
	if w.Code >= 500 {
		t.Errorf("negative head produced %d", w.Code)
	}

	// Empty query rejected.
	w, _ = do(e, "POST", "/api/v1/search", map[string]any{"query": ""}, nil)
	if w.Code != 400 {
		t.Errorf("empty query code %d", w.Code)
	}
}

func TestBatchEvents(t *testing.T) {
	e := newEnv(t)
	batch := map[string]any{"events": []map[string]any{
		{"message": "b1", "source": "u"},
		{"message": "b2", "source": "u"},
	}}
	w, _ := do(e, "POST", "/api/v1/events/batch", batch, nil)
	if w.Code != 201 {
		t.Fatalf("batch %d %s", w.Code, w.Body.String())
	}
	w, _ = do(e, "POST", "/api/v1/events/batch", map[string]any{"events": []any{}}, nil)
	if w.Code != 400 {
		t.Errorf("empty batch %d", w.Code)
	}
	w, _ = do(e, "POST", "/api/v1/events/batch", "not-json", nil)
	if w.Code != 400 {
		t.Errorf("invalid batch %d", w.Code)
	}
}

func TestEventCRUD(t *testing.T) {
	e := newEnv(t)
	do(e, "POST", "/api/v1/events", map[string]any{"id": "d1", "message": "del", "source": "u"}, nil)
	w, _ := do(e, "DELETE", "/api/v1/events/d1", nil, nil)
	if w.Code != 200 {
		t.Fatalf("delete %d %s", w.Code, w.Body.String())
	}
	w, _ = do(e, "GET", "/api/v1/events/d1", nil, nil)
	if w.Code != 404 {
		t.Errorf("get deleted %d", w.Code)
	}
	w, _ = do(e, "POST", "/api/v1/events", "garbage{", nil)
	if w.Code != 400 {
		t.Errorf("invalid json %d", w.Code)
	}
}

func TestIncidentEndpoint(t *testing.T) {
	e := newEnv(t)
	w, _ := do(e, "POST", "/api/v1/incidents", map[string]any{
		"title": "phishing", "severity": "high", "description": "d",
	}, nil)
	if w.Code != 201 {
		t.Fatalf("create incident %d: %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	id, _ := data["id"].(string)
	if id == "" {
		t.Fatal("no id")
	}
	w, _ = do(e, "GET", "/api/v1/incidents/"+id, nil, nil)
	if w.Code != 200 {
		t.Fatalf("get incident %d: %s", w.Code, w.Body.String())
	}
	w, _ = do(e, "POST", "/api/v1/incidents/"+id+"/acknowledge", nil, nil)
	if w.Code != 200 {
		t.Errorf("ack incident %d", w.Code)
	}
	w, _ = do(e, "POST", "/api/v1/incidents", map[string]any{}, nil)
	if w.Code != 400 {
		t.Errorf("missing title %d", w.Code)
	}
}

func TestAlertEndpoints(t *testing.T) {
	e := newEnv(t)
	// Seed an alert through the store directly (alerts are generated by detections).
	db := e.db
	db.ExecContext(context.Background(),
		"INSERT INTO alerts (id, timestamp, detection_id, severity, status, title) VALUES (?,?,?,?,?,?)",
		"al-1", "2026-01-01T00:00:00Z", "det", "high", "new", "t")

	w, _ := do(e, "GET", "/api/v1/alerts/al-1", nil, nil)
	if w.Code != 200 {
		t.Fatalf("get alert %d: %s", w.Code, w.Body.String())
	}
	w, _ = do(e, "POST", "/api/v1/alerts/al-1/notes", map[string]any{"content": "note!", "author": "a"}, nil)
	if w.Code != 200 {
		t.Fatalf("add note %d: %s", w.Code, w.Body.String())
	}
	w, _ = do(e, "GET", "/api/v1/alerts/al-1", nil, nil)
	out := decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	notes, _ := data["notes"].([]any)
	if len(notes) != 1 {
		t.Errorf("notes missing from alert payload: %#v", data["notes"])
	}
	w, _ = do(e, "POST", "/api/v1/alerts/al-1/acknowledge", nil, nil)
	if w.Code != 200 {
		t.Errorf("ack %d", w.Code)
	}
	w, _ = do(e, "POST", "/api/v1/alerts/al-1/notes", map[string]any{}, nil)
	if w.Code != 400 {
		t.Errorf("empty note %d", w.Code)
	}
}

func TestDetectionEndpoints(t *testing.T) {
	e := newEnv(t)
	w, _ := do(e, "POST", "/api/v1/detections", map[string]any{
		"name": "r1", "query": "source=auth", "severity": "high",
	}, nil)
	if w.Code != 201 {
		t.Fatalf("create detection %d %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	id, _ := data["ID"].(string)
	if id == "" {
		// fall back to case-insensitive lookup
		for k, v := range data {
			if strings.ToLower(k) == "id" {
				id, _ = v.(string)
			}
		}
	}
	if id == "" {
		t.Fatalf("no rule id returned: %#v", data)
	}
	w, _ = do(e, "GET", "/api/v1/detections", nil, nil)
	if w.Code != 200 {
		t.Fatalf("list %d", w.Code)
	}
	out = decodeBody(t, w)
	rules, _ := out["data"].([]any)
	if len(rules) != 1 {
		t.Errorf("rules %d", len(rules))
	}
	w, _ = do(e, "PUT", "/api/v1/detections/"+id, map[string]any{
		"name": "r1b", "query": "source=auth2", "severity": "high", "enabled": true,
	}, nil)
	if w.Code != 200 {
		t.Errorf("update %d %s", w.Code, w.Body.String())
	}
	w, _ = do(e, "POST", "/api/v1/detections/"+id+"/exec", nil, nil)
	if w.Code != 200 {
		t.Errorf("exec %d %s", w.Code, w.Body.String())
	}
	w, _ = do(e, "DELETE", "/api/v1/detections/"+id, nil, nil)
	if w.Code != 200 {
		t.Errorf("delete %d", w.Code)
	}
	w, _ = do(e, "POST", "/api/v1/detections", map[string]any{"name": "", "query": "q"}, nil)
	if w.Code != 400 {
		t.Errorf("missing name %d", w.Code)
	}
}

func TestStats(t *testing.T) {
	e := newEnv(t)
	do(e, "POST", "/api/v1/events", map[string]any{"id": "st1", "message": "m", "source": "u", "severity": "err"}, nil)
	w, _ := do(e, "GET", "/api/v1/stats", nil, nil)
	if w.Code != 200 {
		t.Fatalf("stats %d %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	if total, _ := data["total"].(float64); total < 1 {
		t.Errorf("stats total %v", data["total"])
	}
}

func TestPaginationShape(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 15; i++ {
		do(e, "POST", "/api/v1/events", map[string]any{"id": fmt.Sprintf("pg-%d", i), "message": "m", "source": "u"}, nil)
	}
	w, _ := do(e, "GET", "/api/v1/events?limit=5&offset=0", nil, nil)
	if w.Code != 200 {
		t.Fatalf("list %d", w.Code)
	}
	out := decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	p, _ := data["pagination"].(map[string]any)
	if p == nil {
		t.Fatal("pagination missing")
	}
	if hm, _ := p["has_more"].(bool); !hm {
		t.Errorf("has_more wrong: %#v", p)
	}
	if total, _ := p["total"].(float64); total != 15 {
		t.Errorf("total %#v", p["total"])
	}
}

func TestLoginAndMeFlow(t *testing.T) {
	e := newEnv(t)
	// Bootstrap: the system must have a usable auth schema + default admin after
	// SetupRouter (see README: default admin changeme, first-run usability).
	w, _ := do(e, "POST", "/api/v1/login", map[string]any{"username": "admin", "password": "changeme"}, nil)
	if w.Code != 200 {
		t.Fatalf("login failed %d: %s (auth schema/bootstrap missing?)", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	token, _ := data["token"].(string)
	if token == "" {
		t.Fatal("no token")
	}
	authH := map[string]string{"Authorization": "Bearer " + token}

	w, _ = do(e, "GET", "/api/v1/users/me", nil, authH)
	if w.Code != 200 {
		t.Fatalf("me %d %s", w.Code, w.Body.String())
	}
	out = decodeBody(t, w)
	userInfo, _ := out["data"].(map[string]any)
	if userInfo["username"] != "admin" {
		t.Errorf("me wrong: %#v", userInfo)
	}

	// Wrong password rejected.
	w, _ = do(e, "POST", "/api/v1/login", map[string]any{"username": "admin", "password": "wrong"}, nil)
	if w.Code != 401 {
		t.Errorf("bad password %d", w.Code)
	}

	// Logout revokes the token.
	w, _ = do(e, "POST", "/api/v1/logout", nil, authH)
	if w.Code != 200 {
		t.Fatalf("logout %d %s", w.Code, w.Body.String())
	}
	w, _ = do(e, "GET", "/api/v1/users/me", nil, authH)
	if w.Code != 401 {
		t.Errorf("token still valid after logout (%d) — revocation broken", w.Code)
	}
}

func TestAdminUserManagement(t *testing.T) {
	e := newEnv(t)
	w, _ := do(e, "POST", "/api/v1/login", map[string]any{"username": "admin", "password": "changeme"}, nil)
	if w.Code != 200 {
		t.Fatalf("login %d %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	token, _ := data["token"].(string)
	authH := map[string]string{"Authorization": "Bearer " + token}

	w, _ = do(e, "POST", "/api/v1/users", map[string]any{"username": "ana", "password": "secret123", "role": "analyst"}, authH)
	if w.Code != 201 {
		t.Fatalf("create user %d %s", w.Code, w.Body.String())
	}
	w, _ = do(e, "POST", "/api/v1/users", map[string]any{"username": "ana", "password": "secret123", "role": "analyst"}, authH)
	if w.Code != 409 {
		t.Errorf("duplicate user %d", w.Code)
	}

	// Non-admin cannot list users.
	w, _ = do(e, "POST", "/api/v1/login", map[string]any{"username": "ana", "password": "secret123"}, nil)
	if w.Code != 200 {
		t.Fatalf("analyst login %d %s", w.Code, w.Body.String())
	}
	out = decodeBody(t, w)
	data, _ = out["data"].(map[string]any)
	analystTok, _ := data["token"].(string)
	w, _ = do(e, "GET", "/api/v1/users", nil, map[string]string{"Authorization": "Bearer " + analystTok})
	if w.Code != 403 {
		t.Errorf("RBAC violation: analyst listed users (%d)", w.Code)
	}

	// Update with partial payload must not panic (nil pointer deref regression).
	w, _ = do(e, "GET", "/api/v1/users", nil, authH)
	out = decodeBody(t, w)
	users, _ := out["data"].([]any)
	var targetID string
	for _, u := range users {
		m, _ := u.(map[string]any)
		if m["username"] == "ana" {
			targetID, _ = m["id"].(string)
		}
	}
	if targetID == "" {
		t.Fatal("target user not found")
	}
	w, _ = do(e, "PUT", "/api/v1/users/"+targetID, map[string]any{"enabled": false}, authH)
	if w.Code != 200 {
		t.Errorf("partial update returned %d (%s) — nil deref panic suspected", w.Code, w.Body.String())
	}
	// User without auth header is rejected from admin endpoints.
	w, _ = do(e, "GET", "/api/v1/users", nil, nil)
	if w.Code != 401 {
		t.Errorf("no-auth admin list %d", w.Code)
	}
}

func TestAPIAuthTokensEnforcedWhenConfigured(t *testing.T) {
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.Migrate(db); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := config.DefaultConfig()
	cfg.Auth.APIToken = "s3cret-token"
	h, err := api.SetupRouter(cfg,
		events.NewStore(db), query.NewService(db), alerts.NewStore(db),
		incidents.NewStore(db), detections.NewStore(db), auth.NewStore(db), logger)
	if err != nil {
		t.Fatalf("setup router: %v", err)
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/events", nil))
	if w.Code != 401 {
		t.Errorf("unauthenticated access allowed (%d) despite configured API token — auth bypass", w.Code)
	}

	w = httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer s3cret-token")
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("valid token rejected %d", w.Code)
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Errorf("bad token accepted %d", w.Code)
	}
}
