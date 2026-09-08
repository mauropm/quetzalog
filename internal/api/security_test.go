package api_test

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
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

// testAdminPassword pins the default-admin bootstrap password through the
// supported env override (product code must not hardcode it).
const testAdminPassword = "audit-admin-Pw-9182"

// newSecureEnv builds an API router with an explicit config.
func newSecureEnv(t *testing.T, cfg config.Config) func(method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
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
		t.Fatalf("setup router: %v", err)
	}
	return func(method, path, token string, body any) *httptest.ResponseRecorder {
		var rdr io.Reader = strings.NewReader("")
		switch v := body.(type) {
		case nil:
		case string:
			rdr = strings.NewReader(v)
		default:
			b, _ := json.Marshal(v)
			rdr = strings.NewReader(string(b))
		}
		r := httptest.NewRequest(method, path, rdr)
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
}

func setAdminPassword(t *testing.T) {
	t.Helper()
	old, had := os.LookupEnv("QUETZALOG_ADMIN_PASSWORD")
	if err := os.Setenv("QUETZALOG_ADMIN_PASSWORD", testAdminPassword); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("QUETZALOG_ADMIN_PASSWORD", old)
		} else {
			_ = os.Unsetenv("QUETZALOG_ADMIN_PASSWORD")
		}
	})
}

func doLogin(t *testing.T, req func(method, path, token string, body any) *httptest.ResponseRecorder, username, password string) (string, *httptest.ResponseRecorder) {
	t.Helper()
	w := req("POST", "/api/v1/login", "", map[string]any{"username": username, "password": password})
	if w.Code != 200 {
		return "", w
	}
	var out struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("login decode: %v", err)
	}
	return out.Data.Token, w
}

// SEC-01: default (Auth.Enabled) config must never expose a world-writable
// management API just because no static token was configured.
func TestSEC_DefaultConfigNotUnauthenticated(t *testing.T) {
	setAdminPassword(t)
	req := newSecureEnv(t, config.DefaultConfig())

	w := req("POST", "/api/v1/events", "", map[string]any{"message": "evil write"})
	if w.Code != 401 && w.Code != 403 {
		t.Errorf("unauthenticated event write returned %d — API exposed without auth (SEC-01)", w.Code)
	}
	w = req("POST", "/api/v1/detections", "", map[string]any{"name": "x", "query": "source=y"})
	if w.Code != 401 && w.Code != 403 {
		t.Errorf("unauthenticated detection create returned %d (SEC-01)", w.Code)
	}
	w = req("DELETE", "/api/v1/events/whatever", "", nil)
	if w.Code != 401 && w.Code != 403 {
		t.Errorf("unauthenticated event delete returned %d (SEC-01)", w.Code)
	}

	w = req("GET", "/api/v1/health", "", nil)
	if w.Code != 200 {
		t.Errorf("health returned %d, want 200", w.Code)
	}

	tok, w := doLogin(t, req, "admin", testAdminPassword)
	if w.Code != 200 {
		t.Fatalf("admin login returned %d — legit workflow broken", w.Code)
	}
	w = req("POST", "/api/v1/events", tok, map[string]any{"message": "legit write"})
	if w.Code != 201 {
		t.Errorf("user-token event write returned %d: %s", w.Code, w.Body.String())
	}
}

// SEC-02: default admin must not keep the hardcoded 'changeme' password.
func TestSEC_DefaultAdminNotStaticPassword(t *testing.T) {
	setAdminPassword(t)
	req := newSecureEnv(t, config.DefaultConfig())

	w := req("POST", "/api/v1/login", "", map[string]any{"username": "admin", "password": "changeme"})
	if w.Code == 200 {
		t.Error("admin/changeme login succeeded — hardcoded default credential reachable (SEC-02)")
	}
	w = req("POST", "/api/v1/login", "", map[string]any{"username": "admin", "password": testAdminPassword})
	if w.Code != 200 {
		t.Errorf("env-overridden admin password rejected: %d", w.Code)
	}
}

type userOp struct {
	method string
	path   string
}

// SEC-03: tokens of disabled/soft-deleted users must stop working.
func TestSEC_DisabledUserTokenRejected(t *testing.T) {
	setAdminPassword(t)
	cfg := config.DefaultConfig()
	cfg.Auth.APIToken = "static-op-token"
	req := newSecureEnv(t, cfg)

	adminTok, w := doLogin(t, req, "admin", testAdminPassword)
	if w.Code != 200 {
		t.Fatalf("admin login: %d %s", w.Code, w.Body.String())
	}

	w = req("POST", "/api/v1/users", adminTok, map[string]any{"username": "analyst1", "password": "analyst-pass-9", "role": "analyst"})
	if w.Code != 201 {
		t.Fatalf("create analyst: %d %s", w.Code, w.Body.String())
	}
	analystTok, w := doLogin(t, req, "analyst1", "analyst-pass-9")
	if w.Code != 200 {
		t.Fatalf("analyst login: %d", w.Code)
	}
	w = req("POST", "/api/v1/events", analystTok, map[string]any{"message": "analyst write"})
	if w.Code != 201 {
		t.Fatalf("analyst write before disable: %d %s", w.Code, w.Body.String())
	}

	w = req("GET", "/api/v1/users", adminTok, nil)
	if w.Code != 200 {
		t.Fatalf("list users: %d", w.Code)
	}
	var listOut struct {
		Data []struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listOut); err != nil {
		t.Fatalf("list decode: %v", err)
	}
	analystID := ""
	for _, u := range listOut.Data {
		if u.Username == "analyst1" {
			analystID = u.ID
		}
	}
	if analystID == "" {
		t.Fatal("analyst1 missing from list")
	}

	w = req("PUT", "/api/v1/users/"+analystID, adminTok, map[string]any{"enabled": false})
	if w.Code != 200 {
		t.Fatalf("disable: %d %s", w.Code, w.Body.String())
	}

	for _, op := range []userOp{
		{"GET", "/api/v1/users/me"},
		{"POST", "/api/v1/events"},
		{"GET", "/api/v1/events"},
	} {
		w = req(op.method, op.path, analystTok, map[string]any{"message": "post-disable write"})
		if w.Code != 401 && w.Code != 403 {
			t.Errorf("disabled analyst %s %s returned %d — token survives disable (SEC-03)", op.method, op.path, w.Code)
		}
	}

	w = req("PUT", "/api/v1/users/"+analystID, adminTok, map[string]any{"enabled": true})
	if w.Code != 200 {
		t.Fatalf("re-enable: %d", w.Code)
	}
	w = req("POST", "/api/v1/events", analystTok, map[string]any{"message": "post-enable write"})
	if w.Code != 201 {
		t.Errorf("re-enabled analyst write returned %d — recovery broken (SEC-03)", w.Code)
	}
}

// SEC-04: query/search limits must be clamped; no unbounded SQL LIMIT.
func TestSEC_ListAndSearchLimitClamped(t *testing.T) {
	setAdminPassword(t)
	cfg := config.DefaultConfig()
	cfg.Auth.Enabled = false
	req := newSecureEnv(t, cfg)

	w := req("GET", "/api/v1/events?limit=999999999&offset=-5", "", nil)
	if w.Code != 200 {
		t.Fatalf("list: %d", w.Code)
	}
	var out struct {
		Data struct {
			Pagination struct {
				Limit  int `json:"limit"`
				Offset int `json:"offset"`
			} `json:"pagination"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Data.Pagination.Limit <= 0 || out.Data.Pagination.Limit > 1000 {
		t.Errorf("list limit not clamped: %v (SEC-04)", out.Data.Pagination.Limit)
	}
	if out.Data.Pagination.Offset < 0 {
		t.Errorf("negative offset accepted: %v", out.Data.Pagination.Offset)
	}

	w = req("POST", "/api/v1/search", "", map[string]any{"query": "source=x", "limit": 999999999})
	if w.Code != 200 {
		t.Fatalf("search: %d %s", w.Code, w.Body.String())
	}
}

// SEC-05: oversized request bodies must be rejected, not buffered unbounded.
func TestSEC_OversizedBodyRejected(t *testing.T) {
	setAdminPassword(t)
	cfg := config.DefaultConfig()
	cfg.Auth.APIToken = "static-op-token"
	req := newSecureEnv(t, cfg)

	huge := strings.Repeat("A", 60*1024*1024)
	w := req("POST", "/api/v1/search", "static-op-token", huge)
	if w.Code < 400 || w.Code > 413 {
		t.Errorf("60MB body on /search returned %d, want 4xx (SEC-05)", w.Code)
	}

	w = req("POST", "/api/v1/search", "static-op-token", map[string]any{"query": "source=y"})
	if w.Code != 200 {
		t.Errorf("normal search body returned %d", w.Code)
	}
}

// SEC-06: login must be rate limited per client IP.
func TestSEC_LoginRateLimited(t *testing.T) {
	setAdminPassword(t)
	cfg := config.DefaultConfig()
	cfg.Auth.APIToken = "static-op-token"
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(db); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	h, err := api.SetupRouter(cfg,
		events.NewStore(db), query.NewService(db), alerts.NewStore(db),
		incidents.NewStore(db), detections.NewStore(db), auth.NewStore(db), logger)
	if err != nil {
		t.Fatal(err)
	}

	// Realistic credential-stuffing burst: many concurrent attempts from one
	// source. Slow single-threaded guessing is handled by per-account
	// lockout; this exercises the per-IP throttle.
	const attempts = 200
	blocked := 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := httptest.NewRequest("POST", "/api/v1/login", strings.NewReader(`{"username":"nobody","password":"bad"}`))
			r.Header.Set("Content-Type", "application/json")
			r.RemoteAddr = fmt.Sprintf("203.0.113.7:%d", 40000+i)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code == http.StatusTooManyRequests {
				mu.Lock()
				blocked++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if blocked == 0 {
		t.Error("200 concurrent login attempts, none rate limited (SEC-06)")
	}

	// A single legitimate login from a different source must still work.
	r := httptest.NewRequest("POST", "/api/v1/login", strings.NewReader(`{"username":"admin","password":"whatever-legit"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "198.51.100.9:55555"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code == http.StatusTooManyRequests {
		t.Error("legit separate client rate limited after burst from other IP")
	}
}

// SEC-07: path normalization tricks must not bypass the token gate.
func TestSEC_PathNormalizationNoBypass(t *testing.T) {
	setAdminPassword(t)
	cfg := config.DefaultConfig()
	cfg.Auth.APIToken = "static-op-token"
	req := newSecureEnv(t, cfg)

	for _, p := range []string{
		"/api/v1/login/../events",
		"//api/v1//events",
		"/api/v1/./events",
	} {
		w := req("GET", p, "", nil)
		if w.Code == 200 {
			t.Errorf("unauthenticated access via path %q (SEC-07)", p)
		}
	}
	w := req("GET", "/api/v1/events", "static-op-token", nil)
	if w.Code != 200 {
		t.Errorf("normal token request broke: %d", w.Code)
	}
}

// SEC-08: attribute filter injection attempts must be 4xx, never 5xx.
func TestSEC_AttrInjectionRejected(t *testing.T) {
	setAdminPassword(t)
	cfg := config.DefaultConfig()
	cfg.Auth.Enabled = false
	req := newSecureEnv(t, cfg)

	for _, p := range []string{
		`attr=a%22%3D%221%22%20OR%201%3D1%20--`,
		`attr.id=%27%20OR%20%271%27%3D%271`,
		`attr.%24)%3B%20DELETE%20FROM%20events%3B%20--=1`,
		`attr.unicode_key=1`,
		`attr.=1`,
	} {
		w := req("GET", "/api/v1/events?"+p, "", nil)
		if w.Code >= 500 {
			t.Errorf("attr payload %q caused %d (SEC-08)", p, w.Code)
		}
	}
}

// SEC-09: baseline security headers on API responses.
func TestSEC_SecurityHeaders(t *testing.T) {
	setAdminPassword(t)
	cfg := config.DefaultConfig()
	cfg.Auth.Enabled = false
	req := newSecureEnv(t, cfg)

	w := req("GET", "/api/v1/health", "", nil)
	for _, hdr := range []string{"X-Content-Type-Options", "X-FRAME-OPTIONS", "Referrer-Policy", "Cache-Control"} {
		if w.Header().Get(hdr) == "" {
			t.Errorf("missing security header %s (SEC-09)", hdr)
		}
	}
}

// SEC-10: bounded property fuzz — no panics, no 5xx, no auth bypass.
func TestSEC_PropertyFuzz(t *testing.T) {
	setAdminPassword(t)
	state := uint64(0xC0FFEE12345678)
	next := func(n int) int {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		return int(state % uint64(n))
	}
	pick := func(opts ...string) string { return opts[next(len(opts))] }
	junk := func(n int) string {
		if n < 1 {
			n = 1
		}
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(33 + next(94))
		}
		return string(b)
	}

	cfg := config.DefaultConfig()
	cfg.Auth.APIToken = "fuzz-static-token"
	req := newSecureEnv(t, cfg)

	for i := 0; i < 1200; i++ {
		m := pick("GET", "POST", "PUT", "DELETE")
		p := pick("/api/v1/events", "/api/v1/login", "/api/v1/search",
			"/api/v1/alerts", "/api/v1/incidents", "/api/v1/detections")
		q := pick("", "?limit="+junk(1+next(9)), "?offset=-"+junk(3), "?sort_by="+junk(6),
			"?attr."+junk(4)+"="+junk(8), "?q="+junk(20), "?start="+junk(10))
		tok := pick("", "fuzz-static-token", junk(10), "siem_"+junk(64))
		var body any
		switch next(4) {
		case 0:
			body = map[string]any{"query": junk(1+next(200)), "limit": next(2000000) - 1}
		case 1:
			body = map[string]any{"message": junk(next(2000)), "attributes": map[string]any{junk(4): junk(20)}}
		case 2:
			body = `{"events":[` + strings.Repeat(`{"message":"x"},`, 3) + `{"m":1}]}`
		}
		w := req(m, p+q, tok, body)
		if w.Code >= 500 {
			t.Fatalf("fuzz %d: %s %s%s token=%q body=%v (SEC-10)", w.Code, m, p, q, tok, body)
		}
		if tok == "" && (m == "POST" || m == "PUT" || m == "DELETE") && p != "/api/v1/login" &&
			w.Code >= 200 && w.Code < 300 {
			t.Fatalf("unauthenticated %s %s succeeded with %d (SEC-10)", m, p, w.Code)
		}
	}
}

// SEC-11: concurrent valid/invalid/absent token traffic stays consistent.
func TestSEC_ConcurrentAuthZ(t *testing.T) {
	setAdminPassword(t)
	cfg := config.DefaultConfig()
	cfg.Auth.APIToken = "race-token"
	req := newSecureEnv(t, cfg)

	var wg sync.WaitGroup
	var mu sync.Mutex
	badUnauth, badInvalid, badValid := 0, 0, 0
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			w := req("GET", "/api/v1/events", "", nil)
			if w.Code != 401 && w.Code != 403 {
				mu.Lock()
				badUnauth++
				mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			w := req("GET", "/api/v1/events", "race-token", nil)
			if w.Code != 200 {
				mu.Lock()
				badValid++
				mu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			w := req("GET", "/api/v1/events", "wrong-token", nil)
			if w.Code != 401 && w.Code != 403 {
				mu.Lock()
				badInvalid++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if badUnauth+badInvalid+badValid > 0 {
		t.Errorf("authz race: unauth-ok=%d invalid-ok=%d valid-fail=%d (SEC-11)", badUnauth, badInvalid, badValid)
	}
}
