package api_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"quetzalog/internal/ai"
	"quetzalog/internal/alerts"
	"quetzalog/internal/api"
	"quetzalog/internal/auth"
	"quetzalog/internal/config"
	"quetzalog/internal/database"
	"quetzalog/internal/detections"
	"quetzalog/internal/events"
	"quetzalog/internal/findings"
	"quetzalog/internal/incidents"
	"quetzalog/internal/query"
)

// validAnalysisJSON returns a schema-valid analysis payload for tests.
func validAnalysisJSON() string {
	return `{
		"title": "Possible credential stuffing",
		"summary": "Repeated failed logins followed by a successful login.",
		"severity": "high",
		"confidence": 0.82,
		"what_is_happening": "17 failed logins followed by a successful login from one source.",
		"why_it_matters": "Pattern is consistent with account takeover.",
		"evidence": ["17 failed logins", "successful login from the same source"],
		"alternative_explanations": ["User repeatedly mistyping the password"],
		"recommended_action": {
			"type": "investigate",
			"description": "Review the successful login and source reputation.",
			"risk": "low"
		},
		"requires_human_approval": false
	}`
}

// apiFakeProvider is an injectable ai.Provider for API-level tests.
type apiFakeProvider struct {
	out   string
	err   error
	calls int32
}

func (p *apiFakeProvider) Name() string { return "fake" }
func (p *apiFakeProvider) Analyze(ctx context.Context, req ai.Request) (string, error) {
	atomic.AddInt32(&p.calls, 1)
	return p.out, p.err
}
func (p *apiFakeProvider) Health(ctx context.Context) (ai.Health, error) {
	return ai.Health{OK: true, Provider: "fake", Detail: "ok"}, nil
}
func (p *apiFakeProvider) Models(ctx context.Context) ([]string, bool, error) {
	return []string{"fake-model-a", "fake-model-b"}, true, nil
}

type aiEnv struct {
	req func(method, path, token string, body any) *httptest.ResponseRecorder
	db  *sql.DB
	fs  *findings.Store
	svc *ai.Service
}

func newAIEnv(t *testing.T, fake *apiFakeProvider) *aiEnv {
	t.Helper()
	// Pin the admin bootstrap password before the router bootstraps users.
	setAdminPassword(t)
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := config.DefaultConfig()
	cfg.Auth.APIToken = "test-api-token"
	// A nominal endpoint/model so the "configured" gate passes; the provider
	// factory below is injected, so no real model is ever contacted.
	cfg.AIAnalyst.Enabled = true
	cfg.AIAnalyst.Provider = "openai-compatible"
	cfg.AIAnalyst.Endpoint = "http://fake-model.local/v1"
	cfg.AIAnalyst.Model = "fake-model"

	fs, is, rs, rr := socStores(db)
	ev := events.NewStore(db)
	aiS, aiSvc := aiStores(t, db, &cfg, ev, fs)
	if fake != nil {
		aiSvc.SetProviderFor(func(c config.AIAnalyst) (ai.Provider, error) { return fake, nil })
	}
	h, err := api.SetupRouter(cfg,
		ev,
		query.NewService(db),
		alerts.NewStore(db),
		incidents.NewStore(db),
		detections.NewStore(db),
		fs, is, rs, rr,
		auth.NewStore(db),
		aiS, aiSvc,
		logger,
	)
	if err != nil {
		t.Fatalf("setup router: %v", err)
	}
	req := func(method, path, token string, body any) *httptest.ResponseRecorder {
		var rdr io.Reader = strings.NewReader("")
		switch v := body.(type) {
		case nil:
		case string:
			rdr = strings.NewReader(v)
		default:
			b, _ := json.Marshal(v)
			rdr = bytes.NewReader(b)
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
	return &aiEnv{req: req, db: db, fs: fs, svc: aiSvc}
}

func (e *aiEnv) seedFinding(t *testing.T, severity string) string {
	t.Helper()
	f := &findings.Finding{
		Title:       "API test finding",
		Severity:    severity,
		Status:      "new",
		Description: "created by test",
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
	}
	if err := e.fs.Create(context.Background(), f); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return f.ID
}

// pollAnalysis waits for the background analysis to reach a terminal state.
func (e *aiEnv) pollAnalysis(t *testing.T, token, findingID string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		w := e.req("GET", "/api/v1/ai-analyst/finding/"+findingID, token, nil)
		if w.Code != http.StatusOK {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		var out struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		analysis, _ := out.Data["analysis"].(map[string]any)
		st, _ := analysis["status"].(string)
		if st == "analyzed" || st == "failed" {
			return out.Data
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("analysis did not reach a terminal state within 10s")
	return nil
}

func dataOf(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %d: %v — %s", w.Code, err, w.Body.String())
	}
	return out.Data
}

func TestAIAnalystListEmpty(t *testing.T) {
	e := newAIEnv(t, nil)
	w := e.req("GET", "/api/v1/ai-analyst", "test-api-token", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list %d: %s", w.Code, w.Body.String())
	}
	data := dataOf(t, w)
	analyses, _ := data["analyses"].([]any)
	if len(analyses) != 0 {
		t.Errorf("expected empty list, got %d", len(analyses))
	}
}

func TestAIAnalystGetUnknown(t *testing.T) {
	e := newAIEnv(t, nil)
	w := e.req("GET", "/api/v1/ai-analyst/does-not-exist", "test-api-token", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown analysis %d, want 404", w.Code)
	}
	w = e.req("GET", "/api/v1/ai-analyst/finding/does-not-exist", "test-api-token", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown finding %d, want 404", w.Code)
	}
}

func TestAIAnalystAnalyzeUnknownFinding(t *testing.T) {
	e := newAIEnv(t, nil)
	w := e.req("POST", "/api/v1/ai-analyst/analyze", "test-api-token", map[string]any{"finding_id": "nope"})
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown finding analyze %d, want 404", w.Code)
	}
	w = e.req("POST", "/api/v1/ai-analyst/analyze", "test-api-token", map[string]any{})
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing finding_id %d, want 400", w.Code)
	}
}

func TestAIAnalystFullWorkflow(t *testing.T) {
	fake := &apiFakeProvider{out: validAnalysisJSON()}
	e := newAIEnv(t, fake)
	tok := "test-api-token"
	findingID := e.seedFinding(t, "high")

	// Start the analysis (async, 202).
	w := e.req("POST", "/api/v1/ai-analyst/analyze", tok, map[string]any{"finding_id": findingID})
	if w.Code != http.StatusAccepted {
		t.Fatalf("analyze %d: %s", w.Code, w.Body.String())
	}

	// Wait for completion, then verify the payload.
	data := e.pollAnalysis(t, tok, findingID)
	analysis, _ := data["analysis"].(map[string]any)
	if analysis["status"] != "analyzed" {
		t.Fatalf("status: %v", analysis["status"])
	}
	aiPayload, _ := data["ai"].(map[string]any)
	if aiPayload["title"] != "Possible credential stuffing" {
		t.Errorf("ai payload: %#v", aiPayload)
	}
	// The safety invariant must hold in the stored payload.
	if aiPayload["requires_human_approval"] != true {
		t.Error("stored analysis must force requires_human_approval=true")
	}

	// Fetch by id.
	id, _ := analysis["id"].(string)
	w = e.req("GET", "/api/v1/ai-analyst/"+id, tok, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get %d", w.Code)
	}

	// List shows the row with the finding title joined.
	w = e.req("GET", "/api/v1/ai-analyst", tok, nil)
	data = dataOf(t, w)
	analyses, _ := data["analyses"].([]any)
	if len(analyses) != 1 {
		t.Fatalf("list count %d", len(analyses))
	}
	row, _ := analyses[0].(map[string]any)
	if row["finding_title"] != "API test finding" {
		t.Errorf("join lost: %#v", row)
	}
	if row["status"] != "analyzed" || row["recommended_action_type"] != "investigate" {
		t.Errorf("row: %#v", row)
	}
}

// TestAIAnalystApproveAndDismiss drives the human decision endpoints with a
// real user token.
func TestAIAnalystApproveAndDismiss(t *testing.T) {
	fake := &apiFakeProvider{out: validAnalysisJSON()}
	e := newAIEnv(t, fake)

	adminTok, w := doLogin(t, e.req, "admin", testAdminPassword)
	if w.Code != http.StatusOK {
		t.Fatalf("admin login %d: %s", w.Code, w.Body.String())
	}

	highID := e.seedFinding(t, "high")
	if w = e.req("POST", "/api/v1/ai-analyst/analyze", adminTok, map[string]any{"finding_id": highID}); w.Code != http.StatusAccepted {
		t.Fatalf("analyze %d: %s", w.Code, w.Body.String())
	}
	data := e.pollAnalysis(t, adminTok, highID)
	analysis, _ := data["analysis"].(map[string]any)
	id, _ := analysis["id"].(string)

	// Approve.
	w = e.req("POST", "/api/v1/ai-analyst/"+id+"/approve", adminTok, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("approve %d: %s", w.Code, w.Body.String())
	}
	data = dataOf(t, w)
	if data["status"] != "approved" || data["decision"] != "approve" {
		t.Errorf("approved: %#v", data)
	}

	// An analyst (non-admin) can approve/dismiss too (write role is allowed).
	analystID := e.seedFinding(t, "medium")
	if w = e.req("POST", "/api/v1/ai-analyst/analyze", adminTok, map[string]any{"finding_id": analystID}); w.Code != http.StatusAccepted {
		t.Fatalf("analyze2 %d: %s", w.Code, w.Body.String())
	}
	data = e.pollAnalysis(t, adminTok, analystID)
	analysis, _ = data["analysis"].(map[string]any)
	id2, _ := analysis["id"].(string)

	w = e.req("POST", "/api/v1/users", adminTok, map[string]any{"username": "ai-analyst", "password": "ai-pass-123", "role": "analyst"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create analyst %d: %s", w.Code, w.Body.String())
	}
	analystTok, w := doLogin(t, e.req, "ai-analyst", "ai-pass-123")
	if w.Code != http.StatusOK {
		t.Fatalf("analyst login %d", w.Code)
	}
	w = e.req("POST", "/api/v1/ai-analyst/"+id2+"/dismiss", analystTok, map[string]any{"reason": "false positive"})
	if w.Code != http.StatusOK {
		t.Fatalf("dismiss %d: %s", w.Code, w.Body.String())
	}
	data = dataOf(t, w)
	if data["status"] != "dismissed" || data["decision_reason"] != "false positive" {
		t.Errorf("dismissed: %#v", data)
	}

	// Deciding the same analysis twice must fail (409).
	w = e.req("POST", "/api/v1/ai-analyst/"+id2+"/dismiss", analystTok, map[string]any{"reason": "again"})
	if w.Code != http.StatusConflict {
		t.Errorf("second dismiss %d, want 409", w.Code)
	}

	// A note was attached to the findings (audit link).
	notes, err := e.fs.GetNotes(context.Background(), highID)
	if err != nil || len(notes) != 1 || !strings.Contains(notes[0].Content, "approved") {
		t.Errorf("finding note after approve: %v (notes=%+v)", err, notes)
	}
}

// TestAIAnalystFailedAnalysisCannotBeApproved: a failed analysis (garbage
// model output) must not carry a recommendation and must refuse decisions.
func TestAIAnalystFailedAnalysisCannotBeApproved(t *testing.T) {
	fake := &apiFakeProvider{out: "I think it is bad. Block the IP."}
	e := newAIEnv(t, fake)
	tok := "test-api-token"
	id := e.seedFinding(t, "high")

	w := e.req("POST", "/api/v1/ai-analyst/analyze", tok, map[string]any{"finding_id": id})
	if w.Code != http.StatusAccepted {
		t.Fatalf("analyze %d: %s", w.Code, w.Body.String())
	}
	data := e.pollAnalysis(t, tok, id)
	analysis, _ := data["analysis"].(map[string]any)
	if analysis["status"] != "failed" {
		t.Fatalf("status: %v", analysis["status"])
	}
	if analysis["recommended_action_type"] != nil && analysis["recommended_action_type"] != "" {
		t.Errorf("failed analysis carries a recommendation: %#v", analysis)
	}
	analysisID, _ := analysis["id"].(string)
	w = e.req("POST", "/api/v1/ai-analyst/"+analysisID+"/approve", tok, nil)
	if w.Code != http.StatusConflict {
		t.Errorf("approve on failed %d, want 409", w.Code)
	}
}

func TestAIAnalystConfigRedaction(t *testing.T) {
	fake := &apiFakeProvider{out: validAnalysisJSON()}
	e := newAIEnv(t, fake)

	adminTok, w := doLogin(t, e.req, "admin", testAdminPassword)
	if w.Code != http.StatusOK {
		t.Fatalf("admin login %d", w.Code)
	}

	// Configure with a key; the key must never come back.
	body := map[string]any{
		"enabled": true, "provider": "ollama", "endpoint": "http://127.0.0.1:11434",
		"api_key": "super-secret-key", "model": "qwen3.8",
		"minimum_severity": "high", "max_requests_per_minute": 5,
		"timeout_seconds": 30, "max_context_events": 40, "retry_count": 1,
	}
	w = e.req("PUT", "/api/v1/settings/ai-analyst", adminTok, body)
	if w.Code != http.StatusOK {
		t.Fatalf("put config %d: %s", w.Code, w.Body.String())
	}
	data := dataOf(t, w)
	if data["api_key_set"] != true {
		t.Errorf("api_key_set: %#v", data)
	}
	for k, v := range data {
		if s, ok := v.(string); ok && strings.Contains(s, "super-secret-key") {
			t.Errorf("config response leaked the API key in field %q", k)
		}
	}
	if data["provider"] != "ollama" || data["enabled"] != true {
		t.Errorf("config not updated: %#v", data)
	}
	if data["persisted"] != false {
		t.Errorf("persisted flag: %#v", data)
	}

	// GET must match and stay redacted.
	w = e.req("GET", "/api/v1/settings/ai-analyst", "test-api-token", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get config %d", w.Code)
	}
	data = dataOf(t, w)
	if data["api_key_set"] != true || data["model"] != "qwen3.8" {
		t.Errorf("get config: %#v", data)
	}

	// $CLEAR removes the key.
	w = e.req("PUT", "/api/v1/settings/ai-analyst", adminTok, map[string]any{
		"provider": "ollama", "endpoint": "http://127.0.0.1:11434",
		"api_key": "$CLEAR", "model": "qwen3.8",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("clear key %d: %s", w.Code, w.Body.String())
	}
	data = dataOf(t, w)
	if data["api_key_set"] != false {
		t.Errorf("key not cleared: %#v", data)
	}

	// Invalid provider must be a 400, not a 500.
	w = e.req("PUT", "/api/v1/settings/ai-analyst", adminTok, map[string]any{
		"provider": "skynet", "endpoint": "http://x", "model": "m",
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid provider %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

// Endpoint may be saved without a model while discovery is in progress;
// enabling automatic analysis without a model must still be rejected.
func TestAIAnalystConfigModelRequiredOnlyWhenEnabled(t *testing.T) {
	e := newAIEnv(t, &apiFakeProvider{out: validAnalysisJSON()})
	adminTok, w := doLogin(t, e.req, "admin", testAdminPassword)
	if w.Code != http.StatusOK {
		t.Fatalf("admin login %d", w.Code)
	}

	w = e.req("PUT", "/api/v1/settings/ai-analyst", adminTok, map[string]any{
		"enabled": false, "provider": "openai-compatible", "endpoint": "http://10.0.0.1:8000",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("endpoint-only save %d, want 200: %s", w.Code, w.Body.String())
	}

	w = e.req("PUT", "/api/v1/settings/ai-analyst", adminTok, map[string]any{
		"enabled": true, "provider": "openai-compatible", "endpoint": "http://10.0.0.1:8000",
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("enabled without model %d, want 400: %s", w.Code, w.Body.String())
	}
}

func TestAIAnalystConfigRBAC(t *testing.T) {
	fake := &apiFakeProvider{out: validAnalysisJSON()}
	e := newAIEnv(t, fake)

	adminTok, w := doLogin(t, e.req, "admin", testAdminPassword)
	if w.Code != http.StatusOK {
		t.Fatalf("admin login %d", w.Code)
	}
	w = e.req("POST", "/api/v1/users", adminTok, map[string]any{"username": "rbac-a", "password": "rbac-pass-1", "role": "analyst"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create user %d", w.Code)
	}
	analystTok, w := doLogin(t, e.req, "rbac-a", "rbac-pass-1")
	if w.Code != http.StatusOK {
		t.Fatalf("analyst login %d", w.Code)
	}

	// Analysts can read the config...
	w = e.req("GET", "/api/v1/settings/ai-analyst", analystTok, nil)
	if w.Code != http.StatusOK {
		t.Errorf("analyst get config %d", w.Code)
	}
	// ...but only admins may change it.
	w = e.req("PUT", "/api/v1/settings/ai-analyst", analystTok, map[string]any{
		"provider": "ollama", "endpoint": "http://x", "model": "m",
	})
	if w.Code != http.StatusForbidden {
		t.Errorf("analyst put config %d, want 403 (RBAC)", w.Code)
	}
	// Unknown user tokens are rejected.
	w = e.req("PUT", "/api/v1/settings/ai-analyst", "not-a-user-token", map[string]any{
		"provider": "ollama", "endpoint": "http://x", "model": "m",
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("static token put config %d, want 401 (RBAC)", w.Code)
	}
}

func TestAIAnalystTestConnectionAndModels(t *testing.T) {
	fake := &apiFakeProvider{out: validAnalysisJSON()}
	e := newAIEnv(t, fake)
	tok := "test-api-token"

	w := e.req("POST", "/api/v1/settings/ai-analyst/test", tok, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("test %d: %s", w.Code, w.Body.String())
	}
	data := dataOf(t, w)
	if data["ok"] != true || data["provider"] != "fake" {
		t.Errorf("test: %#v", data)
	}

	w = e.req("GET", "/api/v1/settings/ai-analyst/models", tok, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("models %d: %s", w.Code, w.Body.String())
	}
	data = dataOf(t, w)
	if data["supported"] != true {
		t.Errorf("supported: %#v", data)
	}
	models, _ := data["models"].([]any)
	if len(models) != 2 {
		t.Errorf("models: %#v", data["models"])
	}
}

// TestAIAnalystTestConnectionFailure reports provider failures as ok:false
// (200) rather than an error status, so the UI can show the detail.
func TestAIAnalystTestConnectionFailure(t *testing.T) {
	fake := &apiFakeProvider{err: fmt.Errorf("%w: endpoint refused", ai.ErrUnavailable)}
	e := newAIEnv(t, fake)

	// TestConnection uses Health, not Analyze; this fake's Health is OK, so
	// verify the failure path through a provider whose Health fails.
	svc := e.svc
	svc.SetProviderFor(func(c config.AIAnalyst) (ai.Provider, error) {
		return &healthFailProvider{}, nil
	})
	w := e.req("POST", "/api/v1/settings/ai-analyst/test", "test-api-token", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("test %d", w.Code)
	}
	data := dataOf(t, w)
	if data["ok"] != false || data["detail"] == "" {
		t.Errorf("failure not reported: %#v", data)
	}
	_ = fake
}

type healthFailProvider struct{}

func (p *healthFailProvider) Name() string { return "fake" }
func (p *healthFailProvider) Analyze(ctx context.Context, req ai.Request) (string, error) {
	return "", nil
}
func (p *healthFailProvider) Health(ctx context.Context) (ai.Health, error) {
	return ai.Health{Detail: "connection refused"}, fmt.Errorf("%w: connection refused", ai.ErrUnavailable)
}
func (p *healthFailProvider) Models(ctx context.Context) ([]string, bool, error) {
	return nil, false, nil
}
