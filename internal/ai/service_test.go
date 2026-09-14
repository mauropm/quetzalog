package ai

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"quetzalog/internal/config"
	"quetzalog/internal/database"
	"quetzalog/internal/findings"
)

// fakeProvider is an injectable provider for service tests.
type fakeProvider struct {
	name  string
	out   string
	err   error
	calls int32
}

func (f *fakeProvider) Name() string { return f.name }
func (f *fakeProvider) Analyze(ctx context.Context, req Request) (string, error) {
	atomic.AddInt32(&f.calls, 1)
	return f.out, f.err
}
func (f *fakeProvider) Health(ctx context.Context) (Health, error) {
	return Health{OK: true, Provider: f.name, Detail: "ok"}, nil
}
func (f *fakeProvider) Models(ctx context.Context) ([]string, bool, error) {
	return []string{"m1"}, true, nil
}

func newServiceEnv(t *testing.T, fake *fakeProvider) (*Service, *findings.Store, *config.Config) {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cfg := config.DefaultConfig()
	cfg.AIAnalyst.Enabled = true
	cfg.AIAnalyst.Provider = "openai-compatible"
	cfg.AIAnalyst.Endpoint = "http://localhost:11434/v1"
	cfg.AIAnalyst.Model = "test-model"
	cfg.AIAnalyst.MaxRequestsPerMinute = 100
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	fs := findings.NewStore(db)
	svc := NewService(&cfg, "", NewStore(db), fs, NewContextBuilder(fs, nil), logger)
	svc.SetProviderFor(func(c config.AIAnalyst) (Provider, error) { return fake, nil })
	return svc, fs, &cfg
}

func seedFinding(t *testing.T, fs *findings.Store, severity string) *findings.Finding {
	t.Helper()
	f := &findings.Finding{
		Title:       "Test finding",
		Severity:    severity,
		Status:      "new",
		Description: "description",
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Entities:    []string{"user:jsmith", "ip:10.0.0.1", "host:web-01"},
	}
	if err := fs.Create(context.Background(), f); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return f
}

func TestServiceAnalyzeFindingSuccess(t *testing.T) {
	fake := &fakeProvider{name: "fake", out: validAnalysisJSON()}
	svc, fs, _ := newServiceEnv(t, fake)
	f := seedFinding(t, fs, "high")

	row, err := svc.AnalyzeFinding(context.Background(), f.ID, false)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if row.Status != "analyzed" {
		t.Errorf("status: %q", row.Status)
	}
	if row.Severity != "high" || row.RecommendationType != "investigate" {
		t.Errorf("row: %+v", row)
	}
	if row.Decision != "" {
		t.Errorf("no decision expected yet: %q", row.Decision)
	}
	if atomic.LoadInt32(&fake.calls) != 1 {
		t.Errorf("provider calls: %d", fake.calls)
	}
}

func TestServiceDeduplicationNoSecondAnalysis(t *testing.T) {
	fake := &fakeProvider{name: "fake", out: validAnalysisJSON()}
	svc, fs, _ := newServiceEnv(t, fake)
	f := seedFinding(t, fs, "high")

	if _, err := svc.AnalyzeFinding(context.Background(), f.ID, false); err != nil {
		t.Fatal(err)
	}
	// Second automatic run: deduplicated, no provider call.
	row, err := svc.AnalyzeFinding(context.Background(), f.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if row.Status != "analyzed" {
		t.Errorf("status: %q", row.Status)
	}
	if atomic.LoadInt32(&fake.calls) != 1 {
		t.Errorf("expected exactly one provider call (dedup), got %d", fake.calls)
	}
	// Manual re-analysis is allowed and re-runs.
	if _, err := svc.AnalyzeFinding(context.Background(), f.ID, true); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&fake.calls) != 2 {
		t.Errorf("manual re-analysis should call the provider, calls=%d", fake.calls)
	}
}

func TestServiceSeverityGate(t *testing.T) {
	fake := &fakeProvider{name: "fake", out: validAnalysisJSON()}
	svc, fs, cfg := newServiceEnv(t, fake)
	cfg.AIAnalyst.MinimumSeverity = "high"
	f := seedFinding(t, fs, "low")

	_, err := svc.AnalyzeFinding(context.Background(), f.ID, false)
	if !errors.Is(err, ErrBelowSeverity) {
		t.Fatalf("want ErrBelowSeverity, got %v", err)
	}
	if atomic.LoadInt32(&fake.calls) != 0 {
		t.Error("provider must not be called below the severity gate")
	}
	// Manual analysis bypasses the gate.
	if _, err := svc.AnalyzeFinding(context.Background(), f.ID, true); err != nil {
		t.Fatalf("manual analyze: %v", err)
	}
}

func TestServiceDisabledGatesAutomaticButNotManual(t *testing.T) {
	fake := &fakeProvider{name: "fake", out: validAnalysisJSON()}
	svc, fs, cfg := newServiceEnv(t, fake)
	cfg.AIAnalyst.Enabled = false
	f := seedFinding(t, fs, "high")

	if _, err := svc.AnalyzeFinding(context.Background(), f.ID, false); !errors.Is(err, ErrDisabled) {
		t.Fatalf("want ErrDisabled, got %v", err)
	}
	if _, err := svc.AnalyzeFinding(context.Background(), f.ID, true); err != nil {
		t.Fatalf("manual analyze while disabled: %v", err)
	}
}

func TestServiceFailedAnalysisRecordsNoRecommendation(t *testing.T) {
	fake := &fakeProvider{name: "fake", out: "I recommend we block the IP immediately."}
	svc, fs, _ := newServiceEnv(t, fake)
	f := seedFinding(t, fs, "high")

	_, err := svc.AnalyzeFinding(context.Background(), f.ID, false)
	if err == nil {
		t.Fatal("malformed output must fail the analysis")
	}
	row, err := svc.store.ActiveByFinding(context.Background(), f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row.Status != "failed" {
		t.Errorf("status: %q", row.Status)
	}
	if row.RecommendationType != "" || row.Severity != "" {
		t.Errorf("failed analysis must not carry a recommendation: %+v", row)
	}
	// Deciding a failed analysis must fail.
	if _, err := svc.Approve(context.Background(), row.ID, "analyst"); !errors.Is(err, ErrNoAnalysis) {
		t.Errorf("approve on failed analysis: %v", err)
	}
}

func TestServiceTransientRetry(t *testing.T) {
	var calls int32
	provider := &statefulProvider{fn: func() (string, error) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			return "", fmt.Errorf("%w: 503", ErrUnavailable)
		}
		return validAnalysisJSON(), nil
	}}

	db, _ := database.Open(":memory:", 5, 2, "5m")
	defer db.Close()
	_ = database.Migrate(db)
	cfg := config.DefaultConfig()
	cfg.AIAnalyst.Enabled = true
	cfg.AIAnalyst.Model = "m"
	cfg.AIAnalyst.RetryCount = 2
	cfg.AIAnalyst.TimeoutSeconds = 5
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	fs := findings.NewStore(db)
	svc := NewService(&cfg, "", NewStore(db), fs, NewContextBuilder(fs, nil), logger)
	svc.SetProviderFor(func(c config.AIAnalyst) (Provider, error) { return provider, nil })
	f := seedFinding(t, fs, "high")

	row, aerr := svc.AnalyzeFinding(context.Background(), f.ID, false)
	if aerr != nil {
		t.Fatalf("retry should succeed: %v", aerr)
	}
	if row.Status != "analyzed" {
		t.Errorf("status: %q", row.Status)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Errorf("expected 2 provider calls (1 fail + 1 success), got %d", calls)
	}
}

func TestServiceApproveAndDismiss(t *testing.T) {
	fake := &fakeProvider{name: "fake", out: validAnalysisJSON()}
	svc, fs, _ := newServiceEnv(t, fake)
	f := seedFinding(t, fs, "high")

	row, err := svc.AnalyzeFinding(context.Background(), f.ID, false)
	if err != nil {
		t.Fatal(err)
	}

	approved, err := svc.Approve(context.Background(), row.ID, "analyst-x")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if approved.Status != "approved" || approved.DecidedBy != "analyst-x" || approved.DecidedAt.IsZero() {
		t.Errorf("approved row: %+v", approved)
	}

	// A second finding: dismissal with reason.
	f2 := seedFinding(t, fs, "high")
	row2, err := svc.AnalyzeFinding(context.Background(), f2.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	dismissed, err := svc.Dismiss(context.Background(), row2.ID, "false positive", "analyst-y")
	if err != nil {
		t.Fatalf("dismiss: %v", err)
	}
	if dismissed.Status != "dismissed" || dismissed.DecisionReason != "false positive" || dismissed.DecidedBy != "analyst-y" {
		t.Errorf("dismissed row: %+v", dismissed)
	}

	// A note was attached to both findings (audit link).
	notes, _ := fs.GetNotes(context.Background(), f.ID)
	if len(notes) != 1 || !strings.Contains(notes[0].Content, "approved by analyst-x") {
		t.Errorf("finding note after approve: %+v", notes)
	}
}

func TestServiceRateLimit(t *testing.T) {
	fake := &fakeProvider{name: "fake", out: validAnalysisJSON()}
	svc, fs, cfg := newServiceEnv(t, fake)
	cfg.AIAnalyst.MaxRequestsPerMinute = 2
	f1 := seedFinding(t, fs, "high")
	f2 := seedFinding(t, fs, "high")
	f3 := seedFinding(t, fs, "high")

	if _, err := svc.AnalyzeFinding(context.Background(), f1.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AnalyzeFinding(context.Background(), f2.ID, false); err != nil {
		t.Fatal(err)
	}
	_, err := svc.AnalyzeFinding(context.Background(), f3.ID, false)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
}

// statefulProvider returns a different result per call.
type statefulProvider struct {
	out string
	err error
	fn  func() (string, error)
}

func (p *statefulProvider) Name() string { return "stateful" }
func (p *statefulProvider) Analyze(ctx context.Context, req Request) (string, error) {
	if p.fn != nil {
		return p.fn()
	}
	return p.out, p.err
}
func (p *statefulProvider) Health(ctx context.Context) (Health, error) { return Health{OK: true}, nil }
func (p *statefulProvider) Models(ctx context.Context) ([]string, bool, error) {
	return nil, false, nil
}

// TestConnectionUsesProviderHealth ensures the test endpoint exercises the
// provider without running an analysis.
func TestServiceTestConnection(t *testing.T) {
	fake := &fakeProvider{name: "fake"}
	svc, _, _ := newServiceEnv(t, fake)
	health, err := svc.TestConnection(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !health.OK || health.Provider != "fake" {
		t.Errorf("health: %+v", health)
	}
}

// TestServiceErrorNeverLeaksKey guarantees provider errors cannot carry
// credentials into logs/UI.
func TestServiceErrorNeverLeaksKey(t *testing.T) {
	const key = "sk-super-secret-1234567890"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo nothing; 401 with a generic body.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := config.DefaultConfig()
	cfg.AIAnalyst.Enabled = true
	cfg.AIAnalyst.Provider = "openai-compatible"
	cfg.AIAnalyst.Endpoint = srv.URL
	cfg.AIAnalyst.APIKey = key
	cfg.AIAnalyst.Model = "m"
	db, _ := database.Open(":memory:", 5, 2, "5m")
	defer db.Close()
	_ = database.Migrate(db)
	fs := findings.NewStore(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewService(&cfg, "", NewStore(db), fs, NewContextBuilder(fs, nil), logger)
	f := seedFinding(t, fs, "high")

	_, err := svc.AnalyzeFinding(context.Background(), f.ID, true)
	if err == nil {
		t.Fatal("expected auth failure")
	}
	if strings.Contains(err.Error(), key) {
		t.Fatalf("error leaked the API key: %v", err)
	}
	if !errors.Is(err, ErrAuth) {
		t.Errorf("want ErrAuth, got %v", err)
	}
}

// TestServiceListModelsWithoutModel: discovery must work before the model
// name is known — the whole point of the button is to find it.
func TestServiceListModelsWithoutModel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"data":[{"id":"alpha"},{"id":"beta"}]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := config.DefaultConfig()
	cfg.AIAnalyst.Enabled = true
	cfg.AIAnalyst.Provider = "openai-compatible"
	cfg.AIAnalyst.Endpoint = srv.URL // no /v1, no model — both tolerated for discovery
	db, _ := database.Open(":memory:", 5, 2, "5m")
	defer db.Close()
	_ = database.Migrate(db)
	fs := findings.NewStore(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewService(&cfg, "", NewStore(db), fs, NewContextBuilder(fs, nil), logger)

	ids, ok, err := svc.ListModels(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !ok || len(ids) != 2 || ids[0] != "alpha" || ids[1] != "beta" {
		t.Errorf("models: %v ok=%v", ids, ok)
	}
}
