package api_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"quetzalog/internal/assets"
	"quetzalog/internal/risk"
)

func TestRiskExplain(t *testing.T) {
	e := newEnv(t)
	riskStore := risk.NewEntityRiskStore(e.db)
	ctx := context.Background()

	for _, c := range []risk.Contribution{
		{EntityType: "host", EntityValue: "web1", SourceType: "event", Points: 50, Description: "severity base critical"},
		{EntityType: "host", EntityValue: "web1", SourceType: "event", Points: 10, Description: "critical asset web1"},
	} {
		if err := riskStore.Record(ctx, c); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	w, _ := do(e, "GET", "/api/v1/risk/entities/host/web1/explain", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	er, _ := data["risk"].(map[string]any)
	if er == nil {
		t.Fatalf("missing risk: %s", w.Body.String())
	}
	if er["risk_score"] != 60.0 {
		t.Errorf("risk_score %v, want 60", er["risk_score"])
	}
	contribs, _ := data["contributions"].([]any)
	if len(contribs) != 2 {
		t.Errorf("contributions %d, want 2", len(contribs))
	}

	// Unknown entity yields a zeroed risk, not an error.
	w, _ = do(e, "GET", "/api/v1/risk/entities/host/ghost/explain", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	out = decodeBody(t, w)
	data, _ = out["data"].(map[string]any)
	er, _ = data["risk"].(map[string]any)
	if er["risk_score"] != 0.0 {
		t.Errorf("ghost risk_score %v, want 0", er["risk_score"])
	}
}

func TestCoverageEndpoints(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	assetStore := assets.NewStore(e.db)
	a, err := assetStore.Create(ctx, &assets.Asset{
		EntityType: "server",
		EntityRef:  "host:db1",
		Name:       "db1",
		OS:         "linux",
	})
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := e.db.ExecContext(ctx,
		`INSERT INTO events (id, timestamp, received_at, source, source_type, host, severity, message, attributes)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		"evt-cov-api", now, now, "test", "json", "db1", "info", "x",
		`{"source_class":"os.linux.auditd"}`); err != nil {
		t.Fatalf("insert event: %v", err)
	}

	w, _ := do(e, "GET", "/api/v1/coverage/assets/"+a.ID, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	cov, _ := data["coverage"].(map[string]any)
	if cov == nil {
		t.Fatalf("missing coverage: %s", w.Body.String())
	}
	if cov["coverage_pct"] != 30.0 {
		t.Errorf("coverage_pct %v, want 30 (auditd only)", cov["coverage_pct"])
	}

	// Mark a class expected, then the summary lists the asset.
	w, _ = do(e, "POST", "/api/v1/coverage/assets/"+a.ID+"/expected", map[string]any{"source_class": "os.linux.journal"}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d: %s", w.Code, w.Body.String())
	}

	w, _ = do(e, "GET", "/api/v1/coverage/summary", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("summary status %d", w.Code)
	}
	out = decodeBody(t, w)
	data, _ = out["data"].(map[string]any)
	if data["total"].(float64) != 1 {
		t.Errorf("summary total %v, want 1", data["total"])
	}

	// Unknown source class is rejected.
	w, _ = do(e, "POST", "/api/v1/coverage/assets/"+a.ID+"/expected", map[string]any{"source_class": "os.mars.auditd"}, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad class status %d, want 400", w.Code)
	}

	// Unknown asset is 404.
	w, _ = do(e, "GET", "/api/v1/coverage/assets/asset-does-not-exist", nil, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown asset status %d, want 404", w.Code)
	}
}
