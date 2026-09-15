package api_test

import (
	"database/sql"
	"net/http"
	"testing"

	"quetzalog/internal/detections"
	"quetzalog/internal/events"
	"quetzalog/internal/findings"
	"quetzalog/internal/mitre"
	"quetzalog/internal/risk"
)

func mitreMapperForTest(t *testing.T) *mitre.Mapper {
	t.Helper()
	m, err := mitre.NewMapper()
	if err != nil {
		t.Fatalf("mitre mapper: %v", err)
	}
	return m
}

func correlationEngineForTest(t *testing.T, db *sql.DB) *detections.CorrelationEngine {
	t.Helper()
	return detections.NewCorrelationEngine(
		db,
		detections.NewStore(db),
		events.NewStore(db),
		findings.NewStore(db),
		risk.NewEntityRiskStore(db),
		nil,
	)
}

func TestMappingRulesAPI(t *testing.T) {
	e := newEnv(t)

	// List built-in rules.
	w, _ := do(e, "GET", "/api/v1/mitre/mapping-rules", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list status %d: %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	if rules, _ := data["rules"].([]any); len(rules) < 20 {
		t.Errorf("rules: %d", len(rules))
	}

	// Register a runtime rule.
	w, _ = do(e, "POST", "/api/v1/mitre/mapping-rules", map[string]any{
		"id": "api-custom", "tactic": "TA0002", "technique": "T1059.004",
		"confidence": 0.9,
		"when": map[string]any{"process": "bash", "message_regex": "api-custom-marker"},
	}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("register status %d: %s", w.Code, w.Body.String())
	}

	// It now appears in the list.
	w, _ = do(e, "GET", "/api/v1/mitre/mapping-rules", nil, nil)
	out = decodeBody(t, w)
	data, _ = out["data"].(map[string]any)
	found := false
	for _, r := range data["rules"].([]any) {
		rm, _ := r.(map[string]any)
		if rm["id"] == "api-custom" {
			found = true
		}
	}
	if !found {
		t.Error("runtime rule not listed")
	}

	// Invalid rule (unknown technique) → 400.
	w, _ = do(e, "POST", "/api/v1/mitre/mapping-rules", map[string]any{
		"id": "bad", "tactic": "TA0002", "technique": "T9999", "confidence": 0.5,
	}, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad rule status %d, want 400", w.Code)
	}

	// Technique pivot (no mapped events yet → empty list, 200).
	w, _ = do(e, "GET", "/api/v1/mitre/techniques/T1059.001/events", nil, nil)
	if w.Code != http.StatusOK {
		t.Errorf("pivot status %d", w.Code)
	}
	// Unknown technique → 400.
	w, _ = do(e, "GET", "/api/v1/mitre/techniques/T9999/events", nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("unknown technique status %d, want 400", w.Code)
	}

	// Pivot with data: an event whose mitre.attack attribute maps T1059.001.
	attrs := `{"mitre":{"attack":[{"tactic":"TA0002","technique":"T1059.001","confidence":0.95,"rule_id":"builtin-encoded-powershell"}]}}`
	if _, err := e.db.Exec(
		`INSERT INTO events (id, timestamp, severity, source, source_type, message, process, user, attributes)
		 VALUES ('evt-mitre-1', datetime('now'), 'medium', 'test', 'powershell',
			'powershell.exe -NoProfile -EncodedCommand ...', 'powershell.exe', 'svc-deploy', ?)`,
		attrs,
	); err != nil {
		t.Fatalf("insert mapped event: %v", err)
	}
	w, _ = do(e, "GET", "/api/v1/mitre/techniques/T1059.001/events", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("pivot status %d: %s", w.Code, w.Body.String())
	}
	out = decodeBody(t, w)
	data, _ = out["data"].(map[string]any)
	if evs, _ := data["events"].([]any); len(evs) != 1 {
		t.Errorf("pivot events: %d, want 1 (%s)", len(evs), w.Body.String())
	}
	// A technique that was NOT mapped must not pick up the event.
	w, _ = do(e, "GET", "/api/v1/mitre/techniques/T1003.001/events", nil, nil)
	out = decodeBody(t, w)
	data, _ = out["data"].(map[string]any)
	if evs, _ := data["events"].([]any); len(evs) != 0 {
		t.Errorf("unrelated technique picked up event: %d", len(evs))
	}
}
