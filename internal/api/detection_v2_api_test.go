package api_test

import (
	"database/sql"
	"net/http"
	"testing"
	"time"
)

func TestDetectionV2API(t *testing.T) {
	e := newEnv(t)

	// Create a v2 SPL rule.
	w, _ := do(e, "POST", "/api/v1/detections", map[string]any{
		"name":      "spl-test",
		"kind":      "spl",
		"query":     "search source=auth | stats count by user",
		"severity":  "high",
		"enabled":   true,
		"confidence": 0.75,
		"mitre_techniques": []string{"T1110"},
		"tactic_ids":       []string{"TA0006"},
		"required_sources": []string{"os.windows.security"},
		"response_actions": []string{"investigation.create"},
		"version":          2,
	}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status %d: %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	id, _ := data["id"].(string)
	if data["kind"] != "spl" {
		t.Errorf("kind: %v", data["kind"])
	}
	if conf, _ := data["confidence"].(float64); conf != 0.75 {
		t.Errorf("confidence: %v", data["confidence"])
	}

	// Suppression without reason → 400.
	w, _ = do(e, "POST", "/api/v1/detections/"+id+"/suppression", map[string]any{
		"suppressed": true,
	}, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("suppress w/o reason status %d, want 400", w.Code)
	}

	// Suppression with reason → 200.
	w, _ = do(e, "POST", "/api/v1/detections/"+id+"/suppression", map[string]any{
		"suppressed": true,
		"reason":     "known noisy rule",
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("suppress status %d: %s", w.Code, w.Body.String())
	}
	out = decodeBody(t, w)
	data, _ = out["data"].(map[string]any)
	if data["suppressed"] != true {
		t.Errorf("suppressed: %v", data["suppressed"])
	}
	if data["suppressed_by"] == "" {
		t.Error("suppressed_by empty")
	}

	// Stats (no feedback yet) → 200 with zero totals.
	w, _ = do(e, "GET", "/api/v1/detections/"+id+"/stats", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("stats status %d: %s", w.Code, w.Body.String())
	}
	out = decodeBody(t, w)
	data, _ = out["data"].(map[string]any)
	if fb, ok := data["feedback"].(map[string]any); !ok || fb["total"].(float64) != 0 {
		t.Errorf("feedback stats: %v", data["feedback"])
	}

	// Unsuspend.
	w, _ = do(e, "POST", "/api/v1/detections/"+id+"/suppression", map[string]any{
		"suppressed": false,
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("unsuppress status %d: %s", w.Code, w.Body.String())
	}
	out = decodeBody(t, w)
	data, _ = out["data"].(map[string]any)
	if data["suppressed"] != false {
		t.Errorf("unsuppress failed: %v", data["suppressed"])
	}

	// A sequence rule with no query is acceptable (logic lives in definition).
	w, _ = do(e, "POST", "/api/v1/detections", map[string]any{
		"name":     "seq-test",
		"kind":     "sequence",
		"severity": "high",
		"enabled":  false,
		"definition": map[string]any{
			"correlation_key": []string{"user"},
			"window":          "4h",
			"steps": []map[string]any{
				{"id": "a", "predicate": "event_type=auth"},
				{"id": "b", "predicate": "event_type=admin"},
			},
		},
	}, nil)
	if w.Code != http.StatusCreated {
		t.Errorf("sequence rule create status %d: %s", w.Code, w.Body.String())
	}

	// Unknown ID → 404.
	w, _ = do(e, "POST", "/api/v1/detections/nope/suppression", map[string]any{
		"suppressed": true, "reason": "x",
	}, nil)
	if w.Code != http.StatusNotFound && w.Code != http.StatusBadRequest {
		t.Errorf("unknown rule suppression status %d", w.Code)
	}

	// States endpoint: a sequence rule with no activity → empty list, 200.
	w, _ = do(e, "GET", "/api/v1/detections/"+id+"/states", nil, nil)
	if w.Code != http.StatusOK {
		t.Errorf("states status %d: %s", w.Code, w.Body.String())
	}
	// Unknown rule → 404.
	w, _ = do(e, "GET", "/api/v1/detections/nope/states", nil, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown rule states status %d, want 404", w.Code)
	}
}

func TestCatalogEndpoints(t *testing.T) {
	e := newEnv(t)

	w, _ := do(e, "GET", "/api/v1/detections/catalog", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("catalog status %d: %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	if list, _ := out["data"].([]any); len(list) < 3 {
		t.Fatalf("catalog entries: %d, want >= 3", len(list))
	}

	w, _ = do(e, "GET", "/api/v1/detections/catalog?category=hunting", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("catalog hunting status %d: %s", w.Code, w.Body.String())
	}
	out = decodeBody(t, w)
	list, _ := out["data"].([]any)
	if len(list) == 0 {
		t.Errorf("no hunting entries")
	}
	for _, it := range list {
		if row, _ := it.(map[string]any); !row["hunting"].(bool) {
			t.Errorf("non-hunting entry in hunting filter: %v", row)
		}
	}

	// Install one entry; it becomes a regular detection rule.
	w, _ = do(e, "POST", "/api/v1/detections/catalog/brute_force_login/install", nil, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("install status %d: %s", w.Code, w.Body.String())
	}

	w, _ = do(e, "GET", "/api/v1/detections", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list detections status %d: %s", w.Code, w.Body.String())
	}
	out = decodeBody(t, w)
	installed := false
	if list, _ := out["data"].([]any); list != nil {
		for _, it := range list {
			if row, _ := it.(map[string]any); row["name"] == "Brute Force Login Attempt" {
				installed = true
			}
		}
	}
	if !installed {
		t.Errorf("installed catalog rule not in detection list")
	}

	w, _ = do(e, "POST", "/api/v1/detections/catalog/nope/install", nil, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown entry status %d, want 404", w.Code)
	}
}

func TestScenarioEndpoints(t *testing.T) {
	e := newEnv(t)

	// Seed an active scenario run + a step directly.
	if _, err := e.db.Exec(`INSERT INTO scenario_runs (id, definition, scope, status, confidence, risk, opened_at)
		VALUES ('run-1', '{"name":"web_compromise"}', 'host:web01', 'active', 0.4, 10, datetime('now'))`); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	if _, err := e.db.Exec(`INSERT INTO scenario_steps (run_id, step_id, tactic, technique, status)
		VALUES ('run-1', 'T1190', 'TA0001', 'T1190', 'observed')`); err != nil {
		t.Fatalf("seed step: %v", err)
	}

	w, _ := do(e, "GET", "/api/v1/scenarios", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("scenarios status %d: %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	if list, _ := out["data"].([]any); len(list) != 1 {
		t.Errorf("scenario runs: %d, want 1", len(list))
	}

	w, _ = do(e, "GET", "/api/v1/scenarios/run-1", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("scenario run status %d: %s", w.Code, w.Body.String())
	}
	out = decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	if data["what_next"] == nil {
		t.Errorf("what_next missing: %v", data)
	}

	w, _ = do(e, "GET", "/api/v1/scenarios/nope", nil, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("missing run status %d, want 404", w.Code)
	}
}

func TestBehavioralEndpoints(t *testing.T) {
	e := newEnv(t)

	// Seed one baseline + one anomaly row directly.
	if _, err := e.db.Exec(`INSERT INTO baselines (entity_type, entity_value, feature, window_days, mean, stddev, p95, sample_count, last_updated)
		VALUES ('user', 'zoe', 'login_count_per_hour', 30, 3, 1, 6, 40, datetime('now'))`); err != nil {
		t.Fatalf("seed baseline: %v", err)
	}
	if _, err := e.db.Exec(`INSERT INTO anomalies (id, entity_type, entity_value, feature, observed, baseline_mean, z, detected_at)
		VALUES ('an-1', 'user', 'zoe', 'login_count_per_hour', 12, 3, 9, datetime('now'))`); err != nil {
		t.Fatalf("seed anomaly: %v", err)
	}

	w, _ := do(e, "GET", "/api/v1/behavioral/baselines?entity_type=user&entity_value=zoe", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("baselines status %d: %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	if list, _ := out["data"].([]any); len(list) != 1 {
		t.Errorf("baselines: %d", len(list))
	} else if row, _ := list[0].(map[string]any); !row["trusted"].(bool) {
		t.Errorf("baseline trusted flag: %v", row)
	}

	w, _ = do(e, "GET", "/api/v1/behavioral/anomalies?entity_value=zoe", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("anomalies status %d: %s", w.Code, w.Body.String())
	}
	out = decodeBody(t, w)
	if list, _ := out["data"].([]any); len(list) != 1 {
		t.Errorf("anomalies: %d", len(list))
	} else if row, _ := list[0].(map[string]any); row["z"].(float64) != 9 {
		t.Errorf("anomaly z: %v", row)
	}
}

func insertFinding(t *testing.T, db *sql.DB, id, detectionID string) {
	t.Helper()
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	_, err := db.Exec(`INSERT INTO findings (id, title, severity, status, risk_score, detection_id, dedup_key,
		first_seen, last_seen, created_at, updated_at)
		VALUES (?, ?, 'high', 'new', 10, ?, ?, ?, ?, ?, ?)`,
		id, "fb-test", detectionID, "fb|"+id, now, now, now, now)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}
}

func TestFindingFeedbackAPI(t *testing.T) {
	e := newEnv(t)

	// Invalid label → 400.
	w, _ := do(e, "POST", "/api/v1/findings/fx/feedback", map[string]any{
		"label": "surely",
	}, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid label status %d, want 400", w.Code)
	}

	// FP without reason → 400.
	w, _ = do(e, "POST", "/api/v1/findings/fx/feedback", map[string]any{
		"label": "false_positive",
	}, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("fp w/o reason status %d, want 400", w.Code)
	}

	// Seed a finding linked to a detection, then valid feedback.
	insertFinding(t, e.db, "fb1", "det-x")
	w, _ = do(e, "POST", "/api/v1/findings/fb1/feedback", map[string]any{
		"label":  "false_positive",
		"reason": "VPN concentrator noise",
	}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("feedback status %d: %s", w.Code, w.Body.String())
	}

	// List it back.
	w, _ = do(e, "GET", "/api/v1/findings/fb1/feedback", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list feedback status %d", w.Code)
	}
	out := decodeBody(t, w)
	if list, _ := out["data"].([]any); len(list) != 1 {
		t.Errorf("feedback list: %d", len(list))
	}

	// The detection's stats now show one FP.
	// (det-x is not a real rule; the join is on findings.detection_id, so it still aggregates.)
	w, _ = do(e, "POST", "/api/v1/detections", map[string]any{
		"name": "det-x", "query": "source=x", "severity": "low", "enabled": false,
	}, nil)
	if w.Code == http.StatusCreated {
		out = decodeBody(t, w)
		data, _ := out["data"].(map[string]any)
		did, _ := data["id"].(string)
		// Relink the finding to the real detection id.
		_, _ = e.db.Exec(`UPDATE findings SET detection_id = ? WHERE id = 'fb1'`, did)

		w, _ = do(e, "GET", "/api/v1/detections/"+did+"/stats", nil, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("stats status %d", w.Code)
		}
		out = decodeBody(t, w)
		data, _ = out["data"].(map[string]any)
		if fb, ok := data["feedback"].(map[string]any); !ok {
			t.Fatalf("no feedback block: %v", data)
		} else if fb["total"].(float64) != 1 {
			t.Errorf("stats total: %v", fb["total"])
		}
	}
}
