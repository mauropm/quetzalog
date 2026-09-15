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
