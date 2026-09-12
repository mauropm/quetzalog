package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// doWithToken behaves like do but authenticates with a specific bearer token.
func doWithToken(e *env, method, path string, body any, token string) (*httptest.ResponseRecorder, *http.Request) {
	if token == "" {
		token = "test-api-token"
	}
	return do(e, method, path, body, map[string]string{"Authorization": "Bearer " + token})
}

// seedDemoData ingests a few events through the API and runs a detection so
// the SOC endpoints have real findings to serve.
func seedDemoData(t *testing.T, e *env) (findingID, detectionID string) {
	t.Helper()

	ingest := func(user, host, et, action, severity string) {
		t.Helper()
		ev := map[string]any{
			"message":    "test event",
			"severity":   severity,
			"event_type": et,
			"action":     action,
			"user":       user,
			"host":       host,
			"source_ip":  "185.220.101.47",
		}
		w, _ := do(e, "POST", "/api/v1/events", ev, nil)
		if w.Code != http.StatusCreated && w.Code != http.StatusOK {
			t.Fatalf("ingest: %d %s", w.Code, w.Body.String())
		}
	}
	ingest("jsmith", "workstation-42", "authentication", "login_failed", "warning")
	ingest("jsmith", "workstation-42", "authentication", "login_failed", "warning")

	rule := map[string]any{
		"name":        "Geo Anomaly Logins",
		"description": "test",
		"query":       "event_type=authentication action=login_failed user=jsmith",
		"severity":    "high",
		"enabled":     true,
		"risk_score":  35,
		"group_by":    []string{"user"},
		"mitre_tactic": "TA0006",
		"mitre_technique": "T1110",
		"tags":        []string{"test"},
	}
	w, _ := do(e, "POST", "/api/v1/detections", rule, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("create detection: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		Data struct{ ID string } `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.Data.ID == "" {
		t.Fatalf("decode detection: %s", w.Body.String())
	}
	detectionID = created.Data.ID

	w, _ = do(e, "POST", "/api/v1/detections/"+detectionID+"/exec", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("exec detection: %d %s", w.Code, w.Body.String())
	}

	w, _ = do(e, "GET", "/api/v1/findings", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list findings: %d %s", w.Code, w.Body.String())
	}
	var list struct {
		Data struct {
			Findings []map[string]any `json:"findings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list.Data.Findings) == 0 {
		t.Fatalf("no findings: %s", w.Body.String())
	}
	findingID = list.Data.Findings[0]["id"].(string)
	return findingID, detectionID
}

func TestFindingsAPI(t *testing.T) {
	e := newEnv(t)
	findingID, _ := seedDemoData(t, e)

	// Get.
	w, _ := do(e, "GET", "/api/v1/findings/"+findingID, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: %d %s", w.Code, w.Body.String())
	}

	// Status + owner + risk patch.
	w, _ = do(e, "PATCH", "/api/v1/findings/"+findingID, map[string]any{
		"status": "in_progress", "owner": "analyst", "risk_score": 50.0,
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", w.Code, w.Body.String())
	}

	// Invalid status rejected.
	w, _ = do(e, "PATCH", "/api/v1/findings/"+findingID, map[string]any{"status": "bogus"}, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad status, got %d", w.Code)
	}

	// Note.
	w, _ = do(e, "POST", "/api/v1/findings/"+findingID+"/notes", map[string]any{"content": "triaged"}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("note: %d %s", w.Code, w.Body.String())
	}

	// Linked events.
	w, _ = do(e, "GET", "/api/v1/findings/"+findingID+"/events", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("events: %d %s", w.Code, w.Body.String())
	}

	// Risk breakdown.
	w, _ = do(e, "GET", "/api/v1/findings/"+findingID+"/risk", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("risk: %d %s", w.Code, w.Body.String())
	}

	// Filters.
	w, _ = do(e, "GET", "/api/v1/findings?status=in_progress&user=jsmith&severity=high", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("filtered list: %d %s", w.Code, w.Body.String())
	}
	var filtered struct {
		Data struct {
			Total int `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &filtered); err != nil || filtered.Data.Total != 1 {
		t.Errorf("filter total = %+v (%s)", filtered, w.Body.String())
	}

	// 404.
	w, _ = do(e, "GET", "/api/v1/findings/does-not-exist", nil, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestSavedViewsAPI(t *testing.T) {
	e := newEnv(t)

	w, _ := do(e, "POST", "/api/v1/saved-views", map[string]any{
		"name":    "My Criticals",
		"filters": map[string]string{"severity": "critical"},
	}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("save view: %d %s", w.Code, w.Body.String())
	}

	w, _ = do(e, "GET", "/api/v1/saved-views", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list views: %d %s", w.Code, w.Body.String())
	}
	var views struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &views); err != nil || len(views.Data) != 1 {
		t.Fatalf("views = %s", w.Body.String())
	}
	viewID := views.Data[0]["id"].(string)

	w, _ = do(e, "DELETE", "/api/v1/saved-views/"+viewID, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("delete view: %d %s", w.Code, w.Body.String())
	}
}

func TestInvestigationsAPI(t *testing.T) {
	e := newEnv(t)
	findingID, _ := seedDemoData(t, e)

	// Create linked to the finding.
	w, _ := do(e, "POST", "/api/v1/investigations", map[string]any{
		"title":       "jsmith compromise",
		"severity":    "critical",
		"assignee":    "analyst",
		"finding_ids": []string{findingID},
	}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		Data struct{ ID string } `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &created)
	invID := created.Data.ID
	if invID == "" {
		t.Fatalf("no investigation id: %s", w.Body.String())
	}

	// Status transition.
	w, _ = do(e, "POST", "/api/v1/investigations/"+invID+"/status", map[string]any{"status": "in_progress"}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
	w, _ = do(e, "POST", "/api/v1/investigations/"+invID+"/status", map[string]any{"status": "bogus"}, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad status, got %d", w.Code)
	}

	// Note.
	w, _ = do(e, "POST", "/api/v1/investigations/"+invID+"/notes", map[string]any{"body": "timeline entry"}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("note: %d %s", w.Code, w.Body.String())
	}

	// Evidence + linked findings.
	w, _ = do(e, "POST", "/api/v1/investigations/"+invID+"/evidence", map[string]any{"event_ids": []string{"nonexistent"}}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("evidence: %d %s", w.Code, w.Body.String())
	}
	w, _ = do(e, "GET", "/api/v1/investigations/"+invID+"/findings", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("findings: %d %s", w.Code, w.Body.String())
	}

	// Patch adds entities (deduped) and techniques.
	w, _ = do(e, "PATCH", "/api/v1/investigations/"+invID, map[string]any{
		"add_entities": []map[string]any{{"type": "user", "value": "jsmith"}, {"type": "ip", "value": "185.220.101.47"}},
		"techniques":   []string{"T1110"},
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("patch entities: %d %s", w.Code, w.Body.String())
	}
	var patched struct {
		Data struct {
			Entities   []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"entities"`
			Techniques []string `json:"techniques"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &patched)
	if len(patched.Data.Entities) != 2 {
		t.Errorf("entities = %d, want 2: %+v", len(patched.Data.Entities), patched.Data.Entities)
	}
	if len(patched.Data.Techniques) != 1 || patched.Data.Techniques[0] != "T1110" {
		t.Errorf("techniques = %v", patched.Data.Techniques)
	}
	// Duplicate add is a no-op.
	w, _ = do(e, "PATCH", "/api/v1/investigations/"+invID, map[string]any{
		"add_entities": []map[string]any{{"type": "user", "value": "jsmith"}},
	}, nil)
	json.Unmarshal(w.Body.Bytes(), &patched)
	if len(patched.Data.Entities) != 2 {
		t.Errorf("duplicate entity not deduped: %d", len(patched.Data.Entities))
	}

	// List.
	w, _ = do(e, "GET", "/api/v1/investigations", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}

	// 404.
	w, _ = do(e, "GET", "/api/v1/investigations/missing", nil, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestSOCOverview(t *testing.T) {
	e := newEnv(t)
	seedDemoData(t, e)

	w, _ := do(e, "GET", "/api/v1/soc/overview?range=24h", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("overview: %d %s", w.Code, w.Body.String())
	}
	var overview struct {
		Data struct {
			Events struct {
				Total int `json:"total"`
			} `json:"events"`
			Findings struct {
				Posture map[string]int `json:"posture"`
			} `json:"findings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &overview); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if overview.Data.Events.Total < 2 {
		t.Errorf("events total = %d", overview.Data.Events.Total)
	}
	if overview.Data.Findings.Posture["open"] < 1 {
		t.Errorf("posture = %+v", overview.Data.Findings.Posture)
	}

	// Bad range rejected.
	w, _ = do(e, "GET", "/api/v1/soc/overview?range=never", nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad range, got %d", w.Code)
	}
}

func TestRiskEntitiesAndEntityDetail(t *testing.T) {
	e := newEnv(t)
	seedDemoData(t, e)

	// Risk entities (jsmith got points from the detection run).
	w, _ := do(e, "GET", "/api/v1/risk/entities?type=user&limit=5", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("risk entities: %d %s", w.Code, w.Body.String())
	}

	// Entity detail.
	w, _ = do(e, "GET", "/api/v1/entities/user/jsmith", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("entity: %d %s", w.Code, w.Body.String())
	}
	var entity struct {
		Data struct {
			Value    string   `json:"value"`
			Findings []string `json:"findings"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &entity)
	if entity.Data.Value != "jsmith" {
		t.Errorf("entity value = %q", entity.Data.Value)
	}

	// Intel reputation.
	w, _ = do(e, "GET", "/api/v1/intel/user/jsmith", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("intel: %d %s", w.Code, w.Body.String())
	}
	var intel struct {
		Data struct {
			Reputation string `json:"reputation"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &intel)
	if intel.Data.Reputation == "" || intel.Data.Reputation == "unknown" {
		t.Errorf("reputation = %q, want derived from risk", intel.Data.Reputation)
	}

	// Invalid type.
	w, _ = do(e, "GET", "/api/v1/entities/bogus/x", nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad type, got %d", w.Code)
	}
}

func TestMITREEndpoints(t *testing.T) {
	e := newEnv(t)
	seedDemoData(t, e)

	w, _ := do(e, "GET", "/api/v1/mitre/techniques", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("techniques: %d %s", w.Code, w.Body.String())
	}
	var techs []map[string]any
	if err := json.Unmarshal(decodeData(t, w), &techs); err != nil {
		t.Fatalf("decode techniques: %v", err)
	}
	if len(techs) < 50 {
		t.Errorf("techniques = %d", len(techs))
	}

	w, _ = do(e, "GET", "/api/v1/mitre/tactics", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("tactics: %d %s", w.Code, w.Body.String())
	}

	w, _ = do(e, "GET", "/api/v1/mitre/active", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("active: %d %s", w.Code, w.Body.String())
	}
	var active []map[string]any
	json.Unmarshal(decodeData(t, w), &active)
	if len(active) != 1 || active[0]["technique"] != "T1110" {
		t.Errorf("active = %v", active)
	}
}

func TestResponseActionsAPI(t *testing.T) {
	e := newEnv(t)
	findingID, _ := seedDemoData(t, e)

	w, _ := do(e, "GET", "/api/v1/response-actions", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("catalog: %d %s", w.Code, w.Body.String())
	}

	w, _ = do(e, "POST", "/api/v1/response-actions/execute", map[string]any{
		"action": "finding.assign",
		"target": findingID,
		"owner":  "analyst",
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("execute: %d %s", w.Code, w.Body.String())
	}

	w, _ = do(e, "POST", "/api/v1/response-actions/execute", map[string]any{
		"action": "webhook.execute",
		"url":    "http://127.0.0.1:1/stealth",
	}, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for SSRF webhook, got %d", w.Code)
	}

	w, _ = do(e, "GET", "/api/v1/response-actions/history?limit=10", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("history: %d %s", w.Code, w.Body.String())
	}
	var hist []map[string]any
	json.Unmarshal(decodeData(t, w), &hist)
	if len(hist) < 1 {
		t.Errorf("history empty")
	}
}

func TestAuditLog(t *testing.T) {
	e := newEnv(t)
	seedDemoData(t, e)

	// Static operator token has no user; audit entries are written when a
	// user performs an action. Log in as admin first.
	w, _ := do(e, "POST", "/api/v1/login", map[string]any{"username": "admin", "password": "changeme"}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	var login struct {
		Data struct{ Token string } `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &login); err != nil || login.Data.Token == "" {
		t.Fatalf("decode login: %s", w.Body.String())
	}

	// Perform an action as the user.
	findingID := listOneFindingID(t, e)
	_, _ = doWithToken(e, "PATCH", "/api/v1/findings/"+findingID, map[string]any{"status": "contained"}, login.Data.Token)

	// Admin can read the audit log.
	w, _ = doWithToken(e, "GET", "/api/v1/audit?limit=10", nil, login.Data.Token)
	if w.Code != http.StatusOK {
		t.Fatalf("audit: %d %s", w.Code, w.Body.String())
	}
	var entries []map[string]any
	json.Unmarshal(decodeData(t, w), &entries)
	found := false
	for _, entry := range entries {
		if entry["action"] == "finding.status_change" {
			found = true
		}
	}
	if !found {
		t.Errorf("audit log missing finding.status_change: %v", entries)
	}
}

func listOneFindingID(t *testing.T, e *env) string {
	t.Helper()
	w, _ := do(e, "GET", "/api/v1/findings", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list findings: %d", w.Code)
	}
	var list struct {
		Data struct {
			Findings []map[string]any `json:"findings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list.Data.Findings) == 0 {
		t.Fatalf("no findings: %s", w.Body.String())
	}
	return list.Data.Findings[0]["id"].(string)
}

// decodeData extracts the "data" field of the API envelope.
func decodeData(t *testing.T, w *httptest.ResponseRecorder) []byte {
	t.Helper()
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode envelope: %v (%s)", err, w.Body.String())
	}
	return []byte(envelope.Data)
}
