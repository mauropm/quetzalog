package api_test

import (
	"net/http"
	"strings"
	"testing"
)

func TestEventTokenEndpoints(t *testing.T) {
	e := newEnv(t)

	// Admin session.
	w, _ := do(e, "POST", "/api/v1/login", map[string]any{"username": "admin", "password": "changeme"}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("login %d %s", w.Code, w.Body.String())
	}
	data := decodeBody(t, w)["data"].(map[string]any)
	adminTok := data["token"].(string)
	authH := map[string]string{"Authorization": "Bearer " + adminTok}

	// Create.
	w, _ = do(e, "POST", "/api/v1/event-tokens", map[string]any{"name": "fwd-dc1", "tag": "splunk", "group": "prod"}, authH)
	if w.Code != http.StatusCreated {
		t.Fatalf("create %d %s", w.Code, w.Body.String())
	}
	created := decodeBody(t, w)["data"].(map[string]any)
	full := created["token"].(string)
	if !strings.HasPrefix(full, "qev_") || len(full) < 40 {
		t.Fatalf("token shape: %q", full)
	}
	id := created["id"].(string)
	prefix := created["token_prefix"].(string)
	if prefix != full[:12] {
		t.Errorf("prefix %q vs token[:12] %q", prefix, full[:12])
	}

	// List: masked, no token value, metadata intact.
	w, _ = do(e, "GET", "/api/v1/event-tokens", nil, authH)
	if w.Code != http.StatusOK {
		t.Fatalf("list %d %s", w.Code, w.Body.String())
	}
	list := decodeBody(t, w)["data"].([]any)
	if len(list) != 1 {
		t.Fatalf("list len %d", len(list))
	}
	row := list[0].(map[string]any)
	if row["token"] != nil {
		t.Errorf("list must not expose the token value: %#v", row)
	}
	if row["token_prefix"] != prefix || row["name"] != "fwd-dc1" || row["group"] != "prod" || row["tag"] != "splunk" {
		t.Errorf("row: %#v", row)
	}

	// The event token may POST events (ingest-only boundary).
	evBody := `{"severity":"info","message":"token ingest test","source_type":"test"}`
	w, _ = do(e, "POST", "/api/v1/events", evBody, map[string]string{"Authorization": "Bearer " + full})
	if w.Code != http.StatusCreated {
		t.Fatalf("ingest with event token %d %s", w.Code, w.Body.String())
	}

	// ...but nothing else (control-plane forbidden).
	w, _ = do(e, "GET", "/api/v1/events", nil, map[string]string{"Authorization": "Bearer " + full})
	if w.Code != http.StatusForbidden {
		t.Fatalf("control-plane with event token %d, want 403", w.Code)
	}

	// Reveal (admin only) returns the exact token.
	w, _ = do(e, "GET", "/api/v1/event-tokens/"+id+"/reveal", nil, authH)
	if w.Code != http.StatusOK {
		t.Fatalf("reveal %d %s", w.Code, w.Body.String())
	}
	if got := decodeBody(t, w)["data"].(map[string]any)["token"]; got != full {
		t.Fatalf("reveal %q != %q", got, full)
	}

	// Rename / retag / regroup.
	w, _ = do(e, "PATCH", "/api/v1/event-tokens/"+id, map[string]any{"name": "fwd-dc1-renamed", "tag": "siem", "group": "staging"}, authH)
	if w.Code != http.StatusOK {
		t.Fatalf("patch %d %s", w.Code, w.Body.String())
	}
	w, _ = do(e, "GET", "/api/v1/event-tokens", nil, authH)
	row = decodeBody(t, w)["data"].([]any)[0].(map[string]any)
	if row["name"] != "fwd-dc1-renamed" || row["tag"] != "siem" || row["group"] != "staging" {
		t.Errorf("after patch: %#v", row)
	}

	// Expire: token stops authorizing ingest immediately.
	w, _ = do(e, "POST", "/api/v1/event-tokens/"+id+"/expire", map[string]any{}, authH)
	if w.Code != http.StatusOK {
		t.Fatalf("expire %d %s", w.Code, w.Body.String())
	}
	w, _ = do(e, "POST", "/api/v1/events", evBody, map[string]string{"Authorization": "Bearer " + full})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expired token still ingests (%d)", w.Code)
	}

	// Delete.
	w, _ = do(e, "DELETE", "/api/v1/event-tokens/"+id, nil, authH)
	if w.Code != http.StatusOK {
		t.Fatalf("delete %d %s", w.Code, w.Body.String())
	}
	w, _ = do(e, "GET", "/api/v1/event-tokens", nil, authH)
	if got := decodeBody(t, w)["data"].([]any); len(got) != 0 {
		t.Errorf("expected empty list after delete, got %d", len(got))
	}
}

func TestEventTokenNonAdminRejected(t *testing.T) {
	e := newEnv(t)

	w, _ := do(e, "POST", "/api/v1/login", map[string]any{"username": "admin", "password": "changeme"}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("admin login %d", w.Code)
	}
	adminH := map[string]string{"Authorization": "Bearer " + decodeBody(t, w)["data"].(map[string]any)["token"].(string)}

	// Create an analyst.
	w, _ = do(e, "POST", "/api/v1/users", map[string]any{"username": "ana-et", "password": "secret123", "role": "analyst"}, adminH)
	if w.Code != http.StatusCreated {
		t.Fatalf("create analyst %d %s", w.Code, w.Body.String())
	}
	w, _ = do(e, "POST", "/api/v1/login", map[string]any{"username": "ana-et", "password": "secret123"}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("analyst login %d", w.Code)
	}
	anaH := map[string]string{"Authorization": "Bearer " + decodeBody(t, w)["data"].(map[string]any)["token"].(string)}

	for _, req := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/v1/event-tokens", nil},
		{"POST", "/api/v1/event-tokens", map[string]any{"name": "x"}},
		{"POST", "/api/v1/event-tokens/nope/expire", map[string]any{}},
		{"DELETE", "/api/v1/event-tokens/nope", nil},
	} {
		w, _ = do(e, req.method, req.path, req.body, anaH)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s: got %d, want 403", req.method, req.path, w.Code)
		}
	}
}
