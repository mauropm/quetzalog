package api_test

import (
	"context"
	"net/http"
	"testing"

	"quetzalog/internal/threatintel"
)

func newTI(t *testing.T, e *env) *threatintel.Store {
	t.Helper()
	// The test env builds a registry over its own store instance on the
	// same DB; grab a store bound to the same DB for direct seeding.
	return threatintel.NewStore(e.db)
}

func TestIndicatorCRUDAndLookup(t *testing.T) {
	e := newEnv(t)
	ti := newTI(t, e)

	// Create.
	w, _ := do(e, "POST", "/api/v1/intel/indicators", map[string]any{
		"type": "domain", "value": ".Evil.COM", "severity": "high",
	}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status %d: %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	ind, _ := data["indicator"].(map[string]any)
	if ind["normalized_value"] != "evil.com" {
		t.Errorf("normalized: %v", ind["normalized_value"])
	}

	// List.
	w, _ = do(e, "GET", "/api/v1/intel/indicators", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list status %d", w.Code)
	}
	out = decodeBody(t, w)
	data, _ = out["data"].(map[string]any)
	if data["total"].(float64) != 1 {
		t.Errorf("total: %v", data["total"])
	}

	// Lookup by raw and by normalized form.
	for _, v := range []string{"EVIL.com", "evil.com"} {
		w, _ = do(e, "POST", "/api/v1/intel/indicators/lookup", map[string]any{"value": v}, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("lookup status %d", w.Code)
		}
		out = decodeBody(t, w)
		data, _ = out["data"].(map[string]any)
		if hits, _ := data["hits"].([]any); len(hits) != 1 {
			t.Errorf("lookup %q hits: %v", v, data["hits"])
		}
	}

	// Get by type+value.
	w, _ = do(e, "GET", "/api/v1/intel/indicators/domain/evil.com", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get status %d: %s", w.Code, w.Body.String())
	}

	// Unknown value → 404.
	w, _ = do(e, "GET", "/api/v1/intel/indicators/domain/nosuch.example", nil, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("404 status %d", w.Code)
	}

	// Invalid type → 400.
	w, _ = do(e, "POST", "/api/v1/intel/indicators", map[string]any{
		"type": "quantum", "value": "x",
	}, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad type status %d", w.Code)
	}
	_ = ti
}

func TestTIProvidersAndActors(t *testing.T) {
	e := newEnv(t)
	ti := newTI(t, e)

	// Seed an actor + campaign + malware via the store.
	if _, err := ti.UpsertActor(context.Background(), threatintel.Actor{Name: "APT-X", Type: "group"}); err != nil {
		t.Fatalf("actor: %v", err)
	}
	actorsW, _ := do(e, "GET", "/api/v1/threat-actors", nil, nil)
	if actorsW.Code != http.StatusOK {
		t.Fatalf("actors status %d", actorsW.Code)
	}
	out := decodeBody(t, actorsW)
	data, _ := out["data"].(map[string]any)
	if actors, _ := data["actors"].([]any); len(actors) != 1 {
		t.Errorf("actors: %v", data["actors"])
	}

	// Providers listing (the test env registers no providers → empty list).
	w, _ := do(e, "GET", "/api/v1/threat-intel/providers", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("providers status %d", w.Code)
	}

	// Syncing an unknown provider → 502 with error.
	w, _ = do(e, "POST", "/api/v1/threat-intel/providers/ghost/sync", nil, nil)
	if w.Code != http.StatusBadGateway {
		t.Errorf("unknown provider sync status %d, want 502", w.Code)
	}

	// Sync status.
	w, _ = do(e, "GET", "/api/v1/threat-intel/sync/status", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("sync status %d", w.Code)
	}

	// Campaigns + malware (empty but well-formed).
	for _, path := range []string{"/api/v1/campaigns", "/api/v1/malware"} {
		w, _ = do(e, "GET", path, nil, nil)
		if w.Code != http.StatusOK {
			t.Errorf("%s status %d", path, w.Code)
		}
	}
}
