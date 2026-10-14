package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"quetzalog/internal/api"
	"quetzalog/internal/config"
	"quetzalog/internal/events"
	"quetzalog/internal/ingestion"
	"quetzalog/internal/ingestion/otlp"
)

// TestOTLPSettingsToggle drives the settings API end-to-end against a
// manager bound to ephemeral ports.
func TestOTLPSettingsToggle(t *testing.T) {
	e := newEnv(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	pipeline := ingestion.NewPipeline(events.NewStore(e.db), 1, 10, logger)
	if err := pipeline.Start(context.TODO()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pipeline.Stop(context.TODO()) })

	cfg := config.DefaultConfig()
	cfg.OTel.HttpPort = 0 // ephemeral: tests must not fight the developer's ports
	cfg.OTel.GrpcPort = 0
	mgr := otlp.NewManager(&cfg, "", pipeline, logger)
	t.Cleanup(mgr.Stop)

	// A router without a manager (the default test env) reports the state as
	// read-only instead of failing.
	w, _ := do(e, "GET", "/api/v1/settings/otlp", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET without manager: %d %s", w.Code, w.Body.String())
	}
	var probe otlp.ManagerStatus
	if err := json.Unmarshal(decodeData(t, w), &probe); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if probe.Running {
		t.Fatal("unmanaged router reports running")
	}

	// Rebuild with the manager wired in through the router option.
	e2 := newEnv(t, api.WithOTLPManager(mgr))
	w, _ = do(e2, "POST", "/api/v1/login", map[string]any{"username": "admin", "password": "changeme"}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("admin login failed: %d %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	adminTok, _ := data["token"].(string)
	if adminTok == "" {
		t.Fatal("login returned no token")
	}
	authH := func() map[string]string { return map[string]string{"Authorization": "Bearer " + adminTok} }

	for _, tc := range []struct {
		method, path string
		body         any
		wantEnabled  bool
		wantRunning  bool
	}{
		{"GET", "/api/v1/settings/otlp", nil, false, false},
		{"PUT", "/api/v1/settings/otlp", map[string]any{"enabled": true}, true, true},
		{"PUT", "/api/v1/settings/otlp", map[string]any{"enabled": false}, false, false},
	} {
		w, _ = do(e2, tc.method, tc.path, tc.body, authH())
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s: %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
		var st otlp.ManagerStatus
		if err := json.Unmarshal(decodeData(t, w), &st); err != nil {
			t.Fatalf("decode %s %s: %v", tc.method, tc.path, err)
		}
		if st.Enabled != tc.wantEnabled || st.Running != tc.wantRunning {
			t.Fatalf("%s %s: enabled=%v running=%v want enabled=%v running=%v",
				tc.method, tc.path, st.Enabled, st.Running, tc.wantEnabled, tc.wantRunning)
		}
	}

	// Missing `enabled` field is a bad request.
	w, _ = do(e2, "PUT", "/api/v1/settings/otlp", map[string]any{"nope": 1}, authH())
	if w.Code != http.StatusBadRequest {
		t.Fatalf("PUT bad body: %d %s", w.Code, w.Body.String())
	}
}
