package api_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"

	"quetzalog/internal/api"
	"quetzalog/internal/config"
	"quetzalog/internal/logging"
)

func TestLoggingSettings(t *testing.T) {
	// Routers without a controller report the startup config read-only.
	e := newEnv(t)
	w, _ := do(e, "GET", "/api/v1/settings/logging", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", w.Code, w.Body.String())
	}
	var got struct {
		Level   string `json:"level"`
		Managed bool   `json:"managed"`
	}
	if err := json.Unmarshal(decodeData(t, w), &got); err != nil {
		t.Fatal(err)
	}
	if got.Managed {
		t.Fatal("plain env reports managed")
	}

	live := new(slog.LevelVar)
	cfg := config.DefaultConfig()
	ctl := logging.NewController(live, &cfg, "")
	e2 := newEnv(t, api.WithLoggingController(ctl))

	w, _ = do(e2, "POST", "/api/v1/login", map[string]any{"username": "admin", "password": "changeme"}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	data, _ := out["data"].(map[string]any)
	adminTok, _ := data["token"].(string)
	authH := map[string]string{"Authorization": "Bearer " + adminTok}

	w, _ = do(e2, "PUT", "/api/v1/settings/logging", map[string]any{"level": "debug"}, authH)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT debug: %d %s", w.Code, w.Body.String())
	}
	json.Unmarshal(decodeData(t, w), &got)
	if got.Level != "debug" || live.Level() != slog.LevelDebug {
		t.Fatalf("after PUT debug: response=%+v live=%v", got, live.Level())
	}

	// GET now reflects the live switch.
	w, _ = do(e2, "GET", "/api/v1/settings/logging", nil, authH)
	json.Unmarshal(decodeData(t, w), &got)
	if !got.Managed || got.Level != "debug" {
		t.Fatalf("GET after switch: %+v", got)
	}

	// Invalid names are rejected and change nothing.
	w, _ = do(e2, "PUT", "/api/v1/settings/logging", map[string]any{"level": "loud"}, authH)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("PUT bad level: %d %s", w.Code, w.Body.String())
	}
	if live.Level() != slog.LevelDebug {
		t.Fatal("bad level changed the live logger")
	}

	// Back to normal operation.
	w, _ = do(e2, "PUT", "/api/v1/settings/logging", map[string]any{"level": "events"}, authH)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT events: %d", w.Code)
	}
	if live.Level() != slog.LevelInfo {
		t.Fatalf("events must map to info, live=%v", live.Level())
	}
}
