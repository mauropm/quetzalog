package otlp_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"quetzalog/internal/database"
	"quetzalog/internal/events"
	"quetzalog/internal/ingestion"
	"quetzalog/internal/ingestion/otlp"
)

func setupOtlp(t *testing.T) (*otlp.Handler, *events.Store, *ingestion.Pipeline, func()) {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(db); err != nil {
		db.Close()
		t.Fatalf("migrate (requires FTS5 CGO env): %v", err)
	}
	store := events.NewStore(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	p := ingestion.NewPipeline(store, 2, 50, logger)
	if err := p.Start(context.Background()); err != nil {
		db.Close()
		t.Fatal(err)
	}
	h := otlp.NewHandler(p, logger)
	return h, store, p, func() {
		p.Stop(context.Background())
		db.Close()
	}
}

func sendOtlp(h *otlp.Handler, ct, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/v1/logs", strings.NewReader(body))
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	err := h.Handle(w, req)
	if err != nil && w.Header().Get("Content-Type") == "" {
		// error returned without an HTTP response — server-side wiring must surface it
		w.Header().Set("X-Handler-Error", err.Error())
	}
	return w
}

func waitOtlp(t *testing.T, store *events.Store, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := store.Count(context.Background(), events.Query{}); n >= want {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("want %d events", want)
}

func TestOtlpJSONIngest(t *testing.T) {
	h, store, _, cleanup := setupOtlp(t)
	defer cleanup()

	payload := map[string]any{
		"resourceLogs": []any{map[string]any{
			"resource": map[string]any{"attributes": []any{
				map[string]any{"key": "service.name", "value": map[string]any{"stringValue": "my-app"}},
				map[string]any{"key": "host.name", "value": map[string]any{"stringValue": "server01"}},
			}},
			"scopeLogs": []any{map[string]any{
				"scope": map[string]any{"name": "scope-a", "version": "1.0.0"},
				"logRecords": []any{map[string]any{
					"timeUnixNano": "1725392400000000000",
					"severityText": "ERROR",
					"body":         map[string]any{"stringValue": "Failed SSH login for user admin"},
					"attributes": []any{
						map[string]any{"key": "user.name", "value": map[string]any{"stringValue": "admin"}},
						map[string]any{"key": "source.ip", "value": map[string]any{"stringValue": "10.1.2.3"}},
					},
				}},
			}},
		}},
	}
	b, _ := json.Marshal(payload)
	w := sendOtlp(h, "application/json", string(b))
	if w.Code != 200 {
		t.Fatalf("otlp %d %s %s", w.Code, w.Body.String(), w.Header().Get("X-Handler-Error"))
	}
	waitOtlp(t, store, 1)
	list, err := store.Search(context.Background(), events.Query{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	ev := list[0]
	if ev.Message != "Failed SSH login for user admin" {
		t.Errorf("body mapping %q", ev.Message)
	}
	if ev.Service != "my-app" || ev.Host != "server01" {
		t.Errorf("resource attrs: %+v", ev)
	}
	if ev.User != "admin" {
		t.Errorf("user.name mapping %q", ev.User)
	}
	if ev.SourceIP != "10.1.2.3" {
		t.Errorf("source.ip mapping %q", ev.SourceIP)
	}
	if ev.Timestamp.Year() != 2024 {
		t.Errorf("time mapping %v", ev.Timestamp)
	}
}

func TestOtlpNonStringServiceAttrNoPanic(t *testing.T) {
	// resource attribute service.name with an integer value used to hit an
	// unchecked string type assertion and panic the request handler.
	h, _, _, cleanup := setupOtlp(t)
	defer cleanup()

	payload := map[string]any{
		"resourceLogs": []any{map[string]any{
			"resource": map[string]any{"attributes": []any{
				map[string]any{"key": "service.name", "value": map[string]any{"intValue": "42"}},
			}},
			"scopeLogs": []any{map[string]any{
				"logRecords": []any{map[string]any{"body": map[string]any{"stringValue": "x"}}},
			}},
		}},
	}
	b, _ := json.Marshal(payload)

	var code int
	var panicked any
	done := make(chan struct{})
	go func() {
		defer func() { panicked = recover(); close(done) }()
		w := sendOtlp(h, "application/json", string(b))
		code = w.Code
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler hung")
	}
	if panicked != nil {
		t.Errorf("handler panicked on non-string service.name: %v", panicked)
	}
	if code != 200 {
		t.Errorf("expected handler to survive and respond 200, got %d", code)
	}
}

func TestOtlpInvalidJSON(t *testing.T) {
	h, _, _, cleanup := setupOtlp(t)
	defer cleanup()
	w := sendOtlp(h, "application/json", "}}bad")
	if w.Code != 400 && w.Header().Get("X-Handler-Error") == "" {
		t.Errorf("invalid JSON not reported: %d %s", w.Code, w.Body.String())
	}
	if w.Code == 200 {
		t.Errorf("invalid JSON accepted with 200 (silent success)")
	}
}

func TestOtlpBadContentType(t *testing.T) {
	h, _, _, cleanup := setupOtlp(t)
	defer cleanup()
	w := sendOtlp(h, "application/xml", "<x/>")
	if w.Code == 200 {
		t.Errorf("unsupported media type returned 200")
	}
}
