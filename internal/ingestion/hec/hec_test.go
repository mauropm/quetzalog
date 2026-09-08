package hec_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"quetzalog/internal/database"
	"quetzalog/internal/events"
	"quetzalog/internal/ingestion"
	"quetzalog/internal/ingestion/hec"
)

func setupHec(t *testing.T) (*hec.Handler, *events.Store, func()) {
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
	tokens := []hec.HECToken{{ID: "t1", Token: "good-token", Meta: "desc"}}
	h := hec.NewHandler(p, tokens, logger)
	return h, store, func() {
		p.Stop(context.Background())
		db.Close()
	}
}

func post(t *testing.T, h *hec.Handler, path, auth, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Handle(w, req)
	return w
}

func waitCount(t *testing.T, store *events.Store, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n, _ := store.Count(context.Background(), events.Query{})
		if n >= want {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("expected >=%d events", want)
}

func TestHECAuthRequired(t *testing.T) {
	h, _, cleanup := setupHec(t)
	defer cleanup()

	w := post(t, h, "/services/collector", "", `{"event":{"message":"x"}}`)
	if w.Code != 401 {
		t.Errorf("missing token: %d", w.Code)
	}
	w = post(t, h, "/services/collector", "Splunk wrong-token", `{"event":{"message":"x"}}`)
	if w.Code != 401 {
		t.Errorf("bad token: %d", w.Code)
	}
}

func TestHECSingleEvent(t *testing.T) {
	h, store, cleanup := setupHec(t)
	defer cleanup()

	body := `{"event":{"message":"disk at 90%","host":"db01"},"host":"db01","source":"monitoring","sourcetype":"syslog","time":1756900000}`
	w := post(t, h, "/services/collector", "Splunk good-token", body)
	if w.Code != 200 {
		t.Fatalf("hec single %d %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if code, _ := resp["code"].(float64); code != 0 {
		t.Errorf("hec response: %v", resp)
	}
	waitCount(t, store, 1)
	list, err := store.Search(context.Background(), events.Query{Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if list[0].Message != "disk at 90%" {
		t.Errorf("message mapping %q", list[0].Message)
	}
	if list[0].Host != "db01" || list[0].Source != "monitoring" {
		t.Errorf("metadata mapping %+v", list[0])
	}
	if list[0].Timestamp.Year() != 2025 {
		t.Errorf("unix time mapping produced %v", list[0].Timestamp)
	}
}

func TestHECBatch(t *testing.T) {
	h, store, cleanup := setupHec(t)
	defer cleanup()

	events := make([]map[string]any, 0, 10)
	for i := 0; i < 10; i++ {
		events = append(events, map[string]any{"event": map[string]any{"message": "e", "i": i}})
	}
	body, _ := json.Marshal(map[string]any{"events": events})
	w := post(t, h, "/services/collector", "Splunk good-token", string(body))
	if w.Code != 200 {
		t.Fatalf("batch %d %s", w.Code, w.Body.String())
	}
	waitCount(t, store, 10)
}

func TestHECRaw(t *testing.T) {
	h, store, cleanup := setupHec(t)
	defer cleanup()
	w := post(t, h, "/services/collector/raw", "Splunk good-token", "plain raw text payload")
	if w.Code != 200 {
		t.Fatalf("raw %d %s", w.Code, w.Body.String())
	}
	waitCount(t, store, 1)
	list, _ := store.Search(context.Background(), events.Query{Limit: 2})
	if list[0].Message != "plain raw text payload" {
		t.Errorf("raw message %q", list[0].Message)
	}
}

func TestHECInvalidJSON(t *testing.T) {
	h, _, cleanup := setupHec(t)
	defer cleanup()
	w := post(t, h, "/services/collector", "Splunk good-token", "{not json")
	if w.Code != 400 {
		t.Errorf("invalid json: %d %s", w.Code, w.Body.String())
	}
}

func TestHECMassiveBodyBounded(t *testing.T) {
	h, _, cleanup := setupHec(t)
	defer cleanup()
	// ~64 MiB body: must not OOM the process; handler must reject or read bounded.
	garbage := strings.Repeat("A", 64*1024*1024)
	done := make(chan int, 1)
	go func() {
		req := httptest.NewRequest("POST", "/services/collector/raw", strings.NewReader(garbage))
		req.Header.Set("Authorization", "Splunk good-token")
		w := httptest.NewRecorder()
		h.Handle(w, req)
		done <- w.Code
	}()
	select {
	case code := <-done:
		if code < 400 {
			t.Errorf("oversized raw body accepted (%d) — DoS risk", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("handler stuck on oversized body")
	}
}

var _ = http.MethodPost
