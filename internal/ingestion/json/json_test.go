package json_test

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
	ingestjson "quetzalog/internal/ingestion/json"
)

func setupJSON(t *testing.T) (*ingestjson.IngestHandler, *events.Store, *ingestion.Pipeline, func()) {
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
	h := ingestjson.NewIngestHandler(p, logger)
	return h, store, p, func() { db.Close() }
}

func send(h *ingestjson.IngestHandler, method, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/v1/json", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	err := h.Handle(w, req)
	if err != nil {
		if w.Header().Get("Content-Type") == "" && w.Code == 200 && w.Body.Len() == 0 {
			// The handler reported an error without writing any HTTP response.
			// Server wiring (main.go) discards these errors today, which leaves
			// clients with an empty 200. Record that as a failure signal via the
			// sentinel header so tests can detect silent-success responses.
			w.Header().Set("X-Handler-Error", err.Error())
		}
	}
	return w
}

func TestJSONSingleIngest(t *testing.T) {
	h, store, p, cleanup := setupJSON(t)
	defer cleanup()
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer p.Stop(context.Background())

	w := send(h, "POST", `{"message":"single event","source":"unit","severity":"err"}`)
	if w.Code != 202 {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var resp ingestjson.IngestResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Accepted != 1 || resp.Rejected != 0 {
		t.Errorf("resp %+v", resp)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := store.Count(context.Background(), events.Query{}); n >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	n, _ := store.Count(context.Background(), events.Query{})
	if n != 1 {
		t.Errorf("event not persisted: %d", n)
	}
}

func TestJSONSingleIngestFailureReported(t *testing.T) {
	h, _, p, cleanup := setupJSON(t)
	defer cleanup()
	// Pipeline never started => Ingest returns error. The handler must report
	// it as rejected, not claim success.
	w := send(h, "POST", `{"message":"doomed"}`)
	if w.Code >= 200 && w.Code < 300 {
		var resp ingestjson.IngestResponse
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp.Rejected == 0 {
			t.Errorf("handler reported success (%+v) while ingest failed into stopped pipeline", resp)
		}
	} else {
		return // proper error status also acceptable
	}
	_ = p
}

func TestJSONBatchCounts(t *testing.T) {
	h, _, p, cleanup := setupJSON(t)
	defer cleanup()
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer p.Stop(context.Background())

	w := send(h, "POST", `{"events":[{"message":"a","source":"u"},{"message":"b","source":"u"}]}`)
	if w.Code != 202 {
		t.Fatalf("batch %d %s", w.Code, w.Body.String())
	}
	var resp ingestjson.IngestResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Accepted != 2 {
		t.Errorf("batch accepted %d", resp.Accepted)
	}
}

func TestJSONInvalidBody(t *testing.T) {
	h, _, p, cleanup := setupJSON(t)
	defer cleanup()
	_ = p
	w := send(h, "POST", `{"events": "not-an-array"}`)
	if w.Code != 400 {
		t.Errorf("invalid batch body -> %d", w.Code)
	}
	w = send(h, "POST", `{{{`)
	if w.Code != 400 {
		t.Errorf("garbage body -> %d", w.Code)
	}
}

func TestJSONMethodGuard(t *testing.T) {
	h, _, p, cleanup := setupJSON(t)
	defer cleanup()
	_ = p
	w := send(h, "GET", ``)
	if w.Code != 405 {
		t.Errorf("GET -> %d want 405", w.Code)
	}
}

func TestJSONEmptyBatch(t *testing.T) {
	h, _, p, cleanup := setupJSON(t)
	defer cleanup()
	_ = p
	w := send(h, "POST", `{"events":[]}`)
	if w.Code != 400 {
		t.Errorf("empty batch -> %d want 400", w.Code)
	}
}
