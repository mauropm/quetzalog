package hec_test

import (
	"bytes"
	"database/sql"
	"log/slog"
	"testing"

	"quetzalog/internal/database"
	"quetzalog/internal/events"
	"quetzalog/internal/ingestion"
	"quetzalog/internal/ingestion/hec"
)

func openHECDatabase(t *testing.T) (*sql.DB, error) {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(db); err != nil {
		return nil, err
	}
	return db, nil
}

func newHECStore(db *sql.DB) *events.Store {
	return events.NewStore(db)
}

// HEC-SEC-01: valid HEC tokens must never be written to logs (logs are a
// common exfiltration path: log shippers, bug reports, stdout capture).
func TestHECSec_TokenNotLogged(t *testing.T) {
	db, err := openHECDatabase(t)
	if err != nil {
		t.Fatal(err)
	}
	store := newHECStore(db)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	p := ingestion.NewPipeline(store, 2, 50, logger)
	if err := p.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Stop(t.Context()) })

	const secretToken = "sup3r-s3cret-hec-token-9f2a"
	h := hec.NewHandler(p, []hec.HECToken{{ID: "t1", Token: secretToken, Meta: "desc"}}, logger)

	w := post(t, h, "/services/collector", "Splunk "+secretToken, `{"event":{"message":"hello"}}`)
	if w.Code != 200 {
		t.Fatalf("ingest returned %d %s", w.Code, w.Body.String())
	}
	waitCount(t, store, 1)

	if bytes.Contains(buf.Bytes(), []byte(secretToken)) {
		t.Errorf("HEC token leaked into logs: %s", buf.String())
	}

	w = post(t, h, "/services/collector/raw", "Splunk "+secretToken, "raw line")
	if w.Code != 200 {
		t.Fatalf("raw ingest returned %d", w.Code)
	}
	waitCount(t, store, 2)
	if bytes.Contains(buf.Bytes(), []byte(secretToken)) {
		t.Errorf("HEC token leaked into logs after raw ingest: %s", buf.String())
	}
}
