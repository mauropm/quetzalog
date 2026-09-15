package threatintel

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"quetzalog/internal/database"
	"quetzalog/internal/risk"
	"quetzalog/pkg/event"
)

func insertEvent(t *testing.T, db *sql.DB, id, host, sourceIP, sev string, attrs map[string]any) {
	t.Helper()
	b, _ := json.Marshal(attrs)
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO events (id, timestamp, received_at, source, source_type, host, severity, message, source_ip, attributes)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		id, time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339),
		"test", "json", host, sev, "msg", sourceIP, string(b)); err != nil {
		t.Fatalf("insert event: %v", err)
	}
}

func TestEnricherMatchAndRecord(t *testing.T) {
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()

	store := NewStore(db)
	riskStore := risk.NewEntityRiskStore(db)
	ind, err := store.Upsert(ctx, InIndicator{
		Type: "ip", Value: "6.6.6.6", Severity: "critical",
		Source: "analyst", Confidence: 1.0, Reliability: 1.0,
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// A second indicator on the same event to exercise correlation.
	dom, err := store.Upsert(ctx, InIndicator{Type: "domain", Value: "bad.example", Severity: "high", Source: "analyst"})
	if err != nil {
		t.Fatalf("upsert domain: %v", err)
	}

	enricher := NewEnricher(store, riskStore, db, nil)
	enricher.Start(1)

	insertEvent(t, db, "evt-ti-1", "web1", "6.6.6.6", "err", map[string]any{"domain": "bad.example"})
	enricher.Enqueue(&event.Event{
		ID: "evt-ti-1", Host: "web1", SourceIP: "6.6.6.6", Severity: "err",
		Attributes: map[string]any{"domain": "bad.example"},
	})

	// Wait for the async worker to finish (attribute write is the signal).
	var attrs string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		row := db.QueryRowContext(ctx, `SELECT attributes FROM events WHERE id = 'evt-ti-1'`)
		if err := row.Scan(&attrs); err == nil && contains(attrs, "threat.indicators") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	enricher.Stop()

	var m map[string]any
	if err := json.Unmarshal([]byte(attrs), &m); err != nil {
		t.Fatalf("attributes: %v: %s", err, attrs)
	}
	threat, _ := m["threat"].(map[string]any)
	if threat == nil {
		t.Fatalf("no threat block: %s", attrs)
	}
	if threat["severity"] != "critical" {
		t.Errorf("threat.severity: %v", threat["severity"])
	}
	ids, _ := threat["indicators"].([]any)
	if len(ids) != 2 {
		t.Errorf("threat.indicators: %v", ids)
	}

	// Hit counters bumped.
	got, _ := store.Get(ctx, ind.ID)
	if got.HitCount != 1 {
		t.Errorf("hit count: %d", got.HitCount)
	}
	// Correlation recorded between the two indicators.
	corr, _ := store.CorrelatedIDs(ctx, ind.ID, 10)
	if len(corr) != 1 || corr[0] != dom.ID {
		t.Errorf("correlations: %v", corr)
	}
	// Risk contribution recorded for the matched IP: critical 25 ×
	// confidence 0.8 (single-source discount) = 20.
	er, _ := riskStore.Get(ctx, "ip", "6.6.6.6")
	if er == nil || er.RiskScore != 20 {
		t.Errorf("ip risk: %+v, want 20", er)
	}
	contribs, _ := riskStore.Contributions(ctx, "ip", "6.6.6.6", 10)
	if len(contribs) != 1 || contribs[0].SourceID != "ti-enricher" {
		t.Errorf("contributions: %+v", contribs)
	}
}

func TestEnricherNoMatchNoWrite(t *testing.T) {
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()

	store := NewStore(db)
	enricher := NewEnricher(store, nil, db, nil)
	enricher.Start(1)

	insertEvent(t, db, "evt-ti-2", "clean1", "8.8.8.8", "info", nil)
	enricher.Enqueue(&event.Event{ID: "evt-ti-2", Host: "clean1", SourceIP: "8.8.8.8", Severity: "info"})
	time.Sleep(200 * time.Millisecond)
	enricher.Stop()

	var attrs sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT attributes FROM events WHERE id = 'evt-ti-2'`).Scan(&attrs); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if attrs.Valid && contains(attrs.String, "threat") {
		t.Errorf("clean event got a threat block: %s", attrs.String)
	}
}

func TestEnricherQueueFullNeverBlocks(t *testing.T) {
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	store := NewStore(db)
	enricher := NewEnricher(store, nil, db, nil)
	// Do NOT Start(): the queue is full and Enqueue must not block.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 5000; i++ {
			enricher.Enqueue(&event.Event{ID: "evt-" + string(rune('a'+i%26))})
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Enqueue blocked on a full queue")
	}
}

func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}
