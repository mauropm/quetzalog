package correlation

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"quetzalog/internal/database"
)

func setupGraphDB(t *testing.T) (*Graph, func()) {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(db); err != nil {
		db.Close()
		t.Fatalf("migrate (requires FTS5 CGO env): %v", err)
	}
	return NewGraph(db), func() { db.Close() }
}

// seedHostEvents inserts n events with the given host; ts is the SQLite
// timestamp text. Returns the ids (index 0 oldest).
func seedHostEvents(t *testing.T, db *sql.DB, n int, ts string, host string) []string {
	t.Helper()
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		ids[i] = fmt.Sprintf("ev-%s-%d", host, i)
		_, err := db.Exec(`INSERT INTO events (id, timestamp, source, host, event_type, message) VALUES (?, ?, ?, ?, ?, ?)`,
			ids[i], ts, "bench", host, "auth", "login")
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	return ids
}

// The rewritten GetRelatedEvents pushed LIMIT into SQL; the previous shape
// scanned without a bound. It must return at most `limit`.
func TestGetRelatedEventsRespectsLimit(t *testing.T) {
	graph, cleanup := setupGraphDB(t)
	defer cleanup()
	db := graph.db

	seedHostEvents(t, db, 5, "2026-09-01 12:00:00", "web-01")
	seedHostEvents(t, db, 1, "2026-09-01 12:00:00", "web-99") // must not match

	got, err := graph.GetRelatedEvents(context.Background(), EntityTypeHost, "web-01", 2)
	if err != nil {
		t.Fatalf("GetRelatedEvents: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 related events, got %d", len(got))
	}
}

// A zero limit must fall back to the default, not emit LIMIT 0 (zero rows).
func TestGetRelatedEventsZeroLimit(t *testing.T) {
	graph, cleanup := setupGraphDB(t)
	defer cleanup()
	db := graph.db

	seedHostEvents(t, db, 1, "2026-09-01 12:00:00", "web-01")

	got, err := graph.GetRelatedEvents(context.Background(), EntityTypeHost, "web-01", 0)
	if err != nil {
		t.Fatalf("GetRelatedEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 related event with limit 0, got %d", len(got))
	}
}

// The bootstrap runs once via retryable sync.Once; repeated upserts must not
// re-run DDL nor fail, and upsert dedup must keep a single entity row.
func TestGraphSchemaInitIdempotent(t *testing.T) {
	graph, cleanup := setupGraphDB(t)
	defer cleanup()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := graph.UpsertEntity(ctx, &Entity{
			ID: "e1", Type: EntityTypeHost, Value: "web-01",
		}); err != nil {
			t.Fatalf("upsert %d: %v", i, err)
		}
	}
	got, err := graph.GetEntity(ctx, EntityTypeHost, "web-01")
	if err != nil {
		t.Fatalf("get entity: %v", err)
	}
	if got == nil {
		t.Fatal("entity missing after upserts")
	}
	var n int
	if err := graph.db.QueryRowContext(ctx, `SELECT count(*) FROM entities`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 entity row, got %d", n)
	}
}
