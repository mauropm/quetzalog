package query_test

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"quetzalog/internal/database"
	"quetzalog/internal/events"
	"quetzalog/internal/query"
	"quetzalog/pkg/event"
)

func setup(t *testing.T) (*query.Service, *sql.DB) {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := database.Migrate(db); err != nil {
		db.Close()
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return query.NewService(db), db
}

func seed(t *testing.T, db *sql.DB, n int, base time.Time) []string {
	t.Helper()
	store := events.NewStore(db)
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		ev := event.NewEvent()
		ev.Source = fmt.Sprintf("src%d", i%3)
		ev.Severity = []string{"info", "err", "critical"}[i%3]
		ev.Message = fmt.Sprintf("event number %d", i)
		ev.Timestamp = base.Add(time.Duration(i) * time.Minute)
		ev.User = fmt.Sprintf("u%d", i%5)
		if err := store.Create(context.Background(), ev); err != nil {
			t.Fatalf("seed: %v", err)
		}
		ids = append(ids, ev.ID)
	}
	return ids
}

func TestExecute_FieldFilter(t *testing.T) {
	svc, db := setup(t)
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	seed(t, db, 12, base)

	resp, err := svc.Execute(context.Background(), query.SearchRequest{Query: "source=src1", Limit: 100})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if resp.Count != 4 {
		t.Errorf("field filter: want 4, got %d", resp.Count)
	}
}

func TestExecute_UnknownFieldDoesNotError(t *testing.T) {
	svc, db := setup(t)
	seed(t, db, 3, time.Now())

	// Nonexistent columns must not leak into SQL (previously produced
	// "no such column" DB errors surfaced as HTTP 500).
	resp, err := svc.Execute(context.Background(), query.SearchRequest{Query: "notafield=zzz", Limit: 50})
	if err != nil {
		t.Fatalf("unknown field errored: %v", err)
	}
	if resp.Count != 0 {
		t.Errorf("unknown field matched %d rows, want 0", resp.Count)
	}
}

func TestExecute_AttributeFiltering(t *testing.T) {
	svc, db := setup(t)
	store := events.NewStore(db)
	ev := event.NewEvent()
	ev.Source = "app"
	ev.Message = "attr test"
	ev.Timestamp = time.Now()
	ev.Attributes["tenant"] = "acme"
	if err := store.Create(context.Background(), ev); err != nil {
		t.Fatalf("create: %v", err)
	}

	resp, err := svc.Execute(context.Background(), query.SearchRequest{Query: "tenant=acme", Limit: 50})
	if err != nil {
		t.Fatalf("execute attribute filter: %v", err)
	}
	if resp.Count != 1 {
		t.Errorf("attribute search: want 1 got %d", resp.Count)
	}
}

func TestExecute_NegativeHeadDoesNotPanic(t *testing.T) {
	svc, db := setup(t)
	seed(t, db, 5, time.Now())

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("head -1 panicked: %v", r)
		}
	}()
	_, err := svc.Execute(context.Background(), query.SearchRequest{Query: "source=src0 | head -1", Limit: 100})
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "head") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecute_OffsetAppliedExactlyOnce(t *testing.T) {
	svc, db := setup(t)
	base := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	seed(t, db, 10, base)

	resp, err := svc.Execute(context.Background(), query.SearchRequest{Query: "source=src0 OR source=src1 OR source=src2", Limit: 100, Offset: 3})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	// 10 rows total; offset 3 => 7 rows (rows 4..10 by timestamp desc).
	if resp.Count != 10 {
		t.Errorf("Count should report total %d, got %d", 10, resp.Count)
	}
	if len(resp.Results) != 7 {
		t.Errorf("offset 3: want 7 results, got %d (double-offset bug if 4)", len(resp.Results))
	}
}

func TestExecute_SortDescending(t *testing.T) {
	svc, db := setup(t)
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	seed(t, db, 12, base)

	resp, err := svc.Execute(context.Background(), query.SearchRequest{Query: "user=u1 | sort -timestamp", Limit: 50})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(resp.Results) < 2 {
		t.Fatalf("need >=2 rows for sort check, got %d", len(resp.Results))
	}
	// First result must be the newest (seeded ascending, sort -timestamp => desc).
	firstID, _ := resp.Results[0]["id"].(string)
	lastID, _ := resp.Results[len(resp.Results)-1]["id"].(string)
	if firstID == lastID {
		t.Fatal("sort produced degenerate output")
	}
	// Verify actual timestamps from DB order.
	var tsFirst, tsLast time.Time
	db.QueryRow("SELECT timestamp FROM events WHERE id=?", firstID).Scan(&tsFirst)
	db.QueryRow("SELECT timestamp FROM events WHERE id=?", lastID).Scan(&tsLast)
	if !tsFirst.After(tsLast) {
		t.Errorf("sort -timestamp broken: first=%v last=%v", tsFirst, tsLast)
	}
}

func TestExecute_SQLInjectionViaKeyBlocked(t *testing.T) {
	svc, db := setup(t)
	seed(t, db, 4, time.Now())

	// Space-free boolean-based blind SQL injection probes. Tokens without an "="
	// until the tail end up interpolated raw into "WHERE <key> = ?" by the naive
	// parser; if the true-payload returns rows while the false-payload does not,
	// the expression demonstrably executed inside SQL.
	oracleTrue := "(select count(*)from events)>0=1"
	oracleFalse := "(select count(*)from events)>5=1"

	rT, errT := svc.Execute(context.Background(), query.SearchRequest{Query: oracleTrue, Limit: 10})
	rF, errF := svc.Execute(context.Background(), query.SearchRequest{Query: oracleFalse, Limit: 10})

	if errT == nil && errF == nil {
		if len(rT.Results) != len(rF.Results) {
			t.Errorf("blind SQL injection demonstrated: true-payload returned %d rows, false-payload %d rows",
				len(rT.Results), len(rF.Results))
		}
	}
	// Either rejection (error) or fully data-independent handling is required.

	for _, q := range []string{
		"(select 1where 1=1)=1",
		"id)or(1=1",
		"message LIKE'x'or(1=2",
	} {
		if _, err := svc.Execute(context.Background(), query.SearchRequest{Query: q, Limit: 10}); err != nil {
			continue // rejected: good
		}
	}
}

func TestExecute_StatsAggregation(t *testing.T) {
	svc, db := setup(t)
	seed(t, db, 9, time.Now())

	resp, err := svc.Execute(context.Background(), query.SearchRequest{Query: "| stats count by source", Limit: 50})
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if len(resp.Results) != 3 {
		t.Fatalf("stats by source: want 3 groups, got %d (%v)", len(resp.Results), resp.Results)
	}
	total := 0
	for _, r := range resp.Results {
		c, _ := r["count"].(int)
		total += c
	}
	if total != 9 {
		t.Errorf("stats counts sum to %d, want 9", total)
	}
}

func TestExecute_HeadLimits(t *testing.T) {
	svc, db := setup(t)
	seed(t, db, 20, time.Now())

	resp, err := svc.Execute(context.Background(), query.SearchRequest{Query: "source=src0 | head 2", Limit: 100})
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if len(resp.Results) != 2 {
		t.Errorf("head 2: want 2, got %d", len(resp.Results))
	}
}
