package spl

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"quetzalog/internal/database"
	"quetzalog/internal/events"
	"quetzalog/internal/spl/ast"
	"quetzalog/internal/spl/executor"
	"quetzalog/internal/spl/parser"
	"quetzalog/internal/spl/serializer"
	"quetzalog/pkg/event"
)

func newExecutorDB(t *testing.T) *sql.DB {
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
	store := events.NewStore(db)
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	mk := func(src, host, sev, user string, i int) {
		ev := event.NewEvent()
		ev.Source = src
		ev.SourceType = "audit"
		ev.Host = host
		ev.Severity = sev
		ev.EventType = "auth"
		ev.User = user
		ev.Message = "login attempt " + user
		ev.Timestamp = base.Add(time.Duration(i) * time.Minute)
		// A genuinely non-canonical key so attribute-path filtering is exercised.
		ev.Attributes["requester"] = user
		ev.Attributes["response_time"] = (i % 5) * 100
		if err := store.Create(context.Background(), ev); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	mk("auth", "web-01", "err", "mauro", 1)
	mk("auth", "web-02", "info", "ana", 2)
	mk("web", "web-01", "warning", "bob", 3)
	mk("web", "web-03", "err", "mauro", 4)
	return db
}

func run(t *testing.T, q string, limit int) *executor.Result {
	t.Helper()
	db := newExecutorDB(t)
	res, err := executor.Run(context.Background(), db, q, executor.RunOptions{Limit: limit})
	if err != nil {
		t.Fatalf("run %q: %v", q, err)
	}
	return res
}

func TestExecutor_SearchFilters(t *testing.T) {
	res := run(t, `source=auth | table host`, 100)
	if res.Count == 0 {
		t.Fatal("expected matches for source=auth")
	}
	if len(res.Columns) != 1 || res.Columns[0] != "host" {
		t.Fatalf("table projection columns = %v, want [host]", res.Columns)
	}
	for _, r := range res.Rows {
		if r["host"] == nil || r["host"] == "" {
			t.Fatalf("missing host in projected row: %v", r)
		}
	}
}

func TestExecutor_AttributeField(t *testing.T) {
	res := run(t, `requester=mauro | table requester`, 100)
	if res.Count != 2 {
		t.Fatalf("expected 2 rows for requester=mauro (attribute), got %d", res.Count)
	}
}

func TestExecutor_StatsGroupBy(t *testing.T) {
	res := run(t, `stats count by source | sort -count`, 100)
	if len(res.Rows) != 2 {
		t.Fatalf("expected 2 source groups, got %d (%v)", len(res.Rows), res.Rows)
	}
	if fmtInt(res.Rows[0]["count"]) != 2 {
		t.Fatalf("expected top group count 2 (desc sort), got %v", res.Rows[0]["count"])
	}
}

func TestExecutor_EvalAndSort(t *testing.T) {
	res := run(t, `source=web | eval rt=response_time * 1 | table user,rt | sort -rt`, 100)
	if len(res.Rows) != 2 {
		t.Fatalf("expected 2 web rows, got %d", len(res.Rows))
	}
	// web-03 (i=4) has response_time 400, web-01 (i=3) 300 → mauro first desc.
	if res.Rows[0]["user"] != "mauro" {
		t.Fatalf("sort -rt expected mauro first, got %v (rows=%v)", res.Rows[0]["user"], res.Rows)
	}
}

func TestExecutor_HeadAfterSort(t *testing.T) {
	res := run(t, `table host | sort host | head 2`, 100)
	if len(res.Rows) != 2 {
		t.Fatalf("head 2 -> 2 rows, got %d", len(res.Rows))
	}
	if res.Rows[0]["host"] != "web-01" {
		t.Fatalf("sort host asc expected web-01 first, got %v", res.Rows[0]["host"])
	}
}

func TestExecutor_ErrorIsUserFacing(t *testing.T) {
	db := newExecutorDB(t)
	_, err := executor.Run(context.Background(), db, `search ]`, executor.RunOptions{Limit: 10})
	if err == nil {
		t.Fatal("expected error for invalid query")
	}
	if !errors.Is(err, ast.ErrInvalidQuery) {
		t.Fatalf("expected ast.ErrInvalidQuery-wrapped error, got: %v", err)
	}
}

func TestSerializer_RoundTripStable(t *testing.T) {
	cases := []string{
		`index=auth sourcetype=audit | where status="failed" | stats count by user | sort -count | head 10`,
		`eval x=response_time*2 | table _time,user,x`,
		`dedup host | rename host as server`,
		`timechart count by severity`,
		`user IN (a,b,c) | sort user`,
	}
	for _, in := range cases {
		a := parseSeri(t, in)
		b := parseSeri(t, a)
		if a != b {
			t.Errorf("serialize not idempotent for %q:\n 1: %s\n 2: %s", in, a, b)
		}
	}
}

func TestSerializer_PreservesSelectors(t *testing.T) {
	out := parseSeri(t, `index=auth sourcetype=audit host=web-01 | stats count by user`)
	for _, want := range []string{"index", "auth", "audit", "web-01", "stats", "user"} {
		if !containsSub(out, want) {
			t.Errorf("serialized %q missing %q", out, want)
		}
	}
}

// ───────── helpers ─────────
func parseSeri(t *testing.T, in string) string {
	t.Helper()
	p, err := parser.New(in)
	if err != nil {
		t.Fatalf("tokenize %q: %v", in, err)
	}
	q, err := p.Parse()
	if err != nil {
		t.Fatalf("parse %q: %v", in, err)
	}
	q.EnsureSearchFirst()
	return serializer.Serialize(q)
}

func fmtInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	}
	return -999999
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
