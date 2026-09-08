package detections_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"quetzalog/internal/database"
	"quetzalog/internal/detections"
	"quetzalog/internal/events"
	"quetzalog/pkg/event"
)

func setup(t *testing.T) (*detections.Store, *events.Store, *sql.DB) {
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
	return detections.NewStore(db), events.NewStore(db), db
}

func addEvent(t *testing.T, s *events.Store, src, sev, msg, user, ip string) {
	t.Helper()
	ev := event.NewEvent()
	ev.Source = src
	ev.Severity = sev
	ev.Message = msg
	ev.User = user
	ev.SourceIP = ip
	ev.Timestamp = time.Now().UTC()
	if err := s.Create(context.Background(), ev); err != nil {
		t.Fatalf("create: %v", err)
	}
}

func TestCRUD_RoundTrip(t *testing.T) {
	ds, _, _ := setup(t)
	ctx := context.Background()

	rule := &detections.DetectionRule{
		Name:     "brute",
		Query:    "source=auth",
		Severity: "high",
		Enabled:  true,
		Threshold: &detections.Threshold{Count: 5, Window: "10m"},
		GroupBy:  []string{"source_ip"},
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}
	if rule.ID == "" {
		t.Fatal("id not set")
	}
	got, err := ds.GetByID(ctx, rule.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "brute" || !got.Enabled {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
	if got.Threshold == nil || got.Threshold.Count != 5 || got.Threshold.Window != "10m" {
		t.Errorf("threshold lost: %+v", got.Threshold)
	}
	if len(got.GroupBy) != 1 || got.GroupBy[0] != "source_ip" {
		t.Errorf("group_by lost: %v", got.GroupBy)
	}

	rule.Enabled = false
	if err := ds.Update(ctx, rule); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = ds.GetByID(ctx, rule.ID)
	if got.Enabled {
		t.Error("update did not persist enabled=false")
	}

	if err := ds.Disable(ctx, rule.ID); err != nil {
		t.Fatalf("disable: %v", err)
	}
	got, _ = ds.GetByID(ctx, rule.ID)
	if got.Enabled {
		t.Error("disable did not take effect")
	}
	if err := ds.Enable(ctx, rule.ID); err != nil {
		t.Fatalf("enable: %v", err)
	}
	got, _ = ds.GetByID(ctx, rule.ID)
	if !got.Enabled {
		t.Error("enable did not take effect")
	}

	list, err := ds.List(ctx)
	if err != nil || len(list) != 1 {
		t.Errorf("list: %d err=%v", len(list), err)
	}

	if err := ds.Delete(ctx, rule.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := ds.GetByID(ctx, rule.ID); err == nil {
		t.Error("deleted rule still readable")
	}
}

func TestExecuteNow_ORQueryMatchesAllValues(t *testing.T) {
	ds, es, _ := setup(t)
	addEvent(t, es, "x", "err", "e1", "", "")
	addEvent(t, es, "x", "critical", "e2", "", "")
	addEvent(t, es, "x", "info", "e3", "", "")

	rule := &detections.DetectionRule{
		Name:     "or-rule",
		Query:    "severity=err OR severity=critical",
		Severity: "high",
		Enabled:  true,
	}
	res, err := ds.ExecuteNow(context.Background(), rule, es)
	if err != nil {
		t.Fatalf("executenow: %v", err)
	}
	if res.Total != 2 || res.Matched != 2 {
		t.Errorf("OR query under-matched: total=%d matched=%d, want 2/2", res.Total, res.Matched)
	}
}

func TestExecuteNow_ANDQueryNoError(t *testing.T) {
	ds, es, _ := setup(t)
	addEvent(t, es, "auth", "err", "fail", "", "")
	addEvent(t, es, "auth", "info", "ok", "", "")

	rule := &detections.DetectionRule{
		Name:    "and-rule",
		Query:   "source=auth AND outcome=failure",
		Enabled: true,
	}
	// outcome is not a known column keyword; the AND token previously leaked
	// into the FTS5 MATCH string causing a syntax error. Execution must not error.
	rule.Query = "source=auth AND action=login_failed"
	addEventWithAction(t, es)
	res, err := ds.ExecuteNow(context.Background(), rule, es)
	if err != nil {
		t.Fatalf("AND query errored: %v", err)
	}
	if res.Total != 1 {
		t.Errorf("AND query matched %d, want 1", res.Total)
	}
}

func addEventWithAction(t *testing.T, es *events.Store) {
	ev := event.NewEvent()
	ev.Source = "auth"
	ev.Action = "login_failed"
	ev.Message = "lf"
	ev.Timestamp = time.Now().UTC()
	if err := es.Create(context.Background(), ev); err != nil {
		t.Fatalf("create: %v", err)
	}
}

func TestExecuteNow_ThresholdAbove100Fires(t *testing.T) {
	ds, es, _ := setup(t)
	for i := 0; i < 150; i++ {
		addEvent(t, es, "auth", "err", fmt.Sprintf("brute %d", i), "mallory", "10.0.0.9")
	}

	rule := &detections.DetectionRule{
		Name:      "threshold-big",
		Query:     "source=auth",
		Severity:  "high",
		Enabled:   true,
		Threshold: &detections.Threshold{Count: 120, Window: "1h"},
	}
	res, err := ds.ExecuteNow(context.Background(), rule, es)
	if err != nil {
		t.Fatalf("executenow: %v", err)
	}
	// 150 matching events >= threshold 120 must fire (previously the search
	// silently capped at 100 so the threshold never triggered).
	if res.Matched == 0 {
		t.Errorf("threshold not reached despite 150 matches (100-row cap bug)")
	}
}

func TestExecuteNow_GroupByThreshold(t *testing.T) {
	ds, es, _ := setup(t)
	// group A: 6 events from ip-a; group B: 3 events from ip-b.
	for i := 0; i < 6; i++ {
		addEvent(t, es, "auth", "err", "fail", "", "10.0.0.1")
	}
	for i := 0; i < 3; i++ {
		addEvent(t, es, "auth", "err", "fail", "", "10.0.0.2")
	}

	rule := &detections.DetectionRule{
		Name:      "group-rule",
		Query:     "source=auth",
		Severity:  "high",
		Enabled:   true,
		Threshold: &detections.Threshold{Count: 5, Window: "1h"},
		GroupBy:   []string{"source_ip"},
	}
	res, err := ds.ExecuteNow(context.Background(), rule, es)
	if err != nil {
		t.Fatalf("executenow: %v", err)
	}
	// Per DETECTIONS.md semantics: only events from groups meeting the
	// threshold count; only group A (6 events) qualifies.
	if res.Matched != 6 {
		t.Errorf("group_by threshold semantics: matched=%d, want 6 (only qualifying groups)", res.Matched)
	}
}

func TestExecuteNow_BadWindowErrors(t *testing.T) {
	ds, es, _ := setup(t)
	rule := &detections.DetectionRule{
		Name:      "bad-window",
		Query:     "source=auth",
		Enabled:   true,
		Threshold: &detections.Threshold{Count: 1, Window: "not-a-duration"},
	}
	if _, err := ds.ExecuteNow(context.Background(), rule, es); err == nil {
		t.Error("invalid window should error")
	}
}

func TestExecuteNow_WindowRestricts(t *testing.T) {
	ds, es, _ := setup(t)
	// Old event outside 1m window must not count.
	ev := event.NewEvent()
	ev.Source = "auth"
	ev.Message = "old"
	ev.Timestamp = time.Now().Add(-2 * time.Hour)
	if err := es.Create(context.Background(), ev); err != nil {
		t.Fatalf("create: %v", err)
	}
	recent := event.NewEvent()
	recent.Source = "auth"
	recent.Message = "fresh"
	recent.Timestamp = time.Now()
	if err := es.Create(context.Background(), recent); err != nil {
		t.Fatalf("create: %v", err)
	}

	rule := &detections.DetectionRule{
		Name:      "window-rule",
		Query:     "source=auth",
		Enabled:   true,
		Threshold: &detections.Threshold{Count: 1, Window: "1m"},
	}
	res, err := ds.ExecuteNow(context.Background(), rule, es)
	if err != nil {
		t.Fatalf("executenow: %v", err)
	}
	if res.Total != 1 {
		t.Errorf("window filter: total=%d want 1", res.Total)
	}
}
