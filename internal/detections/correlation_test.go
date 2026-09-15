package detections_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"quetzalog/internal/detections"
	"quetzalog/internal/events"
	"quetzalog/internal/findings"
	"quetzalog/internal/risk"
	"quetzalog/pkg/event"
)

func corrEngine(t *testing.T) (*detections.CorrelationEngine, *detections.Store, *findings.Store, *events.Store, func()) {
	t.Helper()
	ds, es, db := setup(t)
	fs := findings.NewStore(db)
	rs := risk.NewEntityRiskStore(db)
	eng := detections.NewCorrelationEngine(db, ds, es, fs, rs, nil)
	eng.Start(1)
	return eng, ds, fs, es, func() { eng.Stop() }
}

func mkEv(user, et, outcome string, ts time.Time) *event.Event {
	ev := event.NewEvent()
	ev.Timestamp = ts
	ev.User = user
	ev.EventType = et
	ev.Outcome = outcome
	ev.Source = "test"
	ev.Severity = "info"
	ev.Message = "corr test event"
	return ev
}

func waitForFindings(t *testing.T, fs *findings.Store, detectionID string, want int, timeout time.Duration) []*findings.Finding {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		list, _, err := fs.List(context.Background(), findings.Filter{DetectionID: detectionID, Limit: 100})
		if err == nil && len(list) >= want {
			return list
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d findings (detection %s)", want, detectionID)
	return nil
}

func TestSequence_Match(t *testing.T) {
	eng, ds, fs, _, stop := corrEngine(t)
	defer stop()
	ctx := context.Background()

	rule := &detections.DetectionRule{
		Name:     "seq-lateral",
		Kind:     "sequence",
		Severity: "high",
		Enabled:  true,
		RiskScore: 25,
		Definition: json.RawMessage(`{"correlation_key":["user"],"window":"1h","steps":[
			{"id":"in","predicate":{"event_type":"auth","outcome":"success"},"technique":"T1078"},
			{"id":"priv","predicate":{"event_type":"admin"},"technique":"T1068"}]}`),
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}

	now := time.Now().UTC()
	eng.Enqueue(mkEv("alice", "auth", "success", now.Add(-5*time.Minute)))
	eng.Enqueue(mkEv("alice", "admin", "", now.Add(-4*time.Minute)))

	waitForFindings(t, fs, rule.ID, 1, 5*time.Second)

	// State should be cleaned up after a full match.
	states, err := eng.ListStates(ctx, rule.ID)
	if err != nil {
		t.Fatalf("states: %v", err)
	}
	if len(states) != 0 {
		t.Errorf("state not cleared after match: %+v", states)
	}
}

func TestSequence_OutOfOrder(t *testing.T) {
	eng, ds, fs, _, stop := corrEngine(t)
	defer stop()
	ctx := context.Background()

	rule := &detections.DetectionRule{
		Name:     "seq-oob",
		Kind:     "sequence",
		Severity: "medium",
		Enabled:  true,
		Definition: json.RawMessage(`{"correlation_key":["user"],"window":"1h","steps":[
			{"id":"in","predicate":{"event_type":"auth"}},
			{"id":"priv","predicate":{"event_type":"admin"}}]}`),
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}

	now := time.Now().UTC()
	// Step 2 arrives before step 1 (out-of-order delivery).
	eng.Enqueue(mkEv("bob", "admin", "", now.Add(-4*time.Minute)))
	eng.Enqueue(mkEv("bob", "auth", "", now.Add(-5*time.Minute)))

	waitForFindings(t, fs, rule.ID, 1, 5*time.Second)
}

func TestSequence_MaxGapBlocks(t *testing.T) {
	eng, ds, fs, _, stop := corrEngine(t)
	defer stop()
	ctx := context.Background()

	rule := &detections.DetectionRule{
		Name:     "seq-gap",
		Kind:     "sequence",
		Severity: "medium",
		Enabled:  true,
		Definition: json.RawMessage(`{"correlation_key":["user"],"window":"1h","max_gap":"10m","steps":[
			{"id":"in","predicate":{"event_type":"auth"}},
			{"id":"priv","predicate":{"event_type":"admin"}}]}`),
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}

	now := time.Now().UTC()
	eng.Enqueue(mkEv("carol", "auth", "", now.Add(-5*time.Hour)))
	eng.Enqueue(mkEv("carol", "admin", "", now))

	// No finding: the gap between steps exceeds max_gap.
	time.Sleep(300 * time.Millisecond)
	list, _, _ := fs.List(ctx, findings.Filter{DetectionID: rule.ID})
	if len(list) != 0 {
		t.Errorf("expected no match across max_gap, got %d findings", len(list))
	}
}

func TestSequence_PartialStateVisible(t *testing.T) {
	eng, ds, _, _, stop := corrEngine(t)
	defer stop()
	ctx := context.Background()

	rule := &detections.DetectionRule{
		Name:     "seq-partial",
		Kind:     "sequence",
		Severity: "medium",
		Enabled:  true,
		Definition: json.RawMessage(`{"correlation_key":["user"],"window":"1h","steps":[
			{"id":"in","predicate":{"event_type":"auth"}},
			{"id":"priv","predicate":{"event_type":"admin"}}]}`),
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}

	eng.Enqueue(mkEv("dave", "auth", "", time.Now().UTC()))
	time.Sleep(300 * time.Millisecond)

	states, err := eng.ListStates(ctx, rule.ID)
	if err != nil {
		t.Fatalf("states: %v", err)
	}
	if len(states) != 1 {
		t.Fatalf("expected 1 partial state, got %d", len(states))
	}
	if states[0].CurrentStep != 1 {
		t.Errorf("current_step: %d, want 1", states[0].CurrentStep)
	}
}

func TestCorrelation_AllConditions(t *testing.T) {
	eng, ds, fs, _, stop := corrEngine(t)
	defer stop()
	ctx := context.Background()

	rule := &detections.DetectionRule{
		Name:     "corr-brute",
		Kind:     "correlation",
		Severity: "high",
		Enabled:  true,
		RiskScore: 30,
		Definition: json.RawMessage(`{"correlation_key":["user"],"window":"1h","require":"all","conditions":[
			{"id":"failures","predicate":{"event_type":"auth","outcome":"failure"},"count_gte":3},
			{"id":"success","predicate":{"event_type":"auth","outcome":"success"}}]}`),
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}

	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		eng.Enqueue(mkEv("erin", "auth", "failure", now.Add(-time.Minute*time.Duration(i))))
	}
	eng.Enqueue(mkEv("erin", "auth", "success", now))

	list := waitForFindings(t, fs, rule.ID, 1, 5*time.Second)
	if len(list[0].Description) == 0 {
		t.Error("finding has no description")
	}
}

func TestCorrelation_MostConditions(t *testing.T) {
	eng, ds, fs, _, stop := corrEngine(t)
	defer stop()
	ctx := context.Background()

	rule := &detections.DetectionRule{
		Name:     "corr-most",
		Kind:     "correlation",
		Severity: "medium",
		Enabled:  true,
		Definition: json.RawMessage(`{"correlation_key":["user"],"window":"1h","require":"most","min_match":2,"conditions":[
			{"id":"a","predicate":{"event_type":"auth"}},
			{"id":"b","predicate":{"event_type":"admin"}},
			{"id":"c","predicate":{"event_type":"network"}}]}`),
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}

	now := time.Now().UTC()
	eng.Enqueue(mkEv("frank", "auth", "", now.Add(-2*time.Minute)))
	eng.Enqueue(mkEv("frank", "admin", "", now.Add(-1*time.Minute)))
	// Only 2 of 3 conditions, but min_match=2 → match.
	waitForFindings(t, fs, rule.ID, 1, 5*time.Second)
}

func TestCorrelation_NotEnoughConditions(t *testing.T) {
	eng, ds, fs, _, stop := corrEngine(t)
	defer stop()
	ctx := context.Background()

	rule := &detections.DetectionRule{
		Name:     "corr-pending",
		Kind:     "correlation",
		Severity: "medium",
		Enabled:  true,
		Definition: json.RawMessage(`{"correlation_key":["user"],"window":"1h","require":"all","conditions":[
			{"id":"failures","predicate":{"event_type":"auth","outcome":"failure"},"count_gte":3},
			{"id":"success","predicate":{"event_type":"auth","outcome":"success"}}]}`),
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}

	now := time.Now().UTC()
	// Only the failures condition is satisfiable so far (2 < 3, no success).
	eng.Enqueue(mkEv("gina", "auth", "failure", now.Add(-2*time.Minute)))
	eng.Enqueue(mkEv("gina", "auth", "failure", now.Add(-1*time.Minute)))

	time.Sleep(300 * time.Millisecond)
	list, _, _ := fs.List(ctx, findings.Filter{DetectionID: rule.ID})
	if len(list) != 0 {
		t.Errorf("expected no finding while conditions pending, got %d", len(list))
	}
	// But the pending state must be visible.
	states, _ := eng.ListStates(ctx, rule.ID)
	if len(states) != 1 {
		t.Errorf("expected 1 pending correlation state, got %d", len(states))
	}
}

func TestCorrelation_SweepPrunesExpired(t *testing.T) {
	eng, ds, _, _, stop := corrEngine(t)
	defer stop()
	ctx := context.Background()

	rule := &detections.DetectionRule{
		Name:    "corr-sweep",
		Kind:    "correlation",
		Severity: "medium",
		Enabled: true,
		Definition: json.RawMessage(`{"correlation_key":["user"],"window":"1h","conditions":[
			{"id":"a","predicate":{"event_type":"auth"}}]}`),
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Seed an expired state directly.
	_, err := ds.DB().ExecContext(ctx,
		`INSERT INTO correlation_state (rule_id, state_key, current_step, last_event_at, evidence, expires_at)
		 VALUES (?, 'dead', 0, datetime('now','-2 hour'), '[]', datetime('now','-1 hour'))`,
		rule.ID)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A live state.
	if _, err := ds.DB().ExecContext(ctx,
		`INSERT INTO correlation_state (rule_id, state_key, current_step, last_event_at, evidence, expires_at)
		 VALUES (?, 'live', 0, datetime('now'), '[]', datetime('now','+1 hour'))`,
		rule.ID); err != nil {
		t.Fatalf("seed live: %v", err)
	}

	n, err := eng.Sweep(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Errorf("sweep pruned %d, want 1", n)
	}
	states, _ := eng.ListStates(ctx, rule.ID)
	if len(states) != 1 || states[0].StateKey != "live" {
		t.Errorf("after sweep: %+v", states)
	}
}

func TestCorrelation_SuppressedRuleIgnored(t *testing.T) {
	eng, ds, fs, _, stop := corrEngine(t)
	defer stop()
	ctx := context.Background()

	rule := &detections.DetectionRule{
		Name:     "corr-sup",
		Kind:     "correlation",
		Severity: "medium",
		Enabled:  true,
		Definition: json.RawMessage(`{"correlation_key":["user"],"window":"1h","conditions":[
			{"id":"a","predicate":{"event_type":"auth"}}]}`),
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := ds.Suppress(ctx, rule.ID, "analyst", "test"); err != nil {
		t.Fatalf("suppress: %v", err)
	}

	eng.Enqueue(mkEv("hank", "auth", "", time.Now().UTC()))
	time.Sleep(300 * time.Millisecond)
	list, _, _ := fs.List(ctx, findings.Filter{DetectionID: rule.ID})
	if len(list) != 0 {
		t.Errorf("suppressed rule produced findings: %d", len(list))
	}
}
