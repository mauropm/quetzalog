package detections_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"quetzalog/internal/detections"
	"quetzalog/internal/findings"
	"quetzalog/internal/risk"
	"quetzalog/pkg/event"
)

func authEvAt(user string, ts time.Time, attrs map[string]any) *event.Event {
	ev := event.NewEvent()
	ev.Timestamp = ts
	ev.User = user
	ev.EventType = "authentication"
	ev.Severity = "info"
	ev.Message = "auth"
	ev.Attributes = attrs
	return ev
}

func TestBaseline_TrustedAndScored(t *testing.T) {
	ds, es, db := setup(t)
	fs := findings.NewStore(db)
	rs := risk.NewEntityRiskStore(db)
	updater := detections.NewBaselineUpdater(db, nil)
	eng := detections.NewBehavioralEngine(db, ds, fs, rs, nil)
	eng.Start(1)
	defer eng.Stop()
	ctx := context.Background()
	now := time.Now().UTC()

	// 40 distinct hourly buckets for alice (trusted baseline: mean 1/h).
	for i := 0; i < 40; i++ {
		ts := now.Add(-time.Duration(i+1) * time.Hour)
		if err := es.Create(ctx, authEvAt("alice", ts, nil)); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	if err := updater.UpdateAll(ctx, now); err != nil {
		t.Fatalf("update: %v", err)
	}

	var count int
	if err := db.QueryRowContext(ctx,
		`SELECT sample_count FROM baselines WHERE entity_type='user' AND entity_value='alice' AND feature='login_count_per_hour'`).Scan(&count); err != nil {
		t.Fatalf("baseline missing: %v", err)
	}
	if count < 20 {
		t.Fatalf("sample_count %d, want >= 20", count)
	}

	rule := &detections.DetectionRule{
		Name:     "stat-login",
		Kind:     "statistical",
		Severity: "high",
		Enabled:  true,
		RiskScore: 20,
		Definition: json.RawMessage(`{"feature":"login_count_per_hour","entity":"user"}`),
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create rule: %v", err)
	}

	// Spike: 6 logins in the current hour (baseline mean 1, stddev 0 → z=4).
	for i := 0; i < 6; i++ {
		if err := es.Create(ctx, authEvAt("alice", time.Now().UTC(), nil)); err != nil {
			t.Fatalf("spike %d: %v", i, err)
		}
	}
	eng.Enqueue(authEvAt("alice", time.Now().UTC(), nil))

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM anomalies WHERE entity_value='alice' AND feature='login_count_per_hour'`).Scan(&n); err == nil && n > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	var n int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM anomalies WHERE entity_value='alice'`).Scan(&n)
	if n == 0 {
		t.Fatal("no anomaly recorded")
	}
	// Risk contribution recorded (top-3 gate passes with a single feature).
	var points float64
	err := db.QueryRowContext(ctx,
		`SELECT points FROM risk_contributions WHERE entity_value='alice' AND source_type='anomaly'`).Scan(&points)
	if err != nil {
		t.Fatalf("no anomaly risk contribution: %v", err)
	}
	if points != 15 {
		t.Errorf("anomaly points: %v, want 15 (z>=4 band)", points)
	}
}

func TestBaseline_NotTrustedNoScore(t *testing.T) {
	ds, es, db := setup(t)
	fs := findings.NewStore(db)
	rs := risk.NewEntityRiskStore(db)
	updater := detections.NewBaselineUpdater(db, nil)
	eng := detections.NewBehavioralEngine(db, ds, fs, rs, nil)
	eng.Start(1)
	defer eng.Stop()
	ctx := context.Background()
	now := time.Now().UTC()

	// Only 5 hourly buckets: below the 20-sample minimum.
	for i := 0; i < 5; i++ {
		if err := es.Create(ctx, authEvAt("bob", now.Add(-time.Duration(i+1)*time.Hour), nil)); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	if err := updater.UpdateAll(ctx, now); err != nil {
		t.Fatalf("update: %v", err)
	}

	rule := &detections.DetectionRule{
		Name:     "stat-bob",
		Kind:     "statistical",
		Severity: "high",
		Enabled:  true,
		Definition: json.RawMessage(`{"feature":"login_count_per_hour","entity":"user"}`),
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}

	for i := 0; i < 8; i++ {
		if err := es.Create(ctx, authEvAt("bob", time.Now().UTC(), nil)); err != nil {
			t.Fatalf("spike: %v", err)
		}
	}
	eng.Enqueue(authEvAt("bob", time.Now().UTC(), nil))
	time.Sleep(300 * time.Millisecond)

	var n int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM anomalies WHERE entity_value='bob'`).Scan(&n)
	if n != 0 {
		t.Errorf("untrusted baseline produced %d anomalies, want 0", n)
	}
}

func TestBehavioral_FirstSeenDestination(t *testing.T) {
	ds, es, db := setup(t)
	fs := findings.NewStore(db)
	rs := risk.NewEntityRiskStore(db)
	eng := detections.NewBehavioralEngine(db, ds, fs, rs, nil)
	eng.Start(1)
	defer eng.Stop()
	ctx := context.Background()

	// A brand-new destination entity.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO entities (id, type, value, first_seen, last_seen, count)
		 VALUES ('ip-new-1', 'ip', '9.9.9.9', datetime('now'), datetime('now'), 1)`); err != nil {
		t.Fatalf("seed entity: %v", err)
	}

	rule := &detections.DetectionRule{
		Name:     "beh-newdst",
		Kind:     "behavioral",
		Severity: "medium",
		Enabled:  true,
		Definition: json.RawMessage(`{"pattern":"first-seen-destination"}`),
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}

	ev := event.NewEvent()
	ev.Timestamp = time.Now().UTC()
	ev.User = "carol"
	ev.DestinationIP = "9.9.9.9"
	ev.EventType = "network"
	_ = es.Create(ctx, ev)
	eng.Enqueue(ev)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM anomalies WHERE feature LIKE 'first_seen_destination%'`).Scan(&n); err == nil && n > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	var n int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM anomalies WHERE feature LIKE 'first_seen_destination%'`).Scan(&n)
	if n != 1 {
		t.Fatalf("novelty anomalies: %d, want 1", n)
	}
	var points float64
	err := db.QueryRowContext(ctx,
		`SELECT points FROM risk_contributions WHERE entity_value='carol' AND source_type='anomaly'`).Scan(&points)
	if err != nil {
		t.Fatalf("no novelty risk contribution: %v", err)
	}
	if points != 5 {
		t.Errorf("novelty points: %v, want 5", points)
	}

	// Second event to the same destination: deduped within 24h.
	eng.Enqueue(ev)
	time.Sleep(300 * time.Millisecond)
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM anomalies WHERE feature LIKE 'first_seen_destination%'`).Scan(&n)
	if n != 1 {
		t.Errorf("novelty not deduped: %d", n)
	}
}

func TestBehavioral_ImpossibleTravel(t *testing.T) {
	ds, es, db := setup(t)
	fs := findings.NewStore(db)
	rs := risk.NewEntityRiskStore(db)
	eng := detections.NewBehavioralEngine(db, ds, fs, rs, nil)
	eng.Start(1)
	defer eng.Stop()
	ctx := context.Background()
	now := time.Now().UTC()

	rule := &detections.DetectionRule{
		Name:     "beh-travel",
		Kind:     "behavioral",
		Severity: "high",
		Enabled:  true,
		Definition: json.RawMessage(`{"pattern":"impossible-travel"}`),
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Previous login: Madrid. Current login: Tokyo, 3h later (~11000 km/h).
	prev := authEvAt("dave", now.Add(-3*time.Hour), map[string]any{"geo.latitude": 40.4, "geo.longitude": -3.7})
	_ = es.Create(ctx, prev)
	cur := authEvAt("dave", now, map[string]any{"geo.latitude": 35.6, "geo.longitude": 139.7})
	_ = es.Create(ctx, cur)

	eng.Enqueue(cur)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM anomalies WHERE feature='impossible_travel'`).Scan(&n); err == nil && n > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	var points float64
	err := db.QueryRowContext(ctx,
		`SELECT points FROM risk_contributions
		 WHERE entity_value='dave' AND source_type='anomaly'`).Scan(&points)
	if err != nil {
		t.Fatalf("no travel contribution: %v", err)
	}
	if points != 15 {
		t.Errorf("travel points: %v, want 15", points)
	}
	var suppressed string
	_ = db.QueryRowContext(ctx,
		`SELECT COALESCE(suppressed_reason,'') FROM anomalies WHERE feature='impossible_travel' AND entity_value='dave'`).Scan(&suppressed)
	if suppressed != "" {
		t.Errorf("travel not suppressed, reason: %q", suppressed)
	}
}

func TestBehavioral_ImpossibleTravelVPNSuppressed(t *testing.T) {
	ds, es, db := setup(t)
	fs := findings.NewStore(db)
	rs := risk.NewEntityRiskStore(db)
	eng := detections.NewBehavioralEngine(db, ds, fs, rs, nil)
	eng.Start(1)
	defer eng.Stop()
	ctx := context.Background()
	now := time.Now().UTC()

	rule := &detections.DetectionRule{
		Name:     "beh-travel-vpn",
		Kind:     "behavioral",
		Severity: "high",
		Enabled:  true,
		Definition: json.RawMessage(`{"pattern":"impossible-travel"}`),
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}

	prev := authEvAt("erin", now.Add(-3*time.Hour), map[string]any{"geo.latitude": 40.4, "geo.longitude": -3.7})
	_ = es.Create(ctx, prev)
	// Same jump, but the path traverses VPN infrastructure → 0 points, recorded.
	cur := authEvAt("erin", now, map[string]any{"geo.latitude": 35.6, "geo.longitude": 139.7, "network.vpn": true})
	_ = es.Create(ctx, cur)

	eng.Enqueue(cur)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM anomalies WHERE feature='impossible_travel' AND entity_value='erin'`).Scan(&n); err == nil && n > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	var points float64
	err := db.QueryRowContext(ctx,
		`SELECT points FROM risk_contributions
		 WHERE entity_value='erin' AND source_type='anomaly'`).Scan(&points)
	if err != nil {
		t.Fatalf("no travel contribution: %v", err)
	}
	if points != 0 {
		t.Errorf("suppressed travel points: %v, want 0", points)
	}
	var suppressed string
	_ = db.QueryRowContext(ctx,
		`SELECT COALESCE(suppressed_reason,'') FROM anomalies WHERE feature='impossible_travel' AND entity_value='erin'`).Scan(&suppressed)
	if suppressed != "vpn" {
		t.Errorf("suppressed_reason: %q, want vpn", suppressed)
	}
}

func TestZPointsBands(t *testing.T) {
	cases := []struct {
		z    float64
		want float64
	}{
		{1.5, 0}, {2, 5}, {2.9, 5}, {3, 10}, {3.9, 10}, {4, 15}, {10, 15},
	}
	for _, c := range cases {
		if got := detections.ZPoints(c.z); got != c.want {
			t.Errorf("ZPoints(%v) = %v, want %v", c.z, got, c.want)
		}
	}
}
