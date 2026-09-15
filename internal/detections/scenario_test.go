package detections_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"quetzalog/internal/assets"
	"quetzalog/internal/coverage"
	"quetzalog/internal/detections"
	"quetzalog/internal/events"
	"quetzalog/internal/findings"
	"quetzalog/pkg/event"
)

func mitreEvent(t *testing.T, es *events.Store, host, technique, outcome string, ts time.Time) *event.Event {
	t.Helper()
	ev := event.NewEvent()
	ev.Timestamp = ts
	ev.Host = host
	ev.Severity = "high"
	ev.EventType = "security"
	ev.Message = "scenario test"
	ev.Attributes = map[string]any{
		"mitre": map[string]any{
			"attack": []map[string]any{{
				"tactic":     "TA0001",
				"technique":  technique,
				"confidence": 0.9,
				"rule_id":    "test",
			}},
		},
	}
	if outcome != "" {
		ev.Outcome = outcome
	}
	if err := es.Create(context.Background(), ev); err != nil {
		t.Fatalf("create mitre event: %v", err)
	}
	return ev
}

func scenarioFixtures(t *testing.T) (*detections.ScenarioEvaluator, *events.Store, *findings.Store, *assets.Store, *coverage.Store, *sql.DB) {
	t.Helper()
	_, es, db := setup(t)
	fs := findings.NewStore(db)
	as := assets.NewStore(db)
	cov := coverage.NewStore(db)
	evaluator := detections.NewScenarioEvaluator(db, es, fs, as, cov, nil)
	return evaluator, es, fs, as, cov, db
}

func TestScenarios_List(t *testing.T) {
	defs, err := detections.ListScenarios()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(defs) != 3 {
		t.Fatalf("scenarios: %d, want 3", len(defs))
	}
	for _, d := range defs {
		if d.Trigger == "" || len(d.ExpectedTechniques) == 0 {
			t.Errorf("scenario %s incomplete: %+v", d.Name, d)
		}
	}
}

func TestScenario_OpenAndSteps(t *testing.T) {
	evaluator, es, fs, as, cov, db := scenarioFixtures(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Asset + partial telemetry: web.access + net.firewall available, auditd missing.
	a, _, err := as.Observe(ctx, "host", "host:web01", "web01", "linux", now)
	if err != nil {
		t.Fatalf("asset: %v", err)
	}
	if err := cov.Upsert(ctx, coverage.Row{AssetID: a.ID, SourceClass: "web.access", Available: true, LastEvent: &now, EventCount30d: 100}); err != nil {
		t.Fatalf("coverage 1: %v", err)
	}
	if err := cov.Upsert(ctx, coverage.Row{AssetID: a.ID, SourceClass: "net.firewall", Available: true, LastEvent: &now, EventCount30d: 100}); err != nil {
		t.Fatalf("coverage 2: %v", err)
	}

	// Trigger + one observed follow-on; T1136/T1071/T1041 unseen.
	mitreEvent(t, es, "web01", "T1190", "", now.Add(-30*time.Minute))
	mitreEvent(t, es, "web01", "T1059", "", now.Add(-20*time.Minute))

	if _, err := evaluator.Evaluate(ctx, now); err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	runs, err := evaluator.ListRuns(ctx, 10)
	if err != nil {
		t.Fatalf("runs: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("runs: %d, want 1", len(runs))
	}
	run, steps, whatNext, err := evaluator.GetRun(ctx, runs[0].ID)
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	if run.Status != "active" {
		t.Errorf("status: %q", run.Status)
	}
	status := map[string]string{}
	for _, s := range steps {
		status[s.Technique] = s.Status
	}
	if status["T1190"] != "observed" || status["T1059"] != "observed" {
		t.Errorf("observed steps wrong: %v", status)
	}
	if status["T1136"] != "expected" || status["T1071"] != "expected" {
		// Telemetry partially present + young run → expected.
		t.Errorf("pending steps wrong: %v", status)
	}
	if len(whatNext.Expected) != 3 {
		t.Errorf("what_next.expected: %d, want 3", len(whatNext.Expected))
	}
	_ = db
	_ = fs
}

func TestScenario_UnknownWithoutTelemetry(t *testing.T) {
	evaluator, es, _, _, _, _ := scenarioFixtures(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// No asset/telemetry for ghost1 → unseen techniques are "unknown".
	mitreEvent(t, es, "ghost1", "T1190", "", now.Add(-30*time.Minute))

	if _, err := evaluator.Evaluate(ctx, now); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	runs, _ := evaluator.ListRuns(ctx, 10)
	if len(runs) != 1 {
		t.Fatalf("runs: %d", len(runs))
	}
	_, steps, whatNext, err := evaluator.GetRun(ctx, runs[0].ID)
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	status := map[string]string{}
	for _, s := range steps {
		status[s.Technique] = s.Status
	}
	if status["T1190"] != "observed" {
		t.Errorf("T1190: %q", status["T1190"])
	}
	if status["T1136"] != "unknown" {
		t.Errorf("T1136 without telemetry: %q, want unknown", status["T1136"])
	}
	if len(whatNext.Unknown) != 4 {
		t.Errorf("what_next.unknown: %d, want 4", len(whatNext.Unknown))
	}
}

func TestScenario_BlockedStep(t *testing.T) {
	evaluator, es, _, _, _, _ := scenarioFixtures(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Trigger observed; T1059 blocked by firewall.
	mitreEvent(t, es, "web01", "T1190", "", now.Add(-30*time.Minute))
	mitreEvent(t, es, "web01", "T1059", "blocked", now.Add(-20*time.Minute))

	if _, err := evaluator.Evaluate(ctx, now); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	runs, _ := evaluator.ListRuns(ctx, 10)
	if len(runs) != 1 {
		t.Fatalf("runs: %d", len(runs))
	}
	_, steps, _, err := evaluator.GetRun(ctx, runs[0].ID)
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	status := map[string]string{}
	for _, s := range steps {
		status[s.Technique] = s.Status
	}
	if status["T1059"] != "blocked" {
		t.Errorf("T1059: %q, want blocked", status["T1059"])
	}
}

func TestScenario_Completed(t *testing.T) {
	evaluator, es, fs, as, cov, _ := scenarioFixtures(t)
	ctx := context.Background()
	now := time.Now().UTC()

	a, _, err := as.Observe(ctx, "host", "host:web01", "web01", "linux", now)
	if err != nil {
		t.Fatalf("asset: %v", err)
	}
	_ = cov.Upsert(ctx, coverage.Row{AssetID: a.ID, SourceClass: "web.access", Available: true, LastEvent: &now, EventCount30d: 100})

	for _, tech := range []string{"T1190", "T1059", "T1136", "T1071", "T1041"} {
		mitreEvent(t, es, "web01", tech, "", now.Add(-time.Duration(50-len(tech))*time.Minute))
	}

	if _, err := evaluator.Evaluate(ctx, now); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	runs, _ := evaluator.ListRuns(ctx, 10)
	if len(runs) != 1 {
		t.Fatalf("runs: %d", len(runs))
	}
	run, _, _, err := evaluator.GetRun(ctx, runs[0].ID)
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	if run.Status != "completed" {
		t.Errorf("status: %q, want completed", run.Status)
	}
	if run.Risk <= 0 {
		t.Errorf("risk: %v, want > 0", run.Risk)
	}

	// A scenario-completion finding was created.
	list, _, err := fs.List(ctx, findings.Filter{Limit: 10})
	if err != nil {
		t.Fatalf("findings: %v", err)
	}
	found := false
	for _, f := range list {
		if f.DetectionID == "scenario:web_compromise" {
			found = true
		}
	}
	if !found {
		t.Errorf("no scenario completion finding (findings: %d)", len(list))
	}
}
