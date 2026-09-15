package detections_test

import (
	"context"
	"encoding/json"
	"testing"

	"quetzalog/internal/detections"
	"quetzalog/internal/findings"
	"quetzalog/internal/risk"
)

func TestV2_RoundTrip(t *testing.T) {
	ds, _, _ := setup(t)
	ctx := context.Background()

	rule := &detections.DetectionRule{
		Name:              "lateral-spl",
		Query:             "search event_type=admin | stats count by user | where count >= 3",
		Severity:          "high",
		Enabled:           true,
		Kind:              "spl",
		Confidence:        0.75,
		MITRETechniques:   []string{"T1021", "T1078"},
		TacticIDs:         []string{"TA0005"},
		RequiredSources:   []string{"os.windows.security"},
		FalsePositiveNotes: "VPN concentrators generate bursts",
		References:        []string{"https://attack.mitre.org/techniques/T1021"},
		ResponseActions:   []string{"investigation.create"},
		Definition:          json.RawMessage(`{"note":"structured payload"}`),
		Version:           3,
		TestEvents:        []string{"evt-1", "evt-2"},
		MITRETactic:       "TA0005",
		MITRETechnique:    "T1021",
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := ds.GetByID(ctx, rule.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Kind != "spl" {
		t.Errorf("kind: %q", got.Kind)
	}
	if got.Confidence != 0.75 {
		t.Errorf("confidence: %v", got.Confidence)
	}
	if len(got.MITRETechniques) != 2 || got.MITRETechniques[0] != "T1021" {
		t.Errorf("techniques: %v", got.MITRETechniques)
	}
	if len(got.TacticIDs) != 1 || got.TacticIDs[0] != "TA0005" {
		t.Errorf("tactics: %v", got.TacticIDs)
	}
	if len(got.RequiredSources) != 1 {
		t.Errorf("required sources: %v", got.RequiredSources)
	}
	if got.FalsePositiveNotes == "" {
		t.Error("fp notes lost")
	}
	if len(got.References) != 1 {
		t.Errorf("references: %v", got.References)
	}
	if len(got.ResponseActions) != 1 || got.ResponseActions[0] != "investigation.create" {
		t.Errorf("response actions: %v", got.ResponseActions)
	}
	if len(got.Definition) == 0 {
		t.Error("definition lost")
	}
	if got.Version != 3 {
		t.Errorf("version: %d", got.Version)
	}
	if len(got.TestEvents) != 2 {
		t.Errorf("test events: %v", got.TestEvents)
	}
	if got.MITRETactic != "TA0005" || got.MITRETechnique != "T1021" {
		t.Error("legacy single MITRE fields lost")
	}
}

func TestV2_LegacyRuleScansAsThreshold(t *testing.T) {
	ds, _, _ := setup(t)
	ctx := context.Background()

	rule := &detections.DetectionRule{
		Name:     "legacy",
		Query:    "source=auth",
		Severity: "medium",
		Enabled:  true,
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, _ := ds.GetByID(ctx, rule.ID)
	if got.Kind != "threshold" {
		t.Errorf("kind default: %q", got.Kind)
	}
	if got.Version != 1 {
		t.Errorf("version default: %d", got.Version)
	}
}

func TestV2_UpdatePersistsAllColumns(t *testing.T) {
	ds, _, _ := setup(t)
	ctx := context.Background()

	rule := &detections.DetectionRule{
		Name:      "upd",
		Query:     "source=x",
		Severity:  "low",
		Enabled:   true,
		Kind:      "spl",
		Version:   2,
		RiskScore: 10,
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}
	rule.RiskScore = 42
	rule.MITRETactic = "TA0002"
	rule.MITRETechnique = "T1059"
	rule.Tags = []string{"hunting"}
	rule.Confidence = 0.9
	rule.ResponseActions = []string{"block.ip"}
	if err := ds.Update(ctx, rule); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ := ds.GetByID(ctx, rule.ID)
	if got.RiskScore != 42 {
		t.Errorf("risk_score not persisted: %v", got.RiskScore)
	}
	if got.MITRETactic != "TA0002" || got.MITRETechnique != "T1059" {
		t.Errorf("mitre not persisted: %q %q", got.MITRETactic, got.MITRETechnique)
	}
	if len(got.Tags) != 1 || got.Tags[0] != "hunting" {
		t.Errorf("tags not persisted: %v", got.Tags)
	}
	if got.Confidence != 0.9 {
		t.Errorf("confidence not persisted: %v", got.Confidence)
	}
	if len(got.ResponseActions) != 1 {
		t.Errorf("response actions not persisted: %v", got.ResponseActions)
	}
	if got.Kind != "spl" || got.Version != 2 {
		t.Errorf("kind/version not persisted: %q v%d", got.Kind, got.Version)
	}
}

func TestV2_Suppress(t *testing.T) {
	ds, _, _ := setup(t)
	ctx := context.Background()

	rule := &detections.DetectionRule{Name: "sup", Query: "source=x", Severity: "low", Enabled: true}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := ds.Suppress(ctx, rule.ID, "analyst", ""); err == nil {
		t.Error("suppression without reason must fail")
	}
	if err := ds.Suppress(ctx, rule.ID, "analyst", "known noisy rule"); err != nil {
		t.Fatalf("suppress: %v", err)
	}
	got, _ := ds.GetByID(ctx, rule.ID)
	if !got.Suppressed || got.SuppressedBy != "analyst" || got.SuppressReason != "known noisy rule" {
		t.Errorf("suppression state: %+v", got)
	}

	if err := ds.Unsuppress(ctx, rule.ID); err != nil {
		t.Fatalf("unsuppress: %v", err)
	}
	got, _ = ds.GetByID(ctx, rule.ID)
	if got.Suppressed || got.SuppressReason != "" {
		t.Errorf("unsuppression state: %+v", got)
	}
}

func TestSPLRule_CreatesFindings(t *testing.T) {
	ds, es, db := setup(t)
	fs := findings.NewStore(db)
	rs := risk.NewEntityRiskStore(db)
	ctx := context.Background()

	// 5 auth events for alice, 2 for bob.
	for i := 0; i < 5; i++ {
		addEvent(t, es, "auth", "info", "login alice", "alice", "10.0.0.1")
	}
	for i := 0; i < 2; i++ {
		addEvent(t, es, "auth", "info", "login bob", "bob", "10.0.0.2")
	}

	rule := &detections.DetectionRule{
		Name:       "spl-brute",
		Kind:       "spl",
		Query:      "search source=auth | stats count by user",
		Severity:   "high",
		Enabled:    true,
		Threshold:  &detections.Threshold{Count: 3, Window: "1h"},
		RiskScore:  20,
		Confidence: 0.8,
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}

	res, err := ds.RunWithFindings(ctx, rule, es, fs, rs)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Created != 1 {
		t.Fatalf("created %d findings, want 1 (%+v)", res.Created, res)
	}

	f, err := fs.GetByID(ctx, res.Findings[0])
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if f.DetectionID != rule.ID {
		t.Errorf("finding.detection_id: %q", f.DetectionID)
	}
	hasUser := false
	for _, e := range f.Entities {
		if e == "user:alice" {
			hasUser = true
		}
	}
	if !hasUser {
		t.Errorf("finding entities missing user:alice: %v", f.Entities)
	}
	if len(f.Entities) > 1 {
		t.Errorf("bob (count 2) must not be in entities: %v", f.Entities)
	}

	// MarkRun advanced the cursor.
	got, _ := ds.GetByID(ctx, rule.ID)
	if got.LastRunAt.IsZero() {
		t.Error("last_run_at not recorded")
	}

	// Second run: same dedup key → refresh, no new finding.
	res2, err := ds.RunWithFindings(ctx, rule, es, fs, rs)
	if err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if res2.Created != 0 {
		t.Errorf("re-run created %d findings, want 0", res2.Created)
	}
}

func TestSPLRule_BelowThresholdNoFindings(t *testing.T) {
	ds, es, db := setup(t)
	fs := findings.NewStore(db)
	rs := risk.NewEntityRiskStore(db)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		addEvent(t, es, "auth", "info", "login alice", "alice", "10.0.0.1")
	}

	rule := &detections.DetectionRule{
		Name:      "spl-quiet",
		Kind:      "spl",
		Query:     "search source=auth | stats count by user",
		Severity:  "medium",
		Enabled:   true,
		Threshold: &detections.Threshold{Count: 5, Window: "1h"},
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}

	res, err := ds.RunWithFindings(ctx, rule, es, fs, rs)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Created != 0 || len(res.Findings) != 0 {
		t.Errorf("expected no findings, got %+v", res)
	}
}

func TestSPLRule_NoThresholdEveryRowFinds(t *testing.T) {
	ds, es, db := setup(t)
	fs := findings.NewStore(db)
	rs := risk.NewEntityRiskStore(db)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		addEvent(t, es, "auth", "info", "login alice", "alice", "10.0.0.1")
	}

	rule := &detections.DetectionRule{
		Name:     "spl-any",
		Kind:     "spl",
		Query:    "search source=auth | stats count by user",
		Severity: "medium",
		Enabled:  true,
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}

	res, err := ds.RunWithFindings(ctx, rule, es, fs, rs)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Created != 1 {
		t.Errorf("created %d findings, want 1 (%+v)", res.Created, res)
	}
}

func TestSuppressedRuleSkipsRun(t *testing.T) {
	ds, es, db := setup(t)
	fs := findings.NewStore(db)
	rs := risk.NewEntityRiskStore(db)
	ctx := context.Background()

	addEvent(t, es, "auth", "info", "login alice", "alice", "10.0.0.1")

	rule := &detections.DetectionRule{
		Name:    "sup-run",
		Kind:    "spl",
		Query:   "search source=auth | stats count by user",
		Severity: "medium",
		Enabled: true,
	}
	if err := ds.Create(ctx, rule); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := ds.Suppress(ctx, rule.ID, "a", "noisy"); err != nil {
		t.Fatalf("suppress: %v", err)
	}

	res, err := ds.RunWithFindings(ctx, rule, es, fs, rs)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Created != 0 || res.Total != 0 {
		t.Errorf("suppressed rule produced output: %+v", res)
	}
}
