package response

import (
	"context"
	"strings"
	"testing"

	"quetzalog/internal/database"
	"quetzalog/internal/findings"
	"quetzalog/internal/investigations"
	"quetzalog/internal/risk"
)

func openRegistry(t *testing.T) (*Registry, *findings.Store, *investigations.Store, *risk.EntityRiskStore) {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	fs := findings.NewStore(db)
	is := investigations.NewStore(db)
	rs := risk.NewEntityRiskStore(db)
	return NewRegistry(db, Deps{Findings: fs, Investigations: is, Risk: rs}), fs, is, rs
}

func seedFinding(t *testing.T, fs *findings.Store) *findings.Finding {
	t.Helper()
	f := &findings.Finding{
		Title: "Suspicious", Severity: "high", RiskScore: 35,
		User: "jsmith", Host: "workstation-42", SourceIP: "185.220.101.47",
		Entities: []string{"user:jsmith", "host:workstation-42", "ip:185.220.101.47"},
	}
	if err := fs.Create(context.Background(), f); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return f
}

func TestListAndLookup(t *testing.T) {
	reg, _, _, _ := openRegistry(t)

	actions := reg.List()
	if len(actions) < 5 {
		t.Fatalf("too few actions: %d", len(actions))
	}
	a, ok := reg.Lookup("finding.mark_false_positive")
	if !ok || a.Name == "" {
		t.Errorf("lookup = %+v ok=%v", a, ok)
	}
	if _, ok := reg.Lookup("nope"); ok {
		t.Error("expected unknown action to miss")
	}
}

func TestExecuteFindingActions(t *testing.T) {
	reg, fs, _, _ := openRegistry(t)
	ctx := context.Background()
	f := seedFinding(t, fs)

	// Mark false positive.
	if _, err := reg.Execute(ctx, ExecuteParams{Action: "finding.mark_false_positive", Target: f.ID, User: "analyst"}); err != nil {
		t.Fatalf("mark fp: %v", err)
	}
	got, _ := fs.GetByID(ctx, f.ID)
	if got.Status != "false_positive" {
		t.Errorf("status = %q", got.Status)
	}

	// Assign.
	if _, err := reg.Execute(ctx, ExecuteParams{Action: "finding.assign", Target: f.ID, Owner: "jane", User: "analyst"}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	got, _ = fs.GetByID(ctx, f.ID)
	if got.Owner != "jane" {
		t.Errorf("owner = %q", got.Owner)
	}

	// Add tag twice: second call should not duplicate.
	if _, err := reg.Execute(ctx, ExecuteParams{Action: "finding.add_tag", Target: f.ID, Tag: "triaged"}); err != nil {
		t.Fatalf("add tag: %v", err)
	}
	if _, err := reg.Execute(ctx, ExecuteParams{Action: "finding.add_tag", Target: f.ID, Tag: "triaged"}); err != nil {
		t.Fatalf("add tag again: %v", err)
	}
	got, _ = fs.GetByID(ctx, f.ID)
	count := 0
	for _, tag := range got.Tags {
		if tag == "triaged" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("tag count = %d, want 1 (%v)", count, got.Tags)
	}

	// Increase risk.
	before, _ := fs.GetByID(ctx, f.ID)
	if _, err := reg.Execute(ctx, ExecuteParams{Action: "finding.increase_risk", Target: f.ID, Points: 20}); err != nil {
		t.Fatalf("increase risk: %v", err)
	}
	after, _ := fs.GetByID(ctx, f.ID)
	if after.RiskScore != before.RiskScore+20 {
		t.Errorf("risk = %v, want %v", after.RiskScore, before.RiskScore+20)
	}

	// Validation errors.
	if _, err := reg.Execute(ctx, ExecuteParams{Action: "finding.assign", Target: f.ID}); err == nil {
		t.Error("expected error for missing owner")
	}
	if _, err := reg.Execute(ctx, ExecuteParams{Action: "finding.increase_risk", Target: f.ID, Points: -5}); err == nil {
		t.Error("expected error for negative points")
	}
	if _, err := reg.Execute(ctx, ExecuteParams{Action: "bogus"}); err == nil {
		t.Error("expected error for unknown action")
	}
}

func TestExecuteCreateInvestigation(t *testing.T) {
	reg, fs, is, _ := openRegistry(t)
	ctx := context.Background()
	f := seedFinding(t, fs)

	details, err := reg.Execute(ctx, ExecuteParams{
		Action: "investigation.create", Target: f.ID, Title: "Deep dive", User: "analyst",
	})
	if err != nil {
		t.Fatalf("create investigation: %v", err)
	}
	invID, _ := details["investigation_id"].(string)
	if invID == "" {
		t.Fatalf("details = %v", details)
	}

	got, err := is.GetByID(ctx, invID)
	if err != nil {
		t.Fatalf("get investigation: %v", err)
	}
	if got.Title != "Deep dive" || got.FindingIDs[0] != f.ID {
		t.Errorf("investigation = %+v", got)
	}
}

func TestURLAndWebhookGuards(t *testing.T) {
	reg, _, _, _ := openRegistry(t)
	ctx := context.Background()

	if host, err := validateOutboundURL("ftp://example.com"); err == nil {
		t.Errorf("ftp should be rejected, got %q", host)
	}
	if host, err := validateOutboundURL("https://example.com/x"); err != nil || host != "example.com" {
		t.Errorf("https = %q err=%v", host, err)
	}

	restricted := []string{"http://127.0.0.1/x", "http://10.0.0.1/x", "http://169.254.169.254/x", "http://localhost/x"}
	for _, raw := range restricted {
		host, err := validateOutboundURL(raw)
		if err != nil {
			continue
		}
		if err := denyRestrictedHost(host); err == nil {
			t.Errorf("%s should be restricted", raw)
		}
	}

	// The SSRF guard must refuse loopback webhook destinations; a happy-path
	// delivery is not exercised here because the guard (correctly) makes
	// loopback test servers unreachable through the executor.
	_, err := reg.Execute(ctx, ExecuteParams{Action: "webhook.execute", URL: "http://127.0.0.1:1/x", User: "analyst"})
	if err == nil || !strings.Contains(err.Error(), "restricted") {
		t.Errorf("expected SSRF rejection, got %v", err)
	}
}

func TestHistory(t *testing.T) {
	reg, fs, _, _ := openRegistry(t)
	ctx := context.Background()
	f := seedFinding(t, fs)

	for _, tag := range []string{"one", "two"} {
		if _, err := reg.Execute(ctx, ExecuteParams{Action: "finding.add_tag", Target: f.ID, Tag: tag, User: "analyst"}); err != nil {
			t.Fatal(err)
		}
	}

	hist, err := reg.History(ctx, 10)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(hist) != 2 {
		t.Fatalf("history = %d, want 2", len(hist))
	}
	if !strings.Contains(hist[0].Action, "finding.add_tag") {
		t.Errorf("newest action = %q", hist[0].Action)
	}
	if hist[0].Status != "ok" || hist[0].User != "analyst" {
		t.Errorf("execution = %+v", hist[0])
	}
}
