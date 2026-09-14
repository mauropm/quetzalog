package ai

import (
	"context"
	"database/sql"
	"testing"

	"quetzalog/internal/database"
)

func openAITestDB(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewStore(db), db
}

func TestStoreLifecycle(t *testing.T) {
	s, _ := openAITestDB(t)
	ctx := context.Background()

	row, err := s.CreateOrReset(ctx, CreateArgs{
		FindingID: "finding-1", Provider: "ollama", Model: "qwen3.8",
		PromptVersion: PromptVersion, PromptHash: PromptHash(), ContextJSON: `{"finding":{"id":"finding-1"}}`,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if row.Status != "analyzing" {
		t.Fatalf("status: %q", row.Status)
	}

	// Complete with a validated analysis.
	a, err := ValidateAnalysis([]byte(validAnalysisJSON()))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, row.ID, a); err != nil {
		t.Fatalf("complete: %v", err)
	}
	got, _, _, err := s.Get(ctx, row.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != "analyzed" || got.Severity != "high" || got.RecommendationType != "investigate" {
		t.Errorf("row after complete: %+v", got)
	}

	// Approve.
	if err := s.Decide(ctx, row.ID, "approve", "", "analyst"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	got, _, _, _ = s.Get(ctx, row.ID)
	if got.Status != "approved" || got.Decision != "approve" || got.DecidedBy != "analyst" {
		t.Errorf("row after approve: %+v", got)
	}

	// Dismissal of an already-decided analysis must fail.
	if err := s.Decide(ctx, row.ID, "dismiss", "", "analyst"); err == nil {
		t.Error("decide on decided analysis must fail")
	}
}

func TestStoreDeduplicationOneAnalysisPerFinding(t *testing.T) {
	s, _ := openAITestDB(t)
	ctx := context.Background()

	r1, err := s.CreateOrReset(ctx, CreateArgs{FindingID: "f1", Provider: "p", Model: "m", ContextJSON: "{}"})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.CreateOrReset(ctx, CreateArgs{FindingID: "f1", Provider: "p", Model: "m", ContextJSON: "{}"})
	if err != nil {
		t.Fatal(err)
	}
	if r1.ID != r2.ID {
		t.Errorf("re-analysis of the same finding must reuse the row (dedup): %s vs %s", r1.ID, r2.ID)
	}
	// The decision is cleared on reset.
	if err := s.Decide(ctx, r1.ID, "approve", "", "x"); err == nil {
		// row was analyzing; approve must fail
		t.Error("approve on analyzing row must fail")
	}
	_, total, err := s.List(ctx, ListFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Errorf("expected exactly 1 analysis for the finding, got %d", total)
	}
}

func TestStoreFailAndRetry(t *testing.T) {
	s, _ := openAITestDB(t)
	ctx := context.Background()

	row, _ := s.CreateOrReset(ctx, CreateArgs{FindingID: "f1", Provider: "p", Model: "m", ContextJSON: "{}"})
	if err := s.Fail(ctx, row.ID, "provider timeout"); err != nil {
		t.Fatalf("fail: %v", err)
	}
	got, _, _, _ := s.Get(ctx, row.ID)
	if got.Status != "failed" || got.Error != "provider timeout" {
		t.Errorf("failed row: %+v", got)
	}

	// A failed analysis can be re-run (overwrites in place).
	row2, err := s.CreateOrReset(ctx, CreateArgs{FindingID: "f1", Provider: "p", Model: "m", ContextJSON: "{}"})
	if err != nil {
		t.Fatal(err)
	}
	if row2.ID != row.ID || row2.Status != "analyzing" {
		t.Errorf("retry row: %+v", row2)
	}
}

func TestStoreFailedAnalysisCarriesNoRecommendation(t *testing.T) {
	s, _ := openAITestDB(t)
	ctx := context.Background()

	row, _ := s.CreateOrReset(ctx, CreateArgs{FindingID: "f1", Provider: "p", Model: "m", ContextJSON: "{}"})
	_ = s.Fail(ctx, row.ID, "invalid model response: no JSON object in model output")

	got, a, _, err := s.Get(ctx, row.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "failed" {
		t.Errorf("status: %q", got.Status)
	}
	if a != nil {
		t.Errorf("failed analysis must not carry an analysis payload, got %+v", a)
	}
	if got.RecommendationType != "" {
		t.Errorf("failed analysis must not carry a recommendation, got %q", got.RecommendationType)
	}
}

func TestStoreListFilters(t *testing.T) {
	s, _ := openAITestDB(t)
	ctx := context.Background()

	seed := []struct {
		finding string
		sev     string
		decide  string
	}{
		{"f1", "high", "approve"},
		{"f2", "medium", ""},
		{"f3", "critical", "dismiss"},
	}
	for _, x := range seed {
		row, err := s.CreateOrReset(ctx, CreateArgs{FindingID: x.finding, Provider: "p", Model: "m", ContextJSON: "{}"})
		if err != nil {
			t.Fatal(err)
		}
		a := &Analysis{
			Title: "t", Summary: "s", Severity: x.sev, Confidence: 0.5,
			WhatIsHappening: "w", WhyItMatters: "y",
			RecommendedAction: RecommendedAction{Type: "investigate", Description: "d", Risk: "low"},
		}
		if err := s.Complete(ctx, row.ID, a); err != nil {
			t.Fatal(err)
		}
		if x.decide != "" {
			decision := "approve"
			if x.decide == "dismiss" {
				decision = "dismiss"
			}
			if err := s.Decide(ctx, row.ID, decision, "reason", "analyst"); err != nil {
				t.Fatal(err)
			}
		}
	}

	rows, total, err := s.List(ctx, ListFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(rows) != 3 {
		t.Fatalf("total=%d rows=%d", total, len(rows))
	}
	if rows[0].FindingTitle == "" {
		// no finding rows exist; title is empty — acceptable
		_ = rows[0]
	}

	_, total, _ = s.List(ctx, ListFilter{Status: "approved"})
	if total != 1 {
		t.Errorf("approved filter: %d", total)
	}
	_, total, _ = s.List(ctx, ListFilter{Severity: "critical"})
	if total != 1 {
		t.Errorf("severity filter: %d", total)
	}
}

func TestStoreStats(t *testing.T) {
	s, _ := openAITestDB(t)
	ctx := context.Background()

	r1, _ := s.CreateOrReset(ctx, CreateArgs{FindingID: "f1", ContextJSON: "{}"})
	a, _ := ValidateAnalysis([]byte(validAnalysisJSON()))
	_ = s.Complete(ctx, r1.ID, a)
	if _, err := s.CreateOrReset(ctx, CreateArgs{FindingID: "f2", ContextJSON: "{}"}); err != nil {
		t.Fatal(err)
	}

	stats, err := s.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats["analyzed"] != 1 || stats["analyzing"] != 1 {
		t.Errorf("stats: %+v", stats)
	}
}
