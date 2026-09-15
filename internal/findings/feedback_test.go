package findings_test

import (
	"context"
	"testing"

	"quetzalog/internal/database"
	"quetzalog/internal/findings"
)

func feedbackSetup(t *testing.T) (*findings.Store, context.Context) {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return findings.NewStore(db), context.Background()
}

func TestFeedback_Validation(t *testing.T) {
	s, ctx := feedbackSetup(t)

	fb := &findings.Feedback{FindingID: "f1", Label: "false_positive", Analyst: "a"}
	if err := s.AddFeedback(ctx, fb); err == nil {
		t.Error("false_positive without reason must fail")
	}
	fb.Reason = "VPN concentrator noise"
	if err := s.AddFeedback(ctx, fb); err != nil {
		t.Fatalf("valid fp feedback rejected: %v", err)
	}

	// Replace the same analyst's label.
	fb2 := &findings.Feedback{FindingID: "f1", Label: "true_positive", Reason: "re-verified", Analyst: "a"}
	if err := s.AddFeedback(ctx, fb2); err != nil {
		t.Fatalf("replace: %v", err)
	}
	got, _ := s.FeedbackForFinding(ctx, "f1")
	if len(got) != 1 || got[0].Label != "true_positive" {
		t.Errorf("replace did not take effect: %+v", got)
	}

	// Invalid label.
	if err := s.AddFeedback(ctx, &findings.Feedback{FindingID: "f1", Label: "surely", Analyst: "a"}); err == nil {
		t.Error("invalid label accepted")
	}
	// Missing analyst.
	if err := s.AddFeedback(ctx, &findings.Feedback{FindingID: "f1", Label: "benign"}); err == nil {
		t.Error("missing analyst accepted")
	}
}

func TestFeedback_DetectionStats(t *testing.T) {
	s, ctx := feedbackSetup(t)

	// Two findings from detection "d1": one FP, one TP; one from "d2": benign.
	for _, f := range []findings.Finding{{ID: "f1", Title: "a", Severity: "high", DetectionID: "d1"}, {ID: "f2", Title: "b", Severity: "medium", DetectionID: "d1"}, {ID: "f3", Title: "c", Severity: "low", DetectionID: "d2"}} {
		if err := s.Create(ctx, &f); err != nil {
			t.Fatalf("create finding %s: %v", f.ID, err)
		}
	}
	cases := []findings.Feedback{
		{FindingID: "f1", Label: "false_positive", Reason: "noise", Analyst: "a"},
		{FindingID: "f2", Label: "true_positive", Analyst: "b"},
		{FindingID: "f3", Label: "benign", Analyst: "c"},
	}
	for i := range cases {
		if err := s.AddFeedback(ctx, &cases[i]); err != nil {
			t.Fatalf("feedback %d: %v", i, err)
		}
	}

	stats, err := s.FeedbackStatsForDetection(ctx, "d1")
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Total != 2 {
		t.Errorf("total: %d", stats.Total)
	}
	if stats.ByLabel["false_positive"] != 1 || stats.ByLabel["true_positive"] != 1 {
		t.Errorf("by label: %v", stats.ByLabel)
	}
	if stats.FalsePosRate != 0.5 {
		t.Errorf("fp rate: %v", stats.FalsePosRate)
	}

	stats2, _ := s.FeedbackStatsForDetection(ctx, "d2")
	if stats2.Total != 1 || stats2.ByLabel["benign"] != 1 {
		t.Errorf("d2 stats: %+v", stats2)
	}
}
