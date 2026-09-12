package risk

import (
	"context"
	"testing"

	"quetzalog/internal/database"
	"quetzalog/internal/findings"
)

func openRiskStore(t *testing.T) (*EntityRiskStore, *findings.Store) {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewEntityRiskStore(db), findings.NewStore(db)
}

func TestRecordAndGet(t *testing.T) {
	s, _ := openRiskStore(t)
	ctx := context.Background()

	if err := s.Record(ctx, Contribution{EntityType: "user", EntityValue: "jsmith", Points: 35, SourceType: "finding", SourceID: "f1"}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := s.Record(ctx, Contribution{EntityType: "user", EntityValue: "jsmith", Points: 40, SourceType: "finding", SourceID: "f2"}); err != nil {
		t.Fatalf("record: %v", err)
	}

	er, err := s.Get(ctx, "user", "jsmith")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if er == nil || er.RiskScore != 75 {
		t.Errorf("risk = %+v, want 75", er)
	}

	none, err := s.Get(ctx, "user", "nobody")
	if err != nil || none != nil {
		t.Errorf("expected nil risk, got %+v err=%v", none, err)
	}

	if err := s.Record(ctx, Contribution{EntityValue: "x", Points: 1}); err == nil {
		t.Error("expected error for missing entity type")
	}
}

func TestTopAndAtRisk(t *testing.T) {
	s, fstore := openRiskStore(t)
	ctx := context.Background()

	// Two open findings touching bob and one resolved finding touching alice.
	if err := fstore.Create(ctx, &findings.Finding{Title: "a", User: "bob", Status: "new"}); err != nil {
		t.Fatal(err)
	}
	if err := fstore.Create(ctx, &findings.Finding{Title: "b", User: "bob", Status: "investigating"}); err != nil {
		t.Fatal(err)
	}
	if err := fstore.Create(ctx, &findings.Finding{Title: "c", User: "alice", Status: "resolved"}); err != nil {
		t.Fatal(err)
	}

	for _, pts := range []float64{50, 10} {
		if err := s.Record(ctx, Contribution{EntityType: "user", EntityValue: "bob", Points: pts}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Record(ctx, Contribution{EntityType: "user", EntityValue: "alice", Points: 90}); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(ctx, Contribution{EntityType: "host", EntityValue: "web01", Points: 5}); err != nil {
		t.Fatal(err)
	}

	top, err := s.Top(ctx, "user", 10)
	if err != nil {
		t.Fatalf("top: %v", err)
	}
	if len(top) != 2 || top[0].Value != "alice" {
		t.Errorf("top = %+v", top)
	}
	// alice has 0 open findings (resolved); bob has 2.
	for _, e := range top {
		if e.Value == "bob" && e.Findings != 2 {
			t.Errorf("bob findings = %d, want 2", e.Findings)
		}
	}

	if n, err := s.AtRisk(ctx, "user"); err != nil || n != 2 {
		t.Errorf("at-risk users = %d err=%v, want 2", n, err)
	}

	if _, err := s.Top(ctx, "process", 10); err == nil {
		t.Error("expected error for unsupported entity type")
	}
}

func TestContributions(t *testing.T) {
	s, _ := openRiskStore(t)
	ctx := context.Background()

	for i, desc := range []string{"first", "second"} {
		if err := s.Record(ctx, Contribution{
			EntityType: "ip", EntityValue: "1.2.3.4", Points: 10,
			SourceType: "finding", SourceID: "f1", Description: desc, EventID: "e" + string(rune('0'+i)),
		}); err != nil {
			t.Fatal(err)
		}
	}

	contribs, err := s.Contributions(ctx, "ip", "1.2.3.4", 10)
	if err != nil {
		t.Fatalf("contributions: %v", err)
	}
	if len(contribs) != 2 {
		t.Fatalf("contributions = %d, want 2", len(contribs))
	}
	// Newest first.
	if contribs[0].Description != "second" {
		t.Errorf("newest first expected, got %+v", contribs[0])
	}
	if contribs[0].EventID != "e1" || contribs[0].SourceID != "f1" {
		t.Errorf("contribution fields = %+v", contribs[0])
	}
}
