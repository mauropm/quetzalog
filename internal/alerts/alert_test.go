package alerts_test

import (
	"context"
	"database/sql"
	"testing"

	"quetzalog/internal/alerts"
	"quetzalog/internal/database"
)

func setup(t *testing.T) (*alerts.Store, *sql.DB) {
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
	return alerts.NewStore(db), db
}

func TestAlertLifecycle(t *testing.T) {
	s, _ := setup(t)
	ctx := context.Background()

	a := &alerts.Alert{
		DetectionID: "det-1",
		Severity:    "high",
		Title:       "Brute force",
		Description: "many failures",
		Status:      "new",
	}
	if err := s.Create(ctx, a); err != nil {
		t.Fatalf("create: %v", err)
	}
	if a.ID == "" {
		t.Fatal("id not generated")
	}

	got, err := s.GetByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Title != "Brute force" || got.Status != "new" {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
	if got.Notes == nil {
		got.Notes = []alerts.Note{}
	}

	note := &alerts.Note{AlertID: a.ID, Author: "analyst", Content: "looking into it"}
	if err := s.AddNote(ctx, note); err != nil {
		t.Fatalf("AddNote failed (notes table must exist in schema): %v", err)
	}
	got, err = s.GetByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("get after note: %v", err)
	}
	if len(got.Notes) != 1 || got.Notes[0].Content != "looking into it" {
		t.Errorf("notes did not round-trip: %#v", got.Notes)
	}

	for _, st := range []string{"acknowledged", "investigating", "resolved", "false_positive"} {
		if err := s.UpdateStatus(ctx, a.ID, st); err != nil {
			t.Fatalf("update status %s: %v", st, err)
		}
		got, _ := s.GetByID(ctx, a.ID)
		if got.Status != st {
			t.Errorf("status %s did not persist", st)
		}
	}
}

func TestAlertDefaults(t *testing.T) {
	s, _ := setup(t)
	a := &alerts.Alert{DetectionID: "d", Title: "t"}
	if err := s.Create(context.Background(), a); err != nil {
		t.Fatalf("create: %v", err)
	}
	if a.Status != "new" {
		t.Errorf("default status: %q", a.Status)
	}
	got, err := s.GetByID(context.Background(), a.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Severity == "" {
		t.Errorf("empty severity should default to a valid level per API.md (medium), got %q", got.Severity)
	}
}

func TestAlertListFilters(t *testing.T) {
	s, _ := setup(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		a := &alerts.Alert{DetectionID: "d", Severity: "high", Title: "hi", Status: "new"}
		_ = s.Create(ctx, a)
	}
	for i := 0; i < 3; i++ {
		a := &alerts.Alert{DetectionID: "d", Severity: "low", Title: "lo", Status: "resolved"}
		_ = s.Create(ctx, a)
	}
	hi, err := s.List(ctx, alerts.Filter{Severity: "high"})
	if err != nil || len(hi) != 5 {
		t.Errorf("severity filter: %d err %v", len(hi), err)
	}
	res, err := s.List(ctx, alerts.Filter{Status: "resolved"})
	if err != nil || len(res) != 3 {
		t.Errorf("status filter: %d err %v", len(res), err)
	}
	paged, err := s.List(ctx, alerts.Filter{Limit: 2, Offset: 6})
	if err != nil || len(paged) != 2 {
		t.Errorf("paging: %d err %v", len(paged), err)
	}
}

func TestAlertGetNotFound(t *testing.T) {
	s, _ := setup(t)
	if _, err := s.GetByID(context.Background(), "nope"); err == nil {
		t.Error("want not-found error")
	}
	if _, err := s.GetByID(context.Background(), ""); err == nil {
		t.Error("want error for empty id")
	}
}
