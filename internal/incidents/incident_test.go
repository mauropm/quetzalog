package incidents_test

import (
	"context"
	"database/sql"
	"testing"

	"quetzalog/internal/database"
	"quetzalog/internal/incidents"
)

func setup(t *testing.T) (*incidents.Store, *sql.DB) {
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
	return incidents.NewStore(db), db
}

func TestIncidentLifecycleWithLinks(t *testing.T) {
	s, _ := setup(t)
	ctx := context.Background()

	inc := &incidents.Incident{
		Title:       "Ransomware sweep",
		Description: "hosts encrypting",
		AlertIDs:    []string{"a1", "a2"},
		EventIDs:    []string{"e1"},
	}
	if err := s.Create(ctx, inc); err != nil {
		t.Fatalf("Create (link columns must exist in schema): %v", err)
	}
	if inc.ID == "" {
		t.Fatal("id missing")
	}
	got, err := s.GetByID(ctx, inc.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Title != "Ransomware sweep" {
		t.Errorf("title mismatch %q", got.Title)
	}
	if len(got.AlertIDs) != 2 || got.AlertIDs[0] != "a1" {
		t.Errorf("alert ids lost: %v", got.AlertIDs)
	}
	if len(got.EventIDs) != 1 {
		t.Errorf("event ids lost: %v", got.EventIDs)
	}

	if err := s.AddAlerts(ctx, inc.ID, []string{"a2", "a3"}); err != nil {
		t.Fatalf("AddAlerts: %v", err)
	}
	got, _ = s.GetByID(ctx, inc.ID)
	if len(got.AlertIDs) != 3 {
		t.Errorf("dedup/merge failed: %v", got.AlertIDs)
	}

	if err := s.UpdateStatus(ctx, inc.ID, "investigating"); err != nil {
		t.Fatalf("status: %v", err)
	}
	got, _ = s.GetByID(ctx, inc.ID)
	if got.Status != "investigating" {
		t.Errorf("status not persisted: %q", got.Status)
	}
}

func TestIncidentDefaults(t *testing.T) {
	s, _ := setup(t)
	inc := &incidents.Incident{Title: "bare"}
	if err := s.Create(context.Background(), inc); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetByID(context.Background(), inc.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status == "" {
		t.Errorf("empty status should default to open per API.md")
	}
	if got.Severity == "" {
		t.Errorf("empty severity should default to medium per API.md")
	}
}

func TestIncidentListFiltersAndPaging(t *testing.T) {
	s, _ := setup(t)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		_ = s.Create(ctx, &incidents.Incident{Title: "hi", Severity: "high", Status: "open"})
	}
	for i := 0; i < 2; i++ {
		_ = s.Create(ctx, &incidents.Incident{Title: "lo", Severity: "low", Status: "resolved"})
	}
	hi, err := s.List(ctx, incidents.Filter{Severity: "high"})
	if err != nil || len(hi) != 4 {
		t.Errorf("severity filter %d %v", len(hi), err)
	}
	pg, err := s.List(ctx, incidents.Filter{Limit: 3})
	if err != nil || len(pg) != 3 {
		t.Errorf("limit %d %v", len(pg), err)
	}
}
