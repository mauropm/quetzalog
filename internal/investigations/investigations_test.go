package investigations

import (
	"context"
	"testing"

	"quetzalog/internal/database"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewStore(db)
}

func TestCreateAndGet(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	in := &Investigation{Title: "Compromised host", Severity: "critical", Assignee: "analyst"}
	if err := s.Create(ctx, in); err != nil {
		t.Fatalf("create: %v", err)
	}
	if in.Status != "new" {
		t.Errorf("status = %q, want new", in.Status)
	}

	got, err := s.GetByID(ctx, in.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Title != "Compromised host" || got.Assignee != "analyst" {
		t.Errorf("got = %+v", got)
	}
	if got.EventIDs == nil || got.Queries == nil || got.Entities == nil {
		t.Error("list fields should be non-nil slices")
	}

	if _, err := s.GetByID(ctx, "missing"); err == nil {
		t.Error("expected not-found error")
	}
}

func TestUpdateAndStatus(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	in := &Investigation{Title: "x"}
	if err := s.Create(ctx, in); err != nil {
		t.Fatal(err)
	}

	for _, st := range []string{"in_progress", "contained", "resolved"} {
		if err := s.UpdateStatus(ctx, in.ID, st); err != nil {
			t.Fatalf("status %s: %v", st, err)
		}
	}
	if err := s.UpdateStatus(ctx, in.ID, "bogus"); err == nil {
		t.Error("expected invalid status error")
	}

	// Update persists the full struct, so patch from the current state to
	// preserve the lifecycle status set above.
	current, err := s.GetByID(ctx, in.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	current.Severity = "high"
	current.Description = "more detail"
	if err := s.Update(ctx, current); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ := s.GetByID(ctx, in.ID)
	if got.Severity != "high" || got.Description != "more detail" || got.Status != "resolved" {
		t.Errorf("got = %+v", got)
	}
}

func TestMergeListsAndCaps(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	in := &Investigation{Title: "x"}
	s.Create(ctx, in)

	if err := s.AddEvents(ctx, in.ID, []string{"e1", "e2", "e1"}); err != nil {
		t.Fatalf("add events: %v", err)
	}
	if err := s.AddEvents(ctx, in.ID, []string{"e3"}); err != nil {
		t.Fatalf("add more: %v", err)
	}
	got, _ := s.GetByID(ctx, in.ID)
	if len(got.EventIDs) != 3 {
		t.Errorf("event ids = %v (want 3 unique)", got.EventIDs)
	}

	if err := s.AddQuery(ctx, in.ID, "|search index=main"); err != nil {
		t.Fatalf("add query: %v", err)
	}
	if err := s.AddQuery(ctx, in.ID, "   "); err == nil {
		t.Error("expected error for empty query")
	}
	if err := s.AddEntity(ctx, in.ID, Entity{Type: "user", Value: "jsmith"}); err != nil {
		t.Fatalf("add entity: %v", err)
	}
	if err := s.AddEntity(ctx, in.ID, Entity{Type: "user", Value: "jsmith"}); err != nil {
		t.Fatalf("dedup entity: %v", err)
	}
	if err := s.AddTechnique(ctx, in.ID, "T1059.001"); err != nil {
		t.Fatalf("add technique: %v", err)
	}

	got, _ = s.GetByID(ctx, in.ID)
	if len(got.Entities) != 1 || len(got.Queries) != 1 || len(got.Techniques) != 1 {
		t.Errorf("got = %+v", got)
	}

	// Cap enforcement: more than the event cap should truncate.
	many := make([]string, 0, 600)
	for i := 0; i < 600; i++ {
		many = append(many, string(rune('a'+i%26))+string(rune('0'+i/26))+string(rune('a'+(i%10))))
	}
	if err := s.AddEvents(ctx, in.ID, many); err != nil {
		t.Fatalf("add many: %v", err)
	}
	got, _ = s.GetByID(ctx, in.ID)
	if len(got.EventIDs) > 500 {
		t.Errorf("event ids exceed cap: %d", len(got.EventIDs))
	}
}

func TestNotes(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	in := &Investigation{Title: "x"}
	s.Create(ctx, in)

	note, err := s.AddNote(ctx, &Note{InvestigationID: in.ID, Author: "analyst", Body: "first entry"})
	if err != nil {
		t.Fatalf("add note: %v", err)
	}
	notes, err := s.ListNotes(ctx, in.ID)
	if err != nil {
		t.Fatalf("list notes: %v", err)
	}
	if len(notes) != 1 || notes[0].ID != note.ID || notes[0].Body != "first entry" {
		t.Errorf("notes = %+v", notes)
	}

	if _, err := s.AddNote(ctx, &Note{InvestigationID: in.ID, Author: "analyst", Body: ""}); err == nil {
		t.Error("expected error for empty body")
	}
	long := make([]byte, 5000)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := s.AddNote(ctx, &Note{InvestigationID: in.ID, Author: "analyst", Body: string(long)}); err == nil {
		t.Error("expected error for overlong body")
	}
}

func TestListFilters(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	for i, st := range []string{"new", "in_progress", "resolved"} {
		in := &Investigation{Title: string(rune('a' + i)), Status: st}
		if err := s.Create(ctx, in); err != nil {
			t.Fatal(err)
		}
	}

	if _, total, err := s.List(ctx, Filter{}); err != nil || total != 3 {
		t.Errorf("all: total=%d err=%v", total, err)
	}
	if _, total, err := s.List(ctx, Filter{Status: "in_progress"}); err != nil || total != 1 {
		t.Errorf("status filter: total=%d err=%v", total, err)
	}
}
