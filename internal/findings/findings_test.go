package findings

import (
	"context"
	"testing"
	"time"

	"quetzalog/internal/database"
	"quetzalog/pkg/event"
)

func openTestDB(t *testing.T) *Store {
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

func TestCreateAndGetByID(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	f := &Finding{
		Title:       "Suspicious login",
		Description: "geo anomaly",
		Severity:    "high",
		RiskScore:   35,
		User:        "jsmith",
		Host:        "workstation-42",
		SourceIP:    "185.220.101.47",
	}
	if err := s.Create(ctx, f); err != nil {
		t.Fatalf("create: %v", err)
	}
	if f.ID == "" {
		t.Fatal("expected generated ID")
	}
	if f.Status != "new" {
		t.Errorf("default status = %q, want new", f.Status)
	}

	got, err := s.GetByID(ctx, f.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Title != f.Title {
		t.Errorf("title = %q, want %q", got.Title, f.Title)
	}
	if got.Severity != "high" {
		t.Errorf("severity = %q, want high", got.Severity)
	}
	if got.User != "jsmith" {
		t.Errorf("user = %q, want jsmith", got.User)
	}

	if _, err := s.GetByID(ctx, "nope"); err == nil {
		t.Error("expected not-found error")
	}
}

func TestCreateOrUpdateFromDetectionDedup(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	ev := func(user, host string) *event.Event {
		e := event.NewEvent()
		e.User = user
		e.Host = host
		e.SourceIP = "185.220.101.47"
		return e
	}

	args := FromDetectionArgs{
		RuleID: "rule-1", RuleName: "Suspicious Logins", GroupKey: "jsmith",
		Severity: "high", RiskScore: 35, Matched: 3,
		MITRETactic: "TA0006", MITRETechnique: "T1110",
		Tags: []string{"scenario"}, Events: []*event.Event{ev("jsmith", "workstation-42")},
	}

	first, isNew, err := s.CreateOrUpdateFromDetection(ctx, args)
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if !isNew {
		t.Error("first upsert should create")
	}
	if first.DetectionID != "rule-1" || first.User != "jsmith" {
		t.Errorf("finding fields not populated: %+v", first)
	}
	if first.Title != "Suspicious Logins — jsmith" {
		t.Errorf("title = %q, want grouped title", first.Title)
	}

	second, isNew, err := s.CreateOrUpdateFromDetection(ctx, args)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if isNew {
		t.Error("second upsert should refresh, not create")
	}
	if second.ID != first.ID {
		t.Errorf("dedup failed: %s != %s", second.ID, first.ID)
	}
	if second.MatchCount != 2*args.Matched {
		t.Errorf("match count not accumulating: %d, want %d", second.MatchCount, 2*args.Matched)
	}

	// Risk must never decrease on refresh.
	second.RiskScore = 10
	args.RiskScore = 20
	third, _, err := s.CreateOrUpdateFromDetection(ctx, args)
	if err != nil {
		t.Fatalf("third upsert: %v", err)
	}
	if third.RiskScore < 20 {
		t.Errorf("risk score should not decrease: %v", third.RiskScore)
	}

	byKey, err := s.ByDedupKey(ctx, "rule-1|jsmith")
	if err != nil {
		t.Fatalf("by dedup key: %v", err)
	}
	if byKey.ID != first.ID {
		t.Error("dedup key lookup returned wrong finding")
	}
}

func TestUpdateStatusAssign(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	f := &Finding{Title: "x"}
	if err := s.Create(ctx, f); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := s.UpdateStatus(ctx, f.ID, "resolved"); err != nil {
		t.Fatalf("status: %v", err)
	}
	if err := s.UpdateStatus(ctx, f.ID, "bogus"); err == nil {
		t.Error("expected invalid status error")
	}

	if err := s.Assign(ctx, f.ID, "analyst1"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	got, err := s.GetByID(ctx, f.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != "resolved" || got.Owner != "analyst1" {
		t.Errorf("state = %+v", got)
	}
}

func TestListFilters(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	mk := func(title, sev, status, user string, risk float64) *Finding {
		return &Finding{Title: title, Severity: sev, Status: status, User: user, RiskScore: risk}
	}
	for _, f := range []*Finding{
		mk("a", "critical", "new", "alice", 50),
		mk("b", "high", "new", "bob", 35),
		mk("c", "high", "resolved", "bob", 35),
		mk("carol login", "low", "in_progress", "carol", 10),
	} {
		if err := s.Create(ctx, f); err != nil {
			t.Fatalf("create %s: %v", f.Title, err)
		}
	}

	cases := []struct {
		name   string
		filter Filter
		want   int
	}{
		{"all", Filter{}, 4},
		{"severity", Filter{Severity: "high"}, 2},
		{"status", Filter{Status: "new"}, 2},
		{"user", Filter{User: "bob"}, 2},
		{"risk min", Filter{RiskMin: 40}, 1},
		{"has risk", Filter{HasRisk: true}, 4},
		{"text", Filter{Text: "carol"}, 1},
	}
	for _, c := range cases {
		got, total, err := s.List(ctx, c.filter)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if total != c.want {
			t.Errorf("%s: total = %d, want %d (list %d)", c.name, total, c.want, len(got))
		}
	}

	// Invalid sort column/order must fall back, never leak SQL.
	if _, _, err := s.List(ctx, Filter{SortBy: "1; DROP TABLE findings", SortOrder: "asc; DROP"}); err != nil {
		t.Fatalf("invalid sort should fall back, got: %v", err)
	}

	// Cap on limit.
	if _, _, err := s.List(ctx, Filter{Limit: 10000}); err != nil {
		t.Fatalf("limit cap: %v", err)
	}
}

func TestNotes(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	f := &Finding{Title: "x"}
	if err := s.Create(ctx, f); err != nil {
		t.Fatalf("create: %v", err)
	}

	note := &Note{FindingID: f.ID, Author: "analyst", Content: "first"}
	if err := s.AddNote(ctx, note); err != nil {
		t.Fatalf("add note: %v", err)
	}
	notes, err := s.GetNotes(ctx, f.ID)
	if err != nil {
		t.Fatalf("notes: %v", err)
	}
	if len(notes) != 1 || notes[0].Content != "first" {
		t.Errorf("notes = %+v", notes)
	}
}

func TestPostureAndTimeline(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	if err := s.Create(ctx, &Finding{Title: "a", Severity: "critical", Status: "new"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, &Finding{Title: "b", Severity: "low", Status: "resolved"}); err != nil {
		t.Fatal(err)
	}

	posture, err := s.Posture(ctx)
	if err != nil {
		t.Fatalf("posture: %v", err)
	}
	if posture["open"] != 1 || posture["critical"] != 1 || posture["status_new"] != 1 {
		t.Errorf("posture = %+v", posture)
	}

	now := time.Now()
	points, err := s.Timeline(ctx, now.Add(-time.Hour), now.Add(time.Hour), 15*time.Minute)
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	count := 0
	for _, p := range points {
		count += p.Count
	}
	if count != 2 {
		t.Errorf("timeline count = %d, want 2", count)
	}
}

func TestActiveTechniquesAndRelatedByEntity(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	f1 := &Finding{Title: "a", Severity: "high", Status: "new", MITRETactic: "TA0006", MITRETechnique: "T1110", User: "jsmith"}
	f2 := &Finding{Title: "b", Severity: "critical", Status: "resolved", MITRETactic: "TA0010", MITRETechnique: "T1041", SourceIP: "10.0.0.1"}
	f3 := &Finding{Title: "c", Severity: "medium", Status: "investigating", MITRETactic: "TA0006", MITRETechnique: "T1110", Host: "h1"}
	for _, f := range []*Finding{f1, f2, f3} {
		if err := s.Create(ctx, f); err != nil {
			t.Fatal(err)
		}
	}

	techs, err := s.ActiveTechniques(ctx)
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	// f2 is resolved, so only T1110 (x2) should be in play.
	if len(techs) != 1 || techs[0].Technique != "T1110" || techs[0].Count != 2 {
		t.Errorf("active techniques = %+v", techs)
	}

	related, err := s.RelatedByEntity(ctx, "user", "jsmith", 10)
	if err != nil {
		t.Fatalf("related user: %v", err)
	}
	if len(related) != 1 || related[0].ID != f1.ID {
		t.Errorf("related by user = %+v", related)
	}

	related, err = s.RelatedByEntity(ctx, "ip", "10.0.0.1", 10)
	if err != nil {
		t.Fatalf("related ip: %v", err)
	}
	if len(related) != 0 {
		t.Errorf("ip match should be empty (resolved finding excluded): %+v", related)
	}

	related, err = s.RelatedByEntity(ctx, "domain", "x.example", 10)
	if err != nil || len(related) != 0 {
		t.Errorf("unsupported type should be empty, got %+v err=%v", related, err)
	}
}

func TestSavedViews(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	view := &SavedView{User: "analyst", Name: "My criticals", Filters: map[string]string{"severity": "critical"}}
	if err := s.SaveView(ctx, view); err != nil {
		t.Fatalf("save: %v", err)
	}
	views, err := s.ListViews(ctx, "analyst")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(views) != 1 || views[0].Name != "My criticals" {
		t.Errorf("views = %+v", views)
	}

	// Same user+name dedupes.
	if err := s.SaveView(ctx, &SavedView{User: "analyst", Name: "My criticals", Filters: map[string]string{"severity": "low"}}); err != nil {
		t.Fatalf("resave: %v", err)
	}
	views, _ = s.ListViews(ctx, "analyst")
	if len(views) != 1 {
		t.Errorf("expected dedupe, got %d views", len(views))
	}

	// Other users do not see the view.
	other, _ := s.ListViews(ctx, "other")
	if len(other) != 0 {
		t.Errorf("view leaked to other user: %+v", other)
	}

	got, err := s.GetView(ctx, "analyst", view.ID)
	if err != nil || got.Name != "My criticals" {
		t.Errorf("get view = %+v err=%v", got, err)
	}

	if err := s.DeleteView(ctx, "analyst", view.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.DeleteView(ctx, "analyst", view.ID); err == nil {
		t.Error("expected error deleting missing view")
	}
}
