package risk

import (
	"context"
	"testing"

	"quetzalog/internal/assets"
	"quetzalog/internal/database"
	"quetzalog/internal/entities"
	"quetzalog/pkg/event"
)

func TestSeverityBase(t *testing.T) {
	cases := map[string]float64{
		"emergency": 50,
		"critical":  50,
		"alert":     45,
		"err":       35,
		"error":     35,
		"warning":   20,
		"notice":    10,
		"info":      5,
		"debug":     0,
		"":          0,
		"weird":     0,
	}
	for in, want := range cases {
		if got := severityBase(in); got != want {
			t.Errorf("severityBase(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestEventScorerRecordsContributions(t *testing.T) {
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()

	assetStore := assets.NewStore(db)
	metaStore := entities.NewStore(db)
	riskStore := NewEntityRiskStore(db)
	s := NewEventScorer(riskStore, assetStore, metaStore)

	// A critical asset host + an admin user.
	if _, err := assetStore.Create(ctx, &assets.Asset{
		EntityType:  "server",
		EntityRef:   "host:file-srv-01",
		Name:        "FILE-SRV-01",
		OS:          "linux",
		Criticality: "critical",
	}); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if err := metaStore.UpsertMeta(ctx, entities.Meta{Type: "user", Value: "svc_backup", Privilege: "admin"}); err != nil {
		t.Fatalf("upsert meta: %v", err)
	}

	ev := &event.Event{
		ID:       "evt-1",
		Severity: "critical",
		Host:     "file-srv-01",
		User:     "svc_backup",
	}
	contribs, err := s.ScoreEvent(ctx, ev)
	if err != nil {
		t.Fatalf("score: %v", err)
	}

	// host: severity base (50) + asset criticality (10) = 2 contributions.
	// user: admin privilege (10) = 1 contribution.
	if len(contribs) != 3 {
		t.Fatalf("contributions: %d, want 3: %+v", len(contribs), contribs)
	}

	hostRisk, err := riskStore.Get(ctx, "host", "file-srv-01")
	if err != nil {
		t.Fatalf("get host risk: %v", err)
	}
	if hostRisk == nil || hostRisk.RiskScore != 60 {
		t.Errorf("host risk: %+v, want 60", hostRisk)
	}
	userRisk, err := riskStore.Get(ctx, "user", "svc_backup")
	if err != nil {
		t.Fatalf("get user risk: %v", err)
	}
	if userRisk == nil || userRisk.RiskScore != 10 {
		t.Errorf("user risk: %+v, want 10", userRisk)
	}

	// Every point is reconstructable from contributions.
	list, err := riskStore.Contributions(ctx, "host", "file-srv-01", 100)
	if err != nil {
		t.Fatalf("contributions: %v", err)
	}
	var sum float64
	for _, c := range list {
		sum += c.Points
	}
	if sum != 60 {
		t.Errorf("reconstructed host risk: %v, want 60", sum)
	}
}

func TestEventScorerNilSafe(t *testing.T) {
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()

	s := NewEventScorer(NewEntityRiskStore(db), nil, nil)
	ev := &event.Event{ID: "evt-2", Severity: "info", Host: "h", User: "u"}
	if _, err := s.ScoreEvent(ctx, ev); err != nil {
		t.Fatalf("score: %v", err)
	}
	// info(5) for host h only; no asset/user lookups (stores nil).
	r, _ := s.risk.Get(ctx, "host", "h")
	if r == nil || r.RiskScore != 5 {
		t.Errorf("host risk: %+v, want 5", r)
	}
}
