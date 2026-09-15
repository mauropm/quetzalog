package entities

import (
	"context"
	"testing"

	"quetzalog/internal/database"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewStore(db)
}

func TestIdentityPromotionIsMonotonic(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.UpsertIdentity(ctx, Identity{
		CanonicalType: "host", CanonicalValue: "WEB-01",
		AliasType: "ip", AliasValue: "10.0.0.5",
		Status: "probable", Confidence: 0.8,
	}); err != nil {
		t.Fatalf("upsert probable: %v", err)
	}
	// Weaker evidence must not demote.
	if err := s.UpsertIdentity(ctx, Identity{
		CanonicalType: "host", CanonicalValue: "WEB-01",
		AliasType: "ip", AliasValue: "10.0.0.5",
		Status: "possible", Confidence: 0.2,
	}); err != nil {
		t.Fatalf("upsert possible: %v", err)
	}
	ids, err := s.IdentitiesFor(ctx, "host", "WEB-01")
	if err != nil || len(ids) != 1 {
		t.Fatalf("identities: %d %v", len(ids), err)
	}
	if ids[0].Status != "probable" || ids[0].Confidence != 0.8 {
		t.Errorf("demotion happened: %+v", ids[0])
	}
	// Stronger evidence promotes.
	_ = s.UpsertIdentity(ctx, Identity{
		CanonicalType: "host", CanonicalValue: "WEB-01",
		AliasType: "ip", AliasValue: "10.0.0.5",
		Status: "confirmed", Confidence: 0.95,
	})
	ids, _ = s.IdentitiesFor(ctx, "host", "WEB-01")
	if ids[0].Status != "confirmed" || ids[0].Confidence != 0.95 {
		t.Errorf("promotion failed: %+v", ids[0])
	}
}

func TestLinkUnlink(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Link(ctx, "host", "DB-01", "domain", "db01.internal"); err != nil {
		t.Fatalf("link: %v", err)
	}
	ids, _ := s.IdentitiesFor(ctx, "host", "DB-01")
	if len(ids) != 1 || ids[0].Status != "confirmed" || ids[0].Confidence != 1.0 || ids[0].Source != "analyst" {
		t.Errorf("analyst link: %+v", ids)
	}
	if err := s.Unlink(ctx, "host", "DB-01", "domain", "db01.internal"); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	ids, _ = s.IdentitiesFor(ctx, "host", "DB-01")
	if len(ids) != 0 {
		t.Errorf("unlink did not remove: %+v", ids)
	}
	if err := s.Unlink(ctx, "host", "DB-01", "domain", "db01.internal"); err == nil {
		t.Error("double unlink succeeded")
	}
}

func TestResolve(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// A plain value in the hot entities table.
	_, _ = s.db.ExecContext(ctx, `INSERT INTO entities (id, type, value, first_seen, last_seen, count)
		VALUES ('e1', 'ip', '203.0.113.9', '2026-01-01', '2026-01-02', 3)`)
	// An alias pointing at a canonical host.
	_ = s.UpsertIdentity(ctx, Identity{
		CanonicalType: "host", CanonicalValue: "WEB-01",
		AliasType: "ip", AliasValue: "203.0.113.9",
		Status: "probable", Confidence: 0.8,
	})
	// A possible alias must NOT be returned for pivots.
	_ = s.UpsertIdentity(ctx, Identity{
		CanonicalType: "host", CanonicalValue: "MYSTERY-9",
		AliasType: "ip", AliasValue: "10.9.9.9",
		Status: "possible", Confidence: 0.3,
	})

	cands, err := s.Resolve(ctx, "203.0.113.9")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	var valueHit, aliasHit *Candidate
	for i := range cands {
		switch cands[i].MatchedAs + ":" + cands[i].Value {
		case "value:203.0.113.9":
			valueHit = &cands[i]
		case "alias:WEB-01":
			aliasHit = &cands[i]
		}
	}
	if valueHit == nil {
		t.Errorf("direct value hit missing: %+v", cands)
	}
	if aliasHit == nil || aliasHit.Status != "probable" {
		t.Errorf("alias hit missing/wrong: %+v", cands)
	}
	for _, c := range cands {
		if c.Value == "MYSTERY-9" {
			t.Errorf("possible-only alias leaked into resolution: %+v", c)
		}
	}

	if cands, _ = s.Resolve(ctx, "10.9.9.9"); len(cands) != 0 {
		t.Errorf("possible-only alias resolved: %+v", cands)
	}
}

func TestMetaUpsertMerge(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	exposed := true
	if err := s.UpsertMeta(ctx, Meta{Type: "host", Value: "WEB-01", OS: "linux", InternetExposed: &exposed, Tags: []string{"web"}}); err != nil {
		t.Fatalf("upsert meta: %v", err)
	}
	// Second upsert with different fields: first ones must survive.
	if err := s.UpsertMeta(ctx, Meta{Type: "host", Value: "WEB-01", Environment: "production"}); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	m, err := s.GetMeta(ctx, "host", "WEB-01")
	if err != nil || m == nil {
		t.Fatalf("get meta: %v %v", m, err)
	}
	if m.OS != "linux" || m.Environment != "production" {
		t.Errorf("merge lost fields: %+v", m)
	}
	if m.InternetExposed == nil || !*m.InternetExposed {
		t.Errorf("exposure lost: %+v", m)
	}
	if len(m.Tags) != 1 || m.Tags[0] != "web" {
		t.Errorf("tags lost: %+v", m)
	}
	if m, _ = s.GetMeta(ctx, "host", "NOPE"); m != nil {
		t.Errorf("absent meta returned: %+v", m)
	}
}

func TestRelationshipMetaAndEdges(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Hot edges.
	_, _ = s.db.ExecContext(ctx, `INSERT INTO relationships (id, from_type, from_value, to_type, to_value, relation, weight, created_at)
		VALUES ('r1', 'ip', '10.0.0.5', 'ip', '10.0.0.9', 'connected_to', 1, '2026-01-01 00:00:00')`)
	// Meta for one edge only.
	_ = s.UpsertRelationshipMeta(ctx, RelationshipMeta{
		FromType: "ip", FromValue: "10.0.0.5", ToType: "ip", ToValue: "10.0.0.9",
		Relation: "connected_to", Status: "observed",
		SourceType: "event", SourceID: "ev-1", Evidence: `{"count":3}`,
	})
	// Analyst override of the same edge keeps its state.
	_ = s.UpsertRelationshipMeta(ctx, RelationshipMeta{
		FromType: "ip", FromValue: "10.0.0.5", ToType: "ip", ToValue: "10.0.0.9",
		Relation: "connected_to", Status: "blocked",
		SourceType: "analyst", SourceID: "analyst-x",
	})

	edges, err := s.RelationshipsOf(ctx, "ip", "10.0.0.5", 0)
	if err != nil {
		t.Fatalf("edges: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("edges: %+v", edges)
	}
	e := edges[0]
	if e.Status != "blocked" || e.SourceType != "analyst" || e.SourceID != "analyst-x" {
		t.Errorf("analyst state not applied: %+v", e)
	}
	if e.Evidence != `{"count":3}` {
		t.Errorf("evidence lost: %q", e.Evidence)
	}
	// Both directions resolve.
	if edges, _ = s.RelationshipsOf(ctx, "ip", "10.0.0.9", 0); len(edges) != 1 {
		t.Errorf("reverse direction: %+v", edges)
	}
}
