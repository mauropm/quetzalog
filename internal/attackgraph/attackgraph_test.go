package attackgraph_test

import (
	"context"
	"database/sql"
	"testing"

	"quetzalog/internal/assets"
	"quetzalog/internal/attackgraph"
	"quetzalog/internal/database"
)

func setup(t *testing.T) (*attackgraph.Builder, *sql.DB) {
	t.Helper()
	db, err := database.Open(":memory:", 1, 1, "")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	b := attackgraph.NewBuilder(db, assets.NewStore(db), nil, nil)
	return b, db
}

func seedEdge(t *testing.T, db *sql.DB, fromType, fromVal, toType, toVal, rel, state, sourceID string) {
	t.Helper()
	if _, err := db.Exec(`INSERT OR IGNORE INTO relationships (id, from_type, from_value, to_type, to_value, relation)
		VALUES (?, ?, ?, ?, ?, ?)`,
		fromType+"|"+fromVal+"|"+toType+"|"+toVal+"|"+rel,
		fromType, fromVal, toType, toVal, rel); err != nil {
		t.Fatalf("seed relationship: %v", err)
	}
	if _, err := db.Exec(`INSERT OR REPLACE INTO relationship_meta
		(from_type, from_value, to_type, to_value, relation, status, source_type, source_id, first_seen, last_seen, evidence)
		VALUES (?, ?, ?, ?, ?, ?, 'event', ?, datetime('now'), datetime('now'), '[]')`,
		fromType, fromVal, toType, toVal, rel, state, sourceID); err != nil {
		t.Fatalf("seed meta: %v", err)
	}
}

func seedAsset(t *testing.T, ctx context.Context, es *assets.Store, ref, criticality, environment string, exposed bool) {
	t.Helper()
	et, v, _ := splitRef(ref)
	a, err := es.Create(ctx, &assets.Asset{
		EntityType:      et,
		EntityRef:       ref,
		Name:            v,
		Criticality:     criticality,
		Environment:     environment,
		InternetExposed: exposed,
	})
	if err != nil {
		t.Fatalf("asset %s: %v", ref, err)
	}
	_ = a
}

func splitRef(ref string) (string, string, bool) {
	for i := 0; i < len(ref); i++ {
		if ref[i] == ':' {
			return ref[:i], ref[i+1:], true
		}
	}
	return "", ref, false
}

func TestAttackGraph_CompromiseAndPaths(t *testing.T) {
	b, db := setup(t)
	ctx := context.Background()

	es := assets.NewStore(db)
	seedAsset(t, ctx, es, "host:workstation-42", "medium", "dmz", false)
	seedAsset(t, ctx, es, "host:file-srv-01", "critical", "corp", false)
	seedAsset(t, ctx, es, "database:db-01", "critical", "corp", false)

	// 185.220.101.47 (external, no asset) → workstation-42 (observed connect)
	seedEdge(t, db, "ip", "185.220.101.47", "host", "workstation-42", "connects_to", "observed", "ev-1")
	// attacker user (no asset) → workstation-42 (observed auth)
	seedEdge(t, db, "user", "attacker", "host", "workstation-42", "authenticates", "observed", "ev-2")
	// workstation-42 (dmz) → file-srv-01 (corp): inferred lateral movement
	seedEdge(t, db, "host", "workstation-42", "host", "file-srv-01", "lateral_movement", "inferred", "det-1")
	// file-srv-01 → db-01 observed read
	seedEdge(t, db, "host", "file-srv-01", "database", "db-01", "reads", "observed", "ev-3")

	n, err := b.Recompute(ctx)
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	if n == 0 {
		t.Fatalf("no paths materialized")
	}

	paths, err := b.ListPaths(ctx, attackgraph.ListPathsFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list paths: %v", err)
	}
	var obs, pot int
	for _, p := range paths {
		switch p.Status {
		case "observed":
			obs++
		case "potential":
			pot++
		}
	}
	if obs == 0 {
		t.Errorf("no observed path materialized")
	}
	if pot == 0 {
		t.Errorf("no potential path to critical asset materialized")
	}

	// Potential path must reach the critical DB.
	var potPath *attackgraph.AttackPath
	for i := range paths {
		if paths[i].Status == "potential" && paths[i].TargetNode == "database:db-01" {
			potPath = &paths[i]
		}
	}
	if potPath == nil {
		t.Fatalf("no potential path to database:db-01 (paths: %+v)", paths)
	}
	if potPath.Risk <= 0 {
		t.Errorf("potential risk: %v, want > 0", potPath.Risk)
	}

	full, err := b.GetPath(ctx, potPath.ID)
	if err != nil {
		t.Fatalf("get path: %v", err)
	}
	if len(full.Steps) == 0 {
		t.Errorf("potential path has no steps")
	}
}

func TestAttackGraph_Snapshot(t *testing.T) {
	b, db := setup(t)
	ctx := context.Background()

	es := assets.NewStore(db)
	seedAsset(t, ctx, es, "host:ws-1", "high", "corp", false)
	seedAsset(t, ctx, es, "host:dc-1", "critical", "corp", false)
	seedEdge(t, db, "ip", "8.8.4.4", "host", "ws-1", "connects_to", "observed", "ev-1")
	seedEdge(t, db, "host", "ws-1", "host", "dc-1", "lateral_movement", "observed", "ev-2")

	_, _ = b.Recompute(ctx)

	snap, err := b.Snapshot(ctx, []string{"observed", "inferred"}, 3, "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	states := map[string]string{}
	for _, n := range snap.Nodes {
		states[n.Node] = n.Compromise
	}
	if states["host:ws-1"] != "compromised_observed" {
		t.Errorf("ws-1 compromise: %q, want compromised_observed", states["host:ws-1"])
	}
	if states["host:dc-1"] != "compromised_observed" && states["host:dc-1"] != "at_risk_potential" {
		t.Errorf("dc-1 compromise: %q", states["host:dc-1"])
	}
	if snap.GeneratedAt.IsZero() {
		t.Errorf("snapshot missing generated_at")
	}
	if len(snap.Edges) == 0 {
		t.Errorf("snapshot has no edges")
	}
}

func TestAttackGraph_WhatNext(t *testing.T) {
	b, db := setup(t)
	ctx := context.Background()

	es := assets.NewStore(db)
	seedAsset(t, ctx, es, "host:web-1", "high", "dmz", true)
	seedEdge(t, db, "host", "web-1", "host", "app-1", "connects_to", "observed", "ev-1")
	seedEdge(t, db, "host", "web-1", "database", "db-1", "reads", "observed", "ev-2")

	out, err := b.WhatNext(ctx, "host", "web-1")
	if err != nil {
		t.Fatalf("what-next: %v", err)
	}
	if len(out.PotentialEdges) != 2 {
		t.Errorf("potential edges: %d, want 2", len(out.PotentialEdges))
	}
}

// TestAttackGraph_NoCrossBoundaryNoCompromise ensures an internal-only
// relationship does not mark anything compromised.
func TestAttackGraph_NoCrossBoundaryNoCompromise(t *testing.T) {
	b, db := setup(t)
	ctx := context.Background()

	es := assets.NewStore(db)
	seedAsset(t, ctx, es, "host:a-1", "medium", "corp", false)
	seedAsset(t, ctx, es, "host:b-1", "medium", "corp", false)
	seedEdge(t, db, "host", "a-1", "host", "b-1", "connects_to", "observed", "ev-1")

	if _, err := b.Recompute(ctx); err != nil {
		t.Fatalf("recompute: %v", err)
	}
	paths, _ := b.ListPaths(ctx, attackgraph.ListPathsFilter{Limit: 50})
	if len(paths) != 0 {
		t.Errorf("internal-only edges should not materialize paths: %d", len(paths))
	}
}
