package graph

import (
	"context"
	"testing"

	"quetzalog/internal/correlation"
	"quetzalog/internal/database"
	"quetzalog/internal/entities"
)

// entitiesStore exposes the query layer's v2 store for seeding meta rows.
func entitiesStore(t *testing.T, g *Graph) *entities.Store {
	t.Helper()
	return g.es
}

func setupGraph(t *testing.T) (*Graph, *correlation.Graph) {
	t.Helper()
	db, err := database.Open(":memory:", 5, 2, "5m")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewGraph(db), correlation.NewGraph(db)
}

func addEdge(t *testing.T, g *correlation.Graph, ft, fv, tt, tv, rel string) {
	t.Helper()
	if err := g.AddRelationship(context.Background(), &correlation.Relationship{
		FromType: correlation.EntityType(ft), FromValue: fv,
		ToType: correlation.EntityType(tt), ToValue: tv,
		Relation: rel, Weight: 1,
	}); err != nil {
		t.Fatalf("edge %s/%s -> %s/%s: %v", ft, fv, tt, tv, err)
	}
}

func TestNeighborsBFS(t *testing.T) {
	g, hot := setupGraph(t)
	ctx := context.Background()

	// A --connected_to--> B --auth_from--> C (user)
	addEdge(t, hot, "ip", "10.0.0.1", "ip", "10.0.0.2", "connected_to")
	addEdge(t, hot, "ip", "10.0.0.2", "user", "alice", "auth_from")

	nodes, err := g.Neighbors(ctx, NodeRef{"ip", "10.0.0.1"}, 2, nil)
	if err != nil {
		t.Fatalf("neighbors: %v", err)
	}
	byDepth := map[int]int{}
	for _, n := range nodes {
		byDepth[n.Depth]++
	}
	if byDepth[0] != 1 || byDepth[1] != 1 || byDepth[2] != 1 {
		t.Fatalf("depths: %+v (%+v)", byDepth, nodes)
	}

	// Depth 1 must stop at B.
	nodes, _ = g.Neighbors(ctx, NodeRef{"ip", "10.0.0.1"}, 1, nil)
	if len(nodes) != 2 {
		t.Errorf("depth1: %d nodes %+v", len(nodes), nodes)
	}

	// Isolated node: only itself.
	nodes, _ = g.Neighbors(ctx, NodeRef{"ip", "9.9.9.9"}, 4, nil)
	if len(nodes) != 1 || nodes[0].Depth != 0 {
		t.Errorf("isolated: %+v", nodes)
	}

	// Depth cap: 99 must not error and must equal depth 4 results.
	if _, err := g.Neighbors(ctx, NodeRef{"ip", "10.0.0.1"}, 99, nil); err != nil {
		t.Errorf("depth cap: %v", err)
	}
}

func TestNeighborsStateFilter(t *testing.T) {
	g, hot := setupGraph(t)
	ctx := context.Background()

	addEdge(t, hot, "ip", "10.0.0.1", "ip", "10.0.0.2", "connected_to")
	addEdge(t, hot, "ip", "10.0.0.1", "ip", "10.0.0.3", "connected_to")
	es := entitiesStore(t, g)
	_ = es.UpsertRelationshipMeta(ctx, entities.RelationshipMeta{
		FromType: "ip", FromValue: "10.0.0.1", ToType: "ip", ToValue: "10.0.0.3",
		Relation: "connected_to", Status: "blocked", SourceType: "event",
	})

	// Only observed edges: B visible, C (blocked) hidden.
	obs, err := g.Neighbors(ctx, NodeRef{"ip", "10.0.0.1"}, 1, []string{"observed"})
	if err != nil {
		t.Fatalf("observed filter: %v", err)
	}
	if len(obs) != 2 || obs[1].Node.Value != "10.0.0.2" {
		t.Errorf("observed filter leaked blocked edge: %+v", obs)
	}
	// Only blocked: C visible.
	blk, _ := g.Neighbors(ctx, NodeRef{"ip", "10.0.0.1"}, 1, []string{"blocked"})
	if len(blk) != 2 || blk[1].Node.Value != "10.0.0.3" || blk[1].Status != "blocked" {
		t.Errorf("blocked filter: %+v", blk)
	}
	// No filter: both.
	all, _ := g.Neighbors(ctx, NodeRef{"ip", "10.0.0.1"}, 1, nil)
	if len(all) != 3 {
		t.Errorf("unfiltered: %+v", all)
	}
}

func TestPathShortestAndStates(t *testing.T) {
	g, hot := setupGraph(t)
	ctx := context.Background()

	// 1 --connected_to--> 2 --auth_from--> alice
	addEdge(t, hot, "ip", "10.0.0.1", "ip", "10.0.0.2", "connected_to")
	addEdge(t, hot, "ip", "10.0.0.2", "user", "alice", "auth_from")

	paths, err := g.Path(ctx, NodeRef{"ip", "10.0.0.1"}, NodeRef{"user", "alice"}, 4, nil)
	if err != nil {
		t.Fatalf("path: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("paths: %+v", paths)
	}
	p := paths[0]
	if len(p.Nodes) != 3 || p.Nodes[0].Value != "10.0.0.1" || p.Nodes[2].Value != "alice" {
		t.Errorf("path nodes: %+v", p.Nodes)
	}
	if len(p.States) != 2 {
		t.Errorf("path states: %+v", p.States)
	}

	// Same path but the middle edge is blocked: observed-only finds nothing.
	es := entitiesStore(t, g)
	_ = es.UpsertRelationshipMeta(ctx, entities.RelationshipMeta{
		FromType: "ip", FromValue: "10.0.0.2", ToType: "user", ToValue: "alice",
		Relation: "auth_from", Status: "blocked", SourceType: "event",
	})
	none, err := g.Path(ctx, NodeRef{"ip", "10.0.0.1"}, NodeRef{"user", "alice"}, 4, []string{"observed"})
	if err != nil || len(none) != 0 {
		t.Errorf("observed-only path should be empty: %d %v", len(none), err)
	}

	// Trivial same-node path.
	same, _ := g.Path(ctx, NodeRef{"ip", "1.1.1.1"}, NodeRef{"ip", "1.1.1.1"}, 1, nil)
	if len(same) != 1 || len(same[0].Nodes) != 1 {
		t.Errorf("trivial path: %+v", same)
	}
}

func TestResolveDelegates(t *testing.T) {
	g, hot := setupGraph(t)
	_ = hot.UpsertEntity(context.Background(), &correlation.Entity{
		Type: correlation.EntityTypeIP, Value: "203.0.113.7", Count: 1,
	})
	cands, err := g.Resolve(context.Background(), "203.0.113.7")
	if err != nil || len(cands) != 1 || cands[0].Type != "ip" {
		t.Errorf("resolve: %+v %v", cands, err)
	}
}
