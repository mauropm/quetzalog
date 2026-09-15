// Package graph is the read-only query layer over the security knowledge
// graph: state-aware BFS traversal, shortest paths, and entity resolution.
// All queries are parameterized; inferred/potential edges are only included
// when explicitly requested via the state filter.
package graph

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"quetzalog/internal/entities"
)

// MaxDepth caps traversal depth (SQLite BFS, bounded row counts).
const MaxDepth = 4

// maxPaths bounds Path results.
const maxPaths = 20

// NodeRef identifies a graph node.
type NodeRef struct {
	Type  string
	Value string
}

// TraversalNode is one visited node in a Neighbors traversal.
type TraversalNode struct {
	Node      NodeRef `json:"node"`
	Relation  string  `json:"relation,omitempty"` // edge into this node ("" for root)
	Depth     int     `json:"depth"`
	Status    string  `json:"status"`
	Source    string  `json:"source,omitempty"`
	Count     int     `json:"count,omitempty"`
	FirstSeen string  `json:"first_seen,omitempty"`
	LastSeen  string  `json:"last_seen,omitempty"`
}

// Path is one shortest-path hop sequence (nodes include both endpoints).
type Path struct {
	Nodes  []NodeRef `json:"nodes"`
	States []string  `json:"states"` // one per edge, in path order
}

// Graph queries the entities/relationships/relationship_meta tables.
type Graph struct {
	db *sql.DB
	es *entities.Store
}

// NewGraph creates a query layer.
func NewGraph(db *sql.DB) *Graph {
	return &Graph{db: db, es: entities.NewStore(db)}
}

// Resolve delegates raw-string resolution to the entities store.
func (g *Graph) Resolve(ctx context.Context, raw string) ([]entities.Candidate, error) {
	return g.es.Resolve(ctx, raw)
}

// statesFilter renders an IN filter on edge state; empty means no filter.
func statesFilter(states []string, args *[]any) string {
	if len(states) == 0 {
		return ""
	}
	ph := make([]string, len(states))
	for i, s := range states {
		ph[i] = "?"
		*args = append(*args, s)
	}
	return " AND COALESCE(m.status, 'observed') IN (" + strings.Join(ph, ",") + ")"
}

type edgeMeta struct {
	Relation string
	Status   string
	Source   string
}

// edgesOf returns one level of edges around a node, with meta state merged.
func (g *Graph) edgesOf(ctx context.Context, n NodeRef, states []string) (map[NodeRef]edgeMeta, error) {
	args := []any{n.Type, n.Value, n.Type, n.Value, n.Type, n.Value, n.Type, n.Value}
	where := statesFilter(states, &args)
	rows, err := g.db.QueryContext(ctx, `
		SELECT CASE WHEN r.from_type = ? AND r.from_value = ? THEN r.to_type ELSE r.from_type END,
		       CASE WHEN r.from_type = ? AND r.from_value = ? THEN r.to_value ELSE r.from_value END,
		       r.relation,
		       COALESCE(m.status, 'observed'),
		       m.source_type
		FROM relationships r
		LEFT JOIN relationship_meta m ON (
			m.from_type = r.from_type AND m.from_value = r.from_value
			AND m.to_type = r.to_type AND m.to_value = r.to_value
			AND m.relation = r.relation)
		WHERE ((r.from_type = ? AND r.from_value = ?)
		   OR (r.to_type = ? AND r.to_value = ?))`+where,
		args...)
	if err != nil {
		return nil, fmt.Errorf("query edges: %w", err)
	}
	defer rows.Close()
	out := map[NodeRef]edgeMeta{}
	for rows.Next() {
		var (
			nbType, nbVal, rel string
			status             string
			src                sql.NullString
		)
		if err := rows.Scan(&nbType, &nbVal, &rel, &status, &src); err != nil {
			return nil, err
		}
		out[NodeRef{nbType, nbVal}] = edgeMeta{Relation: rel, Status: status, Source: src.String}
	}
	return out, rows.Err()
}

// Neighbors performs a state-aware BFS around a node (depth capped at 4).
func (g *Graph) Neighbors(ctx context.Context, root NodeRef, depth int, states []string) ([]TraversalNode, error) {
	if depth <= 0 {
		return nil, nil
	}
	if depth > MaxDepth {
		depth = MaxDepth
	}
	result := []TraversalNode{{Node: root, Depth: 0, Status: "observed"}}
	visited := map[NodeRef]bool{root: true}
	queue := []NodeRef{root}
	for level := 1; level <= depth && len(queue) > 0; level++ {
		var next []NodeRef
		for _, cur := range queue {
			edges, err := g.edgesOf(ctx, cur, states)
			if err != nil {
				return nil, err
			}
			for nb, meta := range edges {
				if visited[nb] {
					continue
				}
				visited[nb] = true
				tn := TraversalNode{Node: nb, Relation: meta.Relation, Depth: level, Status: meta.Status, Source: meta.Source}
				var fb, lb sql.NullTime
				if err := g.db.QueryRowContext(ctx,
					`SELECT count, first_seen, last_seen FROM entities WHERE type = ? AND value = ?`,
					nb.Type, nb.Value).Scan(&tn.Count, &fb, &lb); err == nil {
					tn.FirstSeen = fb.Time.Format("2006-01-02T15:04:05Z")
					tn.LastSeen = lb.Time.Format("2006-01-02T15:04:05Z")
				}
				result = append(result, tn)
				next = append(next, nb)
			}
		}
		queue = next
	}
	return result, nil
}

// step is one BFS frontier entry carrying its incoming edge.
type step struct {
	node   NodeRef
	rel    string
	status string
	parent *step
}

// pathFrom assembles a Path from the root to nb through cur's incoming edge.
func pathFrom(cur *step, nb NodeRef, rel, status string) Path {
	nodes := []NodeRef{nb}
	states := []string{status}
	for s := cur; s != nil; s = s.parent {
		nodes = append([]NodeRef{s.node}, nodes...)
		if s.rel != "" {
			states = append([]string{s.status}, states...)
		}
	}
	return Path{Nodes: nodes, States: states}
}

// Path finds shortest paths from `from` to `to` (state-aware, capped at
// MaxDepth hops). Returns up to maxPaths distinct shortest paths.
func (g *Graph) Path(ctx context.Context, from, to NodeRef, maxHops int, states []string) ([]Path, error) {
	if from == to {
		return []Path{{Nodes: []NodeRef{from}, States: []string{}}}, nil
	}
	if maxHops <= 0 {
		maxHops = 1
	}
	if maxHops > MaxDepth {
		maxHops = MaxDepth
	}
	seen := map[NodeRef]bool{from: true}
	var frontier []*step
	frontier = append(frontier, &step{node: from})
	var paths []Path
	for hops := 0; hops < maxHops && len(frontier) > 0 && len(paths) < maxPaths; hops++ {
		var next []*step
		for _, cur := range frontier {
			edges, err := g.edgesOf(ctx, cur.node, states)
			if err != nil {
				return nil, err
			}
			for nb, meta := range edges {
				if nb == to {
					paths = append(paths, pathFrom(cur, nb, meta.Relation, meta.Status))
					if len(paths) >= maxPaths {
						return paths, nil
					}
					continue
				}
				if seen[nb] {
					continue
				}
				seen[nb] = true
				next = append(next, &step{node: nb, rel: meta.Relation, status: meta.Status, parent: cur})
			}
		}
		if len(paths) > 0 {
			break // shortest level reached
		}
		frontier = next
	}
	return paths, nil
}
