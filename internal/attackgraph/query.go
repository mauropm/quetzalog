package attackgraph

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"quetzalog/internal/graph"
)

// SnapshotNode is one graph node in a snapshot, with compromise state and
// the asset overlay (criticality, exposure, coverage).
type SnapshotNode struct {
	Node              string `json:"node"`
	Type              string `json:"type"`
	Value             string `json:"value"`
	Compromise        string `json:"compromise"`
	Criticality       string `json:"criticality,omitempty"`
	Environment       string `json:"environment,omitempty"`
	InternetExposed   bool   `json:"internet_exposed"`
	CoverageAvailable int    `json:"coverage_available"`
	CoverageTotal     int    `json:"coverage_total"`
}

// SnapshotEdge is one relationship in a snapshot.
type SnapshotEdge struct {
	From            string `json:"from"`
	To              string `json:"to"`
	Relation        string `json:"relation"`
	State           string `json:"state"`
	SourceType      string `json:"source_type,omitempty"`
	SourceID        string `json:"source_id,omitempty"`
	CrossesBoundary bool   `json:"crosses_boundary"`
	Evidence        string `json:"evidence,omitempty"`
}

// Snapshot is a bounded, state-labeled view of the graph. A snapshot is
// never presented as live truth: it carries generated_at + states.
type Snapshot struct {
	GeneratedAt time.Time      `json:"generated_at"`
	States      []string       `json:"states"`
	Nodes       []SnapshotNode `json:"nodes"`
	Edges       []SnapshotEdge `json:"edges"`
	Truncated   bool           `json:"truncated"`
}

// maxSnapshotNodes / maxSnapshotEdges bound one snapshot (spec §5).
const (
	maxSnapshotNodes = 1000
	maxSnapshotEdges = 5000
)

// Brief is a bounded compromise-labeled graph view around a set of hosts.
type Brief struct {
	CompromisedNodes []string       `json:"compromised_nodes"`
	AtRiskNodes      []string       `json:"at_risk_nodes"`
	Edges            []SnapshotEdge `json:"edges,omitempty"`
	GeneratedAt      time.Time      `json:"generated_at"`
}

// nodeKey dedupes a node id.
func nodeKey(t, v string) string { return t + "\x00" + v }

// Snapshot builds a bounded graph view centered on an asset (or the whole
// observed neighborhood when assetID is empty).
func (b *Builder) Snapshot(ctx context.Context, states []string, depth int, assetID string) (*Snapshot, error) {
	if depth <= 0 {
		depth = 2
	}
	if depth > graph.MaxDepth {
		depth = graph.MaxDepth
	}

	// Root node.
	var root graph.NodeRef
	if assetID != "" {
		a, err := b.assets.Get(ctx, assetID)
		if err != nil {
			return nil, fmt.Errorf("asset %s: %w", assetID, err)
		}
		t, v := ParseNodeID(a.EntityRef)
		root = graph.NodeRef{Type: t, Value: v}
	} else {
		// No asset: start from the entity with the most relationships.
		tn, err := b.topNode(ctx)
		if err != nil {
			return nil, err
		}
		root = tn
	}

	// If root has no edges, still return it with overlay data.
	nodes, err := b.ger.Neighbors(ctx, root, depth, states)
	if err != nil {
		return nil, fmt.Errorf("neighbors: %w", err)
	}

	compromise, _, err := b.evaluateCompromise(ctx, b.edgesCached(ctx))
	if err != nil {
		return nil, err
	}

	out := &Snapshot{
		GeneratedAt: time.Now().UTC(),
		States:      states,
		Nodes:       []SnapshotNode{},
		Edges:       []SnapshotEdge{},
	}
	included := map[string]bool{}
	for _, n := range nodes {
		id := NodeID(n.Node.Type, n.Node.Value)
		if included[id] {
			continue
		}
		included[id] = true
		a, _ := b.assetFor(ctx, n.Node.Type, n.Node.Value)
		covAvail, covTotal := 0, 0
		if a != nil {
			if rows, err := b.coverage.Rows(ctx, a.ID); err == nil {
				for _, r := range rows {
					covTotal++
					if r.Available {
						covAvail++
					}
				}
			}
		}
		crit, env, exposed := "", "", false
		if a != nil {
			crit = a.Criticality
			env = a.Environment
			exposed = a.InternetExposed
		}
		cstate := string(NotAffected)
		if s, ok := compromise[id]; ok {
			cstate = string(s)
		}
		out.Nodes = append(out.Nodes, SnapshotNode{
			Node:              id,
			Type:              n.Node.Type,
			Value:             n.Node.Value,
			Compromise:        cstate,
			Criticality:       crit,
			Environment:       env,
			InternetExposed:   exposed,
			CoverageAvailable: covAvail,
			CoverageTotal:     covTotal,
		})
	}

	// Edges between included nodes (with meta state + boundary flag).
	if len(included) > 0 {
		edges, err := b.edgesWithin(ctx, included, states)
		if err != nil {
			return nil, err
		}
		out.Edges = edges
	}

	if len(out.Nodes) > maxSnapshotNodes {
		out.Nodes = out.Nodes[:maxSnapshotNodes]
		out.Truncated = true
	}
	if len(out.Edges) > maxSnapshotEdges {
		out.Edges = out.Edges[:maxSnapshotEdges]
		out.Truncated = true
	}
	return out, nil
}

// edgesCached returns all stateful edges (used for compromise evaluation).
func (b *Builder) edgesCached(ctx context.Context) []edgeRow {
	edges, _ := b.allStatefulEdges(ctx)
	return edges
}

// topNode picks the entity with the most relationships as a default root.
func (b *Builder) topNode(ctx context.Context) (graph.NodeRef, error) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT type, value FROM (
			SELECT from_type AS type, from_value AS value FROM relationships
			UNION ALL
			SELECT to_type AS type, to_value AS value FROM relationships
		) GROUP BY type, value ORDER BY COUNT(*) DESC LIMIT 1`)
	if err != nil {
		return graph.NodeRef{}, fmt.Errorf("top node: %w", err)
	}
	defer rows.Close()
	var t, v string
	if rows.Next() {
		if err := rows.Scan(&t, &v); err != nil {
			return graph.NodeRef{}, err
		}
	}
	if err := rows.Err(); err != nil {
		return graph.NodeRef{}, err
	}
	if t == "" {
		return graph.NodeRef{}, nil
	}
	return graph.NodeRef{Type: t, Value: v}, nil
}

// edgesWithin lists edges whose both endpoints are in the included set.
// All rows are read (and the cursor closed) before per-edge boundary
// checks run: the shared single-connection DB cannot nest queries.
func (b *Builder) edgesWithin(ctx context.Context, included map[string]bool, states []string) ([]SnapshotEdge, error) {
	type rawEdge struct {
		ft, fv, tt, tv, rel string
		state, srcType, srcID, ev string
	}
	rows, err := b.db.QueryContext(ctx, `
		SELECT r.from_type, r.from_value, r.to_type, r.to_value, r.relation,
		       COALESCE(m.status, 'observed'),
		       COALESCE(m.source_type, ''), COALESCE(m.source_id, ''),
		       COALESCE(m.evidence, '')
		FROM relationships r
		LEFT JOIN relationship_meta m ON (
			m.from_type = r.from_type AND m.from_value = r.from_value
			AND m.to_type = r.to_type AND m.to_value = r.to_value
			AND m.relation = r.relation)`)
	if err != nil {
		return nil, fmt.Errorf("edges: %w", err)
	}
	raw := []rawEdge{}
	for rows.Next() {
		var e rawEdge
		if err := rows.Scan(&e.ft, &e.fv, &e.tt, &e.tv, &e.rel, &e.state, &e.srcType, &e.srcID, &e.ev); err != nil {
			rows.Close()
			return nil, err
		}
		raw = append(raw, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	stateFilter := map[string]bool{}
	for _, s := range states {
		stateFilter[s] = true
	}
	out := []SnapshotEdge{}
	for _, e := range raw {
		if len(stateFilter) > 0 && !stateFilter[e.state] {
			continue
		}
		fid, tid := NodeID(e.ft, e.fv), NodeID(e.tt, e.tv)
		if !included[fid] || !included[tid] {
			continue
		}
		out = append(out, SnapshotEdge{
			From:            fid,
			To:              tid,
			Relation:        e.rel,
			State:           e.state,
			SourceType:      e.srcType,
			SourceID:        e.srcID,
			CrossesBoundary: b.crossesBoundary(ctx, e.ft, e.fv, e.tt, e.tv),
			Evidence:        e.ev,
		})
	}
	return out, nil
}

// ListPathsFilter narrows path queries.
type ListPathsFilter struct {
	From            string
	To              string
	TargetsCritical bool
	Status          string
	Limit           int
}

// ListPaths returns materialized paths matching the filter.
func (b *Builder) ListPaths(ctx context.Context, f ListPathsFilter) ([]AttackPath, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	conds := []string{}
	args := []any{}
	if f.From != "" {
		conds = append(conds, "source_node = ?")
		args = append(args, f.From)
	}
	if f.To != "" {
		conds = append(conds, "target_node = ?")
		args = append(args, f.To)
	}
	if f.TargetsCritical {
		conds = append(conds, "target_node IN (SELECT "+nodeIDExpr()+" FROM assets WHERE criticality = 'critical')")
	}
	if f.Status != "" {
		conds = append(conds, "status = ?")
		args = append(args, f.Status)
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	args = append(args, f.Limit)
	rows, err := b.db.QueryContext(ctx,
		`SELECT id, COALESCE(scenario_run_id, ''), source_node, target_node, status,
		        COALESCE(description, ''), risk, created_by, created_at
		 FROM attack_paths`+where+` ORDER BY risk DESC, created_at DESC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("list paths: %w", err)
	}
	defer rows.Close()
	out := []AttackPath{}
	for rows.Next() {
		var p AttackPath
		if err := rows.Scan(&p.ID, &p.ScenarioRunID, &p.SourceNode, &p.TargetNode, &p.Status, &p.Description, &p.Risk, &p.CreatedBy, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// nodeIDExpr renders asset entity_ref as 'type:value' (it already is).
func nodeIDExpr() string { return "entity_ref" }

// GetPath returns one path with its steps (evidence per step).
func (b *Builder) GetPath(ctx context.Context, id string) (*AttackPath, error) {
	var p AttackPath
	if err := b.db.QueryRowContext(ctx,
		`SELECT id, COALESCE(scenario_run_id, ''), source_node, target_node, status,
		        COALESCE(description, ''), risk, created_by, created_at
		 FROM attack_paths WHERE id = ?`, id).
		Scan(&p.ID, &p.ScenarioRunID, &p.SourceNode, &p.TargetNode, &p.Status, &p.Description, &p.Risk, &p.CreatedBy, &p.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("path %s not found", id)
		}
		return nil, fmt.Errorf("get path: %w", err)
	}
	rows, err := b.db.QueryContext(ctx,
		`SELECT pos, from_node, to_node, edge_relation, edge_state, COALESCE(technique, ''), COALESCE(evidence, '')
		 FROM path_steps WHERE path_id = ? ORDER BY pos`, id)
	if err != nil {
		return nil, fmt.Errorf("path steps: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var s PathStep
		var tech, ev sql.NullString
		if err := rows.Scan(&s.Pos, &s.FromNode, &s.ToNode, &s.EdgeRelation, &s.EdgeState, &tech, &ev); err != nil {
			return nil, err
		}
		s.Technique = tech.String
		s.Evidence = ev.String
		p.Steps = append(p.Steps, s)
	}
	return &p, rows.Err()
}

// WhatNext answers "what could an attacker do next" for a node:
// scenario-expected techniques + potential edges out of the node.
type WhatNext struct {
	Node               string         `json:"node"`
	ExpectedTechniques []string       `json:"expected_techniques"`
	Scenarios          []string       `json:"scenarios"`
	PotentialEdges     []SnapshotEdge `json:"potential_edges"`
	GeneratedAt        time.Time      `json:"generated_at"`
}

// WhatNext builds the next-steps view for one node.
func (b *Builder) WhatNext(ctx context.Context, nodeType, nodeValue string) (*WhatNext, error) {
	id := NodeID(nodeType, nodeValue)
	out := &WhatNext{
		Node:               id,
		ExpectedTechniques: []string{},
		Scenarios:          []string{},
		PotentialEdges:     []SnapshotEdge{},
		GeneratedAt:        time.Now().UTC(),
	}

	// Expected techniques from active scenario runs scoped to this node.
	if nodeType == "host" {
		rows, err := b.db.QueryContext(ctx,
			`SELECT id, definition FROM scenario_runs WHERE status = 'active' AND scope = ?`,
			"host:"+nodeValue)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var runID, def string
				if err := rows.Scan(&runID, &def); err != nil {
					break
				}
				var defJSON map[string]any
				if err := json.Unmarshal([]byte(def), &defJSON); err == nil {
					out.Scenarios = append(out.Scenarios, runID)
					if exp, ok := defJSON["expected_techniques"].([]any); ok {
						for _, e := range exp {
							if s, ok := e.(string); ok {
								out.ExpectedTechniques = append(out.ExpectedTechniques, s)
							}
						}
					}
				}
			}
		}
	}

	// Potential edges: outgoing access relations from this node.
	edges, err := b.allStatefulEdges(ctx)
	if err != nil {
		return nil, err
	}
	for _, e := range edges {
		if NodeID(e.FromType, e.FromValue) != id {
			continue
		}
		if e.State != "observed" && e.State != "inferred" {
			continue
		}
		if !accessRelations[strings.ToLower(e.Relation)] {
			continue
		}
		out.PotentialEdges = append(out.PotentialEdges, SnapshotEdge{
			From:            id,
			To:              NodeID(e.ToType, e.ToValue),
			Relation:        e.Relation,
			State:           e.State,
			CrossesBoundary: b.crossesBoundary(ctx, nodeType, nodeValue, e.ToType, e.ToValue),
			Evidence:        e.Evidence,
		})
	}
	return out, nil
}

// GraphBrief returns the bounded, state-labeled neighborhood of a set of
// hosts: the compromised / at-risk nodes, and the edges touching those
// hosts. It is the AI analyst's attack-graph context
// (ai-security-analysis.md §1) and, like all graph views, is derived on
// demand — never a per-node persisted claim.
func (b *Builder) GraphBrief(ctx context.Context, hosts []string, edgeLimit int) (*Brief, error) {
	if edgeLimit <= 0 || edgeLimit > 100 {
		edgeLimit = 25
	}
	edges, err := b.allStatefulEdges(ctx)
	if err != nil {
		return nil, err
	}
	state, _, err := b.evaluateCompromise(ctx, edges)
	if err != nil {
		return nil, err
	}

	compromised := []string{}
	atRisk := []string{}
	for id, s := range state {
		switch s {
		case CompromisedObserved, CompromisedInferred:
			compromised = append(compromised, id)
		case AtRiskPotential:
			atRisk = append(atRisk, id)
		}
	}
	sort.Strings(compromised)
	sort.Strings(atRisk)

	hostSet := map[string]bool{}
	for _, h := range hosts {
		hostSet["host:"+h] = true
	}
	out := &Brief{
		CompromisedNodes: compromised,
		AtRiskNodes:      atRisk,
		GeneratedAt:      time.Now().UTC(),
	}
	for _, e := range edges {
		if e.State != "observed" && e.State != "inferred" {
			continue
		}
		from := NodeID(e.FromType, e.FromValue)
		to := NodeID(e.ToType, e.ToValue)
		if !hostSet[from] && !hostSet[to] {
			continue
		}
		out.Edges = append(out.Edges, SnapshotEdge{
			From:            from,
			To:              to,
			Relation:        e.Relation,
			State:           e.State,
			CrossesBoundary: b.crossesBoundary(ctx, e.FromType, e.FromValue, e.ToType, e.ToValue),
			Evidence:        e.Evidence,
		})
		if len(out.Edges) >= edgeLimit {
			break
		}
	}
	return out, nil
}

