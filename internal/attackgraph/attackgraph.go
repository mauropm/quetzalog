// Package attackgraph answers "if X is compromised, what can the attacker
// reach, what have they actually done, and what might they try next?" with
// a strict observed / inferred / potential / blocked separation
// (attack-graph.md; spec §17: never present inferred as confirmed).
package attackgraph

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"quetzalog/internal/assets"
	"quetzalog/internal/coverage"
	"quetzalog/internal/graph"
)

// NodeState is a node's compromise assessment (derived, never stored
// per-edge).
type NodeState string

const (
	// NotAffected has no compromise evidence.
	NotAffected NodeState = "not_affected"
	// CompromisedObserved: observed edges into the node represent
	// access/exec/credentialed activity from outside its trust boundary.
	CompromisedObserved NodeState = "compromised_observed"
	// CompromisedInferred: same, via inferred edges only.
	CompromisedInferred NodeState = "compromised_inferred"
	// AtRiskPotential: reachable from a compromised node.
	AtRiskPotential NodeState = "at_risk_potential"
)

// step weights for path risk (documented defaults, attack-graph.md §2).
var stepWeight = map[string]float64{
	"observed":  1.0,
	"inferred":  0.6,
	"potential": 0.3,
	"blocked":   0.0,
}

// accessRelations are relations that can compromise the target when they
// arrive from outside the target's trust boundary.
var accessRelations = map[string]bool{
	"authenticates": true, "auth": true, "login": true, "logon": true,
	"exec": true, "execs": true, "executes": true, "runs": true,
	"accesses": true, "reads": true, "writes": true, "transfers": true,
	"lateral_movement": true, "connects_to": true, "connects": true,
}

// critFactor maps asset criticality to a risk multiplier.
var critFactor = map[string]float64{
	"critical": 1.0,
	"high":     0.7,
	"medium":   0.4,
	"low":      0.2,
}

// maxPaths caps materialized potential paths per recompute.
const maxPaths = 50

// Builder computes compromise state and materializes attack paths.
type Builder struct {
	db       *sql.DB
	assets   *assets.Store
	coverage *coverage.Store
	ger      *graph.Graph
	logger   *slog.Logger
}

// NewBuilder creates a builder over the shared database.
func NewBuilder(db *sql.DB, assetsStore *assets.Store, cov *coverage.Store, logger *slog.Logger) *Builder {
	if assetsStore == nil {
		assetsStore = assets.NewStore(db)
	}
	if cov == nil {
		cov = coverage.NewStore(db)
	}
	return &Builder{db: db, assets: assetsStore, coverage: cov, ger: graph.NewGraph(db), logger: logger}
}

func (b *Builder) log(msg string, kv ...any) {
	if b.logger != nil {
		b.logger.Info("attackgraph: "+msg, kv...)
	}
}

// NodeID renders a node in the spec's 'type:value' form.
func NodeID(nodeType, value string) string { return nodeType + ":" + value }

// ParseNodeID splits a 'type:value' node id.
func ParseNodeID(id string) (string, string) {
	t, v, _ := strings.Cut(id, ":")
	return t, v
}

// assetFor returns the asset backing a node, or nil.
func (b *Builder) assetFor(ctx context.Context, nodeType, value string) (*assets.Asset, error) {
	if nodeType == "" || value == "" {
		return nil, nil
	}
	a, err := b.assets.GetByEntityRef(ctx, NodeID(nodeType, value))
	if err != nil {
		return nil, nil
	}
	return a, nil
}

// trustKey is the boundary an asset sits in: explicit trust_boundary:*
// tag, else its environment, else "unknown".
func trustKey(a *assets.Asset) string {
	if a == nil {
		return "unknown"
	}
	for _, t := range a.Tags {
		if strings.HasPrefix(t, "trust_boundary:") {
			return strings.TrimPrefix(t, "trust_boundary:")
		}
	}
	if a.Environment != "" {
		return a.Environment
	}
	return "unknown"
}

// crossesBoundary reports whether an edge from `from` into `to` crosses a
// trust boundary (the dangerous direction is outside → inside).
func (b *Builder) crossesBoundary(ctx context.Context, fromType, fromValue, toType, toValue string) bool {
	fa, _ := b.assetFor(ctx, fromType, fromValue)
	ta, _ := b.assetFor(ctx, toType, toValue)

	// A known external source into a known internal target always crosses.
	if fa != nil && fa.InternetExposed && ta != nil && !ta.InternetExposed {
		return true
	}
	// Explicit boundary tags differ.
	if fa != nil && ta != nil {
		fb, tb := trustKey(fa), trustKey(ta)
		if fb != "unknown" && tb != "unknown" && fb != tb {
			return true
		}
	}
	// An unattributed source (no asset) into a known internal target is
	// treated as crossing: unknown origin cannot be cleared.
	if fa == nil && ta != nil && !ta.InternetExposed {
		return true
	}
	return false
}

type edgeRow struct {
	FromType, FromValue string
	ToType, ToValue     string
	Relation            string
	State               string
	SourceID            string
	Evidence            string
}

// allStatefulEdges loads relationships with their meta state.
func (b *Builder) allStatefulEdges(ctx context.Context) ([]edgeRow, error) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT r.from_type, r.from_value, r.to_type, r.to_value, r.relation,
		       COALESCE(m.status, 'observed'),
		       COALESCE(m.source_id, ''), COALESCE(m.evidence, '')
		FROM relationships r
		LEFT JOIN relationship_meta m ON (
			m.from_type = r.from_type AND m.from_value = r.from_value
			AND m.to_type = r.to_type AND m.to_value = r.to_value
			AND m.relation = r.relation)`)
	if err != nil {
		return nil, fmt.Errorf("query relationships: %w", err)
	}
	defer rows.Close()
	out := []edgeRow{}
	for rows.Next() {
		var e edgeRow
		if err := rows.Scan(&e.FromType, &e.FromValue, &e.ToType, &e.ToValue, &e.Relation, &e.State, &e.SourceID, &e.Evidence); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// evaluateCompromise derives each node's compromise state from the edges.
func (b *Builder) evaluateCompromise(ctx context.Context, edges []edgeRow) (map[string]NodeState, map[string]string, error) {
	state := map[string]NodeState{}
	source := map[string]string{} // compromised node → originating external node

	crossCache := map[string]bool{}
	edgeCrosses := func(e edgeRow) bool {
		key := e.FromType + "\x00" + e.FromValue + "\x00" + e.ToType + "\x00" + e.ToValue
		if v, ok := crossCache[key]; ok {
			return v
		}
		v := b.crossesBoundary(ctx, e.FromType, e.FromValue, e.ToType, e.ToValue)
		crossCache[key] = v
		return v
	}

	for _, e := range edges {
		if !accessRelations[strings.ToLower(e.Relation)] {
			continue
		}
		if e.State != "observed" && e.State != "inferred" {
			continue
		}
		if !edgeCrosses(e) {
			continue
		}
		dst := NodeID(e.ToType, e.ToValue)
		switch e.State {
		case "observed":
			if cur, ok := state[dst]; !ok || cur != CompromisedObserved {
				state[dst] = CompromisedObserved
				source[dst] = NodeID(e.FromType, e.FromValue)
			}
		case "inferred":
			if cur, ok := state[dst]; !ok || cur != CompromisedObserved {
				state[dst] = CompromisedInferred
				source[dst] = NodeID(e.FromType, e.FromValue)
			}
		}
	}

	// Potential reachability: BFS over observed/inferred edges from every
	// compromised node (depth ≤ 4).
	adj := map[string]map[string]bool{}
	for _, e := range edges {
		if e.State != "observed" && e.State != "inferred" {
			continue
		}
		from, to := NodeID(e.FromType, e.FromValue), NodeID(e.ToType, e.ToValue)
		if adj[from] == nil {
			adj[from] = map[string]bool{}
		}
		adj[from][to] = true
	}
	compromised := []string{}
	for n, s := range state {
		if s == CompromisedObserved || s == CompromisedInferred {
			compromised = append(compromised, n)
		}
	}
	seen := map[string]bool{}
	for _, c := range compromised {
		seen[c] = true
	}
	queue := append([]string{}, compromised...)
	depth := map[string]int{}
	for _, c := range compromised {
		depth[c] = 0
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if depth[cur] >= 4 {
			continue
		}
		for nb := range adj[cur] {
			if seen[nb] {
				continue
			}
			seen[nb] = true
			if cur2, ok := state[nb]; !ok || (cur2 != CompromisedObserved && cur2 != CompromisedInferred) {
				state[nb] = AtRiskPotential
			}
			depth[nb] = depth[cur] + 1
			queue = append(queue, nb)
		}
	}
	// Mark everything seen but unclassified as not affected (so snapshots
	// can enumerate the full neighborhood).
	for n := range seen {
		if _, ok := state[n]; !ok {
			state[n] = NotAffected
		}
	}
	return state, source, nil
}

// PathStep is one hop of a materialized attack path.
type PathStep struct {
	Pos          int    `json:"pos"`
	FromNode     string `json:"from_node"`
	ToNode       string `json:"to_node"`
	EdgeRelation string `json:"edge_relation"`
	EdgeState    string `json:"edge_state"`
	Technique    string `json:"technique,omitempty"`
	Evidence     string `json:"evidence,omitempty"`
}

// AttackPath is one materialized path row.
type AttackPath struct {
	ID            string     `json:"id"`
	ScenarioRunID string     `json:"scenario_run_id,omitempty"`
	SourceNode    string     `json:"source_node"`
	TargetNode    string     `json:"target_node"`
	Status        string     `json:"status"`
	Description   string     `json:"description,omitempty"`
	Risk          float64    `json:"risk"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	Steps         []PathStep `json:"steps,omitempty"`
}

// pathRisk computes Σ step_weight × target criticality factor.
func pathRisk(steps []PathStep, targetCriticality string) float64 {
	f := critFactor[targetCriticality]
	if f == 0 {
		f = 0.4
	}
	total := 0.0
	for _, s := range steps {
		w, ok := stepWeight[s.EdgeState]
		if !ok {
			w = 0.3
		}
		total += w
	}
	return total * f
}

// writePath upserts one path (and its steps).
func (b *Builder) writePath(ctx context.Context, p *AttackPath, steps []PathStep) error {
	if _, err := b.db.ExecContext(ctx,
		`INSERT INTO attack_paths (id, scenario_run_id, source_node, target_node, status, description, risk, created_by, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   status = excluded.status,
		   description = excluded.description,
		   risk = excluded.risk,
		   created_at = excluded.created_at`,
		p.ID, p.ScenarioRunID, p.SourceNode, p.TargetNode, p.Status, p.Description, p.Risk, p.CreatedBy, p.CreatedAt); err != nil {
		return fmt.Errorf("write path: %w", err)
	}
	if _, err := b.db.ExecContext(ctx, `DELETE FROM path_steps WHERE path_id = ?`, p.ID); err != nil {
		return fmt.Errorf("clear steps: %w", err)
	}
	for i, s := range steps {
		s.Pos = i
		if _, err := b.db.ExecContext(ctx,
			`INSERT INTO path_steps (path_id, pos, from_node, to_node, edge_relation, edge_state, technique, evidence)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			p.ID, s.Pos, s.FromNode, s.ToNode, s.EdgeRelation, s.EdgeState, s.Technique, s.Evidence); err != nil {
			return fmt.Errorf("write step: %w", err)
		}
	}
	return nil
}

// materializeObservedPaths replays observed edges from the originating
// external node to each observed-compromised internal node.
func (b *Builder) materializeObservedPaths(ctx context.Context, edges []edgeRow, source map[string]string) int {
	n := 0
	seen := map[string]bool{}
	// Build per-destination observed compromise edges.
	byDest := map[string]edgeRow{}
	for _, e := range edges {
		if e.State != "observed" || !accessRelations[strings.ToLower(e.Relation)] {
			continue
		}
		dst := NodeID(e.ToType, e.ToValue)
		if _, ok := source[dst]; ok {
			if _, dup := byDest[dst]; !dup {
				byDest[dst] = e
			}
		}
	}
	for dst, e := range byDest {
		src := source[dst]
		key := "observed\x00" + src + "\x00" + dst
		if seen[key] {
			continue
		}
		seen[key] = true

		// Prefer a multi-hop observed path if one exists; fall back to the
		// direct edge.
		steps := []PathStep{{
			FromNode:     src,
			ToNode:       dst,
			EdgeRelation: e.Relation,
			EdgeState:    "observed",
			Evidence:     e.Evidence,
		}}
		ft, fv := ParseNodeID(src)
		tt, tv := ParseNodeID(dst)
		if paths, err := b.ger.Path(ctx, graph.NodeRef{Type: ft, Value: fv}, graph.NodeRef{Type: tt, Value: tv}, 4, []string{"observed"}); err == nil && len(paths) > 0 {
			if p := pathFromGraph(paths[0]); p != nil {
				steps = p
			}
		}

		crit := b.criticalityOf(ctx, tt, tv)
		p := &AttackPath{
			ID:         "ap-" + stableHash(key),
			SourceNode: src,
			TargetNode: dst,
			Status:     "observed",
			Risk:       pathRisk(steps, crit),
			CreatedBy:  "engine",
			CreatedAt:  time.Now().UTC(),
		}
		p.Description = fmt.Sprintf("Observed access chain %s → %s (%s)", src, dst, e.Relation)
		if err := b.writePath(ctx, p, steps); err != nil {
			b.log("write observed path", "error", err)
			continue
		}
		n++
	}
	return n
}

// pathFromGraph converts a graph.Path to PathSteps.
func pathFromGraph(p graph.Path) []PathStep {
	if len(p.Nodes) < 2 {
		return nil
	}
	steps := make([]PathStep, 0, len(p.Nodes)-1)
	for i := 0; i+1 < len(p.Nodes); i++ {
		st := "observed"
		if i < len(p.States) {
			st = p.States[i]
		}
		steps = append(steps, PathStep{
			FromNode:     NodeID(p.Nodes[i].Type, p.Nodes[i].Value),
			ToNode:       NodeID(p.Nodes[i+1].Type, p.Nodes[i+1].Value),
			EdgeState:    st,
			EdgeRelation: "observed-edge",
		})
	}
	return steps
}

// materializePotentialPaths runs a bounded BFS from each compromised node
// over observed ∪ inferred edges toward critical assets. Stale potential
// paths are dropped first (they are recomputed, never accumulated).
func (b *Builder) materializePotentialPaths(ctx context.Context, edges []edgeRow, state map[string]NodeState, now time.Time) int {
	if _, err := b.db.ExecContext(ctx, `DELETE FROM attack_paths WHERE status = 'potential'`); err != nil {
		b.log("drop stale potential paths", "error", err)
	}
	if _, err := b.db.ExecContext(ctx, `DELETE FROM path_steps WHERE path_id IN (SELECT id FROM attack_paths WHERE status = 'potential')`); err != nil {
		b.log("drop stale potential steps", "error", err)
	}

	// Candidate targets: critical assets.
	targets := map[string]bool{}
	assetsList, total, _ := b.assets.List(ctx, assets.ListFilter{})
	_ = total
	for _, a := range assetsList {
		if a.Criticality == "critical" {
			targets[NodeID(a.EntityType, assetValue(a))] = true
		}
	}

	adj := map[string]map[string]edgeRow{}
	for _, e := range edges {
		if e.State != "observed" && e.State != "inferred" {
			continue
		}
		from, to := NodeID(e.FromType, e.FromValue), NodeID(e.ToType, e.ToValue)
		if adj[from] == nil {
			adj[from] = map[string]edgeRow{}
		}
		if _, ok := adj[from][to]; !ok {
			adj[from][to] = e
		}
	}

	type cand struct {
		steps []PathStep
		to    string
	}
	compromised := []string{}
	for n, s := range state {
		if s == CompromisedObserved || s == CompromisedInferred {
			compromised = append(compromised, n)
		}
	}
	sort.Strings(compromised)

	found := map[string]cand{}
	for _, c := range compromised {
		frontier := []cand{{steps: []PathStep{}, to: c}}
		visited := map[string]bool{c: true}
		depth := 0
		for depth < 4 && len(frontier) > 0 {
			depth++
			var next []cand
			for _, cur := range frontier {
				for nb, e := range adj[cur.to] {
					if visited[nb] {
						continue
					}
					visited[nb] = true
					st := e.State
					if st == "inferred" {
						st = "inferred"
					}
					step := PathStep{
						FromNode:     cur.to,
						ToNode:       nb,
						EdgeRelation: e.Relation,
						EdgeState:    st,
						Evidence:     e.Evidence,
					}
					if _, ok := targets[nb]; ok {
						if prev, ok := found[nb]; !ok || len(cur.steps) < len(prev.steps) {
							found[nb] = cand{steps: append(append([]PathStep{}, cur.steps...), step), to: nb}
						}
						continue
					}
					next = append(next, cand{steps: append(append([]PathStep{}, cur.steps...), step), to: nb})
				}
			}
			frontier = next
		}
	}

	// Rank: edge-count ascending, then target criticality (all critical
	// here), then source node.
	keys := make([]string, 0, len(found))
	for k := range found {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := found[keys[i]], found[keys[j]]
		if len(a.steps) != len(b.steps) {
			return len(a.steps) < len(b.steps)
		}
		return keys[i] < keys[j]
	})

	n := 0
	for _, k := range keys {
		if n >= maxPaths {
			break
		}
		c := found[k]
		src := c.steps[0].FromNode
		key := "potential\x00" + src + "\x00" + k
		p := &AttackPath{
			ID:         "ap-" + stableHash(key),
			SourceNode: src,
			TargetNode: k,
			Status:     "potential",
			Risk:       pathRisk(c.steps, "critical"),
			CreatedBy:  "engine",
			CreatedAt:  now,
		}
		p.Description = fmt.Sprintf("Potential path %s → %s (%d hops, %s)", src, k, len(c.steps), stateClass(c.steps))
		if err := b.writePath(ctx, p, c.steps); err != nil {
			b.log("write potential path", "error", err)
			continue
		}
		n++
	}
	return n
}

func stateClass(steps []PathStep) string {
	classes := map[string]bool{}
	for _, s := range steps {
		classes[s.EdgeState] = true
	}
	out := make([]string, 0, len(classes))
	for c := range classes {
		out = append(out, c)
	}
	sort.Strings(out)
	return strings.Join(out, "+")
}

// assetValue extracts the value part of an asset's entity_ref.
func assetValue(a *assets.Asset) string {
	if a.EntityRef == "" {
		return a.Name
	}
	_, v, _ := strings.Cut(a.EntityRef, ":")
	if v == "" {
		return a.Name
	}
	return v
}

// Recompute rebuilds compromise state and (re)materializes attack paths.
// Returns the number of observed + potential paths written.
func (b *Builder) Recompute(ctx context.Context) (int, error) {
	edges, err := b.allStatefulEdges(ctx)
	if err != nil {
		return 0, err
	}
	state, source, err := b.evaluateCompromise(ctx, edges)
	if err != nil {
		return 0, err
	}
	obs := b.materializeObservedPaths(ctx, edges, source)
	pot := b.materializePotentialPaths(ctx, edges, state, time.Now().UTC())
	b.log("recomputed", "compromised_nodes", len(source), "observed_paths", obs, "potential_paths", pot)
	return obs + pot, nil
}

// criticalityOf resolves a node's asset criticality.
func (b *Builder) criticalityOf(ctx context.Context, nodeType, value string) string {
	if a, _ := b.assetFor(ctx, nodeType, value); a != nil {
		return a.Criticality
	}
	return ""
}

// stableHash renders a deterministic short id.
func stableHash(s string) string {
	var h uint32 = 2166136261
	for _, c := range s {
		h ^= uint32(c)
		h *= 16777619
	}
	return fmt.Sprintf("%08x", h)
}
