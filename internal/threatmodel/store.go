// Package threatmodel implements multi-framework threat models (STRIDE,
// MITRE ATT&CK, Cyber Kill Chain, D3FEND) derived from observed telemetry
// and labeled observed / inferred / assumed, with drift tracking
// (threat-model.md; specs §15, §49, §50).
package threatmodel

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Model is one threat model.
type Model struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Source    string    `json:"source"` // analyst | telemetry | hybrid
	Version   int       `json:"version"`
	Scope     string    `json:"scope,omitempty"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TMNode is one node of a model.
type TMNode struct {
	ModelID    string `json:"model_id"`
	NodeID     string `json:"node_id"`
	Kind       string `json:"kind"`
	Label      string `json:"label"`
	EntityRef  string `json:"entity_ref,omitempty"`
	LabelState string `json:"label_state"`
	Attrs      string `json:"attrs,omitempty"`
}

// TMEdge is one directed relation between nodes.
type TMEdge struct {
	ModelID    string `json:"model_id"`
	FromNode   string `json:"from_node"`
	ToNode     string `json:"to_node"`
	Relation   string `json:"relation"`
	LabelState string `json:"label_state"`
	Evidence   string `json:"evidence,omitempty"`
}

// Threat is one threat, multi-framework labeled.
type Threat struct {
	ModelID          string   `json:"model_id"`
	ThreatID         string   `json:"threat_id"`
	NodeID           string   `json:"node_id,omitempty"`
	EdgeID           string   `json:"edge_id,omitempty"`
	Description      string   `json:"description"`
	Stride           string   `json:"stride,omitempty"`
	KillChainPhase   string   `json:"kill_chain_phase,omitempty"`
	Techniques       []string `json:"techniques,omitempty"`
	D3FendMitigations []string `json:"d3fend_mitigations,omitempty"`
	Likelihood       string   `json:"likelihood"`
	Impact           string   `json:"impact"`
	LabelState       string   `json:"label_state"`
}

// Control is one catalog control.
type Control struct {
	ControlID   string `json:"control_id"`
	Framework   string `json:"framework"`
	Ref         string `json:"ref"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// ThreatControl maps a threat to a control.
type ThreatControl struct {
	ThreatRef    string `json:"threat_ref"`
	ControlID    string `json:"control_id"`
	MappingState string `json:"mapping_state"`
	Evidence     string `json:"evidence,omitempty"`
}

// Snapshot is one drift-tracking snapshot of a model version.
type Snapshot struct {
	ModelID     string    `json:"model_id"`
	Version     int       `json:"version"`
	Snapshot    string    `json:"snapshot"`
	Changes     string    `json:"changes"`
	TriggeredBy string    `json:"triggered_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Changes is the structured diff of a refresh (spec §50).
type Changes struct {
	AddedNodes     []string `json:"added_nodes"`
	RemovedNodes   []string `json:"removed_nodes"`
	AddedEdges     []string `json:"added_edges"`
	RemovedEdges   []string `json:"removed_edges"`
	AddedThreats   []string `json:"added_threats"`
	RemovedThreats []string `json:"removed_threats"`
	NewRisks       []string `json:"new_risks"`
	RemovedRisks   []string `json:"removed_risks"`
}

// Store persists threat models and their content.
type Store struct {
	db *sql.DB
}

// NewStore creates a threat-model store.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

func encodeList(list []string) string {
	if len(list) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(list)
	return string(b)
}

func decodeList(s string) []string {
	if s == "" {
		return []string{}
	}
	var out []string
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// CreateModel inserts a new model.
func (s *Store) CreateModel(ctx context.Context, m *Model) error {
	if m == nil {
		return fmt.Errorf("nil model")
	}
	if m.ID == "" {
		m.ID = "tm-" + randomID()
	}
	if m.Source == "" {
		m.Source = "analyst"
	}
	if m.Version <= 0 {
		m.Version = 1
	}
	if m.Status == "" {
		m.Status = "active"
	}
	now := time.Now().UTC()
	m.CreatedAt = now
	m.UpdatedAt = now
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO threat_models (id, name, source, version, scope, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, m.Name, m.Source, m.Version, m.Scope, m.Status, m.CreatedAt, m.UpdatedAt); err != nil {
		return fmt.Errorf("create model: %w", err)
	}
	return nil
}

// GetModel fetches one model.
func (s *Store) GetModel(ctx context.Context, id string) (*Model, error) {
	var m Model
	if err := s.db.QueryRowContext(ctx,
		`SELECT id, name, source, version, COALESCE(scope, ''), status, created_at, updated_at
		 FROM threat_models WHERE id = ?`, id).
		Scan(&m.ID, &m.Name, &m.Source, &m.Version, &m.Scope, &m.Status, &m.CreatedAt, &m.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("model %s not found", id)
		}
		return nil, fmt.Errorf("get model: %w", err)
	}
	return &m, nil
}

// ListModels lists all models.
func (s *Store) ListModels(ctx context.Context) ([]Model, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, source, version, COALESCE(scope, ''), status, created_at, updated_at
		 FROM threat_models ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list models: %w", err)
	}
	defer rows.Close()
	out := []Model{}
	for rows.Next() {
		var m Model
		if err := rows.Scan(&m.ID, &m.Name, &m.Source, &m.Version, &m.Scope, &m.Status, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteModel removes a model and its content.
func (s *Store) DeleteModel(ctx context.Context, id string) error {
	for _, q := range []string{
		`DELETE FROM tm_nodes WHERE model_id = ?`,
		`DELETE FROM tm_edges WHERE model_id = ?`,
		`DELETE FROM threats WHERE model_id = ?`,
		`DELETE FROM model_snapshots WHERE model_id = ?`,
		`DELETE FROM threat_models WHERE id = ?`,
	} {
		if _, err := s.db.ExecContext(ctx, q, id); err != nil {
			return fmt.Errorf("delete model: %w", err)
		}
	}
	return nil
}

// ReplaceContent atomically swaps a model's nodes/edges/threats and bumps
// its version.
func (s *Store) ReplaceContent(ctx context.Context, modelID string, nodes []TMNode, edges []TMEdge, threats []Threat, triggeredBy string) (*Snapshot, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Read the current content first so the drift diff is exact.
	prevNodes, prevEdges, prevThreats, err := s.readContentTx(ctx, tx, modelID)
	if err != nil {
		return nil, err
	}

	for _, q := range []string{
		`DELETE FROM tm_nodes WHERE model_id = ?`,
		`DELETE FROM tm_edges WHERE model_id = ?`,
		`DELETE FROM threats WHERE model_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, modelID); err != nil {
			return nil, fmt.Errorf("clear content: %w", err)
		}
	}
	for _, n := range nodes {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO tm_nodes (model_id, node_id, kind, label, entity_ref, label_state, attrs)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			modelID, n.NodeID, n.Kind, n.Label, n.EntityRef, n.LabelState, n.Attrs); err != nil {
			return nil, fmt.Errorf("insert node: %w", err)
		}
	}
	for _, e := range edges {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO tm_edges (model_id, from_node, to_node, relation, label_state, evidence)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			modelID, e.FromNode, e.ToNode, e.Relation, e.LabelState, e.Evidence); err != nil {
			return nil, fmt.Errorf("insert edge: %w", err)
		}
	}
	for _, th := range threats {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO threats (model_id, threat_id, node_id, edge_id, description, stride,
			                      kill_chain_phase, techniques, d3fend_mitigations, likelihood, impact, label_state)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			modelID, th.ThreatID, th.NodeID, th.EdgeID, th.Description, th.Stride,
			th.KillChainPhase, encodeList(th.Techniques), encodeList(th.D3FendMitigations),
			th.Likelihood, th.Impact, th.LabelState); err != nil {
			return nil, fmt.Errorf("insert threat: %w", err)
		}
	}

	var version int
	if err := tx.QueryRowContext(ctx,
		`SELECT version FROM threat_models WHERE id = ?`, modelID).Scan(&version); err != nil {
		return nil, fmt.Errorf("get version: %w", err)
	}
	version++
	if _, err := tx.ExecContext(ctx,
		`UPDATE threat_models SET version = ?, updated_at = ? WHERE id = ?`,
		version, time.Now().UTC(), modelID); err != nil {
		return nil, fmt.Errorf("bump version: %w", err)
	}

	// Snapshot the new content (capped) + exact structured changes vs. the
	// pre-replace content (spec §50).
	snapshotJSON, _ := json.Marshal(map[string]any{
		"version": version,
		"nodes":   len(nodes),
		"edges":   len(edges),
		"threats": len(threats),
	})
	if len(snapshotJSON) > 50*1024 {
		snapshotJSON, _ = json.Marshal(map[string]any{
			"version": version, "summarized": true,
			"nodes": len(nodes), "edges": len(edges), "threats": len(threats),
		})
	}
	changes := computeChanges(prevNodes, prevEdges, prevThreats, nodes, edges, threats)
	changesJSON, _ := json.Marshal(changes)
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO model_snapshots (model_id, version, snapshot, changes, triggered_by, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		modelID, version, string(snapshotJSON), string(changesJSON), triggeredBy, now); err != nil {
		return nil, fmt.Errorf("write snapshot: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return &Snapshot{
		ModelID:     modelID,
		Version:     version,
		Snapshot:    string(snapshotJSON),
		Changes:     string(changesJSON),
		TriggeredBy: triggeredBy,
		CreatedAt:   now,
	}, nil
}

// readContentTx reads the current content within a transaction (before a
// replace) for drift diffing.
func (s *Store) readContentTx(ctx context.Context, tx *sql.Tx, modelID string) (map[string]bool, map[string]bool, map[string]Threat, error) {
	nodeSet := map[string]bool{}
	rows, err := tx.QueryContext(ctx, `SELECT node_id FROM tm_nodes WHERE model_id = ?`, modelID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read nodes: %w", err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, nil, nil, err
		}
		nodeSet[id] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, nil, err
	}

	edgeSet := map[string]bool{}
	rows, err = tx.QueryContext(ctx, `SELECT from_node, to_node, relation FROM tm_edges WHERE model_id = ?`, modelID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read edges: %w", err)
	}
	for rows.Next() {
		var f, t, rel string
		if err := rows.Scan(&f, &t, &rel); err != nil {
			rows.Close()
			return nil, nil, nil, err
		}
		edgeSet[f+"→"+t+":"+rel] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, nil, err
	}

	threats := map[string]Threat{}
	rows, err = tx.QueryContext(ctx,
		`SELECT threat_id, COALESCE(likelihood, 'unknown'), COALESCE(impact, 'unknown') FROM threats WHERE model_id = ?`, modelID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read threats: %w", err)
	}
	for rows.Next() {
		var th Threat
		if err := rows.Scan(&th.ThreatID, &th.Likelihood, &th.Impact); err != nil {
			rows.Close()
			return nil, nil, nil, err
		}
		threats[th.ThreatID] = th
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, nil, err
	}
	return nodeSet, edgeSet, threats, nil
}

// riskRank orders impact levels for new/removed risk detection.
var riskRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// computeChanges produces the structured drift diff (spec §50):
// added/removed nodes/edges/threats + new_risks (impact increased) +
// removed_risks (a previously tracked risk vanished after the change).
func computeChanges(prevNodes, prevEdges map[string]bool, prevThreats map[string]Threat,
	nodes []TMNode, edges []TMEdge, threats []Threat) *Changes {
	c := &Changes{}
	newNodeSet := map[string]bool{}
	for _, n := range nodes {
		newNodeSet[n.NodeID] = true
		if !prevNodes[n.NodeID] {
			c.AddedNodes = append(c.AddedNodes, n.NodeID)
		}
	}
	for id := range prevNodes {
		if !newNodeSet[id] {
			c.RemovedNodes = append(c.RemovedNodes, id)
		}
	}

	newEdgeSet := map[string]bool{}
	for _, e := range edges {
		key := e.FromNode + "→" + e.ToNode + ":" + e.Relation
		newEdgeSet[key] = true
		if !prevEdges[key] {
			c.AddedEdges = append(c.AddedEdges, key)
		}
	}
	for key := range prevEdges {
		if !newEdgeSet[key] {
			c.RemovedEdges = append(c.RemovedEdges, key)
		}
	}

	newThreatSet := map[string]Threat{}
	for _, th := range threats {
		newThreatSet[th.ThreatID] = th
		if _, existed := prevThreats[th.ThreatID]; !existed {
			c.AddedThreats = append(c.AddedThreats, th.ThreatID)
			if riskRank[th.Impact] >= riskRank["high"] {
				c.NewRisks = append(c.NewRisks, th.ThreatID)
			}
			continue
		}
		old := prevThreats[th.ThreatID]
		if riskRank[th.Impact] > riskRank[old.Impact] {
			c.NewRisks = append(c.NewRisks, th.ThreatID)
		}
	}
	for id, old := range prevThreats {
		if _, still := newThreatSet[id]; !still {
			c.RemovedThreats = append(c.RemovedThreats, id)
			if riskRank[old.Impact] >= riskRank["high"] {
				c.RemovedRisks = append(c.RemovedRisks, id)
			}
		}
	}
	return c
}

// ListNodes lists a model's nodes.
func (s *Store) ListNodes(ctx context.Context, modelID string) ([]TMNode, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT model_id, node_id, kind, label, COALESCE(entity_ref, ''), label_state, COALESCE(attrs, '')
		 FROM tm_nodes WHERE model_id = ?`, modelID)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	defer rows.Close()
	out := []TMNode{}
	for rows.Next() {
		var n TMNode
		if err := rows.Scan(&n.ModelID, &n.NodeID, &n.Kind, &n.Label, &n.EntityRef, &n.LabelState, &n.Attrs); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ListEdges lists a model's edges.
func (s *Store) ListEdges(ctx context.Context, modelID string) ([]TMEdge, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT model_id, from_node, to_node, relation, label_state, COALESCE(evidence, '')
		 FROM tm_edges WHERE model_id = ?`, modelID)
	if err != nil {
		return nil, fmt.Errorf("list edges: %w", err)
	}
	defer rows.Close()
	out := []TMEdge{}
	for rows.Next() {
		var e TMEdge
		if err := rows.Scan(&e.ModelID, &e.FromNode, &e.ToNode, &e.Relation, &e.LabelState, &e.Evidence); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListThreats lists a model's threats.
func (s *Store) ListThreats(ctx context.Context, modelID string) ([]Threat, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT model_id, threat_id, COALESCE(node_id, ''), COALESCE(edge_id, ''), description,
		        COALESCE(stride, ''), COALESCE(kill_chain_phase, ''),
		        COALESCE(techniques, '[]'), COALESCE(d3fend_mitigations, '[]'),
		        COALESCE(likelihood, 'unknown'), COALESCE(impact, 'unknown'), label_state
		 FROM threats WHERE model_id = ?`, modelID)
	if err != nil {
		return nil, fmt.Errorf("list threats: %w", err)
	}
	defer rows.Close()
	out := []Threat{}
	for rows.Next() {
		var th Threat
		var tech, d3 string
		if err := rows.Scan(&th.ModelID, &th.ThreatID, &th.NodeID, &th.EdgeID, &th.Description,
			&th.Stride, &th.KillChainPhase, &tech, &d3, &th.Likelihood, &th.Impact, &th.LabelState); err != nil {
			return nil, err
		}
		th.Techniques = decodeList(tech)
		th.D3FendMitigations = decodeList(d3)
		out = append(out, th)
	}
	return out, rows.Err()
}

// ListSnapshots lists a model's drift snapshots (newest first).
func (s *Store) ListSnapshots(ctx context.Context, modelID string) ([]Snapshot, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT model_id, version, snapshot, changes, COALESCE(triggered_by, ''), created_at
		 FROM model_snapshots WHERE model_id = ? ORDER BY version DESC`, modelID)
	if err != nil {
		return nil, fmt.Errorf("list snapshots: %w", err)
	}
	defer rows.Close()
	out := []Snapshot{}
	for rows.Next() {
		var sn Snapshot
		var trig sql.NullString
		if err := rows.Scan(&sn.ModelID, &sn.Version, &sn.Snapshot, &sn.Changes, &trig, &sn.CreatedAt); err != nil {
			return nil, err
		}
		sn.TriggeredBy = trig.String
		out = append(out, sn)
	}
	return out, rows.Err()
}

// EnsureControls seeds the embedded control catalog into the controls table.
func (s *Store) EnsureControls(ctx context.Context, catalog []Control) error {
	for _, c := range catalog {
		if _, err := s.db.ExecContext(ctx,
			`INSERT OR IGNORE INTO controls (control_id, framework, ref, name, description)
			 VALUES (?, ?, ?, ?, ?)`,
			c.ControlID, c.Framework, c.Ref, c.Name, c.Description); err != nil {
			return fmt.Errorf("seed control %s: %w", c.ControlID, err)
		}
	}
	return nil
}

// ListControls lists all catalog controls.
func (s *Store) ListControls(ctx context.Context) ([]Control, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT control_id, framework, ref, name, COALESCE(description, '') FROM controls ORDER BY framework, ref`)
	if err != nil {
		return nil, fmt.Errorf("list controls: %w", err)
	}
	defer rows.Close()
	out := []Control{}
	for rows.Next() {
		var c Control
		if err := rows.Scan(&c.ControlID, &c.Framework, &c.Ref, &c.Name, &c.Description); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpsertThreatControl maps a threat to a control.
func (s *Store) UpsertThreatControl(ctx context.Context, tc ThreatControl) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO threat_controls (threat_ref, control_id, mapping_state, evidence)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(threat_ref, control_id) DO UPDATE SET
		   mapping_state = excluded.mapping_state,
		   evidence = excluded.evidence`,
		tc.ThreatRef, tc.ControlID, tc.MappingState, tc.Evidence); err != nil {
		return fmt.Errorf("upsert threat control: %w", err)
	}
	return nil
}

// ThreatRef builds the stable reference for a threat's control mappings.
func ThreatRef(modelID, threatID string) string {
	return "model:" + modelID + ":threat:" + threatID
}

// randomID returns a short random id.
func randomID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 16)
	for i, c := range b {
		out[i*2] = hex[c>>4]
		out[i*2+1] = hex[c&0xF]
	}
	return string(out)
}
