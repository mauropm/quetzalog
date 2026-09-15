package threatmodel

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"quetzalog/internal/assets"
	"quetzalog/internal/coverage"
)

// Derivation is the derived content of one model refresh.
type Derivation struct {
	Nodes   []TMNode
	Edges   []TMEdge
	Threats []Threat
}

// kindFor maps an asset entity type to a tm_nodes kind.
func kindFor(entityType string) string {
	switch strings.ToLower(entityType) {
	case "database", "db":
		return "data_store"
	case "application", "app":
		return "application"
	case "cloud_resource", "cloud":
		return "cloud_resource"
	default:
		return "asset"
	}
}

// relationFor maps a raw relationship to a model edge relation.
func relationFor(rel string) string {
	switch strings.ToLower(rel) {
	case "connects_to", "connects", "flows_to", "network_flow":
		return "flows_to"
	case "authenticates", "login", "logon", "auth":
		return "authenticates"
	case "reads":
		return "reads"
	case "writes":
		return "writes"
	case "depends_on", "lateral_movement":
		return rel
	default:
		return rel
	}
}

// nodeKeyFor builds the stable node id for an entity.
func nodeKeyFor(kind, entityRef string) string {
	return kind + ":" + entityRef
}

// Derive builds a preliminary threat model from observed telemetry
// (spec §49): assets → nodes, relationships → edges, STRIDE×asset-class
// threat templates → threats. Every item carries an observed/inferred/
// assumed label.
func Derive(ctx context.Context, db *sql.DB, assetsStore *assets.Store, covStore *coverage.Store, cw *Crosswalk) (*Derivation, error) {
	assetList, _, err := assetsStore.List(ctx, assets.ListFilter{Limit: 1000})
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}

	// Entity ref → asset id (node key) lookup.
	refToNode := map[string]string{}
	envs := map[string]bool{}
	hasInternet := false
	for _, a := range assetList {
		ref := a.EntityRef
		if ref == "" {
			ref = a.ID
		}
		refToNode[ref] = a.ID
		if a.Environment != "" {
			envs[a.Environment] = true
		}
		if a.InternetExposed {
			hasInternet = true
		}
	}

	// Relationships (observed/inferred only — potential is never materialized).
	type rawRel struct {
		fromType, fromVal, toType, toVal, rel, state, sourceID string
	}
	rels := []rawRel{}
	rows, err := db.QueryContext(ctx, `
		SELECT r.from_type, r.from_value, r.to_type, r.to_value, r.relation,
		       COALESCE(m.status, 'observed'), COALESCE(m.source_id, '')
		FROM relationships r
		LEFT JOIN relationship_meta m ON (
			m.from_type = r.from_type AND m.from_value = r.from_value
			AND m.to_type = r.to_type AND m.to_value = r.to_value
			AND m.relation = r.relation)
		WHERE COALESCE(m.status, 'observed') IN ('observed','inferred')`)
	if err != nil {
		return nil, fmt.Errorf("query relationships: %w", err)
	}
	for rows.Next() {
		var rr rawRel
		if err := rows.Scan(&rr.fromType, &rr.fromVal, &rr.toType, &rr.toVal, &rr.rel, &rr.state, &rr.sourceID); err != nil {
			rows.Close()
			return nil, err
		}
		rels = append(rels, rr)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Entities that appear in relationships but have no asset: they still
	// get nodes (inferred — implied by flows).
	observedRef := map[string]bool{}
	for _, rr := range rels {
		observedRef[rr.fromType+":"+rr.fromVal] = true
		observedRef[rr.toType+":"+rr.toVal] = true
	}

	d := &Derivation{}

	// ── Nodes: assets ──
	for _, a := range assetList {
		ref := a.EntityRef
		if ref == "" {
			ref = a.ID
		}
		covAvail, covTotal := 0, 0
		if covStore != nil {
			if crows, err := covStore.Rows(ctx, a.ID); err == nil {
				for _, r := range crows {
					covTotal++
					if r.Available {
						covAvail++
					}
				}
			}
		}
		attrs, _ := json.Marshal(map[string]any{
			"asset_id":          a.ID,
			"criticality":       a.Criticality,
			"environment":       a.Environment,
			"internet_exposed":  a.InternetExposed,
			"coverage_available": covAvail,
			"coverage_total":     covTotal,
		})
		d.Nodes = append(d.Nodes, TMNode{
			NodeID:     a.ID,
			Kind:       kindFor(a.EntityType),
			Label:      a.Name,
			EntityRef:  ref,
			LabelState: "observed",
			Attrs:      string(attrs),
		})
		// Entry point node for exposed assets.
		if a.InternetExposed {
			d.Nodes = append(d.Nodes, TMNode{
				NodeID:     "ep:" + a.ID,
				Kind:       "entry_point",
				Label:      "Entry point: " + a.Name,
				EntityRef:  ref,
				LabelState: "observed",
				Attrs:      `{"asset_id":"` + a.ID + `"}`,
			})
			d.Edges = append(d.Edges, TMEdge{
				FromNode:   "ep:" + a.ID,
				ToNode:     a.ID,
				Relation:   "exposes",
				LabelState: "observed",
			})
			d.Edges = append(d.Edges, TMEdge{
				FromNode:   "ep:" + a.ID,
				ToNode:     "tb:internet",
				Relation:   "resides_in",
				LabelState: "inferred",
			})
		} else if a.Environment != "" {
			d.Edges = append(d.Edges, TMEdge{
				FromNode:   a.ID,
				ToNode:     "tb:" + a.Environment,
				Relation:   "resides_in",
				LabelState: "assumed",
			})
		}
	}

	// ── Nodes: trust boundaries ──
	if hasInternet {
		d.Nodes = append(d.Nodes, TMNode{
			NodeID:     "tb:internet",
			Kind:       "trust_boundary",
			Label:      "Internet",
			LabelState: "inferred",
		})
	}
	for env := range envs {
		d.Nodes = append(d.Nodes, TMNode{
			NodeID:     "tb:" + env,
			Kind:       "trust_boundary",
			Label:      "Boundary: " + env,
			LabelState: "assumed",
		})
	}

	// ── Nodes: non-asset entities seen in relationships ──
	for ref := range observedRef {
		if _, ok := refToNode[ref]; ok {
			continue
		}
		t, v, _ := strings.Cut(ref, ":")
		d.Nodes = append(d.Nodes, TMNode{
			NodeID:     "ext:" + ref,
			Kind:       kindFor(t),
			Label:      v,
			EntityRef:  ref,
			LabelState: "inferred",
		})
	}

	// nodeIDFor resolves an entity ref to its node id.
	nodeIDFor := func(t, v string) string {
		ref := t + ":" + v
		if id, ok := refToNode[ref]; ok {
			return id
		}
		return "ext:" + ref
	}

	// ── Edges: relationships ──
	edgeSeen := map[string]bool{}
	for _, rr := range rels {
		from := nodeIDFor(rr.fromType, rr.fromVal)
		to := nodeIDFor(rr.toType, rr.toVal)
		rel := relationFor(rr.rel)
		if from == to {
			continue
		}
		key := from + "|" + to + "|" + rel
		if edgeSeen[key] {
			continue
		}
		edgeSeen[key] = true
		d.Edges = append(d.Edges, TMEdge{
			FromNode:   from,
			ToNode:     to,
			Relation:   rel,
			LabelState: rr.state,
			Evidence:   rr.sourceID,
		})
	}

	// ── Threats: STRIDE × asset-class templates (spec §3.4) ──
	impactFor := func(criticality string) string {
		if criticality == "critical" {
			return "critical"
		}
		return "high"
	}
	critByID := map[string]string{}
	for _, a := range assetList {
		critByID[a.ID] = a.Criticality
	}
	exposed := map[string]bool{}
	for _, a := range assetList {
		if a.InternetExposed {
			exposed[a.ID] = true
		}
	}

	addThreat := func(nodeID, edgeID, stride, phase, likelihood, impact, label, desc string, techniques []string) {
		techs := techniques
		if len(techs) == 0 {
			techs = cw.StrideToTechniques[stride]
		}
		d3 := []string{}
		seen := map[string]bool{}
		for _, t := range techs {
			for _, m := range cw.D3FendByTechnique[t] {
				if !seen[m] {
					seen[m] = true
					d3 = append(d3, m)
				}
			}
		}
		id := "thr-" + fnvHash(stride + "|" + nodeID + "|" + edgeID + "|" + desc)
		d.Threats = append(d.Threats, Threat{
			ThreatID:          id,
			NodeID:            nodeID,
			EdgeID:            edgeID,
			Description:       desc,
			Stride:            stride,
			KillChainPhase:    phase,
			Techniques:        techs,
			D3FendMitigations: d3,
			Likelihood:        likelihood,
			Impact:            impact,
			LabelState:        label,
		})
	}

	// Entry-point threats on exposed assets.
	for id, crit := range critByID {
		if !exposed[id] {
			continue
		}
		addThreat(id, "", "spoofing", "exploitation", "possible", impactFor(crit), "assumed",
			"Stolen or spoofed credentials against an internet-exposed endpoint", nil)
		addThreat(id, "", "information_disclosure", "exploitation", "possible", impactFor(crit), "assumed",
			"Sensitive data disclosed through an internet-exposed endpoint", nil)
		addThreat(id, "", "elevation_of_privilege", "exploitation", "possible", "high", "assumed",
			"Privilege escalation via vulnerability in an internet-exposed endpoint", nil)
		addThreat(id, "", "denial_of_service", "exploitation", "possible", "medium", "assumed",
			"Availability impact on an internet-exposed endpoint", nil)
	}

	// Data-store threats.
	for _, n := range d.Nodes {
		if n.Kind != "data_store" {
			continue
		}
		addThreat(n.NodeID, "", "tampering", "actions_on_objectives", "possible", "high", "assumed",
			"Integrity loss: tampering with stored data", nil)
		addThreat(n.NodeID, "", "information_disclosure", "actions_on_objectives", "possible", "high", "assumed",
			"Data exfiltration from the store", nil)
	}

	// Lateral-movement threats on observed edges.
	for _, e := range d.Edges {
		if e.Relation != "lateral_movement" && e.Relation != "flows_to" {
			continue
		}
		if e.LabelState != "observed" {
			continue
		}
		addThreat("", e.FromNode+"→"+e.ToNode, "elevation_of_privilege", "actions_on_objectives", "likely", "high", "inferred",
			"Observed lateral movement "+e.FromNode+" → "+e.ToNode, nil)
	}

	return d, nil
}

// MapThreatControls returns the threat_ref → control mappings for a
// derivation, using the crosswalk's ref→control catalog.
func MapThreatControls(d *Derivation, modelID string, cw *Crosswalk) []ThreatControl {
	refToControl := map[string]string{}
	for _, c := range cw.Controls {
		refToControl[strings.ToUpper(c.Ref)] = c.ControlID
	}
	out := []ThreatControl{}
	for _, th := range d.Threats {
		seen := map[string]bool{}
		for _, mit := range th.D3FendMitigations {
			cid, ok := refToControl[strings.ToUpper(mit)]
			if !ok || seen[cid] {
				continue
			}
			seen[cid] = true
			out = append(out, ThreatControl{
				ThreatRef:    ThreatRef(modelID, th.ThreatID),
				ControlID:    cid,
				MappingState: "assumed",
			})
		}
	}
	return out
}

// fnvHash renders a short deterministic hash.
func fnvHash(s string) string {
	var h uint32 = 2166136261
	for _, c := range s {
		h ^= uint32(c)
		h *= 16777619
	}
	return fmt.Sprintf("%08x", h)
}
