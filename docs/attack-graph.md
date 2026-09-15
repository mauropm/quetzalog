# Quetzalog — Attack Graph

**Status:** Phase 1 design. New package `internal/attackgraph`, built on the entity
relationship graph (`entity-model.md`) + assets + scenarios + coverage.

The attack graph answers: *"if X is compromised, what can the attacker reach, what have
they actually done, and what might they try next?"* — with strict separation of
`observed / inferred / potential / blocked` (spec §17: never present inferred as
confirmed).

---

## 1. Graph Model

Nodes = entities that can hold security state:
`host, workstation, server, container, cloud_resource, database, application,
user, identity, domain, ip, asn` (+ asset overlay: criticality, exposure).

Edges inherit their **state** from `relationship_meta.status`
(`entity-model.md` §2):

| State | Meaning | Set by |
|---|---|---|
| `observed` | a stored event directly implies the relation | event write path |
| `blocked` | a deny/block event implies an *attempted* relation that was stopped | event write path |
| `inferred` | correlation rule / scenario / AI concluded the relation (with evidence) | detection/scenario/AI, always with `source_id` |
| `potential` | reasoning: "reachable if compromised" (network adjacency + vulnerability, service adjacency) | attack-graph builder (recomputed) |

Edge attributes: `first_seen/last_seen`, `weight` (observed count), `evidence` JSON,
`source_type/source_id`, `technique` (when the relation is technique-typed, e.g.
`lateral_movement` = T1021).

### 1.1 Compromise State

Per node, a derived (not stored per-edge) compromise assessment:

```
compromise(node) =
  observed:    observed edges into the node that represent access/exec/credentialed
               activity from outside its trust boundary  → "compromised (observed)"
  inferred:    same via inferred edges only             → "compromised (inferred)"
  potential:   reachable from any compromised node via observed/potential edges
                                              → "at risk (potential)"
```

Trust boundary = asset `environment` + `internet_exposed` + explicit analyst boundary
tags (`trust_boundary:corp`, `trust_boundary:dmz`, …). Edges crossing boundaries get a
`crosses_boundary` flag; compromise propagation weights boundary crossings higher
(outside→inside is the dangerous direction).

## 2. Attack Paths

```sql
-- migration 012_attack_graph.sql
CREATE TABLE attack_paths (
  id TEXT PRIMARY KEY,
  scenario_run_id TEXT,             -- optional link to scenario evaluation
  source_node TEXT NOT NULL,        -- 'type:value'
  target_node TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('observed','inferred','potential')),
  description TEXT,
  risk REAL,
  created_by TEXT,                  -- 'engine' | analyst | 'ai'
  created_at DATETIME NOT NULL
);
CREATE TABLE path_steps (
  path_id TEXT NOT NULL,
  pos INTEGER NOT NULL,
  from_node TEXT NOT NULL, to_node TEXT NOT NULL,
  edge_relation TEXT NOT NULL,
  edge_state TEXT NOT NULL,
  technique TEXT,
  evidence TEXT,                    -- JSON event ids / detection id / reasoning ref
  PRIMARY KEY (path_id, pos)
);
```

Path construction:
- **Observed paths:** replay of ordered observed edges from first-compromise node to
  each subsequently-observed internal node (the demo chain
  `185.220.101.47 → workstation-42 → file-srv-01` becomes a materialized path).
- **Potential paths:** BFS/DFS from each `compromised` node over
  `observed ∪ potential` edges to `criticality=critical` assets; depth cap 4, top-50
  paths by (edge-count ascending, target criticality descending); each step labeled
  with the edge state so the UI shows exactly where certainty ends.
- **Value:** `path.risk = Σ step_weight × target_criticality_factor`
  (step_weight: observed 1.0, inferred 0.6, potential 0.3; documented defaults,
  config-overridable).

Recomputation triggers: new finding with technique, new asset/criticality change,
new vulnerability on an asset, coverage change (potential edges through telemetry gaps
get `confidence reduced` annotation), hourly sweep.

## 3. Graph Query API (`internal/attackgraph` → REST)

```
GET /api/v1/attack-graph?states=observed,inferred&depth=2&asset=<id>
    → nodes (with compromise state, criticality, coverage) + edges (with states)

GET /api/v1/attack-graph/paths?from=<node>&to=<node>
    → all paths between two nodes with per-step states

GET /api/v1/attack-graph/paths?targets=critical
    → all materialized potential paths toward critical assets

GET /api/v1/attack-graph/paths/{id}
    → full path with evidence per step (event ids) → click-through to raw events

GET /api/v1/attack-graph/nodes/{type}/{value}/what-next
    → scenario "expected techniques" + potential edges from this node
      (answers "what could an attacker do next")
```

All responses carry `generated_at` and the states included — a graph snapshot is never
presented as the live truth without its state legend.

## 4. Integration

- **Scenario evaluator** writes `inferred` edges and links `scenario_run_id` to paths.
- **AI Analyst** receives the compact graph around the finding (nodes/edges within
  depth 2, states labeled) in its context — see `ai-security-analysis.md`.
- **UI** (`attack-graph` page): SVG force layout (no external graph DB); edge style:
  observed=solid, inferred=dashed, potential=dotted, blocked=strikethrough/red;
  compromise state as node color; click node → entity dossier; click edge → evidence.
- **Threat model** (`threat-model.md`): potential paths are the "potential attack
  paths" section of a model derived from telemetry.

## 5. Constraints & Limits

- SQLite BFS with depth ≤ 4 and fan-out caps (1000 nodes / 5000 edges per snapshot,
  configurable); beyond that the query returns a truncation warning, not a hang.
- `potential` edges are **never** persisted as observed; the builder table is
  recomputed (upsert by `(path_id,pos)` with `status`), so stale potential paths
  disappear when their precondition vanishes.
- No causal claims: an observed `user→host` auth edge does not imply the user is
  malicious; compromise requires direction + boundary crossing + credential/exec class.
- Missing telemetry: potential paths that traverse a coverage gap are flagged
  `confidence reduced: no <class> telemetry on <asset>` (spec §26).
