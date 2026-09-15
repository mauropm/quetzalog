# Quetzalog — Threat Modeling

**Status:** Phase 1 design. New package `internal/threatmodel` (+ thin
`internal/compliance` for control catalogs).

Goals:
- A threat-model data model covering assets, trust boundaries, identities, entry
  points, data stores, processes, networks, dependencies, threats, controls,
  vulnerabilities, and attack paths (spec §15).
- Frameworks coexist without forcing one: STRIDE, MITRE ATT&CK, Cyber Kill Chain,
  attack trees/graphs, D3FEND, NIST, CIS Controls, OWASP — with stored cross-mappings
  (spec §15, §51, §52).
- **Threat modeling from reality** (spec §49): derive preliminary models from
  observed telemetry, labeled `Observed / Inferred / Assumed`.
- **Model drift** (spec §50): models update as infrastructure changes; track
  previous/current/changes/new-risks/removed-risks.

---

## 1. Data Model

```sql
-- migration 013_threat_models.sql
CREATE TABLE threat_models (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('analyst','telemetry','hybrid')),
  version INTEGER NOT NULL DEFAULT 1,
  scope TEXT,                       -- e.g. 'app:checkout' or 'asset:DC-01' or 'global'
  status TEXT NOT NULL DEFAULT 'active',
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL
);

CREATE TABLE tm_nodes (
  model_id TEXT NOT NULL,
  node_id TEXT NOT NULL,            -- stable within model
  kind TEXT NOT NULL CHECK (kind IN
    ('asset','trust_boundary','identity','entry_point','data_store','process',
     'network','dependency','application','cloud_resource')),
  label TEXT NOT NULL,
  entity_ref TEXT,                  -- 'host:WORKSTATION-42' when backed by a real entity
  label_state TEXT NOT NULL CHECK (label_state IN ('observed','inferred','assumed')),
  attrs TEXT,                       -- JSON (os, criticality, exposure, ...)
  PRIMARY KEY (model_id, node_id)
);

CREATE TABLE tm_edges (
  model_id TEXT NOT NULL,
  from_node TEXT NOT NULL, to_node TEXT NOT NULL,
  relation TEXT NOT NULL,           -- 'depends_on','flows_to','authenticates','reads','exposes'
  label_state TEXT NOT NULL CHECK (label_state IN ('observed','inferred','assumed')),
  evidence TEXT,                    -- JSON: event ids / source / reasoning
  PRIMARY KEY (model_id, from_node, to_node, relation)
);

CREATE TABLE threats (
  model_id TEXT NOT NULL,
  threat_id TEXT NOT NULL,
  node_id TEXT, edge_id TEXT,       -- where the threat sits
  description TEXT NOT NULL,
  stride TEXT CHECK (stride IN ('spoofing','tampering','repudiation',
    'information_disclosure','denial_of_service','elevation_of_privilege')),
  kill_chain_phase TEXT,            -- 'recon','weaponization','delivery','exploitation',
                                    -- 'installation','c2','actions-on-objectives'
  techniques TEXT,                  -- JSON array of ATT&CK ids
  d3fend_mitigations TEXT,          -- JSON array
  likelihood TEXT CHECK (likelihood IN ('rare','possible','likely','almost_certain','unknown')),
  impact TEXT CHECK (impact IN ('low','medium','high','critical','unknown')),
  label_state TEXT NOT NULL CHECK (label_state IN ('observed','inferred','assumed')),
  PRIMARY KEY (model_id, threat_id)
);

CREATE TABLE controls (
  control_id TEXT PRIMARY KEY,      -- stable catalog id
  framework TEXT NOT NULL,          -- 'd3fend','cis','nist_csf','nist_800_53','iso_27001','pci_dss','soc2','owasp'
  ref TEXT NOT NULL,                -- 'CIS 3.8', 'PCI DSS 8.3', ...
  name TEXT NOT NULL,
  description TEXT
);
CREATE TABLE threat_controls (
  threat_ref TEXT NOT NULL,         -- 'model:<id>:threat:<tid>' or global
  control_id TEXT NOT NULL,
  mapping_state TEXT NOT NULL CHECK (mapping_state IN ('observed','inferred','assumed')),
  evidence TEXT,
  PRIMARY KEY (threat_ref, control_id)
);

CREATE TABLE model_snapshots (      -- drift tracking (spec §50)
  model_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  snapshot TEXT NOT NULL,           -- JSON: nodes/edges/threats summary
  changes TEXT NOT NULL,            -- JSON: added/removed/changed + new_risks/removed_risks
  triggered_by TEXT,                -- 'new-asset','new-software','new-public-ip','new-exposed-port',
                                    -- 'new-cloud-resource','new-idp','new-privileged-account',
                                    -- 'new-application','coverage-change','analyst'
  created_at DATETIME NOT NULL,
  PRIMARY KEY (model_id, version)
);
```

Framework crosswalk: `controls` is the join table; technique↔control links reuse
MITRE D3FEND mappings (embedded catalog, same pattern as `internal/mitre`);
STRIDE↔ATT&CK and kill-chain↔ATT&CK mappings are embedded YAML catalogs. A threat may
carry STRIDE + technique + kill-chain + D3FEND simultaneously — that's the point of
multi-framework (spec §15: "Do not force all models into one framework").

## 2. Threats & STRIDE (spec §16)

STRIDE is a classification axis on `threats`, not a separate store. Example flow from
the spec:

```
API (entry_point, observed: nginx access logs show /api)
  ↓ Spoofing risk
stolen credentials (threat, likelihood=possible, inferred: no MFA on this API observed)
  ↓ valid account (technique T1078, observed when a login occurs)
privileged API access (threat on edge application→data_store, elevation_of_privilege)
```

Each threat row is independently labeled observed/inferred/assumed with evidence, so a
model page can show "3 of 12 threats have observed supporting events."

## 3. Modeling From Reality (spec §49)

`POST /threat-models/{id}/refresh` (or auto on drift triggers) derives a model:

1. **Nodes:**
   - observed: entities with observed edges (hosts, applications from `web.access`
     source types, databases from `db.log`, identities from identity source classes);
   - inferred: services implied by flows (a `destination_port 5432` with no db.log
     telemetry → `inferred: data store (postgres?)` — assumption recorded);
   - assumed: analyst-added nodes (e.g. "mainframe z/OS batch processor" with no logs —
     legacy systems are first-class here; spec §2 OS/2/mainframe).
2. **Edges:** observed network flows (src→dst aggregation, top-N by volume,
   with protocol/port/application labels), auth flows (user→host), dependency flows
   (application→database from db statements). Each edge labeled observed/inferred.
3. **Trust boundaries:** from `assets.internet_exposed` + environment + VLAN/segment
   tags where present; an `internet → DMZ → internal` boundary chain is inferred from
   exposure flags.
4. **Threats:** per entry point + boundary crossing, default threat templates
   (STRIDE×asset-class matrix) instantiated, each labeled `assumed` until evidence
   (a matching observed technique event) or analyst review upgrades it.
5. **Controls:** per threat, from the crosswalk catalogs; `mapping_state=assumed`
   until telemetry evidence shows the control operating (e.g. MFA events observed →
   MFA control `observed` on that identity).
6. **Telemetry coverage** is attached per node (from `telemetry-coverage.md`) and per
   "potential attack path" (potential edges from `attack-graph.md`).

Result shape (spec §49): external attack surface, web application, database, trust
boundaries, potential attack paths, relevant threats, relevant controls, telemetry
coverage — every item carrying `Observed / Inferred / Assumed`.

## 4. Drift (spec §50)

Trigger evaluation (async worker, hourly + on asset/coverage changes):

| Trigger | Detection |
|---|---|
| new server | asset first_seen in window |
| new software | `asset_software` row new in window |
| new public IP / exposed port | coverage/asset `internet_exposed` or observed public src/dst first seen |
| new cloud resource | `cloud_resource` asset first seen |
| new identity provider | identity source class first seen |
| new privileged account | user with `entity_meta.privilege=privileged` first seen |
| new application | `application` entity with observed flow first seen |
| coverage change ≥ 10% | coverage worker delta |

On trigger: re-derive → new `threat_models.version`, `model_snapshots` row with
structured `changes` (added/removed nodes/edges/threats, `new_risks` = threats
`likelihood/impact` increased, `removed_risks` = threats without evidence after
infrastructure change). UI shows a diff view; nothing is auto-deleted — removed
*risks* stay visible in the snapshot history.

## 5. Compliance Linkage (spec §51–52)

No separate compliance system. The chain is:

```
control (PCI DSS 8.3: MFA)
  ↓  threat_controls mapping
threat (spoofing on /api)
  ↓  required source classes
telemetry (identity.log observed / missing)
  ↓  events
evidence (MFA challenge events for this identity)
  ↓
risk (risk-model.md contributions)
```

`internal/compliance` (Phase: after coverage is stable) stores:
- the control catalogs (CIS, NIST CSF, NIST 800-53, ISO 27001, PCI DSS, SOC 2, D3FEND)
  as versioned embedded data;
- per-requirement: required source classes + evidence query;
- evidence evaluation reuses coverage + event queries (same unknown semantics —
  missing telemetry ⇒ requirement status `unknown`, never `fail`).
Requirement status values: `met / partially_met / not_met / unknown (no telemetry)`
with evidence pointers. This keeps SOC and compliance sharing one evidence base.

## 6. Backward Compatibility & Limits

- No existing table touched; all new.
- Model derivation is read-only over telemetry; it never writes to `events`.
- Snapshot JSON is capped (50 KB/model/version); large models are summarized
  (counts + top-changes) with the full graph available on demand.
- `source='analyst'` models: full CRUD via UI; `source='telemetry'` models: refresh
  regenerates content but preserves analyst-edited threats/controls (3-way merge:
  analyst changes win on conflict, recorded in the snapshot diff).
