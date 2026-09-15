# Quetzalog — Entity Model & Security Knowledge Graph

**Status:** Phase 1 design. Extends `internal/correlation` (today's entity/relationship
graph) into `internal/entities` + a query layer. See `threat-intelligence-architecture.md`.

Goals:
- Stable identifiers for every entity type the threat model needs.
- Entity **resolution** (aliases → canonical entity) with explicit confidence, never
  aggressive merging.
- Relationships as first-class, provenance-carrying objects with states
  (`observed / inferred / potential / blocked`).
- One knowledge graph the UI pivots on (spec §28, §34, §59).

---

## 1. Entity Types

Today: `ip, user, host, process, file, domain, email, session, trace_id`
(declared in `internal/correlation/graph.go:14-24`; `domain`/`email` never produced).

v2 types (superset; existing types keep their names):

```
identity:   user, identity, credential, api_key, service_account
compute:    host, workstation, server, container, cloud_resource, device, database
process:    process, binary, service, application
network:    ip, domain, url, asn, certificate, network_connection
artifact:   file, hash, email
cloud:      cloud_account, cloud_resource
intel:      indicator, threat_actor, campaign, malware, tool
framework:  technique, tactic, vulnerability, cve, detection, control
case:       investigation, finding, scenario
other:      session, trace_id
```

Normalization rules (applied at extraction):
- `user`: case-insensitive; strip domain prefixes (`DOMAIN\\mauro` → `mauro`, keep
  original as alias); `admin`-like names kept verbatim.
- `host`: uppercase canonical (FQDN if known), else raw; IPs never become host names
  without observed DNS/SMB evidence.
- `ip`: canonical dotted/colon form; CIDR stored as `asn`/`cidr` type, not `ip`.
- `domain`: lowercase, no trailing dot, no port.
- `process`: basename lowercase (POSIX) / `.exe` kept (Windows); full path as alias.
- `hash`: lowercase hex + type prefix in value? No — value stays bare hex; type carried
  in the entity type (`sha256:<hex>` value form `hash:sha256`).
- `indicator`: value+type as identity (`indicator:ip:203.0.113.50`).

## 2. Data Model

Existing tables stay:

```sql
entities(id TEXT PK, type, value, first_seen, last_seen, count, metadata,
         UNIQUE(type,value))
relationships(id TEXT PK, from_type, from_value, to_type, to_value, relation,
              weight, created_at,
              UNIQUE(from_type,from_value,to_type,to_value,relation))
```

New (migration `009_entities_v2.sql`):

```sql
-- Resolution: one canonical entity per resolved identity.
CREATE TABLE entity_identities (
  id TEXT PRIMARY KEY,
  canonical_type TEXT NOT NULL,
  canonical_value TEXT NOT NULL,
  alias_type TEXT NOT NULL,          -- e.g. ip, domain, hostname, fqdn
  alias_value TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN
    ('confirmed','probable','possible','unknown')),
  confidence REAL NOT NULL DEFAULT 0.5,
  source TEXT NOT NULL,              -- 'observation' | 'dns' | 'smb' | 'analyst' | 'ti' | 'asset'
  first_seen DATETIME NOT NULL,
  last_seen DATETIME NOT NULL,
  UNIQUE(canonical_type, canonical_value, alias_type, alias_value)
);

-- Rich per-entity metadata (assets live in their own table; this is the generic side).
CREATE TABLE entity_meta (
  type TEXT NOT NULL, value TEXT NOT NULL,
  display_name TEXT,
  os TEXT, os_version TEXT,
  environment TEXT,                  -- production/dev/test/lab
  internet_exposed INTEGER,
  privilege TEXT,                    -- for users/service accounts: standard/privileged/admin
  cloud_provider TEXT, cloud_account TEXT,
  tags TEXT,                         -- JSON array
  updated_at DATETIME NOT NULL,
  PRIMARY KEY (type, value)
);

-- v2 edge metadata: state + provenance, without touching the hot 5-tuple table.
CREATE TABLE relationship_meta (
  from_type TEXT NOT NULL, from_value TEXT NOT NULL,
  to_type TEXT NOT NULL, to_value TEXT NOT NULL,
  relation TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('observed','inferred','potential','blocked')),
  source_type TEXT NOT NULL,         -- 'event' | 'detection' | 'intel' | 'ai' | 'analyst' | 'attackgraph'
  source_id TEXT,                    -- event id / detection id / indicator id / analysis id
  first_seen DATETIME NOT NULL,
  last_seen DATETIME NOT NULL,
  evidence TEXT,                     -- JSON: minimal supporting facts
  PRIMARY KEY (from_type, from_value, to_type, to_value, relation)
);
```

State semantics (spec §17):
- `observed` — directly implied by a stored event (the only state the write path sets).
- `inferred` — set by correlation rules / scenario evaluation / AI, always with
  `source_type` + `source_id`; never rendered as confirmed in UI.
- `potential` — attack-graph reasoning ("if host X is compromised, it *could* reach Y");
  recomputed, not accumulated.
- `blocked` — a denied/blocked event (firewall `deny`, EDR block); kept distinct so
  analysts can tell attempted from successful.

Relationship vocabulary (additive; existing `connected_to`, `auth_from`, `executed`,
`accessed` keep working): `auth_to, executed, spawned, connects_to, resolves_to,
belongs_to, runs, has_file, uses_technique, associated_with, consistent_with,
possibly_related_to, attributed_to, vulnerable_to, mitigated_by, part_of_campaign,
member_of, exposes, depends_on`.

## 3. Resolution Rules

```
raw observation (ip / hostname / domain / user@domain ...)
   │
   ▼
extractor → candidate entity rows (as today)
   │
   ▼
resolver (async, bounded work):
   1. exact type+value hit → done
   2. alias table hit → canonical entity
   3. evidence rules:
        host H observed with ip I in ≥ N events        → alias (probable, conf 0.8)
        DNS A-record H→I observed                      → alias (confirmed, conf 0.95)
        SMB/WMI H↔I observed                           → alias (confirmed)
        TI feed links domain→ip (same infra)           → alias (possible, conf from feed)
   4. analyst API: explicit link (confirmed, conf 1.0)
```

Rules:
- **No aggressive merges.** Below-threshold links create `entity_identities` rows with
  `status='possible'` and are not used for pivots until promoted (by evidence or analyst).
- Promotions are monotonic in evidence but reversible by an analyst (`DELETE` alias row
  → falls back to independent entity; history kept via audit log).
- Every alias row carries `source` + confidence; `first_seen/last_seen` per alias.
- Confidence dimensions (kept separate, spec §36): `source_reliability`,
  `indicator_confidence`, `context_confidence`, `temporal_relevance`, `corroboration`
  — stored in `entity_identities.confidence` only as the *final* value; the per-dimension
  values live in the `evidence` JSON of `relationship_meta` / `indicator_sources`.

## 4. Relationship Provenance

Every `relationship_meta` row answers: *who said this, when, and what supports it?*
`source_type/source_id` + `evidence` JSON. The UI "click Finding → Evidence → Raw Event"
path (spec §35) is: finding.event_ids → event ids; graph edge → `source_id` (event) or
detection → its events; AI statement → `ai_statements.evidence_refs` → event ids.

## 5. Query Layer (`internal/graph`)

API over the graph (used by API + UI + AI context builder):

```go
type Graph struct { db *sql.DB }

func (g *Graph) Neighbors(ctx, et EntityType, v string, depth int, states []EdgeState) ([]TraversalNode, error)
func (g *Graph) Resolve(ctx, raw string) ([]CandidateEntity, error)      // raw → entity candidates
func (g *Graph) EventsForEntity(ctx, et, v string, since time.Time) ([]string, error)
func (g *Graph) EventsForTechnique(ctx, technique string, since time.Time) ([]string, error)
func (g *Graph) HostsExecuting(ctx, hash string, since time.Time) ([]string, error)
func (g *Graph) UsersAccessing(ctx, host string, before time.Time) ([]string, error)
func (g *Graph) AssetsVulnerableTo(ctx, cve string) ([]string, error)
func (g *Graph) SoftwareInstances(ctx, pkg string) ([]SoftwareInstance, error)
func (g *Graph) Path(ctx, from, to NodeRef, maxHops int) ([]Path, error)   // BFS, state-aware
```

Depth cap: 4 for `Neighbors` (SQLite BFS, bounded row counts; no external graph DB).
All queries are read-only, parameterized, and respect `state` filters so inferred paths
are never mixed into observed views without opt-in.

Pivot examples from spec §28/§59 map 1:1 to the functions above ("everything connected
to this IP" → `Neighbors(ip, v, 3, all)`; "users who accessed this server before the
compromise" → `UsersAccessing(host, before)`; "possible paths from this compromised host
to critical assets" → `Path` with `potential` edges enabled, targets = assets with
`criticality=critical`).

## 6. Write-Path Cost

Per event (write path, unchanged shape): entity upserts + relationship upserts as today
(synchronous, cheap). New cost: one `entity_identities` probe on host/ip co-occurrence
(only when resolution enabled) and `relationship_meta` upsert for observed edges
(batched in the same transaction). If profiling (Phase 2 exit criteria) shows write
regression > 10%, both move to the async work queue with a documented lag.

## 7. Backward Compatibility

- `/api/v1/entities/{type}/{value}` and `/api/v1/intel/{type}/{value}` keep their
  responses; v2 adds fields (`aliases`, `states`, `provenance`) — additive JSON.
- The `entities`/`relationships` tables are unchanged; all v2 data is in new tables.
- `correlation.Graph.AddEntityFromEvent` keeps its signature; the v2 store wraps it.
