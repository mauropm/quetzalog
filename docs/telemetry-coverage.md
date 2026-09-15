# Quetzalog — Assets & Telemetry Coverage

**Status:** Phase 1 design. New packages `internal/assets`, `internal/coverage`.

Two goals:
1. **Assets are first-class** with criticality/ownership/exposure context (spec §23, §38).
2. **Coverage is explicit** so the system can distinguish *"no evidence of X"* from
   *"evidence that X did not happen"* — missing telemetry yields **unknown**, never
   negative (spec §26, §27, §74.4).

---

## 1. Missing-Telemetry Semantics (the invariant)

Every analytical consumer follows one rule:

```
if the source class needed for claim C has no telemetry observed for the asset in the
window, and no deny/blocked event class is observed either:
    result = unknown
    telemetry_coverage = missing
else if deny/blocked events observed:
    result = blocked
else:
    result = observed (positive or negative depending on events)
```

Concrete examples:

| Situation | Today (implicit) | Required |
|---|---|---|
| No SSH logs available for host H | (absent) | `ssh activity: unknown; coverage: missing` |
| Firewall shows deny to H:445 | not modeled | `smb lateral movement: blocked` |
| 0 failed logins in auth logs H *does* emit | "no failures" | `failures: 0 (observed)` |
| Sysmon absent, process events needed by scenario | silent gap | scenario step `persistence: unknown (no process telemetry)` |

Implementation: coverage is computed per asset × source class (`os.windows.security`,
`os.linux.auditd`, `net.dns`, …) from the event stream itself (distinct
`source_type` per host/asset, last event time, volume). No agent registration required —
coverage is *observed*, which is the honest signal. Optional static expectations
("asset H is a Windows server, we *expect* Sysmon") raise the gap when the expected
source class never appears.

## 2. Data Model

```sql
-- migration 008_assets.sql
CREATE TABLE assets (
  id TEXT PRIMARY KEY,                -- asset-<uuid>
  entity_type TEXT NOT NULL,          -- host | server | workstation | container | cloud_resource | database | application | identity_provider | network
  entity_ref TEXT NOT NULL,           -- 'host:WORKSTATION-42' (type:value) — links to graph
  name TEXT NOT NULL,
  os TEXT, os_version TEXT,
  environment TEXT,                   -- production/dev/test/lab
  criticality TEXT NOT NULL DEFAULT 'medium'
    CHECK (criticality IN ('critical','high','medium','low')),
  owner TEXT, business_unit TEXT, location TEXT,
  data_classification TEXT,
  internet_exposed INTEGER NOT NULL DEFAULT 0,
  tags TEXT,                          -- JSON
  first_seen DATETIME NOT NULL,
  last_seen DATETIME NOT NULL,
  created_by TEXT, updated_at DATETIME NOT NULL,
  UNIQUE(entity_type, entity_ref)
);

CREATE TABLE asset_aliases (
  asset_id TEXT NOT NULL REFERENCES assets(id),
  alias_type TEXT NOT NULL, alias_value TEXT NOT NULL,
  UNIQUE(asset_id, alias_type, alias_value)
);

CREATE TABLE asset_software (          -- software inventory (spec §38)
  asset_id TEXT NOT NULL,
  name TEXT NOT NULL, vendor TEXT, version TEXT,
  cpe TEXT,
  first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL,
  source TEXT,                        -- 'observed:file' | 'observed:otlp' | 'analyst'
  PRIMARY KEY (asset_id, name, version)
);

CREATE TABLE asset_vulnerabilities (   -- see risk-model.md §8
  asset_id TEXT NOT NULL, cve TEXT NOT NULL,
  severity TEXT, cvss REAL, epss REAL,
  exploit_available TEXT,             -- 'in-the-wild' | 'public-poc' | 'theoretical' | 'unknown'
  evidence TEXT,                      -- JSON provenance
  first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL,
  PRIMARY KEY (asset_id, cve)
);
```

Asset creation:
- **Observed:** first event naming a host/cloud resource auto-creates a draft asset
  (`created_by='observed'`, criticality suggested by heuristics, tagged `draft`).
  Draft assets never influence scoring until an analyst confirms criticality
  (default `medium` is used meanwhile, documented in the score explanation).
- **Analyst:** created/edited via UI/API with full fields.
- **Cloud resources** (spec §7): `cloud_resource` assets carry `cloud.provider`,
  `cloud.account`, ARN; relationships `cloud_account → iam_role → ec2 → container →
  process` are ordinary graph edges, so cloud chains use the same pivot machinery.

## 3. Telemetry Coverage Model

```sql
-- migration 016_coverage.sql
CREATE TABLE asset_telemetry (
  asset_id TEXT NOT NULL,
  source_class TEXT NOT NULL,         -- 'os.windows.security', 'os.linux.auditd', 'net.dns', ...
  available INTEGER NOT NULL,         -- 1 observed in window
  last_event DATETIME,
  event_count_30d INTEGER,
  expected INTEGER NOT NULL DEFAULT 0,-- 1 = analyst declared this source expected on the asset
  collector TEXT,                     -- which collector/agent reported it (heuristic: source_type prefix)
  PRIMARY KEY (asset_id, source_class)
);
```

Coverage computation (background worker, hourly + on-demand):

```
coverage(asset) = Σ weight(class, asset) × availability(class, asset) / Σ weight(class, asset)

weights per asset entity_type:
  windows host:  security 0.25, sysmon 0.25, powershell 0.15, defender 0.10,
                 dns 0.05, network 0.10, audit 0.10
  linux host:    auditd 0.30, sshd 0.15, sudo 0.10, journal 0.15, network 0.15, dns 0.15
  network dev:   firewall 0.4, dns 0.2, netflow 0.2, ids 0.2
  (defaults; overridable per asset)
```

Output per asset: `coverage_pct`, `missing[]` (expected-but-absent classes),
`stale[]` (present but last event > freshness window, default 24h), `unexpected[]`.

Spec §27 example: HOST-42 Windows → security ✓, sysmon ✓, powershell ✓, defender ✓,
dns ✗, network ✗ → coverage ≈ 72% (weights: (0.25+0.25+0.15+0.10)/(0.25+0.25+0.15+
0.10+0.05+0.10+0.10) = 0.75 → "75% (4 of 7 source classes); gaps: dns, network, audit").

## 4. Consumers

- **Scenario evaluation** (`detection-engine.md` §6): each step's required source class
  checked against coverage; gap → step status `unknown` + note
  "telemetry insufficient to determine whether X occurred".
- **Attack graph** (`attack-graph.md`): `potential` edges through a telemetry gap are
  flagged `confidence reduced: no <class> telemetry`.
- **Risk** (`risk-model.md`): coverage does not add points (missing telemetry is not
  guilt), but *suppressed* behavioral checks are annotated.
- **AI context** (`ai-security-analysis.md`): asset block always includes
  `telemetry_coverage` so the model states gaps explicitly.
- **Threat model drift** (`threat-model.md` §5): new asset / new source class / coverage
  drop ≥ 10% → model snapshot diff.
- **UI** (`coverage` page): matrix view per asset, gaps highlighted, stale marked.

## 5. Source-Class Taxonomy (canonical list, extensible)

```
os.windows.security, os.windows.sysmon, os.windows.powershell, os.windows.defender,
os.windows.dns, os.windows.rdp, os.windows.kerberos,
os.macos.unified, os.macos.launchd, os.macos.endpoint,
os.linux.auditd, os.linux.auth, os.linux.sshd, os.linux.sudo, os.linux.journal,
os.linux.syslog, os.solaris.audit, os.generic,
web.access, web.error, db.log, identity.log, net.firewall, net.ids, net.dns,
net.dhcp, net.flow, net.vpn, net.proxy, cloud.audit, cloud.flow, cloud.iam,
container.runtime, k8s.audit, ci.log, generic
```

The taxonomy is data (`internal/coverage/classes.yaml`), so new platforms (mainframe
`mainframe.smf`, `mainframe.racf`; OS/2 `os.os2`) join without code changes.
