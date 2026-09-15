# Quetzalog — Detection & Correlation Engine

**Status:** Phase 1 design. Extends `internal/detections` (today: threshold rules with
`count ≥ N within window`, `group_by`, own mini query parser, scheduled ticker).

Design constraints:
- Keep legacy threshold rules working unchanged (backward compat).
- New rule kinds build on the **existing SPL engine** where practical (spec §20:
  SPL, rules, correlation, threshold, sequence, statistical, behavioral).
- Severity, confidence, risk remain distinct (spec §56).
- Everything explainable: a finding stores the exact rule version + matched evidence.

---

## 1. Detection Rule Model (v2)

```go
type DetectionRule struct {
    // existing fields keep their meaning
    ID, Name, Description, Query, Severity, Enabled string/bool
    Threshold   *Threshold          // threshold kind only
    GroupBy     []string
    RiskScore   float64
    MITRETactic string             // legacy single; kept for compat
    MITRETechnique string          // legacy single
    ScheduleSeconds int
    CreatedBy, DataSources []string

    // v2 additions (migration 018)
    Kind            string    // "threshold" | "spl" | "sequence" | "correlation" | "statistical" | "behavioral" | "scenario"
    Confidence      float64   // default per kind, see risk-model.md §4
    MITRETechniques []string  // multi-technique (JSON column)
    TacticIDs       []string
    RequiredSources []string  // source classes; if any missing → run reports coverage gap
    FalsePositiveNotes string
    References      []string
    ResponseActions []string   // action keys from internal/response registry
    Version         int
    TestEvents      []string   // synthetic events (id'd in a test harness table) for CI
    LastRunAt       time.Time
    Suppressed      bool       // explicit analyst suppression (never implicit)
    SuppressedBy    string
    SuppressReason  string
}
```

Storage: `detection_rules` table extended in place (additive columns; legacy rows get
`kind='threshold'`, `version=1`). Fixes debt #8: `Update()` persists all columns.

### 1.1 Kinds

| Kind | Semantics | Engine |
|---|---|---|
| `threshold` | today's `count ≥ N in window, group_by` — unchanged | legacy mini-parser + `events.Query` |
| `spl` | full SPL pipeline (`search … \| stats … \| where …`); rows above a `HAVING`-style threshold (first aggregate column ≥ N) create findings; `group_by` from SPL `by` | existing SPL executor (synchronous run at schedule/trigger) |
| `sequence` | ordered steps A→B→C per correlation key, each step a predicate, global window, optional per-step max gap | correlation state machine (§3) |
| `correlation` | unordered multi-condition within one window; all/most conditions required; confidence scales with condition count | correlation state (§3) |
| `statistical` | feature deviates from rolling baseline (per entity) by z-score threshold | behavioral engine (§7) |
| `behavioral` | named behavioral pattern (rare process, impossible sequence, first-seen destination) = statistical with semantic naming + optional technique mapping | behavioral engine (§7) |
| `scenario` | threat scenario instance (technique chain with required telemetry) — see §6 | scenario evaluator |

### 1.2 Execution & Triggers

- **Scheduled:** existing ticker, per-rule `ScheduleSeconds` (default from config
  `detections.interval`); each run records `last_run_at`.
- **Incremental:** runs query only `[last_run_at − overlap, now]` (overlap = window +
  2min skew margin) instead of full history; findings dedup as today
  (`dedup_key = rule_id|group_key`) so re-runs bump match counts, not noise.
- **Event-driven hooks:** high-priority rules (sequence/correlation with state) receive
  `event_written` notifications from the async work queue and evaluate immediately;
  the scheduled run remains the safety net. Ingestion never calls detection code
  synchronously (spec §60, principle 17).
- **Test runs:** `POST /detections/{id}/exec` (existing) accepts `test` payload →
  evaluates against `test_events` only; used by CI (spec §67) and by the detection
  catalog (§9).

## 2. Sequence Rules (spec §21)

```yaml
kind: sequence
name: Lateral Movement After Initial Access
correlation_key: [user, host]     # entities that must match across steps
window: 4h
max_gap_between_steps: 30m
steps:
  - id: initial
    predicate: source_type=os.windows.security AND vendor_event_id=4624 AND logon_type IN (2,3,10)
    technique: T1078
  - id: priv
    predicate: source_type=os.windows.security AND vendor_event_id=4672
    technique: T1068
  - id: lateral
    predicate: source_type=os.smb AND action=connect
    technique: T1021
on_match:
  severity: high
  confidence: 0.8
  techniques: [T1078, T1068, T1021]
```

State (per rule × correlation-key hash) in `correlation_state`:

```sql
CREATE TABLE correlation_state (
  rule_id TEXT NOT NULL,
  state_key TEXT NOT NULL,          -- hash(correlation_key values)
  current_step INTEGER NOT NULL,
  step_first_event TEXT,            -- event id
  last_event_at DATETIME NOT NULL,
  evidence TEXT,                    -- JSON: event ids per matched step
  expires_at DATETIME NOT NULL,     -- last_event_at + window
  PRIMARY KEY (rule_id, state_key)
);
```

Properties: steps must arrive in order (out-of-order events within `max_gap` are
buffered up to 20 entries per state, then re-ordered by timestamp); expired states
pruned by a sweeper (15 min); all states are inspectable via API
(`GET /detections/{id}/states`) — a stuck sequence must be debuggable, not a black box.

## 3. Correlation Rules (spec §21 example)

```yaml
kind: correlation
name: Brute Force + New Device + Privileged Action
correlation_key: [user]
window: 1h
require: all            # or "most" with min_match: 3
conditions:
  - failed_logins:  { predicate: outcome=failure AND event_type=auth,  count_gte: 5 }
  - success:        { predicate: outcome=success  AND event_type=auth }
  - new_device:     { predicate: attributes.device_id NOT SEEN in baselines (entity first_seen < 24h) }
  - privileged:     { predicate: event_type=admin OR user privilege=privileged }
on_match:
  severity: high
  confidence: 0.85     # base; +0.05 per additional condition beyond required, cap 0.95
  techniques: [T1110.003]
```

Temporal windows honored: `within 5 minutes / 1 hour / 24 hours` are plain
`window:` values. Each condition is an SPL predicate run against the window; the
correlation engine is a thin loop over conditions + state bookkeeping (same table as
sequences, `rule_id`-scoped). Higher-confidence investigation: the produced finding
carries `confidence` and per-condition evidence, and auto-suggests
`response_actions: [investigation.create]`.

## 4. Statistical & Behavioral Rules (spec §18)

Baselines (table in `014_behavioral.sql`):

```sql
CREATE TABLE baselines (
  entity_type TEXT NOT NULL,        -- user | host | process | destination | identity | application | service
  entity_value TEXT NOT NULL,
  feature TEXT NOT NULL,            -- 'login_count_per_hour','dest_rarity','process_tree','bytes_per_hour','login_hour_hist',...
  window_days INTEGER NOT NULL DEFAULT 30,
  mean REAL, stddev REAL, p95 REAL, sample_count INTEGER,
  last_updated DATETIME NOT NULL,
  PRIMARY KEY (entity_type, entity_value, feature, window_days)
);
CREATE TABLE anomalies (
  id TEXT PRIMARY KEY,
  entity_type TEXT, entity_value TEXT, feature TEXT,
  observed REAL, baseline_mean REAL, z REAL,
  detected_at DATETIME NOT NULL,
  detection_id TEXT,                -- link to the rule that scored it
  suppressed_reason TEXT            -- e.g. 'vpn-traversal' (risk-model.md §5)
);
```

- Baseline updater (async worker, hourly): rolling window stats from stored events;
  minimum 20 samples / 14 days before a feature is "trusted" (below that → unknown,
  no anomaly scores — spec: no telemetry ≠ no activity).
- Deviation scoring per `risk-model.md` §5.
- Rare-destination / rare-process: novelty count from `entities.last_seen` vs
  `first_seen` (first_seen in window → novelty contribution, capped).
- Impossible sequences: login-time histogram + travel-speed check **suppressed** when
  the route includes VPN/proxy-tagged infrastructure (documented; spec §19).

## 5. MITRE Mapping in Detections

- v2 rules carry `MITRETechniques []string` + `TacticIDs`; findings store them
  (additive columns; legacy single fields remain populated for compat).
- Technique-level coverage view: `GET /mitre/active` (existing) + new
  `GET /mitre/techniques/{id}/events` and `/findings` (graph queries,
  `entity-model.md` §5).
- Behavior chains are scenario constructs (§6), never single-event claims.

## 6. Threat Scenarios (spec §25)

A scenario is a reusable, composable attack chain with explicit telemetry requirements:

```sql
CREATE TABLE scenario_runs (
  id TEXT PRIMARY KEY,
  definition TEXT NOT NULL,         -- JSON snapshot of the scenario (versioned copy)
  scope TEXT,                       -- e.g. 'host:WORKSTATION-42' or 'global'
  status TEXT NOT NULL,             -- active | completed | stale
  confidence REAL, risk REAL,
  opened_at DATETIME, closed_at DATETIME,
  PRIMARY KEY (id)
);
CREATE TABLE scenario_steps (
  run_id TEXT NOT NULL,
  step_id TEXT NOT NULL,
  tactic TEXT, technique TEXT,
  status TEXT NOT NULL CHECK (status IN ('observed','expected','missing','unknown','blocked')),
  evidence TEXT,                    -- JSON event ids (observed/blocked) or coverage gap ref
  confidence REAL,
  PRIMARY KEY (run_id, step_id)
);
```

Scenario definition (data, e.g. `scenarios/web-compromise.yaml`, spec §53):

```yaml
name: Web Server Compromise
prerequisites:
  - asset.internet_exposed
  - asset.software(vulnerable)
signals:
  - technique: T1190        # exploitation
  - technique: T1059       # execution
  - technique: T1136       # persistence
  - technique: T1071       # C2
expected_techniques: [T1190, T1059, T1136, T1071, T1041]
required_sources: [web.access, net.firewall, os.linux.auditd]
risk: high
```

Evaluator (async, on new findings + hourly):
1. A matching finding (or technique-observed event) with `T1190` on an internet-exposed
   asset opens a run.
2. Each expected technique checked against events in the run window:
   - evidence events → `observed` (with event ids + confidence);
   - deny/blocked events → `blocked`;
   - no events **and** required source present → `missing` (evidence that it likely
     did not happen, within telemetry bounds);
   - no events **and** source missing → `unknown` + coverage note
     "telemetry insufficient to determine whether lateral movement occurred"
     (spec §25 verbatim behavior).
3. Run risk = weighted observed-technique severity × coverage factor; scenario
   completion (all observed) → finding with `confidence` boosted.
Output feeds UI (attack-chain view), AI context, and the "what could happen next"
question: `expected` steps are the next-likely actions, `unknown` steps are the
*we-don't-know* list.

## 7. False-Positive Learning (spec §55)

```sql
CREATE TABLE finding_feedback (
  finding_id TEXT NOT NULL,
  label TEXT NOT NULL CHECK (label IN ('true_positive','false_positive','benign',
    'expected_behavior','accepted_risk')),
  reason TEXT,                      -- required for false_positive/accepted_risk
  analyst TEXT NOT NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (finding_id, analyst)
);
```

- FP label on a finding → `detection_rules` gets an optional `suppressed` **only if**
  the analyst explicitly chooses "suppress detection" (two-step, never implicit).
  Suppression stores rule + reason + analyst + timestamp and is visible on the rule
  page and in every run report.
- Feedback influences: (a) detection confidence calibration (rolling FP rate per rule
  shown in the rule UI — informational in v1, no silent weight changes), (b) AI context
  ("analyst marked N similar findings false positive: reason …").
- No rule is auto-disabled by the system.

## 8. Sigma Compatibility (spec §42)

Importer only — Sigma is **not** the internal model:

```
sigma yaml ─▶ sigma importer ─▶ detection abstraction ─▶ Quetzalog rule (kind=spl|threshold)
```

- Supported: `detection.status: active`, `logsource.product/category` →
  `source_type` mapping, `detection.*` selectors → SPL `search` predicates
  (`contains/startswith/endswith/and/requires` subsets), `condition` with `of them`
  counts → thresholds or `stats ... where`, `fields`, `tags` → MITRE mapping.
- Unsupported constructs fail import with a structured error listing each unsupported
  clause (never partial silent import).
- Imported rules are tagged `sigma:<name>@<version>` and versioned like catalog rules.

## 9. Detection Catalog / Marketplace (spec §41)

Versioned detection bundles: `examples/detections/*.yaml` (dir exists; today holds
demo rules) become the seed catalog. Catalog entry = rule v2 + `test_events` +
`data_sources` + MITRE + FP notes + references. `quetzalog demo` and the UI "catalog"
page install them; each install stamps `version` so upgrades are detectable.

## 10. Built-in Hunting Queries (spec §54)

Shipped as data (catalog entries with `hunting: true`), not code:
- **Windows:** suspicious PowerShell (`-enc`/`-noninteractive`/download cradles),
  encoded commands, LSASS access (Sysmon 10 / comsvcs), unusual services, scheduled
  task persistence (4698/Task Scheduler EIDs), RDP lateral movement (4624 type 10),
  Kerberos anomalies (4769 ticket options, golden-ticket heuristics).
- **Linux:** suspicious SSH (auth failures burst, new keys), sudo abuse (no TTY,
  abnormal commands), cron persistence (`/etc/cron*` writes), systemd persistence
  (unit file writes), unusual shell execution (reverse-shell patterns),
  suspicious binaries (temp-dir execution).
- **macOS:** launch agent persistence (`~/Library/LaunchAgents`, `/Library/LaunchAgents`
  writes), unusual shell execution, unsigned applications (Gatekeeper/XProtect events),
  credential access (keychain access patterns), abnormal network connections.
- **Web:** scanning (404/405 bursts, user-agent sweeps), exploitation (known path
  patterns), web shells (script exec from web process), path traversal, SQL injection,
  SSRF, command injection.
- **Network:** beaconing (interval regularity in `streamstats`), DNS tunneling
  (label-entropy/length heuristics over DNS source class), port scanning, unusual
  outbound, lateral movement.

These run through the normal detection engine as `kind=spl`/`threshold` rules with
`hunting` tag — visible, editable, disable-able like any other rule.

## 11. Performance (spec §60, §69)

- Detection runs are off the write path (async queue + schedule); a run is one or a few
  bounded SQL queries over `[last_run_at−overlap, now]`.
- `streamstats`-style beaconing queries are the expensive case: cap the window
  (default 6h) and group set (top-N destinations by volume); documented in the rule.
- Correlation state table pruned hourly; sequence buffers capped (20 events/state).
- Baseline updates batched per entity-feature, off-peak.
- Exit criteria (benchmarks): at 1k EPS, detection trigger-to-finding p95 < 5s for
  event-driven rules; scheduled sweep < 30s over 24h window at 100k events.
