# Quetzalog — Threat Intelligence, Threat Analysis & Threat Modeling Architecture

**Status:** Phase 1 — Architecture (design only; no code changes yet)
**Scope:** Extend Quetzalog from a log-search SIEM into a security reasoning system,
without breaking the existing SPL search, ingestion, findings, investigations, or AI Analyst.

> **Design principle**
> Quetzalog should evolve from a log search system into a security reasoning system:
> evidence in, context added, relationships understood, threats modeled, uncertainty
> preserved, and actionable intelligence presented to a human analyst.

---

## 1. Mission

The threat-analysis layer must let Quetzalog answer:

1. What is happening in this environment?
2. Why does it matter?
3. How does it relate to known attacker behavior (MITRE ATT&CK)?
4. What could an attacker do next (attack paths / scenarios)?
5. What do we **not** know (missing telemetry, low confidence, unobserved steps)?
6. What should the analyst investigate or do about it?

The core security model everything correlates through:

```
Assets → Telemetry → Normalized Events → Entities → Behaviors → Indicators
→ Techniques → Tactics → Threat Actors / Campaigns → Attack Paths → Risk
→ Investigations → Recommended Actions
```

## 2. Current-State Audit

What exists today (verified against the codebase, `main` @ `1781c7c`):

| Area | Today | Where |
|---|---|---|
| Event model | `event.Event`, 28 typed fields + `attributes map[string]any`; `Raw []byte` preserved **only** by HEC `/raw`; all other sources discard wire bytes | `pkg/event/event.go:13-45` |
| Ingestion | Pipeline (channel → N workers → batch → SQLite tx). Sources: JSON/HTTP (8081), Splunk HEC (8088), Syslog UDP/TCP (RFC 3164/5424 regex), file tail (json/ndjson, syslog, regex, plain), OTLP HTTP+gRPC. Buffer-full events are **dropped** | `internal/ingestion/*` |
| Storage | Single SQLite DB, WAL + FTS5 on `(message, attributes)`, 12 B-tree indexes, embedded numbered migrations `001,002,004,005,006,007` (003 missing) | `internal/events/store.go`, `internal/database/migrations/` |
| Query | SPL engine: 17 commands parsed (`search where eval fields table rename stats timechart sort head tail dedup rex bin lookup eventstats streamstats`); `bin`/`lookup` parse but are no-ops; synchronous, no caching; default limit 100 / cap 1000 (service), 50000 (executor) | `internal/spl/*`, `internal/query/service.go` |
| Detections | Threshold rule: `count ≥ N within window, group_by key`, own mini query parser (not SPL); scheduled ticker; emits findings + risk contributions; rule has one MITRE tactic/technique, **no confidence** | `internal/detections/detection.go` |
| Findings | Dedup by `detection_id|group_key`; statuses `new in_progress investigating contained resolved false_positive`; severity `critical/high/medium/low`; rich filter queue; saved views | `internal/findings/*` |
| Investigations | Persistent workbench: linked findings/events/entities/queries/techniques + notes; statuses incl. `contained` | `internal/investigations/investigations.go` |
| Risk | Additive per-entity risk: `entity_risk` + `risk_contributions` (every contribution recorded with source/description/points — already explainable). Event-level `risk.Scorer` is **dead code** | `internal/risk/entity_risk.go` |
| Entity graph | `entities` (`type,value` unique; first/last_seen, count) + `relationships` (5-tuple, weight). Built **synchronously on every event write**. 9 entity types; `domain`/`email` declared but never produced. No observed/inferred states, no provenance per edge. `GetRelatedEvents` references a nonexistent `events.email` column (latent bug) | `internal/correlation/graph.go` |
| MITRE | Static embedded catalog: 14 tactics, ~73 techniques/sub-techniques. Mapping exists only via detection-rule fields → findings | `internal/mitre/mitre.go` |
| Enrichment | `Enricher` interface + `LocalIPEnricher` + `GeoIPEnricher` (MaxMind DB or HTTP) exist but are **constructed and discarded** in `cmd/siem` — nothing is registered with the pipeline | `internal/enrichment/*`, `cmd/siem/main.go:239-243` |
| AI Analyst | OpenAI-compatible (+ opencode) provider; 48 KB structured context (finding + ≤100 events @240 chars + ≤5 related findings + entity summary); strict `Analysis` schema with type-drift tolerance; `requires_human_approval` forced true; approve/dismiss workflow; correlate-to-search; auto-analysis on new findings (async, severity-gated, rate-limited) | `internal/ai/*`, migration `007_ai_analyst.sql` |
| Response | Action registry (FP, assign, tag, risk+, create investigation, run search, open URL, webhook); SSRF-guarded; audited; **no approval gate** beyond role checks | `internal/response/response.go` |
| Auth/RBAC | `admin/analyst/viewer`; per-user tokens; audit log; bcrypt; lockout | `internal/auth/*` |
| Config | Sections: `server, database, ingestion, http, otel, syslog, splunk, logging, file_ingestion, auth, detections, ai_analyst`. No TI/MITRE/behavioral/coverage/assets sections | `internal/config/config.go` |
| UI pages | `overview, queue, finding, investigations, investigation, aianalyst, search, builder, detections, risk, entities, entity, mitre, settings, notfound` | `internal/web/static/js/pages-*.js` |
| Tests | Per-package unit tests (ai, api, events, spl, detections, findings, risk, …), SPL test suites, simple benchmark harness. No adversarial/EPS-scale suites | `internal/**/_test.go`, `tests/spl/`, `benchmarks/` |

### Known technical debt (must not be worsened; some items fixed by this plan)

1. Raw payload preserved only by HEC `/raw`; syslog/JSON/file/OTLP lose original bytes.
2. No CEF / LEVF / GELF parsers; RFC 5424 structured data not parsed (SDID token only).
3. Entity extraction reads fixed struct fields only — nothing extracted from `message`/`attributes`/`raw` (no IP/domain/email/hash regexes).
4. Enrichment pipeline wired but never activated; GeoIP config absent from `Config`.
5. No event-level dedup (UUID PK only); no out-of-order/watermark machinery.
6. Pipeline drops under back-pressure (channel `default:` branch); batch write failure drops the batch.
7. `correlation.GetRelatedEvents` queries nonexistent `events.email` (graph.go:267).
8. `detections.Store.Update` does not persist `mitre_*`, `tags`, `risk_score`, `schedule_seconds`, `data_sources`.
9. Incident status values used by API (`open`, `investigating`, `resolved`) don't match `incidents.Statuses`.
10. `bin`/`lookup` SPL commands are silent no-ops; `docs/compatibility.md` claims `/services/search/jobs` support that does not exist.
11. `risk.Scorer` and webhook notifier plumbing exist but are unregistered.
12. Attribute-based queries are unindexed `json_extract` scans.
13. OTLP HTTP protobuf is a stub; gRPC path drops non-string attribute values.

## 3. Target Architecture

### 3.1 Concept-to-component map

| Security concept | Quetzalog package | Status |
|---|---|---|
| Telemetry (collectors) | `internal/ingestion/*` | exists, extended |
| Parsers (per format) | `internal/parsers/*` (new; split out of ingestion) | new |
| Normalizers (format → canonical) | `internal/normalization/*` (new) | new |
| Canonical event model | `pkg/event` | extended |
| Assets | `internal/assets` (new) | new |
| Entities + resolution | `internal/entities` (new; supersedes `internal/correlation`) | new (correlation re-scoped) |
| Relationship graph / knowledge graph | `internal/entities` + `internal/graph` (new query layer over `relationships`) | extended |
| Behaviors / baselines | `internal/behavior` (new) | new |
| Indicators (IOCs) | `internal/threatintel` (new) | new |
| Threat actors / campaigns / malware | `internal/threatintel` | new |
| TI provider abstraction + STIX | `internal/threatintel` | new |
| Enrichment (IOC lookup, GeoIP, assets) | `internal/enrichment` | extended, finally activated |
| MITRE ATT&CK | `internal/mitre` | extended (event mapping, chains) |
| Vulnerabilities (CVE/CVSS/CPE/EPSS) | `internal/vulnerabilities` (new) | new |
| Detections + correlation + scenarios | `internal/detections` | extended |
| Attack graph / paths | `internal/attackgraph` (new) | new |
| Threat modeling + STRIDE + controls | `internal/threatmodel` (new) | new |
| Telemetry coverage | `internal/coverage` (new) | new |
| Risk scoring | `internal/risk` | extended |
| Investigations / hypotheses | `internal/investigations` | extended |
| Findings (analyst queue) | `internal/findings` | unchanged core, new fields |
| AI Analyst | `internal/ai` | extended (context v2, statement classification, model roles) |
| Response actions | `internal/response` | extended (maps to AI-recommended actions; approval record) |
| Compliance / control mapping | `internal/compliance` (new, thin: control catalog + evidence links) | new |
| API | `internal/api` | extended |
| UI | `internal/web` | new pages |

**Rule:** no new capability may add a dependency to the ingestion hot path. The pipeline
must stay AI-free and TI-free at write time; enrichment/detection/graph work happens in
background workers (spec principle 17).

### 3.2 Data flow (target)

```
 ┌────────────────────────── INGESTION (synchronous, fast, no AI) ──────────────────────────┐
 │  collectors ─▶ parsers ─▶ normalizers ─▶ Event (v2, raw preserved) ─▶ events table      │
 │                                                          │            + FTS5             │
 │                                                          ▼                               │
 │                                            entity extraction (typed regex/field rules)   │
 │                                                          │                               │
 │                                              entities / entity_identities (fast upserts) │
 └──────────────────────────────────────────────────────────┼───────────────────────────────┘
                                                            │  async work queue (channel)
      ┌──────────────┬───────────────┬──────────────┬───────┴──────┬───────────────┐
      ▼              ▼               ▼              ▼               ▼               ▼
 enrichment     baseline         detection      correlation/    threat-intel     risk
 (IOC lookup,   update           engine         attackgraph     provider sync    contribution
  GeoIP, asset) (behaviors)      (threshold,    (observed edges) (feeds, STIX)   recorder
                        │            sequence,      │                    │
                        │            correlation,   │                    ▼
                        │            scenario)      │              indicators table
                        ▼              ▼            ▼                     │
                   findings ◀────── risk scoring ◀──┴────────────────────┘
                        │
                        ▼
              investigations ◀── hypotheses / findings / evidence
                        │
                        ▼
              AI Analyst (async, budgeted context, OBSERVED/INFERRED/
              HYPOTHESIS/UNKNOWN statements, human approve/dismiss)
                        │
                        ▼
              recommended actions → analyst approval → response actions (audited)
```

Async boundary: a single bounded work queue (channel + N workers, same pattern as
`internal/ingestion/pipeline.go`) consumes `event_written` notifications. Consumers:
enricher fan-out, baseline updater, incremental detection evaluation, graph updater,
coverage refresher. Every consumer is independently disable-able via config and must
degrade gracefully (drop + metric, never block ingestion).

### 3.3 New config sections (additive; existing sections untouched)

```yaml
threat_intelligence:
  enabled: true
  providers:
    - name: internal
      type: internal            # built-in indicator store as provider
    - name: abuse-ch
      type: abusech
      enabled: true
  io_caching:
    ttl: 24h
mitre:
  enabled: true
  event_mapping: true           # map normalized events to techniques
behavioral_analysis:
  enabled: true
  baseline_window: 30d
attack_graph:
  enabled: true
vulnerability_correlation:
  enabled: true
assets:
  enabled: true
telemetry_coverage:
  enabled: true
ai_analyst:                     # existing section; see ai-security-analysis.md
  enabled: true
  # + model_roles: (fast/reasoning/embedding endpoints)
```

All new features default to **disabled** on existing installs (backward compatibility);
`config.example.yaml` gains commented-out examples.

### 3.4 API surface (new, all under `/api/v1`, same envelope/pagination conventions)

| Area | Endpoints |
|---|---|
| Indicators | `GET/POST /indicators`, `GET /indicators/{id}`, `POST /indicators/lookup` (value → hits), `GET /indicators/{id}/events` |
| Threat actors | `GET /threat-actors`, `GET /threat-actors/{id}` (campaigns, malware, infra, techniques) |
| TI providers | `GET /threat-intel/providers`, `POST /threat-intel/providers/{name}/sync`, `GET /threat-intel/sync/status` |
| Assets | `GET/POST /assets`, `GET /assets/{id}` (telemetry, software, risk, coverage), `PATCH /assets/{id}` |
| Coverage | `GET /coverage/assets/{id}`, `GET /coverage/summary` |
| Entities v2 | `GET /entities-v2/{type}/{value}` (aliases, intel, risk, coverage, techniques, vulnerabilities, investigations), `GET /entities-v2/{type}/{value}/neighbors?depth=`, `GET /entities-v2/resolve` (candidate entities for a raw string) |
| Attack graph | `GET /attack-graph` (nodes/edges with states), `GET /attack-graph/paths?from=&to=`, `GET /attack-graph/paths/{id}` |
| Threat models | `GET/POST /threat-models`, `GET /threat-models/{id}`, `POST /threat-models/{id}/refresh` (re-derive from telemetry), `GET /threat-models/{id}/drift` |
| Scenarios | `GET /scenarios`, `GET /scenarios/{id}/status` (observed/expected/missing per step) |
| Detections v2 | existing routes extended: rule `kind`, `confidence`, multi-technique, `data_sources`, `test_events` |
| Risk explain | `GET /risk/entities/{type}/{value}/explain` (contributions list, same as existing contributions, formatted) |
| Exports | `GET /export/findings?format=json|csv|stix`, `GET /export/investigations/{id}?format=stix` |
| AI analyst | existing routes + `GET /ai-analyst/{id}/statements` (classified statements) |

### 3.5 UI pages (new)

`threat` (Threat Overview), `investigation-v2` (timeline/entity/technique/tactic/chain views,
hypotheses, AI findings), `entity-v2` (full entity dossier per spec §47), `attack-graph`
(SVG graph, observed/inferred/potential/blocked edge styling), `threat-model`,
`threat-intel` (indicators, providers, sync status), `coverage` (per-asset telemetry matrix),
`mitre-v2` (technique → detections/events/investigations pivots).
Existing pages keep working; new pages are additive menu entries.

## 4. Cross-Cutting Data Model (SQLite, additive migrations)

Migration numbering continues from `007_ai_analyst.sql`. Each file is small and reversible
(documented in comments). No `DROP` of existing columns.

| Migration | Tables |
|---|---|
| `008_assets.sql` | `assets`, `asset_aliases`, `asset_software` (software inventory) |
| `009_entities_v2.sql` | `entity_identities` (aliases/resolution), `entity_meta` (criticality/OS/cloud context), extended `relationships` via new table `relationship_meta` (status, source, provenance, first/last_seen — avoids breaking the hot-write 5-tuple) |
| `010_indicators.sql` | `indicators`, `indicator_sources`, `indicator_correlations`, `threat_actors`, `campaigns`, `malware_families`, `ti_provider_state` |
| `011_vulnerabilities.sql` | `vulnerabilities` (CVE/CVSS/CPE/EPSS), `asset_vulnerabilities` |
| `012_attack_graph.sql` | `attack_paths`, `path_steps` |
| `013_threat_models.sql` | `threat_models`, `tm_nodes`, `tm_edges`, `threats`, `controls`, `threat_controls`, `model_snapshots` (drift) |
| `014_behavioral.sql` | `baselines`, `anomalies` |
| `015_correlation.sql` | `correlation_rules`, `correlation_state` (sequence cursors), `scenario_runs`, `scenario_steps` |
| `016_coverage.sql` | `asset_telemetry` (availability per source type, freshness) |
| `017_ai_v2.sql` | `ai_analyses` additions: `model_version`, `context_hash`; `ai_statements` (classified statements + evidence refs); `ai_action_decisions` (recommendation/approval record) |
| `018_detection_v2.sql` | `detection_rules` additions: `kind`, `confidence`, `mitre_techniques` (JSON multi), `false_positive_notes`, `references`, `response_actions`, `version`, `test_events`, `last_run_at`, `suppressed` + `finding_feedback` (FP learning, explicit reasons) |

Details per domain in the companion docs:
`security-event-schema.md`, `entity-model.md`, `risk-model.md`, `telemetry-coverage.md`,
`detection-engine.md`, `attack-graph.md`, `threat-model.md`, `ai-security-analysis.md`.

## 5. Migration & Backward-Compatibility Strategy

1. **Events table stays.** All existing columns keep meaning. New canonical fields land
   first in `attributes` (zero schema change), then as real columns only when queries need
   indexing (migration notes say why). `raw` becomes mandatory-preserving for all sources
   (fix debt #1) — stored as today, just populated by every parser.
2. **SPL untouched.** Search bar, builder, `/api/v1/search` semantics unchanged. Detections
   may optionally use full SPL (new `kind: spl`) while legacy threshold queries keep working.
3. **Findings/investigations unchanged in lifecycle.** New fields only (multi-technique,
   hypothesis links). Existing API responses keep every current field.
4. **Entity graph is additive.** `entities`/`relationships` keep their shape; v2 metadata
   rides on new tables keyed by `(from_type, from_value, to_type, to_value, relation)`.
   The synchronous write path gains only one extra cheap upsert when resolution is enabled.
5. **AI Analyst keeps its schema.** `Analysis` JSON gains optional new fields; old analyses
   remain readable; `RequiresHumanApproval` invariant stays.
6. **Feature flags.** Every new subsystem behind a config flag, default off on upgrades.
   `quetzalog demo` seeds a richer scenario (Windows/Linux/web attack chain) so all new
   views are demonstrable.
7. **Rollout order** matches spec phases 2–8:
   - Phase 2 Foundation: event schema v2 + raw preservation, parsers/normalizers split,
     entity extraction/resolution, assets, provenance, risk contributions v2, coverage.
   - Phase 3 Threat intel: indicator model, enrichment framework activation, provider
     interface + internal provider, first external provider (Abuse.ch), correlation.
   - Phase 4 MITRE: event→technique mapping rules, technique/tactic views, detection mapping.
   - Phase 5 Detection + correlation: rule `kind`s (sequence, correlation, statistical,
     behavioral), threat scenarios, FP feedback.
   - Phase 6 Attack graph / threat modeling: edge states, attack paths, trust boundaries,
     modeling-from-telemetry, drift.
   - Phase 7 AI Analyst v2: context builder v2, statement classification, provenance
     validation, model roles.
   - Phase 8 UI: Threat Overview, Investigation v2, Entity dossier, Attack Graph,
     Threat Model, Threat Intel, Coverage, MITRE v2.

## 6. Testing Strategy (spec §67–69)

- **Unit:** per new package (parsers: CEF/LEEF/GELF/RFC5424-SD vectors; extractor: golden
  datasets; resolver: alias cases; TI: provider fake; scorer: explainability assertions).
- **Integration (new `tests/threat/`):** realistic synthetic attack scripts (extend the
  existing demo scenario into a 10-event chain: phishing → valid login → encoded PowerShell
  → credential access → lateral SMB → C2 beacon → exfil) asserting: entities resolved,
  techniques mapped, scenario coverage correct, attack path states, risk reasons, coverage
  gaps reported as `unknown`.
- **Adversarial (new `tests/adversarial/`):** log injection, malformed logs, timestamp
  manipulation, spoofed IP fields, malicious usernames, command-injection strings, prompt
  injection payloads inside event data, poisoned TI feeds, conflicting sources, missing
  telemetry, duplicate events, out-of-order events. Each case asserts safe failure
  (no panic, no state corruption, `unknown` where evidence absent).
- **Performance:** extend `benchmarks/` with 100/1k/10k EPS synthetic load measuring
  ingestion latency, detection latency, query latency, graph generation; thresholds recorded
  in `benchmarks/README.md`, not hardcoded.

## 7. Security Principles (enforced throughout; spec §74)

1. Raw evidence is immutable — parsers never mutate `Raw`; corrections happen via
   enrichment attributes with provenance.
2. Every conclusion has provenance — findings/edges/AI statements cite event IDs.
3. Observed ≠ inferred — graph edges and AI statements carry an explicit state; UI never
   renders inferred as observed.
4. No telemetry ≠ no activity — analysis over a missing source yields `unknown` +
   `telemetry_coverage: missing`, never "no activity".
5. Severity ≠ confidence ≠ risk — three distinct fields; a `critical/30%/42` triple is legal.
6. TI is contextual — indicator hits carry multi-dimensional confidence
   (source_reliability, indicator_confidence, context_confidence, temporal_relevance,
   corroboration); a single weak source cannot classify an indicator malicious.
7. Attribution requires evidence — confidence ladder: `associated with` → `consistent with`
   → `possibly related to` → `attributed to`.
8. AI recommendations require human approval for consequential actions (existing invariant,
   extended to the full recommended-action vocabulary).
9. Logs are untrusted input — all event text is data in every consumer (queries parameterized,
   AI context fenced, no eval of log content).
10. External TI is untrusted input — provider payloads are validated, quarantined in their
    own tables, and never influence system prompts.
11. No secrets leak into AI context — redaction pass over context fields before send.
12. Do not hide uncertainty — `unknown` is a first-class value in scenarios, coverage,
    hypotheses, and AI output.
13. Explainable scoring — every risk number is a sum of recorded contributions.
14. Interoperability preserved — HEC/OTLP/SPL semantics unchanged; STIX only at import/export
    boundaries.
15. Design for legacy systems — generic parsers + file-based ingestion cover OS/2, mainframe
    exports, unknown vendors without dedicated code.
16. Design for unknown future software — application profiles (YAML) + parser registry, no
    hard-coded support lists.
17. Ingestion never depends on AI/TI — the write path only touches events + FTS + (optional)
    entity upserts; everything else is background and skippable.

## 8. Open Questions

1. Entity write path: keep entity upserts synchronous (today's behavior) or move to the
   async queue with a bounded lag? Decision: keep synchronous for Phase 2 (data is cheap;
   ordering matters for first/last_seen), move to async only if profiling shows write cost.
2. `incidents` vs `investigations`: keep both (backward compat) and mark `incidents`
   legacy in docs; new workflows use investigations.
3. Graph query engine: SQLite BFS with depth cap (≤ 4) vs materialized `attack_paths`.
   Decision: both — on-demand BFS for pivots, materialized paths only for scenario
   evaluation and UI attack-graph view.
4. Retention engine (spec §45): defer to a follow-up doc; until then retention is manual
   (DB file level) and documented as a limitation.
5. Compliance depth: `internal/compliance` stays thin in Phase 1 (control catalog +
   threat↔control links + evidence pointers); full control-telemetry evidence chains come
   after coverage is stable.
