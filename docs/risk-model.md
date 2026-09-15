# Quetzalog — Explainable Risk Model

**Status:** Phase 1 design. Extends `internal/risk` (today: additive
`entity_risk` + `risk_contributions` — keep as the foundation).

Core rules (spec §22, §56, §74):
- **Severity ≠ confidence ≠ risk.** Three distinct values, always stored separately.
- **No magic numbers without documentation.** Every weight in this doc is a default;
  every produced score is a sum of recorded contributions with reasons.
- **Explainable:** any risk number must be reconstructable from `risk_contributions`
  rows and the weights table.

---

## 1. Scored Objects

| Object | Risk meaning |
|---|---|
| Event | "How bad is this event in context?" (computed async; `events.risk_score`) |
| Finding | "How urgent is this detection result?" (queue ranking) |
| Entity (user/host/ip/process) | "How suspicious is this entity lately?" (existing) |
| Asset | "How much damage matters if this asset is compromised?" (criticality, static-ish) |
| Investigation | Aggregated risk of linked findings/entities |
| Attack path | "Value of the shortest credible compromise route" |

## 2. Event Risk Formula

```
Risk(event) = clamp( Σ contributions , 0, 100 )

contributions (each recorded as a risk_contributions row, signed, with reason):

  severity_base        severity points (critical 50 / high 35 / medium 20 / low 10)
                       × detection confidence when the event came from a detection
  ti_confidence        matched indicator: +15×corroboration×recency (see §3)
  asset_criticality    asset of host/resource: critical +10, high +6, medium +3, low +1
  identity_privilege   privileged/admin user: +10; service account acting interactively: +12
  behavioral_anomaly   baseline deviation z-score band: +5..+15 (see §5)
  attack_path          event completes an observed step of an active scenario: +10
                       event on a path toward a critical asset: +5
  technique_weight     mapped technique in high-impact tactic (Exfil/Impact/PrivEsc): +5
```

Example (spec §22 style, fully reconstructable):

```
Risk: 87
  +25  known malicious destination        (ti_confidence, indicator i-4482, corroboration 3, recency 1.0)
  +20  privileged account                 (identity_privilege, user 'svc_backup' is admin)
  +15  unusual process                    (behavioral_anomaly, powershell z=4.1 for host)
  +12  rare destination                   (behavioral_anomaly, dest 203.0.113.50 never seen for user)
  +10  lateral movement technique         (technique_weight T1021, tactic Lateral Movement)
  +5   critical server                    (asset_criticality, file-srv-01 = critical)
```

Weights are the defaults above; all are overridable in config
(`risk.weights.*`) — changing weights changes *future* contributions only; stored
contributions keep the weight they were computed with (row has `points` + `reason`).

## 3. TI Confidence Contribution (multi-dimensional, spec §13/§36)

An indicator match does **not** classify the entity malicious by itself. Contribution:

```
ti_confidence = base(15)
  × source_reliability      (0.2 low … 1.0 high, from indicator_sources.reliability)
  × corroboration_factor    (min(1.0, independent_sources / 3))
  × temporal_relevance      (1.0 if last_seen < 90d, decay to 0.3 at 2y; see §6)
  × context_confidence      (1.0 same context as event, 0.5 related, 0.2 weak)
```

One weak source (reliability 0.3, 1 source, 2-year-old) → ~0.4 points → effectively
inert, but still recorded and visible. The *display* classification
(`associated with / consistent with / possibly related to / attributed to`) is a
separate function of the same dimensions (spec §37), not of the risk number.

## 4. Detection Rule Confidence

Rules gain a `confidence` (0–1, default per `kind`: threshold 0.6, sequence 0.75,
correlation 0.8, behavioral 0.5, scenario 0.7). The finding's stored `confidence` is
the rule confidence adjusted by corroboration (additional independent techniques
observed in the same window: +0.05 each, cap 0.95). Severity stays the rule's severity.
A `critical / confidence 0.3 / risk 42` finding is legal and must render as such.

## 5. Behavioral Anomaly Contribution

Baselines (per spec §18–19) are per-entity features with rolling stats
(`baselines` table, see `detection-engine.md` §7):

```
z = |observed − mean| / stddev   (minimum baseline: 14 days, 20 samples, else no score)
bands: z≥4 → +15, z≥3 → +10, z≥2 → +5   (per feature; top-3 features contribute only)
```

Guardrails (spec §19):
- Login geography anomalies are **suppressed** when the observed path traverses known
  VPN/proxy infrastructure (asset or IP tagged `network.vpn|proxy`), or when the
  user's baseline already spans multiple regions — recorded as
  `behavioral_anomaly (suppressed: vpn)`, points 0, still explainable.
- First-seen features score +5 (rareness), not +15 — novelty ≠ malice.

## 6. Decay

Contributions carry `created_at`. Entity risk uses **rolling decay** for display:
`effective_points = points × 0.5^(age_hours / half_life_hours)` with default half-lives:
finding 30d, event 72h, ti 90d, anomaly 24h, action (analyst) no decay.
Raw contributions stay intact (explainability); decay is a view-layer function
documented in the UI tooltip. Indicator *temporal_relevance* (§3) uses the same decay
idea on `last_seen`.

## 7. Asset Criticality (input, not score)

`assets.criticality` ∈ `critical/high/medium/low` + `data_classification`,
`internet_exposed` — see `telemetry-coverage.md` §2. Used by §2 (`asset_criticality`),
by attack-path value, and by scenario risk. Criticality is analyst-set with
auto-suggestion heuristics (domain controller / payment DB patterns → `critical`
*suggested*, never auto-applied without confirmation).

## 8. Vulnerability Correlation (spec §24)

When an event's host/application matches a known vulnerability:

```
vuln_contribution = 10
  × exploitability   (EPSS × exploit-availability factor: exploited-in-wild 1.0,
                      public-PoC 0.7, theoretical 0.4)
  × exposure         (internet_exposed asset: 1.0; internal: 0.5; air-gapped 0.2)
  × attack_traffic   (observed suspicious requests against the vulnerable app: ×1.5)
```

`Apache + CVE + internet exposed + exploit available + suspicious request` therefore
out-scores the CVE alone, per spec. Stored as contributions with
`reason="vuln CVE-2024-XXXX (cvss 9.8, epss 0.42, exploited-in-wild)"`.

## 9. What Stays the Same

- `entity_risk` / `risk_contributions` tables and API
  (`/api/v1/risk/entities`, `/findings/{id}/risk`) unchanged in shape; new
  `source_type` values: `ti`, `anomaly`, `vuln`, `scenario`, `path`.
- Additive-only writes: risk code never deletes or rewrites historical contributions.
- `risk.Scorer` (dead code) is deleted in Phase 2 (its formula is superseded by §2).
- Finding dedup/risk merge semantics (max-risk-wins on re-run) unchanged.
