# Quetzalog — Security Event Schema (Canonical Event Model v2)

**Status:** Phase 1 design. Companion to `threat-intelligence-architecture.md`.

Goals:
- A stable canonical schema covering heterogeneous enterprise telemetry (Windows/macOS/
  Linux/Solaris/OS-2/mainframe/server-software/DB/identity/network/cloud/generic).
- Raw evidence is **immutable and always preserved** (today only HEC `/raw` does this).
- Existing events table and SPL field names keep working (backward compatible).
- A parser/normalizer architecture where new formats do not require core changes.

---

## 1. Pipeline Stages

```
raw bytes ─▶ parser (format → structured) ─▶ normalizer (→ event.Event v2)
          ─▶ entity extraction ─▶ [async] enrichment ─▶ store (events + FTS)
```

Every parser records `parser` + `parser_version` on the event so normalizations are
reproducible and auditable.

### 1.1 Parsers (new package `internal/parsers`)

Split format-specific parsing out of `internal/ingestion/*` (collectors keep only
transport concerns). Registry:

```go
type Parser interface {
    Name() string                    // "syslog5424", "cef", "leef", "gelf", "windows-event", ...
    Version() string
    Parse(raw []byte, meta ParseMeta) (*ParsedEvent, error)  // never mutates raw
}

type ParseMeta struct {
    SourceType  string   // collector hint: "syslog:udp", "file:/var/log/auth.log", "hec", ...
    Hostname    string   // transport-level host if known
    ReceivedAt  time.Time
}
```

`ParsedEvent` = `{ Fields map[string]any; Timestamp time.Time; Severity string;
Message string; Error PartialParseError }`. Partial errors are recorded (field, reason)
and never lose the rest of the record — malformed logs must fail safely.

Built-in parser set (Phase 2):
`syslog3164`, `syslog5424` (with structured-data → attributes: `sd.<id>.<key>`),
`cef` (`|`-delimited + extension key=value), `leef`, `gelf` (JSON + graylog2 extensions),
`ndjson`, `plain`, `regex` (user-defined, existing file-source capability promoted).
Phase 3+: `windows-event` (Sysmon XML + Security/PowerShell EventXML heuristics),
`apache-access`/`nginx-access` (combined + vhost formats), `postgresql`/`mysql` error logs,
`sshd`, `auditd` (JSON + legacy text), `journald` (export format), `k8s-audit` (JSON).
Each Windows/Linux/OS parser targets its documented event IDs / log formats from the
spec §2 list and normalizes into the same canonical fields below.

Unsupported OS (OS/2, mainframe, unknown vendor) → `generic` parser: line/record →
`message` + user-supplied regex extraction; the point is that **no telemetry source is
rejected**, only less is normalized.

### 1.2 Normalizers (new package `internal/normalization`)

One normalizer per domain (OS class, web server, database, identity, network, cloud).
Input: `ParsedEvent` + source profile. Output: `event.Event` v2 with:
- canonical field population (below),
- `source_type` taxonomy: `<domain>.<product>[.<subformat>]`
  e.g. `os.windows.security`, `os.linux.auditd`, `net.firewall.generic`,
  `cloud.aws.cloudtrail`, `web.nginx.access`, `db.postgresql.error`, `id.kerberos`;
- `event_category` taxonomy: `auth, process, network, file, config, error, data_access,
  admin, cloud, container, dns, identity, vuln, ti` ;
- `event_action`: verb normalized (`create, start, stop, connect, disconnect, login,
  logout, grant, deny, modify, delete, exec, transfer, block, allow`);
- `outcome`: `success | failure | unknown`.

Profiles are data, not code: `internal/normalization/profiles/*.yaml` map source-specific
fields → canonical fields (e.g. Sysmon EID 4688 `CommandLine` → `process.command_line`,
`Image` → `process`; IIS `c-ip` → `source_ip`). New integrations = new profile file
(spec §39/§40: Integration/Parser/Normalizer/Detector/Enrichment interfaces).

## 2. Canonical Event Fields (v2)

Existing struct (`pkg/event/event.go`) stays; additions are **first as attributes**
(no DDL), promoted to columns when indexed queries need them.

| Group | Field | Status | Notes |
|---|---|---|---|
| Identity | `id`, `timestamp`, `received_at` | existing | |
| | `event_id` (vendor event ID, e.g. Windows `EventID`, EID) | new attr → col `vendor_event_id` | enables event-ID-based detection (spec §2) |
| Classification | `event_type`, `category`, `action`, `outcome`, `severity` | existing | normalized vocabularies §1.2 |
| | `event_category` | alias of `category` (no new storage) | |
| Source/dest | `source`, `source_type`, `host`, `ip`, `service`, `application` | existing | |
| | `source.ip`, `source.port` | existing `source_ip`/`source_port` | |
| | `destination.ip`, `destination.port` | existing `destination_ip`/`destination_port` | |
| Identity fields | `user`, `user_id` | existing | |
| | `authentication` (method: `password, publickey, kerberos, ntlm, saml, oidc, certificate`) | new attr → col | |
| | `logon_type` (Windows logon type 1–10), `session` id | new attrs | Windows focus per spec §2 |
| Process | `process`, `process_id`, `parent_pid` | existing (`application` unused today → reserved) | |
| | `process.command_line`, `process.hash` (IMPHASH), `parent.process` | new attrs → cols | |
| File | `file_path` | existing | |
| | `file_hash` (md5/sha1/sha256), `file_name` | new attrs → col `file_hash` | YARA/file-intel groundwork (spec §43) |
| Network | `domain`, `url` | new attrs → cols `domain`, `url` | extracted by entity extractor when absent |
| | `protocol`, `bytes`, `packets`, `network.action` (`allow/deny`) | new attrs | network telemetry normalization (spec §6) |
| | `tls.sni`, `tls.issuer` | new attrs | TLS metadata |
| Cloud | `cloud.provider`, `cloud.account`, `cloud.region`, `cloud.resource_type`, `cloud.resource_arn`/`id` | new attrs | spec §7: cloud resources modeled as assets |
| DB | `db.name`, `db.statement` (truncated), `db.operation` | new attrs | spec §4 |
| Raw | `raw` (wire bytes, **all sources**), `raw_format` | existing col; **gap closed** | parsers capture raw bytes; OTLP/HEC/JSON/syslog/file all set it |
| Provenance | `parser`, `parser_version`, `collector` (source of record) | new attrs → cols | spec §66 |
| Scoring | `severity` | existing | |
| | `confidence` (0–1 parser/normalization confidence for derived fields) | new attr → col | not the same as detection confidence |
| | `risk_score` (event-level, computed async) | new attr → col | see `risk-model.md` |
| | `tags` (JSON array) | new attr | |
| MITRE | `mitre.attack.tactic`, `mitre.attack.technique` | new attrs → cols `mitre_tactic`, `mitre_technique` | mapping in `internal/mitre` rules; see §4 |
| TI | `threat.indicators` (JSON: matched indicator IDs) | new attr | set by enrichment (async) |
| Relationships | `relationships` (JSON: entity pairs implied by this event) | new attr | written to graph async; see `entity-model.md` |
| Telemetry gap | `telemetry.coverage` (asset+source availability snapshot) | async only, not on event | see `telemetry-coverage.md` |

Storage note: until column promotion, attributes live in the existing `attributes`
JSON column (FTS-indexed as text; `json_extract` queries as today). Column promotion
only for fields that power indexed detection/graph queries (`vendor_event_id`,
`domain`, `url`, `file_hash`, `mitre_tactic`, `mitre_technique`, `risk_score`,
`confidence`, `threat.indicators`).

## 3. Entity Extraction (post-normalization, still on write path)

Deterministic, cheap, synchronous: a fixed set of typed extractors over the canonical
fields + (regex) over `message`/`raw` bounded to first 2 KB:

| Type | Rule |
|---|---|
| `ip` | v4/v6 from fields + regex |
| `domain` | RFC-952/953 hostname regex on `domain`, `url`, `message` (TLD ≤ 24 chars, registered-SLD sanity) |
| `url` | URL regex |
| `email` | RFC-5322-lite regex |
| `hash` | 32/40/64-hex → md5/sha1/sha256; 128-hex → sha512; `imphash:` prefixed |
| `file` | path-like tokens on `file_path`/`message` (bounded depth) |
| `process` | `process` field + `process.command_line` basename |
| `user` | `user` field |
| `host` | `host` field |
| `service`/`application` | fields |
| `cloud_resource` | ARN/`acs:`/`azure:` regex |
| `certificate` | base64 DER/PEM in fields only (never full raw scan) |

Extraction results populate `Event.Relationships` (event-implied pairs, e.g.
`user→host:auth`, `process→ip:connects_to`) and upsert the entity graph (see
`entity-model.md` §2). Extraction never fails an event: extractor errors are logged,
event still stored.

## 4. MITRE Event Mapping

`internal/mitre` gains a small rule table (embedded YAML, extensible at runtime):

```yaml
- id: win4688-powershell-encoded
  when:
    source_type: os.windows.sysmon.process
    vendor_event_id: "4688"
    process: powershell.exe
    match:
      process.command_line: '(-enc|encodedcommand|frombase64string)'
  tactic: TA0002
  technique: T1059.001
  confidence: 0.9
```

Rules are pure functions (event) → `{tactic, technique, confidence}`; results land in
`mitre.attack.*` fields. A single event may match multiple rules (multi-technique).
Behavior chains (phishing → valid accounts → … → exfil) are **not** produced per-event;
they are scenario/attack-graph constructs over sequences of mapped events
(`detection-engine.md` §6, `attack-graph.md`).

## 5. Backward Compatibility

- All existing field names/JSON tags unchanged; SPL field aliases (`src_ip`, `_time`, …)
  unchanged; FTS behavior unchanged.
- `POST /api/v1/events`, HEC, OTLP, syslog, file ingestion accept the same payloads;
  raw is now additionally preserved (new behavior, not breaking).
- Old events (pre-v2) have no new attributes: consumers must treat absence as
  `unknown`, never as `false` (spec §26).
- `events.source_type` gains the new taxonomy values alongside legacy values
  (`syslog`, `file:json`, `hec_raw`); no migration of old rows.

## 6. Failure Semantics

- Unparseable record → store with `parser=generic`, `message`=raw line, `confidence=0`,
  tag `parse_failed` (visible in search; never silently dropped).
- Missing timestamp → `received_at` used, `confidence` reduced, attribute
  `timestamp_reliability=received`.
- Timestamp manipulation (future timestamps) → stored as-is; attribute
  `timestamp_future=true`; detection/behavioral layers may treat as anomalous.
- Duplicate records (same vendor event ID + host + ms) → content-hash column
  `event_hash` (sha1 of `raw`) with `INSERT OR IGNORE` on `(source, event_hash)`
  within 10-minute window; dedup is best-effort and reported, not silent.
