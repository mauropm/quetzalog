# Quetzalog Architecture

## Overview

Quetzalog is a lightweight, local-first Security Information and Event Management (SIEM) platform
written in Go. It uses SQLite as its primary storage engine with FTS5 for full-text search and
WAL mode for concurrent access. The platform is designed to be self-contained, requiring no
external dependencies beyond the binary itself.

## Architecture Diagram

```
                              ┌─────────────┐
                              │   Web UI    │
                              │  (Embedded) │
                              └──────┬──────┘
                                     │ HTTP
                              ┌──────┴──────┐
                              │   REST API  │
                              └──────┬──────┘
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                 │
          ┌─────────▼────────┐ ┌────▼─────┐ ┌────────▼────────┐
          │  Query Engine    │ │  Alert   │ │  Incident       │
          │  (SPL Parser)    │ │  Engine  │ │  Manager        │
          └─────────┬────────┘ └────┬─────┘ └────────┬────────┘
                    │                │                 │
          ┌─────────▼────────────────▼────────────────▼────────┐
          │                  Normalization Layer               │
          │                  (Canonical Event Model)            │
          └────────────────────┬───────────────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                 │
    ┌─────────▼────────┐ ┌────▼────┐ ┌──────────▼──────────┐
    │  Ingestion Layer │ │ Risk   │ │   Enrichment Layer  │
    │  (Multi-source)  │ │ Scoring│ │   (IP, GeoIP, etc.) │
    └──────────────────┘ └────────┘ └─────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │     Storage Layer    │
                    │  (SQLite + FTS5 +    │
                    │   WAL mode + Indexes)│
                    └─────────────────────┘

    ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
    │  Ingestion Sources│   │ Detection Rules  │   │  Alert Channels  │
    │  - HTTP/JSON     │──▶│  (Threshold-based│──▶│  (Built-in)      │
    │  - Splunk HEC    │   │   Detection)     │   │                  │
    │  - Syslog (UDP)  │   └──────────────────┘   └──────────────────┘
    │  - Syslog (TCP)  │
    │  - File Tailing  │
    │  - OTLP /logs    │
    │  - Stdin         │
    └──────────────────┘
```

## Components

### Ingestion Layer

The ingestion layer handles multiple input formats and protocols:

- **JSON HTTP API** — Standard REST endpoint accepting JSON event payloads
- **Splunk HEC** — HTTP Event Collector compatible endpoint (`POST /services/collector`)
- **Syslog** — UDP and TCP syslog listeners (RFC 5424 and RFC 3164 formats)
- **OTLP** — OpenTelemetry Protocol log ingestion (`POST /v1/logs`)
- **File Tailing** — Inotify-based file watcher for continuous log ingestion
- **Stdin** — Pipe events directly from other tools

Each ingestion source normalizes incoming data into the canonical Event model.

### Normalization Layer

All events are normalized into a canonical model before being stored:

```go
type Event struct {
    ID          string            // UUID v4
    Timestamp   time.Time         // Ingested event timestamp
    ReceivedAt  time.Time         // When the event was received
    Source      string            // Log source identifier
    Host        string            // Source host
    Severity    string            // Normalized severity level
    EventType   string            // Event type/category
    Outcome     string            // Event outcome (success/failure/unknown)
    Message     string            // Human-readable message
    Attributes  map[string]string // Key-value attributes
    Raw         string            // Raw event payload (JSON)
}
```

### Storage Layer

- **SQLite** as the embedded database engine
- **FTS5** virtual tables for full-text search across event messages and attributes
- **WAL mode** for concurrent read/write access
- **Indexed columns** for fast filtering on common fields (timestamp, severity, source, host)
- **JSON storage** of attributes as a text column with FTS5 indexing

```sql
CREATE TABLE events (
    id          TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    received_at TEXT NOT NULL,
    source      TEXT NOT NULL,
    host        TEXT,
    severity    TEXT,
    event_type  TEXT,
    outcome     TEXT,
    message     TEXT,
    attributes  TEXT,
    raw         TEXT
);

CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_severity ON events(severity);
CREATE INDEX idx_events_source ON events(source);

CREATE VIRTUAL TABLE events_fts USING fts5(
    message, attributes,
    content='events',
    content_rowid='rowid'
);
```

### Query Engine

A SPL-like query parser and execution engine:

- **Parser** — Tokenizes and parses query strings into an AST
- **Planner** — Translates AST into optimized SQLite queries
- **Executor** — Runs queries against the storage layer with pagination

Supported commands: `search`, `where`, `stats`, `sort`, `head`, `tail`, `dedup`, `rename`,
`table`, `eval`, `timechart`, `rex`.

### Detection Engine

Rule-based detection using threshold logic:

```yaml
name: Brute Force Detection
query: source=auth AND outcome=failure
severity: high
threshold:
  count: 5
  window: 300s
group_by: source_ip
```

- Evaluates events against configured rules in the background
- Supports time-windowed threshold detection
- Groups events by specified fields
- Generates alerts when thresholds are exceeded

### Correlation Engine

An entity relationship graph for cross-event correlation:

- Builds relationships between entities (users, IPs, hosts, services)
- Tracks connections across event streams
- Enables contextual investigation of security incidents
- Stored as a directed graph in SQLite

### Alerting

Alert lifecycle management:

```
       ┌──────────┐
       │   NEW    │
       └────┬─────┘
            │
            ├──────────────┬──────────────────┐
            ▼              ▼                  ▼
       ┌──────────┐  ┌──────────┐      ┌──────────────┐
       │ ACKNOWLEDGED ┌───INVESTIGATING ──▶│ RESOLVED     │
       └──────────┘  └──────────┘      └──────────────┘
                                  │
                                  ▼
                           ┌──────────────┐
                           │ FALSE_POSITIVE│
                           └──────────────┘
```

Alert states: `new`, `acknowledged`, `investigating`, `resolved`, `false_positive`

### Incidents

Incidents group related alerts and events:

- **Auto-creation** — Alerts matching certain criteria can be grouped into incidents
- **Manual creation** — Users can create incidents from any set of alerts
- **Lifecycle** — `new`, `investigating`, `resolved`, `closed`
- **Evidence** — Each incident contains linked alerts, events, and investigation notes

### Web UI

An embedded single-page application served directly from the binary:

- Built with vanilla JavaScript, CSS, and HTML
- SOC overview — posture stats, interactive SVG event/finding timeline (severity-stacked), top-risk entities
- Analyst queue — server-side filtered finding triage, saved views, finding side panel (status, owner, risk, tags, notes, linked events, quick response actions)
- Investigations — persistent security stories with notes, evidence, entities, techniques and in-context search prefill
- Risk, Threat Intel and Entity pages — accumulated entity risk, derived reputation, neighbor navigation
- MITRE ATT&CK matrix, response actions + audit trail, SPL Builder
- Real-time event search and filtering
- Alert management dashboard
- Incident investigation workspace
- Detection rule configuration (MITRE tactic/technique, group-by, risk score, schedule)

### REST API

GraphQL-like REST endpoints with pagination and filtering:

- Standardized JSON request/response format
- Consistent error handling
- Cursor-based pagination
- Field selection and filtering

### CLI

Command-line interface for programmatic access:

- `quetzalog serve` — Start the SIEM server
- `quetzalog demo` — Run with example data
- `quetzalog search` — Run queries from the terminal
- `quetzalog alerts` — Manage alerts from the CLI
- `quetzalog detections` — Manage detection rules

### Risk Scoring

Configurable severity-based scoring system:

- Each severity level has a configurable point value
- Events and alerts accumulate risk scores
- Entity-level risk aggregation (per user, per IP, per host) via the
  `internal/risk` entity-risk store: every contribution is recorded
  (source type, points, description) so a score is always explainable
- Detection runs contribute full points to user/host/source-IP entities
  and half points to process entities
- Configurable via YAML configuration

### Findings (Analyst Queue)

`internal/findings` turns detection runs into triage work:

- **Dedup** — findings are keyed by `detection_id + group_key`; re-runs
  bump match count/last-seen instead of creating noise
- **Lifecycle** — `new`, `in_progress`, `investigating`, `contained`,
  `resolved`, `false_positive`
- **Triage data** — entities, MITRE tactic/technique, risk score, tags,
  owner, notes
- **Queue API** — rich server-side filtering (severity, status, owner,
  entities, text, risk floor, time window) with pagination; saved views
  per user

### Investigations

`internal/investigations` persists the security story:

- Collects linked findings, event evidence, typed entities, saved SPL
  queries and MITRE techniques
- Authored timeline notes with author + timestamp
- Lifecycle: `new`, `in_progress`, `contained`, `resolved`,
  `false_positive`, `cancelled`
- Findings stay linked; the investigation is the workbench, not a copy

### Response Actions

`internal/response` provides a registered analyst-action framework:

- Built-in actions: mark false positive, assign, tag, increase risk,
  create investigation, run search, open URL, execute webhook
- Webhook execution is SSRF-guarded (http/https only, private, loopback
  and link-local destinations denied, redirects disabled)
- Every execution is written to the response ledger and the auth audit
  trail, so all analyst actions are reviewable
- New integrations register actions without redesigning the app

### MITRE ATT&CK

`internal/mitre` embeds a static, provider-neutral tactic/technique
catalog used for finding tagging, the active-techniques view and the
matrix page. Threat-intel integrations can extend or replace it without
touching the rest of the platform.

### Enrichment

Interface-based enrichment pipeline:

```go
type Enricher interface {
    Name() string
    Enrich(ctx context.Context, event *Event) error
}
```

Built-in enrichers:
- **Local IP** — Classify IPs as internal/external
- **GeoIP** — Geographic lookup stub (placeholder for database integration)

### LLM Analysis

Optional interface for AI-assisted analysis:

```go
type LLMAnalyzer interface {
    AnalyzeAlert(ctx context.Context, alert *Alert) (*AnalysisResult, error)
    AnalyzeIncident(ctx context.Context, incident *Incident) (*AnalysisResult, error)
}
```

Not required for core operation — implementations are optional.

## Data Flow

```
1. INGESTION
   External Event ──▶ Ingestion Source (HTTP/Syslog/OTLP/...) ──▶ Normalizer

2. NORMALIZATION
   Raw Event ──▶ Canonical Event Model ──▶ Enrichment Pipeline ──▶ Risk Scoring

3. STORAGE
   Event ──▶ SQLite (events table) ──▶ FTS5 Index ───▶ Time-series Index

4. DETECTION
   Event ──▶ Detection Engine (rule matching) ──▶ Alert Created

5. QUERYING
   User Query ──▶ SPL Parser ─▶ Query Planner ──▶ SQLite Executor ──▶ Results

6. ALERTING
   Alert ──▶ Alert Lifecycle Management ──▶ Incident Grouping ──▶ Web UI / API
```

## Extensibility

### Future Storage Backends

The storage interface is abstracted to allow swapping SQLite:

```go
type Storage interface {
    StoreEvent(ctx context.Context, event *Event) error
    Search(ctx context.Context, query string, opts QueryOptions) (*EventSearchResult, error)
    ListEvents(ctx context.Context, opts ListOptions) ([]*Event, error)
    // ...
}
```

Planned backends:

- **PostgreSQL** — For distributed deployments and multi-node setups
- **ClickHouse** — For high-volume, time-series optimized storage
- **Kafka** — As an event buffer/streaming layer between ingestion and storage

### Adding New Ingestion Sources

Implement the `Ingestor` interface:

```go
type Ingestor interface {
    Name() string
    Listen(ctx context.Context, events chan<- *Event) error
    Close() error
}
```

### Adding Detection Rules

Detection rules are YAML-defined with the following structure:

```yaml
name: Rule Name
query: field=value | stats count by field
severity: critical
threshold:
  count: 10
  window: 600s
group_by: source_ip
```

## License

MIT License — see `LICENSE` file for details.
