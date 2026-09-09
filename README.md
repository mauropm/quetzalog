# Quetzalog - A Lightweight Go/SQLite SIEM Platform

A lightweight, local-first Security Information and Event Management (SIEM) platform built in Go
with SQLite. Quetzalog provides real-time event ingestion, SPL-like search, automated detection,
alerting, and incident management -- all in a single binary with no external dependencies.

## Badges

[![Build Status](https://github.com/mauro/quetzalog/actions/workflows/build.yml/badge.svg)](https://github.com/mauro/quetzalog/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/mauro/quetzalog)](https://goreportcard.com/report/github.com/mauro/quetzalog)
[![Go Version](https://img.shields.io/badge/go-1.23+-blue.svg)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Features

- **Multi-source ingestion** -- HTTP/JSON, Splunk HEC, Syslog (UDP/TCP), OTLP, file tailing, stdin
- **SPL-like search** -- Familiar query language with `search`, `stats`, `sort`, `where`, and more
- **SQLite storage** -- Embedded database with FTS5 full-text search and WAL mode
- **Detection engine** -- Threshold-based rules with time-windowed grouping
- **Alert lifecycle** -- Full alert workflow: new, acknowledged, investigating, resolved, false_positive
- **Incident management** -- Group related alerts and events into incidents
- **Risk scoring** -- Configurable severity-based scoring with entity aggregation
- **Entity correlation** -- Relationship graph linking users, IPs, hosts, and services
- **Built-in Web UI** -- Embedded SPA for search, alerts, incidents, and detections
- **REST API** -- Complete API for all functionality with pagination and filtering
- **CLI** -- Command-line interface for search, alerts, detections, and management
- **Splunk compatible** -- HEC endpoints and search API compatibility
- **OpenTelemetry compatible** -- OTLP log ingestion endpoint
- **Prometheus metrics** -- Built-in observability
- **Zero dependencies** -- Single static binary, no external services required

## Quick Start

### Build

Full-text search uses SQLite's FTS5 module, which must be compiled into the binary. This requires CGO plus the `sqlite_fts5` build tag; without it the binary builds but crashes at startup with `no such module: fts5`.

```bash
CGO_ENABLED=1 go build -tags sqlite_fts5 -o quetzalog ./cmd/siem
```

Or use the Makefile, which applies the same CGO settings and builds to `quetzalog`:

```bash
make build
```

### Run Demo (with sample data)

Generates ~200 synthetic events, runs the detection rules, and persists everything (events, alerts, entity correlation graph, demo users) to the configured database (`./data/siem.db` by default). Then start the server to browse it in the web UI:

```bash
./quetzalog demo
./quetzalog serve
```

Both commands read the same `--config` file, so point them at the same `database.path` to view the demo data at http://localhost:8080.

Notes:

- The demo **appends** to the database, so re-running it accumulates events, alerts, and detection rules. Use `--reset` to delete the database first and get a clean run: `./quetzalog demo --reset`.
- The ~200 events are generated in a **random order** on every run (realistic out-of-order arrival), so the row/insertion order differs each time even though the event mix is the same.

### Run Server

```bash
./quetzalog serve
```

Starts the HTTP API and web UI. Defaults: bind `0.0.0.0:8080`, SQLite database at `./data/siem.db`. Accepted flags are `--config <path>` and `--debug`; host, port, and database path are set in the YAML config (keys `server.host`, `server.port`, `database.path`, see `config.example.yaml`) and passed with `--config`:

```bash
./quetzalog serve --config config.yaml
```

### Access

- Web UI: http://localhost:8080
- REST API: http://localhost:8080/api/v1
- Health: http://localhost:8080/api/v1/health
- Metrics: http://localhost:8080/metrics

---

## Ingestion Methods

Quetzalog supports multiple ingestion methods for maximum flexibility.

### JSON HTTP API

```bash
curl -X POST http://localhost:8080/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Failed SSH login for user admin",
    "source": "auth-service",
    "host": "server01",
    "severity": "warning",
    "event_type": "authentication",
    "outcome": "failure",
    "attributes": {"user": "admin", "source_ip": "10.0.0.20"}
  }'
```

### Splunk HTTP Event Collector (HEC)

```bash
curl -X POST http://localhost:8080/services/collector \
  -H "Authorization: Splunk my-hec-token" \
  -H "Content-Type: application/json" \
  -d '{
    "event": {
      "message": "Disk usage at 90%",
      "host": "db01",
      "source": "monitoring"
    },
    "time": 1756900000
  }'
```

### Syslog (UDP)

```bash
echo "<134>Sep  3 18:30:00 server01 sshd: Failed password for admin" | \
  nc -u localhost 1514
```

### Syslog (TCP)

```bash
echo -n "<134>Sep  3 18:30:00 server01 sshd: Failed password for admin" | \
  nc localhost 1515
```

### File Tailing

Configure in YAML to watch and tail log files:

```yaml
inputs:
  - name: auth-log
    type: file
    path: /var/log/auth.log
  - name: app-log
    type: file
    path: /var/log/myapp/*.log
```

### OpenTelemetry Protocol

```bash
curl -X POST http://localhost:8080/v1/logs \
  -H "Content-Type: application/json" \
  -d '{
    "resourceLogs": [{
      "resource": {
        "attributes": [
          {"key": "service.name", "value": {"stringValue": "my-app"}},
          {"key": "host.name", "value": {"stringValue": "server01"}}
        ]
      },
      "scopeLogs": [{
        "scope": {"name": "my-scope", "version": "1.0.0"},
        "logRecords": [{
          "timeUnixNano": "1725392400000000000",
          "severityText": "ERROR",
          "body": {"stringValue": "Failed SSH login for user admin"},
          "attributes": [
            {"key": "user", "value": {"stringValue": "admin"}}
          ]
        }]
      }]
    }]
  }'
```

### Stdin (Piped Input)

Reads newline-delimited JSON events from stdin (finish with Ctrl+D):

```bash
cat events.jsonl | ./quetzalog ingest
```

---

## Search

Quetzalog uses a Splunk-like query language (SPL) for searching events.

### Basic Search

```
POST /api/v1/search

{"query": "message=login", "limit": 100}
```

### Field Filtering

```
{"query": "severity=error | sort -timestamp | head 10", "limit": 100}
```

### Aggregation

```
{"query": "source=auth | stats count by user", "limit": 100}
```

### Time Range

```
{"query": "timestamp>2026-09-01 | stats count by source", "limit": 100}
```

### Boolean Logic

```
{"query": "(severity=error OR severity=critical) AND source=auth", "limit": 100}
```

See [SPL Compatibility](SPL_COMPATIBILITY.md) for the complete list of supported commands.

---

## Detection Rules

Detection rules define conditions that trigger alerts when events match.

### YAML Detection Rule

```yaml
name: Brute Force Detection
query: source=auth AND outcome=failure
severity: high
threshold:
  count: 5
  window: 300s
group_by: source_ip
```

### Create via API

```bash
curl -X POST http://localhost:8080/api/v1/detections \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Brute Force Detection",
    "query": "source=auth AND outcome=failure",
    "severity": "high",
    "threshold": {"count": 5, "window": "300s"},
    "group_by": "source_ip"
  }'
```

### List Rules

```bash
curl http://localhost:8080/api/v1/detections
```

### Execute Rule Manually

```bash
curl -X POST http://localhost:8080/api/v1/detections/{id}/exec \
  -H "Content-Type: application/json" \
  -d '{"start_time": "2026-09-03T00:00:00Z", "end_time": "2026-09-03T23:59:59Z"}'
```

See [Detection Rules Documentation](DETECTIONS.md) for more details.

---

## Web UI

The embedded web interface provides:

- **Event Search** -- Full-text search with filters and pagination
- **Alert Dashboard** -- Real-time alert status, filtering, and state transitions
- **Incident Investigation** -- Group related alerts, view events, add notes
- **Detection Management** -- Create, edit, and execute detection rules
- **Statistics** -- Event counts by severity, source, and time
- **Configuration** -- Manage settings from the UI

Access at http://localhost:8080 after starting the server.

---

## CLI

### Serve

```bash
quetzalog serve [--config path] [--debug]
```

### Demo

```bash
quetzalog demo [--config path] [--reset]
```

Seeds the configured database with ~200 synthetic events (generated in a random order each run) plus detection rules, alerts, and demo users. Runs append to existing data; `--reset` deletes the database first for a clean run.

Search for events (`--limit`, `--offset`, `--format text|json`):

```bash
quetzalog search "severity=error | head 10"
```

List alerts (`--status`, `--severity`, `--limit`, `--format`):

```bash
quetzalog alerts --status new
```

Acknowledge or resolve an alert (API only, requires `Authorization: Bearer <api-token>`, see [API.md](API.md)):

```bash
curl -X POST http://localhost:8080/api/v1/alerts/<alert-id>/acknowledge \
  -H "Authorization: Bearer $QUETZALOG_API_TOKEN"
curl -X POST http://localhost:8080/api/v1/alerts/<alert-id>/resolve \
  -H "Authorization: Bearer $QUETZALOG_API_TOKEN"
```

List detection rules:

```bash
quetzalog detections
```

Enable or disable a detection rule:

```bash
quetzalog detections --enable <rule-id>
quetzalog detections --disable <rule-id>
```

Create a detection rule (API only):

```bash
curl -X POST http://localhost:8080/api/v1/detections \
  -H "Authorization: Bearer $QUETZALOG_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Brute Force","query":"source=auth","severity":"high"}'
```

Ingest events from a file or stdin (newline-delimited JSON):

```bash
quetzalog ingest events.json
cat events.jsonl | quetzalog ingest
```

---

## Configuration

Quetzalog is configured via a YAML file passed with `--config` (see `config.example.yaml` for a complete example) plus a small set of environment variables. There is no default config path; without `--config` built-in defaults are used.

### Example Configuration

```yaml
server:
  host: 0.0.0.0
  port: 8080

database:
  path: ./quetzalog.db

ingestion:
  workers: 4
  batch_size: 100

syslog:
  udp_enabled: true
  udp_port: 5514
  tcp_enabled: false
  tcp_port: 5514

splunk:
  hec_enabled: true
  hec_port: 8088
  hec_tokens:
    - id: my-source
      token: my-hec-token

otel:
  enabled: false
  grpc_port: 4317
  http_port: 4318

auth:
  enabled: true
  local_auth_enabled: true
```

```bash
quetzalog serve --config config.yaml
```

Tip: generate a starter file with `quetzalog config --write config.yaml`.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `QUETZALOG_API_TOKEN` | API bearer token (overrides `auth.api_token`) | (none) |
| `QUETZALOG_ADMIN_PASSWORD` | Bootstrap password for the first admin user; if unset a random one-time password is logged | (random) |

Other settings (host, port, database path, syslog/HEC/OTLP ports, tokens) are YAML-only.

---

## API

Complete REST API documentation is available in [API.md](API.md).

Quick example:

```bash
# Search events
curl -X POST http://localhost:8080/api/v1/search \
  -H "Content-Type: application/json" \
  -d '{"query": "severity=error", "limit": 10}'

# List alerts
curl http://localhost:8080/api/v1/alerts?status=new

# Get system stats
curl http://localhost:8080/api/v1/stats
```

---

## Splunk Compatibility

Quetzalog provides Splunk-compatible endpoints for seamless integration:

| Endpoint | Description |
|----------|-------------|
| `POST /services/collector` | HTTP Event Collector v1.0 |
| `POST /services/collector/raw` | Raw text ingestion |
| `POST /services/collector/event` | Single event ingestion |
| `GET /services/search/jobs` | List async search jobs |
| `GET /services/search/jobs/{sid}` | Get search status |
| `GET /services/search/jobs/{sid}/results` | Get paginated results |

See [API.md](API.md#splunk-hec-compatibility) for full documentation.

---

## OpenTelemetry Compatibility

Quetzalog accepts OpenTelemetry Protocol (OTLP) log exports:

| Endpoint | Format | Description |
|----------|--------|-------------|
| `POST /v1/logs` | JSON | OTLP JSON encoding |
| `POST /v1/logs` | Protobuf | OTLP protobuf encoding (stub) |

Field mapping from OTLP to Quetzalog events is automatic -- resource attributes become event attributes,
severity maps to Quetzalog severity, and the log body becomes the event message.

See [OpenTelemetry Documentation](OPENTELEMETRY.md) for details.

---

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full system architecture,
data flow diagrams, component descriptions, and extensibility guide.

---

## Development

### Prerequisites

- Go 1.23+
- CGO enabled (required for SQLite)

### Make Commands

| Command | Description |
|---------|-------------|
| `make build` | Build the binary |
| `make test` | Run all tests |
| `make test-coverage` | Run tests with coverage report |
| `make lint` | Run golangci-lint |
| `make format` | Format code with gofmt |
| `make vet` | Run go vet |
| `make bench` | Run benchmarks |
| `make docker` | Build Docker image |
| `make run-demo` | Run in demo mode |

### Project Structure

```
quetzalog/
  cmd/siem/              # CLI entrypoint
  internal/           # Internal packages
  pkg/                # Public packages
  web/                # Web UI source
  examples/           # Example configurations and rules
  tests/              # Integration tests
  benchmarks/         # Performance benchmarks
```

### Adding a New Ingestion Source

1. Implement the `Ingestor` interface in `pkg/ingestion/`
2. Register the source in the server config
3. Add CLI flags for configuration
4. Add tests

### Adding a Detection Rule

Detection rules are YAML-defined in the configuration or created via the API/CLI:

```yaml
name: Rule Name
query: field=value | stats count by field
severity: critical
threshold:
  count: 100
  window: 60s
group_by: source_ip
enabled: true
```

---

## License

MIT License -- see [LICENSE](LICENSE) for details.
