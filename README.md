# Quetzalog - A Lightweight Go/SQLite SIEM Platform

A lightweight, local-first Security Information and Event Management (SIEM) platform built in Go
with SQLite. Quetzalog provides real-time event ingestion, SPL-like search, automated detection,
alerting, and incident management -- all in a single binary with no external dependencies.

## Badges

```
[![Build Status](https://github.com/example/quetzalog/actions/workflows/build.yml/badge.svg)](https://github.com/example/quetzalog/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/example/quetzalog)](https://goreportcard.com/report/github.com/example/quetzalog)
[![Go Version](https://img.shields.io/badge/go-1.23+-blue.svg)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
```

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

```bash
go build -o quetzalog ./cmd/quetzalog
```

With CGO (required for SQLite):

```bash
CGO_ENABLED=1 go build -o quetzalog ./cmd/quetzalog
```

### Run Demo (with sample data)

```bash
./quetzalog demo --host 0.0.0.0 --port 8080
```

### Run Server

```bash
./quetzalog serve --host 0.0.0.0 --port 8080 --db ./quetzalog.db
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

```bash
tail -f /var/log/syslog | ./quetzalog ingest --source syslog
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
quetzalog serve --host 0.0.0.0 --port 8080 --db quetzalog.db
```

### Demo

```bash
quetzalog demo --host 0.0.0.0 --port 8080
```

Search for events:

```bash
quetzalog search "severity=error | head 10"
```

List alerts:

```bash
quetzalog alerts --status new
```

Acknowledge an alert:

```bash
quetzalog alerts ack <alert-id>
```

Resolve an alert:

```bash
quetzalog alerts resolve <alert-id>
```

List detection rules:

```bash
quetzalog detections
```

Create a detection rule:

```bash
quetzalog detections create --name "Brute Force" --query "source=auth" --severity high
```

Ingest events from stdin:

```bash
cat events.json | quetzalog ingest --source stdin
```

---

## Configuration

Quetzalog is configured via YAML file and/or environment variables.

### Example Configuration

```yaml
server:
  host: 0.0.0.0
  port: 8080

database:
  path: ./quetzalog.db

api:
  tokens:
    - my-api-token

syslog:
  udp: 1514
  tcp: 1515

hec:
  tokens:
    - my-hec-token

ingestion:
  rate_limit: 10000  # events per second
  max_message_length: 32768

detection:
  check_interval: 30s

risk_scoring:
  severity_weights:
    debug: 0
    info: 0
    warning: 2
    err: 5
    critical: 10
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `QUETZALOG_HOST` | Bind host | `0.0.0.0` |
| `QUETZALOG_PORT` | Bind port | `8080` |
| `QUETZALOG_DB_PATH` | SQLite database path | `./quetzalog.db` |
| `QUETZALOG_API_TOKENS` | Comma-separated API tokens | (none) |
| `QUETZALOG_HEC_TOKENS` | Comma-separated HEC tokens | (none) |
| `QUETZALOG_SYSLOG_UDP` | Syslog UDP port | `1514` |
| `QUETZALOG_SYSLOG_TCP` | Syslog TCP port | `1515` |

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
  cmd/quetzalog/         # CLI entrypoint
  internal/           # Internal packages
  pkg/                # Public packages
  web/                # Web UI source
  migrations/         # Database migrations
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
