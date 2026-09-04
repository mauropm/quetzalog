# Development Guide

This guide covers building, testing, and extending SIEMto.

## Prerequisites

- Go 1.23+ (`go version` should show 1.23 or higher)
- CGO enabled (required for SQLite)
- Git (for development)
- Docker (optional, for container builds)

## Building

### Basic Build

```bash
go build -o quetzalog ./cmd/quetzalog
```

### Build with CGO

```bash
CGO_ENABLED=1 go build -o quetzalog ./cmd/quetzalog
```

### Cross-Compilation

```bash
# Linux amd64
GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o quetzalog ./cmd/quetzalog

# macOS arm64
GOOS=darwin GOARCH=arm64 go build -o quetzalog ./cmd/quetzalog

# Windows amd64
GOOS=windows GOARCH=amd64 go build -o quetzalog.exe ./cmd/quetzalog
```

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

## Testing

### Run All Tests

```bash
go test ./...
```

### Run Tests with Coverage

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out  # Open coverage report in browser
```

### Run Specific Package Tests

```bash
go test ./pkg/ingestion/...
go test ./internal/detection/...
go test ./internal/query/...
```

### Run Benchmarks

```bash
go test -bench=. -benchmem ./pkg/query/...
```

### Integration Tests

Integration tests require a running SQLite instance. Run them with:

```bash
make test-integration
```

## Adding Ingestion Sources

To add a new ingestion source, implement the `Ingestor` interface:

```go
package ingestion

import (
    "context"
    "quetzalog/pkg/event"
)

// Ingestor defines the interface for all event sources.
type Ingestor interface {
    // Name returns the human-readable name of this ingestion source.
    Name() string

    // Listen starts receiving events and sends them to the channel.
    // The provided context is used for cancellation.
    Listen(ctx context.Context, events chan<- *event.Event) error

    // Close cleans up resources used by the ingestor.
    Close() error
}
```

### Example Implementation

```go
type MyIngestor struct {
    config MyConfig
    server *someServer
}

func (m *MyIngestor) Name() string {
    return "my-ingestor"
}

func (m *MyIngestor) Listen(ctx context.Context, events chan<- *event.Event) error {
    go func() {
        defer close(events)
        for {
            select {
            case <-ctx.Done():
                return
            default:
                // Receive data from your source
                // Parse and convert to *event.Event
                ev := parseEvent(rawData)
                events <- ev
            }
        }
    }()
    return nil
}

func (m *MyIngestor) Close() error {
    return nil
}
```

### Register the Ingestor

```go
// In your server setup:
server := siem.NewServer(config)
server.AddIngestor(&MyIngestor{config: myConfig})
```

### Add CLI Flags

```go
cmd.Flags().String("my-ingestor-host", "localhost", "Host for my ingestor")
cmd.Flags().Int("my-ingestor-port", 9000, "Port for my ingestor")
```

### Add Tests

```go
package ingestion_test

import (
    "testing"
    "context"
)

func TestMyIngestor(t *testing.T) {
    ctx := context.Background()
    ing := &MyIngestor{config: MyConfig{...}}
    ch := make(chan *event.Event, 10)

    err := ing.Listen(ctx, ch)
    if err != nil {
        t.Fatalf("Listen error: %v", err)
    }

    select {
    case ev := <-ch:
        if ev == nil {
            t.Fatal("received nil event")
        }
    case <-time.After(time.Second):
        t.Fatal("timeout waiting for event")
    }
}
```

## Adding Detection Rules

Detection rules are YAML-defined and can be created via the API, CLI, or config file.

### Rule File Structure

Each rule file (`.yaml`) contains one or more detection rules using multi-document YAML:

```yaml
# File: /etc/quetzalog/rules/brute-force.yaml
name: Brute Force Detection
query: source=auth AND outcome=failure
severity: high
threshold:
  count: 5
  window: 300s
group_by: source_ip
enabled: true
description: Detects repeated failed authentication attempts
tags:
  - auth
  - brute-force

---

# Second rule in same file
name: Account Lockout
query: source=auth AND outcome=failure
severity: critical
threshold:
  count: 10
  window: 600s
group_by: user
enabled: true
```

### Creating Rules via API

```bash
curl -X POST http://localhost:8080/api/v1/detections \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Custom Rule",
    "query": "source=auth AND outcome=failure",
    "severity": "high",
    "threshold": {"count": 5, "window": "300s"},
    "group_by": "source_ip"
  }'
```

### Creating Rules via CLI

```bash
quetzalog detections create \
  --name "Custom Rule" \
  --query "source=auth AND outcome=failure" \
  --severity high \
  --threshold-count 5 \
  --threshold-window 300s \
  --group-by source_ip
```

## Adding New API Endpoints

### 1. Define Handler

Add your handler function in `internal/api/`:

```go
package api

import (
    "encoding/json"
    "net/http"
)

// MyHandler handles GET /api/v1/myendpoint
func (s *Server) myHandler(w http.ResponseWriter, r *http.Request) {
    resp := MyResponse{
        Status: "ok",
        Data:   someData,
    }
    writeJSON(w, http.StatusOK, resp)
}
```

### 2. Register Route

```go
// In internal/server/server.go:
mux.HandleFunc("/api/v1/myendpoint", s.myHandler)
```

### 3. Add Authentication (if needed)

```go
mux.HandleFunc("/api/v1/myendpoint", s.authMiddleware(s.myHandler))
```

### 4. Add Tests

```go
func TestMyHandler(t *testing.T) {
    s := NewServer(...)
    mux := http.NewServeMux()
    mux.HandleFunc("/api/v1/myendpoint", s.myHandler)

    req := httptest.NewRequest("GET", "/api/v1/myendpoint", nil)
    w := httptest.NewRecorder()
    mux.ServeHTTP(w, req)

    if w.Code != http.StatusOK {
        t.Fatalf("expected 200, got %d", w.Code)
    }
}
```

## Database Migrations

Database migrations are stored in the `migrations/` directory.

### Adding a Migration

Create a new SQL file in `migrations/`:

```
# migrations/002_create_incidents.sql

CREATE TABLE incidents (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'new',
    severity    TEXT,
    notes       TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE INDEX idx_incidents_status ON incidents(status);

-- Link alerts to incidents
ALTER TABLE alerts ADD COLUMN incident_id TEXT REFERENCES incidents(id);
```

### Migration Naming Convention

```
migrations/
  001_init.sql           # Initial schema
  002_create_incidents.sql   # Add incidents table
  003_add_alert_status.sql   # Modify alerts table
  ...
```

### Running Migrations

Migrations are applied automatically on server startup.

```bash
# SIEMto auto-applies migrations on start
./quetzalog serve --db quetzalog.db

# Check migration status
sqlite3 quetzalog.db "SELECT * FROM schema_migrations;"
```

## Web UI Development

The Web UI is a vanilla JavaScript SPA embedded into the Go binary.

### Project Structure

```
web/
  index.html          # Main HTML file
  css/
    style.css         # Main stylesheet
  js/
    main.js           # Main JavaScript
    search.js         # Search functionality
    alerts.js         # Alert management
    incidents.js      # Incident management
    detections.js     # Detection rule management
    lib/              # Third-party libraries (if any)
```

### Building the Web UI

The Web UI assets are embedded into the Go binary using `//go:embed`:

```go
package ui

import "embed"

//go:embed web/*
var WebFS embed.FS
```

### Modifying the Web UI

1. Make changes to files in `web/`
2. Rebuild the binary (`go build`)
3. The embedded filesystem is updated on next build

### Web UI Patterns

The Web UI follows these patterns:

- **Vanilla JavaScript** - No framework dependencies
- **Module pattern** - Each major feature is a separate JS module
- **Fetch API** - HTTP communication via the Fetch API
- **CSS variables** - Theme customization via CSS custom properties
- **Responsive design** - Works on desktop and mobile

### Debugging the Web UI

Run the server and open the browser developer tools:

```bash
./quetzalog serve --host 0.0.0.0 --port 8080
```

Then navigate to http://localhost:8080 and open DevTools.

## Benchmarking

### Run All Benchmarks

```bash
go test -bench=. -benchmem -benchtime=5s ./...
```

### Run Specific Benchmark

```bash
go test -bench=SearchEvent -benchmem ./pkg/query/...
```

### Benchmark Profile

```bash
go test -bench=QueryEngine -memprofile=mem.prof ./pkg/query/...
go tool pprof mem.prof
```

### CPU Profile

```bash
go test -bench=QueryEngine -cpuprofile=cpu.prof ./pkg/query/...
go tool pprof cpu.prof
```

## CI/CD Suggestions

### GitHub Actions Example

```yaml
name: CI

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: "1.23"
          cache: true

      - name: Build
        run: make build

      - name: Test
        run: make test

      - name: Coverage
        run: make test-coverage

      - name: Lint
        run: make lint

      - name: Benchmarks
        run: make bench

  docker:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4

      - uses: docker/setup-buildx-action@v3

      - uses: docker/build-push-action@v5
        with:
          push: true
          tags: ghcr.io/username/quetzalog:${{ github.sha }}
```

### Docker Multi-Stage Build

```dockerfile
FROM golang:1.23-bookworm AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=1 go build -o quetzalog ./cmd/quetzalog

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libsqlite3-dev ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/quetzalog /usr/local/bin/quetzalog
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["quetzalog", "health"]
ENTRYPOINT ["quetzalog"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
```

## Code Organization

### Package Structure

```
quetzalog/
  cmd/quetzalog/              # CLI entrypoint
    root.go                 # Root command
    serve.go                # Serve subcommand
    demo.go                 # Demo subcommand
    search.go               # Search subcommand
    alerts.go               # Alerts subcommand
    detections.go           # Detections subcommand
  internal/
    server/                 # HTTP server setup
    api/                    # HTTP handlers
    db/                     # Database layer
    ingestion/              # Ingestion sources
    detection/              # Detection engine
    query/                  # Query engine
    event/                  # Event model
    alert/                  # Alert management
    incident/               # Incident management
    enrichment/             # Enrichment pipeline
    risk/                   # Risk scoring
  pkg/
    config/                 # Configuration
    event/                  # Public event model
    query/                  # Public query interfaces
```

### Conventions

- **Error handling** - Use explicit error returns; wrap with `fmt.Errorf("...: %w", err)`
- **Context** - Accept `context.Context` as the first parameter of long-running functions
- **Interfaces** - Define interfaces in the package that uses them (not the implementer)
- **Testing** - Use table-driven tests for all public functions
- **Comments** - Document all exported types, functions, and methods with `// Comment`
- **Configuration** - Validate all config at startup with clear error messages
