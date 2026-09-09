# Quetzalog Benchmarks

Performance benchmark suite for Quetzalog components including event ingestion, search, query execution, and alert management.

## Usage

```bash
CGO_CFLAGS="-DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1" CGO_LDFLAGS="-lm" go run benchmarks/main.go

# With in-memory database, 10000 events for ingestion benchmark
CGO_CFLAGS="-DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1" CGO_LDFLAGS="-lm" go run benchmarks/main.go -ingest-n 10000

# Save JSON report
CGO_CFLAGS="-DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1" CGO_LDFLAGS="-lm" go run benchmarks/main.go -report > bench-results.json

# SQLite file database
CGO_CFLAGS="-DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1" CGO_LDFLAGS="-lm" go run benchmarks/main.go -db data/quetzalog.db

# Multiple iterations for averaging
CGO_CFLAGS="-DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1" CGO_LDFLAGS="-lm" go run benchmarks/main.go -iterations 5
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-db` | `:memory:` | Path to SQLite database file |
| `-iterations` | `3` | Number of times to run each benchmark (for averaging) |
| `-ingest-n` | `10000` | Number of events for ingestion benchmark |
| `-search-n` | `1000` | Number of events to pre-seed for search benchmarks |
| `-search-repeat` | `100` | Number of search iterations |
| `-concurrency` | `10` | Number of goroutines for concurrent ingestion benchmark |
| `-report` | `false` | Output benchmark results as JSON |
| `-detail` | `false` | Show timing details for each iteration |

## Benchmarks

1. **Single Event Ingestion** - Insert one event at a time
2. **Batch Ingestion** - Insert 10k events in a single transaction
3. **Concurrent Ingestion** - Multiple goroutines writing simultaneously
4. **Search by Text (FTS5)** - Full-text search on event messages
5. **Search by Field Filter** - Filtered search on host and severity
6. **Stats Aggregation** - SPL-style `stats count by severity`
7. **SPL Query Execution** - Full SPL pipeline query
8. **Detection Rule Execution** - Run detection rules against events
9. **Alert Creation** - Create alerts in the database
10. **Alert Status Update** - Update alert statuses
