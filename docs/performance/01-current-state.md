# Quetzalog — Current State (Performance & Stability Baseline Documentation)

Date: 2026-10-11
Branch/commit: `9bca774` (+ local `opencode.json` change, `logo/` untracked)
Language/toolchain: Go 1.26.2 (go.mod requires 1.26.0), CGO enabled, `mattn/go-sqlite3` v1.14.50 (driver-bundled SQLite), built with `-DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1`.

## 1. System architecture & component inventory

Quetzalog is a single-binary, local-first SIEM. All subsystems share **one `*sql.DB`**
(`cmd/siem/main.go:205`) against one SQLite file in WAL mode.

| Subsystem | Package | Role |
|---|---|---|
| Entry/CLI | `cmd/siem/main.go` (2226 LOC) | `serve`, `demo`, `search`, ingestors wiring, shutdown |
| Ingestion | `internal/ingestion/{pipeline.go, hec, json, otlp, syslog, file}` | Multi-source intake → `Pipeline.Ingest` |
| Events | `internal/events/store.go` | Single/batch inserts, search, count, timeline |
| Correlation graph | `internal/correlation/graph.go` | Entity/relationship upserts on the write path |
| SPL | `internal/spl/{lexer,parser,planner,executor,serializer,ast}` | Parse → plan (parameterized SQL) → execute |
| Query API | `internal/query/service.go`, `internal/api/*` | REST search, SPL preview |
| Detections | `internal/detections/*` | Scheduled rule runs, behavioral, correlation engine, scenarios |
| Findings/Risk/Investigations | `internal/findings`, `internal/risk`, `internal/investigations` | Analyst queue, entity risk |
| AI | `internal/ai/*` | Optional OpenAI-compatible analyst (async goroutines) |
| Telemetry | `internal/telemetry` | Prometheus counters registered but **not wired** to data path |
| Web UI | `web/` (embedded) | Vanilla JS SPA |

### Confirmed execution flow (serve mode)

```
HTTP/HEC/OTLP/syslog/file ──▶ Pipeline.Ingest ──(bounded chan, 4×100)──▶ 4 workers
   workers: enrich (no-op today) ─▶ per-worker batch (size 100 or 100ms ticker)
   ─▶ Store.CreateBatch: ONE tx, prepared stmt, commit
   ─▶ post-commit loop per event: Graph.AddEntityFromEvent (1–11 upserts)
   ─▶ observers (assets/entities/risk/mitre/correlation — some gated by config)
SQLite: WAL, synchronous=NORMAL, pool MaxOpenConns=25, _cache=shared
FTS5 external-content table events_fts(message, attributes) + INSERT/UPDATE/DELETE triggers
12 secondary indexes on events (all maintained per insert)
```

Key facts verified from source:

- Channels: `Pipeline.workerChan` (cap `workers*batchSize`, default 400) — non-blocking send, full ⇒ error to caller (`internal/ingestion/pipeline.go:120-129`). Async queues for MITRE (1024), correlation (4096), behavioral (4096), TI (1024) — drop-on-full with warn-only logs.
- Batch: `CreateBatch` one transaction per batch (`internal/events/store.go:113-169`), prepared stmt reused inside a batch, commit per batch; batch=100 events or 100 ms ticker (`pipeline.go:196`).
- Graph writes run **outside** the batch transaction (post-commit, separate connections) — deliberate, to avoid writer contention (`store.go:155-157`).
- `Graph.initTables()` executes 7 `CREATE ... IF NOT EXISTS` statements **on every entity/relationship upsert** (`internal/correlation/graph.go:106,150`) — the dominant per-event write amplification (~11 upserts × 8 statements ≈ 88 statements/event, most no-ops).
- SPL: parse every request (no plan cache); free-text → FTS5 `MATCH`; row path materializes ≤limit(≤50k) rows as `[]map[string]any`; `rex` compiles regex **per row** (`eval.go:76`); `eval` re-tokenizes expressions **per row** (`eval.go:43`).
- Background workers: detection scheduler, coverage, baselines, scenarios, attack-graph, TI sync, correlation sweep — mostly anchored to `context.Background()`, not the SIGTERM context (`cmd/siem/main.go:292,334-344,356-436`).
- Shutdown: only jsonServer, pipeline, metrics, DB are shut down; the main API `server` is never `Shutdown()`d; deferred `database.Shutdown(db)` runs *before* some workers finish (ordering race, `main.go:767-773`).

## 2. Performance-sensitive modules (hot paths)

1. **Event write path** — `events.Store.Create/CreateBatch` + `correlation.Graph.AddEntityFromEvent`: per-event UUID (crypto/rand), double `time.Now()`, `EventToMap` (map alloc + attrs marshal + `attr.*` copies), 1 insert + 12 index updates + 1 FTS entry + up to ~88 no-op DDL/exec statements.
2. **Batching/flush** — 100 ms ticker fixed; SQLITE_BUSY ⇒ whole batch dropped (no retry) with log-only error (`pipeline.go:257-270`); **no `busy_timeout` configured** (driver default 5 s; `_cache=shared` in DSN `database.go:27`).
3. **Search path** — every `GET /events`/SPL search executes COUNT(*) + SELECT (two scans of the same predicate), wide 30-column SELECT incl. `raw`, double JSON marshal on API responses (`pkg/api/response.go`).
4. **SPL row pipeline** — per-row `regexp.Compile` for rex, per-row tokenizer for eval expressions, per-comparison `fmt.Sprintf` in sorts (`executor.go:837-850`).
5. **File tailer** — 1 s poll, fresh 1 MB `bufio.Scanner` per poll per file, regex compiled per line (`file.go:183-207,366`).

## 3. Storage & schema

- Schema: 30-column `events` rowid table, timestamps bound as UTC `time.Time` (driver text format), 12 indexes (`migrations/001_initial.sql:67-78` — no later migration adds any), external-content FTS5 with `events_au` trigger performing delete+reinsert per UPDATE.
- WAL + `synchronous=NORMAL`; no checkpoint, cache-size, or busy_timeout tuning; no retention/VACUUM/ANALYZE anywhere (DB grows unbounded by design so far; only `correlation_state` is pruned every 15 min).

## 4. Existing testing & benchmarking capability

- `go test -p 1 ./...` — broad unit/integration suite (api, ingestion, spl, detections, stress tests).
- `benchmarks/main.go` — standalone benchmark harness: single/batch/concurrent ingestion, search, alert CRUD, JSON report (`-report`), flags for `-db/-ingest-n/-search-n/-concurrency/-iterations`.
- No CI config; `make lint` runs `go vet` (golangci-lint not installed).
- Race detector available (`go test -race`) — not currently run by convention.

## 5. Known risks & knowledge gaps (initial)

1. Batch loss under SQLite write contention (no busy_timeout + no retry) — **stability, confirmed mechanism**.
2. Silent success on ingestion failure (OTLP HTTP/gRPC return OK even when `Ingest` errors; syslog/file warn-and-drop; file offset advanced before ingest succeeds).
3. Post-commit correlation/observer loop aborts on first error — later events in batch lose graph/observer side effects (`store.go:158-166`).
4. OTLP protobuf HTTP path is a stub that accepts and **discards** the body (`otlp/otlp.go:97-115`).
5. OTLP gRPC `Stop()` nil-deref panic if `Start()` failed (`internal/ingestion/otlp/grpc.go:67-70`).
6. Confirmed SPL correctness defects: `search *` matches nothing; post-agg `where` both dropped and wrongly pushed into SQL; `LIMIT 0` zero-row results on legacy `Execute` path; `max()/min()` no-args panic; `bin`/`lookup` silently no-op.
7. Unbounded goroutines per syslog TCP connection; not closed on Stop.
8. Shutdown gaps: main HTTP server not gracefully stopped; ticker workers not tied to signal ctx; possible post-shutdown DB writes.
9. Metrics registered but no call sites — ingestion/search/detection invisible in Prometheus.
10. Knowledge gap: actual measured throughput/latency (next document) and which write-path costs dominate at scale.
