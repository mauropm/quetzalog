# Quetzalog — Measured Baseline

Date: 2026-10-11. Commit `9bca774`. All numbers below were actually executed on this machine.
Hardware: Apple M4 (10 cores), 16 GB RAM, macOS 26.6.2. Runtime: go1.26.2 darwin/arm64,
CGO enabled, go-sqlite3 v1.14.50 (bundled SQLite), build flags `-DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1`.
SQLite config: WAL, synchronous=NORMAL, MaxOpenConns=25, no busy_timeout/cache-size/checkpoint tuning.

## Correctness baseline (pre-change)

| Check | Result |
|---|---|
| `go build ./cmd/siem` | PASS |
| `go vet ./...` | PASS (clean) |
| `go test -p 1 -timeout 20m ./...` | **PASS — 34 packages ok, 0 failures** |
| `golangci-lint` | not installed (skipped per Makefile) |

Pre-existing defects found by inspection/execution are documented in `03-quality-audit.md`.
Note: the in-repo benchmark harness itself panicked under concurrent file-DB ingestion
(unsynchronized shared `math/rand` in `benchmarks/main.go`) — fixed in this work; results
below are with the fixed harness.

## In-process benchmarks (`benchmarks/main.go`, 3 iterations, avg)

Command (file-backed, 50 000-event batch ingest, 8×50 000 concurrent, 50 000-event seed for 50 searches):

```
CGO_CFLAGS="-DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1" go run benchmarks/main.go \
  -db bench.db -iterations 3 -ingest-n 50000 -concurrency 8 -search-n 50000 -search-repeat 50 -report
```

| Benchmark | Baseline (file DB) | Baseline (`:memory:`) |
|---|---:|---:|
| Single event ingestion | 545 ev/s | 2 557 ev/s |
| Batch ingestion (50 000) | 1 802 ev/s | 2 692 ev/s |
| Concurrent ingestion (8×50 k) | 7 673 ev/s | 2 140 ev/s* |
| Search by text (FTS5) | 518 q/s | 528 q/s |
| Search by field filter | 1 835 q/s | 1 524 q/s |
| Stats aggregation | 310 q/s | 178 q/s |
| Detection rule execution | 85 845 ev/s | 114 691 ev/s |

\* memory figure contaminated by the harness rand-panic race; the file number is the first clean run.

Observations: batch write throughput ~1.8–2.7 k ev/s is far below a typical SQLite insert budget
(wal + batch should reach 10²× more); per-event work (graph upserts, ~100 statements/event
due to repeated `initTables`) dominates.

## End-to-end server baseline (`quetzalog serve`, 20 000-event synthetic workload)

`scripts/benchmark_e2e.py` — 20 batches of 1 000 events via `POST /api/v1/events/batch`,
200 single `POST /api/v1/events`, 100 mixed SPL searches (`*`, severity filter, stats, table),
fresh DB, RSS sampler at 10 Hz.

| Metric | Baseline |
|---|---:|
| Ingest wall time (20 000 ev) | 3.43 s |
| Ingest rate | 5 837 ev/s |
| Batch latency p50 / p95 | 167 ms / 221 ms |
| Single-event p50 / p95 / p99 | 0.4 ms / 0.6 ms / 3.3 ms |
| Search p50 / p95 / p99 | 1.4 ms / 14.8 ms / 28.3 ms |
| Peak RSS during ingest (idle ≈ 26 MB) | 35.5 MB |
| DB size after 20 000 events | ~13 MB (≈ 650 B/event, index/FTS inflated) |
| `search * | head 1` | returns **0 rows** (confirmed live; see audit F-16) |

## Reproduction

- `scripts/benchmark.sh baseline` — runs the file-backed harness + E2E server suite, writes `bench-file-baseline.json` + `e2e-baseline.txt` into `$OUT` (default `/tmp/qz-bench`).
- Raw JSON baseline: `benchmarks/` outputs captured as `bench-baseline.json` (:memory:) and `bench-file-baseline.json` (file) during this audit; rerun via the script for reproducible numbers.

## Known measurement caveats

- Benchmarks run on a laptop-class SoC with background load — treat ±10 % as noise.
- The E2E ingest path (`/api/v1/events/batch`) writes synchronously on the HTTP goroutine;
  pipeline-worker ingestion rates via other transports are not separately isolated here.
- Detection "85 k ev/s" is dominated by rule-evaluation of an empty-ish predicate; it is a
  harness artifact, kept only for before/after consistency.
- No production-scale (10 M events) dataset was available; synthetic fixtures as described in
  `scripts/benchmark_e2e.py` (seed 1234, deterministic).
