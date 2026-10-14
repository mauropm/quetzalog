# 06 — Remaining Risks & Follow-ups

Honest inventory of what was **not** fixed or not fully verified in this
round, ordered by risk. Each entry says what is known and what would close
it. None of these block the merged behavior; all are follow-ups.

## High

1. **Auth hot path not converted to atomic read.** `internal/auth` token
   lookups still guard a plain map with a mutex on every request; the P2
   plan listed "auth atomic" but it was not implemented in this round
   (`git diff` confirms `internal/auth` untouched). At current QPS it is not
   a measurable bottleneck, but under the same copy-on-write pattern used
   for observers it becomes lock-free. Close by: atomic `map[string]*token`
   swap, same as `internal/events/store.go`.
2. **Race detector never run on the new concurrent code.** The
   `atomic.Pointer` copy-on-write paths (observers, enrichers), graph
   init-retry, and tailer state were validated only with `-p 1` test runs.
   Close by: `go test -race -p 1 ./internal/...` in CI. Note:
   `benchmarks/main.go` had a real math/rand data race caught manually
   during baseline work, so there is precedent.
3. **In-process field-filter anomaly not explained.** `bench-file` field
   filter went 55→81 ms/100 ev while E2E query medians stayed identical
   (1.4→1.5 ms). Most plausibly contention noise on a 285 MB test DB, but
   `busy_timeout=15000` can also *hide* write starvation behind waits —
   latency p99s would then be correct-by-accident under contention. Close
   by: rerun in-process suite ≥3× alternating binaries; if it persists,
   profile field-filter queries with `EXPLAIN QUERY PLAN` under writer load.

## Medium

4. **`bin` is now an explicit error instead of implemented.** Time bucketing
   for row pipelines is straightforward in-memory (`bucket = ts - ts%span`)
   and `timechart` already buckets in SQL; `bin` alone got the "not
   executed" error treatment. Implement before exposing it in the builder UI.
5. **OTLP protobuf decoding unimplemented** (501, was silent-200). Producers
   with JSON/protobuf fallback degrade gracefully; protobuf-only producers
   will see errors. Close by: vendor `go.opentelemetry.io/proto/otlp` +
   protobuf decode, or document JSON-only in the collector config.
6. **Retention/VACUUM untouched.** The benchmark DB crossed 285 MB without
   auto-shrink; there is no scheduled VACUUM or retention sweep wired, and
   FTS index growth is unmeasured beyond that. Close by: nightly
   `PRAGMA wal_checkpoint(TRUNCATE)` + retention DELETE sweep + `auto_vacuum`
   evaluation, with p99 measured before/after enabling.
7. **Detection rule time-window defaults unverified** (deferred in doc 04):
   rules with unset windows may scan full history — same shape as the fixed
   `GetRelatedEvents` problem but in `internal/detections`. Close by: audit
   of catalog rule windows + a LIMIT/ORDER BY bound on rule queries.

## Low / hygiene

8. **SPL eval tokenizer cache deferred.** Expression tokenization still runs
   per row; after the `rex` regex-cache fix its share of row time is small.
   Re-measure with the in-process suite before optimizing.
9. **`_busy_timeout=15000` trade-off.** It eliminated bursty write failures,
   but at the cost of masking pathological contention (see 3). 15 s is the
   upper bound, not a normal wait. Consider exposing it in config.
10. **Streaming JSON responses.** Large query results are still materialized
    fully before the HTTP response; memory scales with result size. Deferred
    (requires API contract review); bounded by `MaxResultRows` today.
11. **Local config noise.** `opencode.json` is modified (local model IDs /
    ports) — unrelated to this work; exclude from any commit. Likewise the
    untracked `logo/` directory predates this task.
12. **Single-writer ceiling.** Batch ingest plateaus ~7k ev/s on this box;
    headroom beyond that needs the write path off the request thread
    entirely (the pipeline already does this server-side) or sharded DBs —
    out of scope for the current architecture.

## Reproduction

```sh
OUT=/tmp/qz-bench scripts/benchmark.sh run          # in-process + E2E suite
CGO_ENABLED=1 CGO_CFLAGS="-DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1" \
  go test -p 1 -timeout 20m ./...                   # full suite
```
