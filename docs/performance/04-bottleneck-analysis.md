# Quetzalog — Bottleneck Analysis

Ranked by expected benefit × evidence strength ÷ regression risk. Baseline numbers: `02-baseline.md`.

## B-1. Write path: per-event DDL storm (`Graph.initTables` per upsert) — **P1, biggest throughput lever**
- **Evidence:** batch ingestion file-DB 1 802 ev/s vs ~10–50 k/s typical for batched WAL inserts.
  Per event: ≤7 entity upserts + 4 relationship upserts, each calling `initTables`
  (7 `CREATE … IF NOT EXISTS`) ⇒ ~8 extra statements per upsert ⇒ **~90 statements per event**,
  ~0.5 ms/event measured (`internal/correlation/graph.go:106,150`; `events/store.go:90,158-162`).
  Expected cost: ~450 µs of pure statement overhead/event ≈ exactly the observed ceiling.
- **Root cause:** schema bootstrap embedded in the per-event path.
- **Fix:** `sync.Once` init in `Graph` (or lazily-once). No semantic change.
- **Validation:** batch-ingest benchmark (target ≥ 3–5×); graph unit tests.
- **Risk:** low. If tables are dropped mid-life the graph errors (visible), acceptable.

## B-2. Write path: no busy_timeout + no retry ⇒ batch loss (stability) — **P1**
- Evidence: F-1; concurrency benchmark shows 8 writers + 4 workers on one pool.
- Fix: `_busy_timeout=15000` in DSN (and `PRAGMA busy_timeout` after open for the :memory: parity),
  retry batch up to 3× with 20/100 ms backoff, count drops in metrics.
- Expected: eliminates `SQLITE_BUSY`-class loss; throughput unchanged.

## B-3. Write path: redundant per-event allocations — **P2**
- `EventToMap` `attr.*` copy loop removed (unconsumed): ~1 map + N entries per event.
- `NewEvent` double `time.Now()` → single.
- OTLP `fmt.Sscanf` → `strconv.ParseUint`; HEC batch single `json.Marshal` per event (unavoidable per-event raw, keep).
- `severityRank`-style slice allocations (parsers) → package-level (minor).
- Expected: −10–20 % per-event CPU on the worker path, lower GC pressure.

## B-4. Write path: 12 indexes incl. redundant `idx_events_id` — **P2 (careful)**
- Every INSERT updates 12 indexes + FTS entry. `idx_events_id` duplicates the PK index:
  drop via additive migration `022` (`DROP INDEX IF EXISTS idx_events_id`). One fewer
  btree update per event (~8 % of index cost). Other indexes are useful for filters; leave.
- No destructive schema change (index-only). Reversible.

## B-5. Read path: search COUNT + SELECT double-scan; FTS `*` bug — **P2**
- Every row query runs `BuildRowCount` (`executor.go:156-163`) with the same predicate →
  2× scans. For the API path, count is only used for `Count` metadata. Make count optional
  (`?count=1` / first-page heuristic `limit+1` fetch?) — semantics risk. **Decision:** keep COUNT
  (results API contract exposes total) but add the `1=1` fast path for `*`, which currently
  forces an FTS scan returning nothing (B-6). Streaming `WriteJSON` for large results is a
  follow-up (F-19) — defer.
- Time-range searches already use `idx_events_timestamp`; confirmed via `EXPLAIN` (range scan).

## B-6. SPL: `search *` returns zero rows — **P1 (correctness, cheap)**
- Fix in `planner.textPredicate`: term `*` ⇒ `1=1`. Verified live at baseline (count=0 with
  20 k events present). Trivial, removes a catastrophic "no data" illusion.

## B-7. SPL: post-aggregate `where` — **P1 (correctness)**
- Stop folding `where` nodes into SQL in the aggregate path (`BuildWhere` gains a flag), and
  apply the post-agg filter with the returned slice. Both sub-bugs fixed together;
  `stats … | where …` becomes correct. Row path unchanged (push-down stays).

## B-8. SPL: `LIMIT 0` legacy path + `max()/min()` panic — **P1 (cheap correctness)**
- `runRows`: `clampLimit(headN(q, limit))` instead of `clampLimit(opts.Limit)`.
- `callFunction` max/min: `len(args)==0` guard (return nil / 0). Panic class closed.
- `bin`/`lookup`: emit explicit `unsupported` error instead of silent no-op (documented change,
  prevents silently wrong results).

## B-9. Ingestion correctness: OTLP success-on-error + protobuf stub 501 — **P1**
- OTLP HTTP: if errored>0 return 200 with `partialSuccess.rejectedLogRecords` (JSON encoding
  allows reporting via response body `partialSuccess`). Simplest honest fix: when
  `errored == total` → 503; when 0<errored<total → 200 + partialSuccess; protobuf → **501**.
- OTLP gRPC: aggregate per-record failures; return `ExportTraceServiceResponse` with
  partial success info? Minimal: log + return an error (`codes.ResourceExhausted`) when any
  ingestion failed so SDKs retry; bounded to correctness.
- These make backpressure visible to producers instead of silent loss.

## B-10. File tailer: seek-to-offset + buffered partial-line handling + cached regex — **P2**
- Replace per-poll fresh Scanner with: seek(file, offset, 0) before scanning; only advance
  offset to the **last complete newline**; cache compiled `source.Regex` per ingestor.
- Fixes loss/duplication (F-13) and CPU. Tailer semantics preserved.

## B-11. Observability: wire metrics — **P2 (enabler)**
- Call `telemetry.RecordEventsIngested(n)` from `Store.Create/CreateBatch`, rejected/dropped
  counters from pipeline + OTLP/HEC/syslog failure paths, `RecordSearch()` + duration from
  search handlers. Avoid per-event metric overhead (atomic counters + histogram Observe only).

## B-12. Shutdown: graceful HTTP + ctx-tied tickers — **P1 (small)**
- `server.Shutdown(shutdownCtx)` in `cmdServe`; pass `ctx` (signal ctx) to
  `coverageRunner.Start`, baseline/scenario/attackgraph tickers, TI sync. Removes post-shutdown
  DB write races and in-flight request kill.

## B-13. Lower-value / deferred items
- Connection pool tuning (`_cache=shared` evaluation) — needs A/B, keep as documented knob.
- Retention/VACUUM/ANALYZE jobs — out of scope here; documented as remaining work.
- Per-row regex/eval-token caching (F-18): hoist rex compile per query (cheap), defer eval-token
  cache (needs cache structure) — **do rex hoist now**, defer rest.
- Detection time-window default (F-20), `GetRelatedEvents` LIMIT (F-21), auth counter atomicity
  (F-7) — cheap fixes: **do F-21 (LIMIT in SQL) and F-7 (single-statement UPDATE) now**;
  F-20 needs a product decision (documented).

## Rejected / too risky for this pass
- Removing the other 11 indexes or changing the events schema (query regression risk).
- Introducing a query-plan cache (invalidation complexity for marginal gain vs SQL parse cost).
- Rewriting OTLP protobuf parsing (new dependency surface) — 501 stopgap instead.
- Streaming JSON responses (touches every endpoint) — deferred.
- Bounded syslog conformance / worker-pool redesign — defer to documented plan.
