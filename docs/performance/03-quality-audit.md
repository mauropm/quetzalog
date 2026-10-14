# Quetzalog — Quality, Stability & Security Audit

Method: static inspection of all hot paths + targeted execution (`go test`, live server,
live SPL queries). Every finding lists evidence and confidence. **C** = Critical, **H** = High,
**M** = Medium, **L** = Low.

## Confirmed findings

### F-1 (H, Stability/Durability) — SQLite write errors silently drop acknowledged batches
Evidence: `internal/ingestion/pipeline.go:257-270` — `flushBatch` logs the `CreateBatch`
error and discards the batch. No `busy_timeout` is configured (`internal/database/database.go:27`);
the DSN has only `_journal_mode/_synchronous/_foreign_keys/_cache=shared`. Driver default is 5 s,
but under `_cache=shared` WAL writers can get `SQLITE_LOCKED`/`SQLITE_BUSY` faster, and four
workers + API writers + background workers contend. An event was already accepted (channel-full
error returned to caller) → client believes it is stored → data loss.
Impact: silent telemetry loss under load. Security-relevant for a SIEM.
Remediation: set `busy_timeout` explicitly (15 s), retry batch on busy errors with bounded
backoff, surface drop count in metrics + a distinguishing error type.
Validation: concurrent ingestion test + sustained-load benchmark.

### F-2 (H, Correctness) — Post-commit correlation/observer loop aborts on first error
Evidence: `internal/events/store.go:158-166` — `CreateBatch` returns on the first
`AddEntityFromEvent` error, skipping graph writes **and observers** (risk, MITRE, correlation,
assets) for all later events in the batch. Events stay committed, so the derived layer silently
diverges.
Remediation: continue, collect errors, return a joined error after the loop.
Validation: unit test injecting a failing graph write; observer must run for all events.

### F-3 (H, Stability) — OTLP gRPC `Stop()` nil-pointer panic when `Start()` failed
Evidence: `internal/ingestion/otlp/grpc.go:67-70` dereferences `s.server` unconditionally;
`cmd/siem/main.go:659-665` defers `Stop` even after `Start` error. Panic during shutdown.
Remediation: nil guard.

### F-4 (H, Stability/Correctness) — Silent success on ingestion failure in OTLP/syslog/file paths
Evidence: `internal/ingestion/otlp/otlp.go:83-94` (counts errors, returns 200 OK),
`otlp/grpc.go:77-84` (warn only, success response), `syslog/syslog.go:121,154`,
`file/file.go:194-196` (warn, offset advanced ⇒ line permanently lost, `file.go:200-203`).
Remediation: return partial-success/error responses where protocol allows (OTLP `partialSuccess`
error count; OTLP gRPC `code=RESOURCE_EXHAUSTED`); file tailer only advance offset on success
(or re-queue).
Validation: OTLP handler unit test asserting non-OK/partial response when ingestion rejects.

### F-5 (H, Correctness) — OTLP protobuf HTTP path is a stub that accepts and discards bodies
Evidence: `internal/ingestion/otlp/otlp.go:97-115` reads the body, logs "stub", returns OK.
Most SDKs default to protobuf ⇒ complete data loss for that transport.
Remediation (minimal, honest): return HTTP 501 with an explanatory message instead of OK,
so producers fall back/retry rather than silently losing. Full protobuf parse recommended next phase.

### F-6 (M, Stability) — Unbounded goroutines per syslog TCP connection; connections not closed on Stop
Evidence: `internal/ingestion/syslog/syslog.go:109` (`go` per `Accept`), scanner blocked
on `Read` ignores ctx until peer disconnects.
Remediation: connection limiter + deadline/close on Stop.

### F-7 (M, Correctness/Security) — Non-atomic failed-login counter
Evidence: `internal/auth/auth.go:297-318` SELECT-then-UPDATE race ⇒ lockout counting can be
bypassed under parallel attempts. Low practical severity locally, but an auth correctness bug.

### F-8 (M, Maintainability) — Shutdown ordering gaps
Evidence: `cmd/siem/main.go:767-773` — main API `server` never `Shutdown()`d (in-flight API
requests die at exit, `main.go:703-736`); background workers (`main.go:292,334-344,356-436`)
use `context.Background()` and can touch the DB after `database.Shutdown` (defer ordering,
`main.go:210,773`).
Remediation: graceful `server.Shutdown`, tie tickers to signal ctx.

### F-9 (M, Correctness) — SPL: post-aggregate `where` is broken two ways
Evidence (verified live): `internal/spl/executor/executor.go:104` folds **all** WhereNodes into
SQL WHERE even in the aggregate path ⇒ `stats count by x | where count > n` emits
`json_extract('$."count"')` predicate (always NULL → 0 rows); additionally
`applyWherePost`'s filtered slice is never reassigned (`executor.go:320`, filter discarded).
Same class: `bin`/`lookup` parsed but never executed → silent wrong results
(`executor.go:294-310`, `parser.go:92-93`).

### F-10 (M, Correctness) — SPL row pipeline: `LIMIT 0` zero-row results
Evidence: `internal/spl/executor/executor.go:128-137` uses `clampLimit(opts.Limit)`; the legacy
`Execute` path (`spl.Execute`, `internal/spl/spl.go`) and `RunQuery` pass `RunOptions{Limit:0}`
(default should clamp to 100 as at `executor.go:92-98`) → `LIMIT 0`. Verified by reading: `Run`
passes `opts` with Limit defaulting, but `runRows` ignores `limit`.

### F-11 (M, Stability) — Panic on `eval x=max()` (zero-arg max/min)
Evidence: `internal/spl/executor/eval.go:382-397` indexes `args[0]` unguarded. Recovery
middleware converts to 500, but it is an attacker-reachable crash-class input in untrusted
queries.

### F-12 (M, Correctness) — `search *` / `search "..."` (punctuation-only) match nothing
Evidence: parser maps `*` to a text term (`parser.go:362-364`); `sanitizeFTS("*")` → `""`
(`planner.go:329-345`) → `events_fts MATCH '""'` → 0 rows. Verified live against running server.
A SIEM search bar that returns "no events" for `*` is a correctness/mis-triage hazard.

### F-13 (M, Performance) — File tailer loses/duplicates lines
Evidence: `internal/ingestion/file/file.go:183-203` — fresh `bufio.Scanner` per poll without
seeking to `tail.offset`; offset recorded from the *buffered* file position (`Seek(0,1)`) so
unread buffered bytes are skipped (loss) and partial trailing lines get re-read next poll
(duplication). Also `regexp.Compile` per line (`file.go:366,441,450`).

### F-14 (L→M, Performance) — Write-path per-event costs
Evidence: UUID v4 via crypto/rand per event (`pkg/event/event.go:258-259`); two `time.Now()`
in `NewEvent` (`event.go:51-52`); `EventToMap` copies every attribute to `"attr.*"` keys that
nothing reads (`event.go:135-137`, `store.go:139-144` reads only `insertColumnOrder`); per-event
`json.Marshal` of attrs; redundant `idx_events_id` duplicating the PK index
(`migrations/001_initial.sql:78`); 12 secondary indexes + external-content FTS trigger per insert;
**`correlation.Graph.initTables` executed on every entity/relationship upsert**
(`graph.go:106,150,66-103`) → ~7 extra DDL round-trips per upsert, ~56–88 per event.

### F-15 (L, Stability) — Latent races (dormant under current wiring)
Evidence: `Pipeline.enrichers` read unsynchronized in `processEvent` (`pipeline.go:182`) while
appended under mutex in `AddEnricher` (`:173-176`); `Store.observers` append/iterate without lock
(`store.go:28-44`). Current `serve` wiring never calls `AddEnricher` (composite enricher built and
discarded at `main.go:574-577`) and registers observers before traffic ⇒ dormant, but one change
away from a race. Fix now: copy-on-write slice or RWMutex.

### F-16 (M, Observability) — Prometheus metrics registered but never updated
Evidence: `internal/telemetry/metrics.go` — counters defined and registered, no call sites
anywhere (`RecordEventsIngested` etc. unreferenced). Only `DatabaseSizeBytes` is live.
Drops, ingestion errors, queue saturation invisible in production.

### F-17 (L, Maintainability) — Benchmark harness bug (fixed in this work)
Evidence: `benchmarks/main.go` — shared `*rand.Rand` used concurrently without the mutex;
`math/rand.rngSource` panicked with `index out of range [-1]` during file-DB concurrent
ingestion. Fixed (lock held across generation).

### F-18 (L, Performance) — Per-query regex compile / per-row tokenization in SPL
Evidence: `eval.go:76` compiles the `rex` pattern for **every row**; `EvalExpr` re-tokenizes
the expression string per row (`eval.go:43`) unless bare identifier/literal. Sort comparison
does `fmt.Sprintf("%v")` per comparison (`executor.go:837-850`).

### F-19 (L, Performance) — Double JSON marshal per API success response
Evidence: `pkg/api/response.go:18-36` marshals payload into `json.RawMessage`, `WriteJSON`
(`:132-149`) re-encodes it. Hot for 1 000-row search responses.

### F-20 (M, Performance) — Detection rules without time windows scan the whole events table
Evidence: `internal/detections/detection.go` (threshold-less rules bind no timestamp predicate;
materializes up to `MaxSearchLimit`=50 000 full events incl. `raw` per rule per tick —
`RunWithFindings`).

### F-21 (L, Security/Correctness) — `GetRelatedEvents` ignores LIMIT in SQL
Evidence: `internal/correlation/graph.go:261-300` — `SELECT DISTINCT` with 8 OR-branches,
breaks only in Go after materializing the distinct set.

### F-22 (L, Robustness) — `executeEmptyQuery` binds time.Time without `.UTC()`
Evidence: `internal/query/service.go:120,128`; consistent storage assumes UTC
(`pkg/event/event.go:99`). Wrong on TZ≠UTC deployments.

## Suspected (not fully proven)

- **S-1:** `_cache=shared` (`database.go:27`) increases `SQLITE_LOCKED` incidence under the
  current 25-conn mixed reader/writer pattern. Plausible, unmeasured.
- **S-2:** The correlation-engine state slice (`correlation.go:350-393` after mutex release,
  2 workers) races on shared `st.buf`. Not demonstrated.
- **S-3:** `loginRateLimit` per-IP bucket map without eviction ⇒ slow memory growth. Unmeasured.

## Security note

Parameterization was verified sound on the audited paths (column whitelists, regex-checked
attribute keys, bound values, `EXPLAIN`-clean). Response-body exposure: `search` errors echo
query text only. HEC tokens compared with `==` (timing-unsafe, `hec.go`) — practical risk low,
worth `subtle.ConstantTimeCompare`. Auth `api_token` empty default ⇒ random admin bootstrap (verified). No tenant isolation exists (single-user local design) — out of scope.
