#!/bin/zsh
# Reproducible Quetzalog benchmark runner.
# Usage: scripts/benchmark.sh [label]
# Produces two JSON reports + E2E server metrics under ${OUT:-/tmp/qz-bench}/.
set -e
LABEL=${1:-run}
OUT=${OUT:-/tmp/qz-bench}
mkdir -p "$OUT"
ROOT=$(cd "$(dirname "$0")/.." && pwd)
export CGO_ENABLED=1 CGO_CFLAGS="-DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_JSON1"

# 1. In-process benchmarks, file-backed (production-like: WAL, fsync)
DB="$OUT/bench_$LABEL.db"; rm -f "$DB" "$DB-wal" "$DB-shm"
go run "$ROOT/benchmarks/main.go" -db "$DB" -iterations 3 \
  -ingest-n 50000 -concurrency 8 -search-n 50000 -search-repeat 50 \
  -report > "$OUT/bench-file-$LABEL.json" 2>&1
rm -f "$DB" "$DB-wal" "$DB-shm"

# 2. Build + E2E server run (20k-event ingest, single-event latency,
#    100 mixed queries), sampling RSS during ingest.
go build -o "$OUT/quetzalog-$LABEL" ./cmd/siem/
CONF="$OUT/config-$LABEL.yaml"
cat > "$CONF" <<EOF
server: {host: "127.0.0.1", port: 18080, read_timeout: "60s", write_timeout: "60s", shutdown_timeout: "10s"}
database: {path: "$OUT/e2e_$LABEL.db", max_open_conns: 25}
ingestion: {workers: 4, batch_size: 500}
logging: {level: "info"}
detections: {scheduled: false}
ai_analyst: {enabled: false}
auth: {enabled: false}
otel: {enabled: false}
EOF
rm -f "$OUT/e2e_$LABEL.db" "$OUT/e2e_$LABEL.db-wal" "$OUT/e2e_$LABEL.db-shm"
# 8081: JSON ingest server binds it unconditionally — abort if occupied.
lsof -iTCP:8081 -sTCP:LISTEN >/dev/null 2>&1 && { echo "port 8081 busy"; exit 1; }
"$OUT/quetzalog-$LABEL" serve --config "$CONF" > "$OUT/server-$LABEL.log" 2>&1 &
SrvPID=$!; trap 'kill $SrvPID 2>/dev/null || true' EXIT
sleep 2
QZ_PID=$SrvPID QZ_PORT=18080 python3 "$ROOT/scripts/benchmark_e2e.py" | tee "$OUT/e2e-$LABEL.txt"
kill $SrvPID; wait $SrvPID 2>/dev/null || true
echo "results in $OUT (label=$LABEL)"
