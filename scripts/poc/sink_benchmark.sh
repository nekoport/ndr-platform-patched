#!/usr/bin/env bash
# sink_benchmark.sh - compare EPS/queue/deadletter across bulk-size configs
# (action report 0.15.0 A3: benchmark 10 / 20 / 200 items per bulk).
#
# WHAT IT DOES (per config):
#   1. records current PIPELINE_BULK_MAX_ITEMS from .env
#   2. sets the benchmark value, recreates ONLY ndr-pipeline
#   3. samples /metrics (eps, sink_pending, sink_retries/failures) and the
#      deadletter dir every SAMPLE seconds for DURATION seconds
#   4. prints a summary line; at the end RESTORES the original value
#
# SAFETY: only the pipeline container is recreated; OpenSearch data is
# untouched. Run on a quiet window (benchmark noise is real traffic).
#
# USAGE (on the VM, project dir /opt/ndr):
#   sudo bash scripts/poc/sink_benchmark.sh                 # 10,20,200 @ 300s
#   sudo CONFIGS=10,200 DURATION=120 bash scripts/poc/sink_benchmark.sh
#
# RESULT FORMAT (paste into docs/SIZING-8c-24GB-3TB.md):
#   bulk_items  eps_avg  eps_min  eps_max  sink_pending_avg  retries  failures  deadletter_delta
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

CONFIGS="${CONFIGS:-10,20,200}"
DURATION="${DURATION:-300}"
SAMPLE="${SAMPLE:-10}"
METRICS_PORT="${METRICS_PORT:-9100}"
METRICS_URL="http://127.0.0.1:${METRICS_PORT}/metrics"

ENVKEY=PIPELINE_BULK_MAX_ITEMS
ORIG="$(grep -E "^${ENVKEY}=" .env | tail -n1 | cut -d= -f2- || true)"
ORIG="${ORIG:-500}"
echo "== benchmark bulk-size: configs=[${CONFIGS}] duration=${DURATION}s sample=${SAMPLE}s =="
echo "   nilai awal ${ENVKEY}=${ORIG} (akan dikembalikan di akhir)"

metrics_get() {  # metrics_get COUNTER_NAME
  curl -sf "$METRICS_URL" 2>/dev/null | awk -v k="$1" '
    $1 ~ k"(_\{|\{|$)" {s+=$NF} END {printf "%.0f", s+0}'
}

deadletter_records() {  # jumlah rekaman deadletter di dalam kontainer pipeline
  docker exec ndr-pipeline python3 - <<'PY' 2>/dev/null || echo 0
import gzip, glob
n = 0
for f in glob.glob("/data/state/deadletter/deadletter-*.jsonl.gz"):
    with gzip.open(f, "rt", encoding="utf-8", errors="replace") as fh:
        n += sum(1 for _ in fh)
print(n)
PY
}

summarize() {  # summarize LABEL
  local label="$1" t=0 n=0 eps_min=999999 eps_max=0 eps_avg=0 pend=0 pend_n=0
  local r0 f0 d0 r1 f1 d1
  r0=$(metrics_get sink_retries); f0=$(metrics_get sink_failures)
  d0=$(deadletter_records)
  local eps_sum=0
  while [ "$t" -lt "$DURATION" ]; do
    eps=$(curl -sf "$METRICS_URL" 2>/dev/null | awk '/^events_indexed/ {v+=$NF} END {print v+0}')
    pend=$(curl -sf "$METRICS_URL" 2>/dev/null | awk '/^sink_pending/ {print $NF+0}')
    echo "$eps" >> "/tmp/bmk_eps_${label}"
    echo "$pend" >> "/tmp/bmk_pend_${label}"
    sleep "$SAMPLE"; t=$((t+SAMPLE))
  done
  # eps per interval = delta counter / seconds
  eps_avg=$(python3 - "/tmp/bmk_eps_${label}" "$SAMPLE" <<'PY'
import sys
vals=[float(x) for x in open(sys.argv[1]) if x.strip()]
if len(vals)<2: print("0"); raise SystemExit
deltas=[(vals[i+1]-vals[i]) for i in range(len(vals)-1)]
print(f"{sum(deltas)/len(deltas)/float(sys.argv[2]):.1f}")
PY
)
  eps_min=$(python3 - "/tmp/bmk_eps_${label}" "$SAMPLE" <<'PY'
import sys
vals=[float(x) for x in open(sys.argv[1]) if x.strip()]
deltas=[(vals[i+1]-vals[i]) for i in range(len(vals)-1)] or [0]
print(f"{min(deltas)/float(sys.argv[2]):.1f}")
PY
)
  eps_max=$(python3 - "/tmp/bmk_eps_${label}" "$SAMPLE" <<'PY'
import sys
vals=[float(x) for x in open(sys.argv[1]) if x.strip()]
deltas=[(vals[i+1]-vals[i]) for i in range(len(vals)-1)] or [0]
print(f"{max(deltas)/float(sys.argv[2]):.1f}")
PY
)
  pend_avg=$(awk '{s+=$1; n++} END {if(n)printf "%.1f",s/n; else print "0"}' "/tmp/bmk_pend_${label}")
  r1=$(metrics_get sink_retries); f1=$(metrics_get sink_failures)
  d1=$(deadletter_records)
  printf "%-10s %8s %8s %8s %17s %8s %9s %16s\n" "$label" "$eps_avg" "$eps_min" "$eps_max" "$pend_avg" "$((r1-r0))" "$((f1-f0))" "$((d1-d0))"
  rm -f "/tmp/bmk_eps_${label}" "/tmp/bmk_pend_${label}"
}

echo
printf "%-10s %8s %8s %8s %17s %8s %9s %16s\n" bulk_items eps_avg eps_min eps_max sink_pending retries failures deadletter
IFS=',' read -ra CFGS <<< "$CONFIGS"
for cfg in "${CFGS[@]}"; do
  cfg="$(echo "$cfg" | tr -d '[:space:]')"
  echo "-- set ${ENVKEY}=${cfg}; recreate ndr-pipeline; settle 30s --"
  sed -i "s|^${ENVKEY}=.*|${ENVKEY}=${cfg}|" .env
  docker compose up -d ndr-pipeline >/dev/null 2>&1 || docker compose up -d pipeline >/dev/null
  sleep 30
  summarize "$cfg"
done

echo
echo "-- restore ${ENVKEY}=${ORIG}; recreate ndr-pipeline --"
sed -i "s|^${ENVKEY}=.*|${ENVKEY}=${ORIG}|" .env
docker compose up -d ndr-pipeline >/dev/null 2>&1 || docker compose up -d pipeline >/dev/null
echo "selesai. tempel hasil ke docs/SIZING-8c-24GB-3TB.md bagian SINK BULK SIZING."
