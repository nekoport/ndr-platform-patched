#!/usr/bin/env bash
# NDR API load test (v0.12): start the synthetic target, run the
# generator, collect results, tear down. Sandbox-safe (no docker,
# no OpenSearch required).
#
# Usage: ./scripts/loadtest/run.sh [VUS] [DURATION_SECONDS] [PORT]
set -euo pipefail

VUS="${1:-25}"
DURATION="${2:-30}"
PORT="${3:-8010}"
BASE_URL="http://127.0.0.1:${PORT}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PLATFORM="$(cd "$HERE/../.." && pwd)"
RESULT="${HERE}/result.json"

cleanup() {
  if [ -n "${TARGET_PID:-}" ] && kill -0 "$TARGET_PID" 2>/dev/null; then
    kill "$TARGET_PID" 2>/dev/null || true
    wait "$TARGET_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "[1/4] starting target (uvicorn, sqlite+synthetic OS) on :${PORT}"
(cd "$HERE" && python -m uvicorn target_app:app \
   --host 127.0.0.1 --port "$PORT" --log-level warning \
   > "${HERE}/target.log" 2>&1) &
TARGET_PID=$!

echo "[2/4] waiting for target health"
for _ in $(seq 1 40); do
  if curl -sf "${BASE_URL}/api/meta" > /dev/null 2>&1; then break; fi
  sleep 0.5
done
curl -sf "${BASE_URL}/api/meta" > /dev/null || {
  echo "target failed to start:"; tail -20 "${HERE}/target.log"; exit 2; }

echo "[3/4] load: ${VUS} VUs x ${DURATION}s mixed SOC traffic"
python "${HERE}/load_api.py" \
  --base-url "$BASE_URL" --vus "$VUS" --duration "$DURATION" \
  --username admin --password 'loadtest-admin-pass' \
  | tee "${HERE}/last_run.txt"
python - <<PY
import json, re, pathlib
txt = pathlib.Path("${HERE}/last_run.txt").read_text()
m = re.search(r"\{\s+\"vus\".*\}", txt, re.S)
if m:
    pathlib.Path("${RESULT}").write_text(json.dumps(json.loads(m.group(0)), indent=2))
    print("saved -> ${RESULT}")
PY

echo "[4/4] done (target stopped by trap)"
