#!/usr/bin/env bash
# PoC Day 4-5 helper: DSL query latency benchmark (P50/P95/P99) while
# ingestion is running. Requires an API session token (cookie).
#
#   ./scripts/poc/dsl_latency.sh <username> <password> [iterations]
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f .env ]] && set -a && source .env && set +a

USER="${1:?usage: $0 <user> <pass> [iterations]}"
PASS="${2:?}"
N="${3:-30}"
API="http://127.0.0.1:${API_PORT:-8080}"

COOKIE=$(curl -sf -c - -X POST "$API/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" | awk '/ndr_session/ {print $NF}')
[[ -n "$COOKIE" ]] || { echo "login failed"; exit 1; }

echo "== running $N searches (24h window, full alias) =="
python3 - "$N" "$API" "$COOKIE" <<'EOF'
import http.cookiejar, json, statistics, sys, time
import urllib.request

n, api, token = int(sys.argv[1]), sys.argv[2], sys.argv[3]
req_body = json.dumps({
    "index": "ndr-events-read", "size": 50,
    "query": {"bool": {"filter": [
        {"terms": {"severity": ["high", "critical"]}}]}},
}).encode()
latencies = []
for _ in range(n):
    t0 = time.monotonic()
    req = urllib.request.Request(
        f"{api}/api/events/search", data=req_body, method="POST",
        headers={"Content-Type": "application/json",
                 "Cookie": f"ndr_session={token}"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()
    latencies.append((time.monotonic() - t0) * 1000)

latencies.sort()
def pct(p):
    idx = min(len(latencies) - 1, int(len(latencies) * p))
    return latencies[idx]

print(f"n={n}  P50={pct(0.5):.0f}ms  P95={pct(0.95):.0f}ms  P99={pct(0.99):.0f}ms")
print(f"min={latencies[0]:.0f}ms max={latencies[-1]:.0f}ms mean={statistics.mean(latencies):.0f}ms")
ok = pct(0.95) < 3000
print("target P95 < 3000ms:", "PASS" if ok else "FAIL")
EOF
