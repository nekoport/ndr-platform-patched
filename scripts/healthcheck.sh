#!/usr/bin/env bash
# Full health probe: containers, OpenSearch, pipeline freshness, disk, API.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

[[ -f .env ]] && set -a && source .env && set +a

C_GREEN='\033[0;32m'; C_RED='\033[0;31m'; C_YELLOW='\033[1;33m'; C_OFF='\033[0m'
ok()   { echo -e "  ${C_GREEN}[ok]${C_OFF} $*"; }
bad()  { echo -e "  ${C_RED}[!!]${C_OFF} $*"; }
warn() { echo -e "  ${C_YELLOW}[~~]${C_OFF} $*"; }

echo "== NDR healthcheck $(date -u +%FT%TZ) =="

# 1. containers
echo "- containers"
for svc in ndr-opensearch ndr-postgres ndr-pipeline ndr-api ndr-ui; do
  STATE=$(docker inspect -f '{{.State.Status}}' "$svc" 2>/dev/null || echo missing)
  [[ "$STATE" == "running" ]] && ok "$svc running" || bad "$svc -> $STATE"
done
for svc in ndr-zeek ndr-suricata ndr-arkime; do
  STATE=$(docker inspect -f '{{.State.Status}}' "$svc" 2>/dev/null || echo "absent")
  if [[ "$STATE" == "absent" ]]; then
    warn "$svc not deployed (sensor profile off)"
  elif [[ "$STATE" == "running" ]]; then
    ok "$svc running"
  else
    bad "$svc -> $STATE"
  fi
done

# 2. OpenSearch
echo "- opensearch"
OS_PORT="${OPENSEARCH_HTTP_PORT:-9200}"
if HEALTH=$(curl -sf "http://127.0.0.1:${OS_PORT}/_cluster/health" 2>/dev/null); then
  STATUS=$(echo "$HEALTH" | grep -o '"status":"[a-z]*"' | cut -d'"' -f4)
  UNASSIGNED=$(echo "$HEALTH" | grep -o '"unassigned_shards":[0-9]*' | cut -d: -f2)
  ok "cluster $STATUS (unassigned=$UNASSIGNED)"
else
  bad "cluster unreachable on 127.0.0.1:${OS_PORT}"
fi

# 3. pipeline freshness via API
echo "- pipeline / api"
API_PORT="${API_PORT:-8080}"
if JSON=$(curl -sf -H "Accept: application/json" "http://127.0.0.1:${API_PORT}/api/meta" 2>/dev/null); then
  ok "api up ($(echo "$JSON" | head -c 80))"
else
  bad "api unreachable on 127.0.0.1:${API_PORT}"
fi

# direct pipeline metrics endpoint (no auth)
if METRICS=$(curl -sf http://127.0.0.1:9100/metrics 2>/dev/null); then
  EPS=$(echo "$METRICS" | grep -o '"eps_total":[0-9.]*' | cut -d: -f2)
  QUEUE=$(echo "$METRICS" | grep -o '"queue_depth":[0-9]*' | cut -d: -f2)
  LAST=$(echo "$METRICS" | grep -o '"backlog_seconds":[0-9.]*' | cut -d: -f2)
  ok "pipeline eps=$EPS queue=$QUEUE backlog=${LAST}s"
else
  warn "pipeline metrics endpoint not reachable (may still be starting)"
fi

# 4. disk
echo "- disk"
DF_LINE=$(df -BG "${NDR_DATA_ROOT:-/var/lib/ndr}" 2>/dev/null | tail -1 || true)
if [[ -n "$DF_LINE" ]]; then
  AVAIL=$(echo "$DF_LINE" | awk '{print $4}' | tr -dc '0-9')
  USEPCT=$(echo "$DF_LINE" | awk '{print $5}' | tr -d '%')
  if (( USEPCT >= 90 )); then bad "data volume ${USEPCT}% used (${AVAIL}GB free) - ACTION REQUIRED"
  elif (( USEPCT >= 80 )); then warn "data volume ${USEPCT}% used (${AVAIL}GB free)"
  else ok "data volume ${USEPCT}% used (${AVAIL}GB free)"; fi
fi

# 5. recent errors in logs
echo "- recent errors (last 5 min)"
ERRS=$(docker compose logs --since 5m 2>/dev/null | grep -ciE "error|fatal|traceback" || true)
(( ERRS > 0 )) && warn "$ERRS error-ish lines in service logs - inspect: docker compose logs --since 5m" || ok "clean"

echo "== healthcheck done =="
