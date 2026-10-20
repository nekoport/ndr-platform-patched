#!/usr/bin/env bash
# Refresh Suricata rules (emerging threats) and live-reload the engine.
# Idempotent; safe to run from cron. Rollback: previous suricata.rules is kept.
set -euo pipefail

CONTAINER="${1:-ndr-suricata}"

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "[rule-update] container $CONTAINER is not running (sensor profile off?)"
  exit 0
fi

echo "[rule-update] fetching rule updates inside $CONTAINER ..."
docker exec "$CONTAINER" suricata-update || {
  echo "[rule-update] WARN: suricata-update failed; keeping previous rule set"
  exit 1
}

echo "[rule-update] reloading rules via unix socket ..."
docker exec "$CONTAINER" suricatasc -c reload-rules || {
  echo "[rule-update] WARN: live reload failed; restarting container instead"
  docker restart "$CONTAINER"
}

echo "[rule-update] done at $(date -u +%FT%TZ)"
