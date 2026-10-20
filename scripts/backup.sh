#!/usr/bin/env bash
# Backup: PostgreSQL dump + config snapshot + OpenSearch repository registration.
# OpenSearch indices are backed up via snapshot into the mounted snapshots dir.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

[[ -f .env ]] && set -a && source .env && set +a

DATA_ROOT="${NDR_DATA_ROOT:-/var/lib/ndr}"
BACKUP_DIR="$DATA_ROOT/backup"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$BACKUP_DIR/$STAMP"
mkdir -p "$OUT"

echo "[backup] writing to $OUT"

# 1. PostgreSQL logical dump
docker exec ndr-postgres pg_dump -U "${POSTGRES_USER:-ndr}" -d "${POSTGRES_DB:-ndr}" \
  | gzip > "$OUT/postgres-${POSTGRES_DB:-ndr}.sql.gz"
echo "[backup] postgres done"

# 2. platform config (compose + env + sensor configs + opensearch init)
tar czf "$OUT/config.tar.gz" \
  docker-compose.yml .env.example \
  sensor/ opensearch/ postgres/ 2>/dev/null || true
cp .env "$OUT/env.backup" && chmod 600 "$OUT/env.backup"
echo "[backup] config done"

# 3. OpenSearch snapshot (registers repository once, then snapshots)
docker exec ndr-opensearch curl -sf -X PUT \
  "http://localhost:9200/_snapshot/ndr-backups" \
  -H 'Content-Type: application/json' \
  -d '{"type":"fs","settings":{"location":"/usr/share/opensearch/snapshots"}}' >/dev/null 2>&1 || true
docker exec ndr-opensearch curl -sf -X PUT \
  "http://localhost:9200/_snapshot/ndr-backups/snapshot-$STAMP?wait_for_completion=true" \
  -H 'Content-Type: application/json' \
  -d '{"indices":"ndr-alerts-*,ndr-events-*,ndr-zeek-*,ndr-suricata-*","ignore_unavailable":true}' \
  > "$OUT/os-snapshot.json" || echo "[backup] WARN: OpenSearch snapshot failed"
echo "[backup] opensearch snapshot attempted"

# 4. retention: keep last 14 backups
ls -1dt "$BACKUP_DIR"/20* 2>/dev/null | tail -n +15 | xargs -r rm -rf
echo "[backup] retention applied (keep 14)"

du -sh "$OUT"
echo "[backup] done: $OUT"
