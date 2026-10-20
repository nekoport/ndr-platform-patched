#!/usr/bin/env bash
# Rolling upgrade: rebuild images, migrate DB schema (idempotent SQL), restart.
# Rollback: keep previous images tagged; see docs/OPERATIONS.md section 7.
set -euo pipefail

# v0.13.0: load the deployed .env so upgrades inherit runtime config, and
# backfill NEW variables from .env.example that the old .env predates
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi
if [ -f .env.example ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ''|\#*) continue ;;
    esac
    key="${line%%=*}"
    case "$key" in
      *[!A-Za-z0-9_]*|'') continue ;;
    esac
    if ! grep -q "^${key}=" .env 2>/dev/null; then
      echo "$line" >> .env
      echo "[upgrade] .env backfilled: ${key}"
    fi
  done < .env.example
fi
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[upgrade] building new images..."
docker compose build

echo "[upgrade] running idempotent schema init (postgres/init is applied on first boot; changes are handled by API startup create_all)..."
# SQLAlchemy create_all runs on API start; destructive migrations are manual.

echo "[upgrade] restarting application layer..."
docker compose up -d ndr-api ndr-ui ndr-pipeline

echo "[upgrade] waiting 15s and probing health..."
sleep 15
if curl -sf http://127.0.0.1:${API_PORT:-8080}/api/meta >/dev/null 2>&1; then
  echo "[upgrade] API healthy"
else
  echo "[upgrade] ERROR: API not healthy - roll back with:"
  echo "   docker compose down && git checkout <previous-release> && docker compose up -d --build"
  exit 1
fi

echo "[upgrade] done $(date -u +%FT%TZ)"
