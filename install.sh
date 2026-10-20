#!/usr/bin/env bash
# ============================================================================
# NDR Platform - one-command installer (Ubuntu 24.04)
# Usage:  sudo ./install.sh
#
# What it does:
#   1. system precheck (docker, resources, sysctl)
#   2. creates the data directory layout on the storage volume
#   3. writes .env (from .env.example) and generates secrets
#   4. builds images and starts the base stack (+ --sensor if requested)
#   5. boots OpenSearch bootstrap (templates/ISM/aliases)
#   6. prints access URLs and the generated admin password
# ============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m'; C_RED='\033[0;31m'; C_OFF='\033[0m'
info()  { echo -e "${C_GREEN}[install]${C_OFF} $*"; }
warn()  { echo -e "${C_YELLOW}[install]${C_OFF} $*"; }
fail()  { echo -e "${C_RED}[install]${C_OFF} $*"; exit 1; }

[[ $EUID -eq 0 ]] || fail "Run as root: sudo ./install.sh"

WITH_SENSOR=false
for arg in "$@"; do
  case "$arg" in
    --sensor) WITH_SENSOR=true ;;
    *) warn "unknown option: $arg" ;;
  esac
done

# ---------------------------------------------------------------- 1. precheck
info "checking system requirements..."

command -v docker >/dev/null 2>&1 || fail "Docker not installed. See docs/DEPLOYMENT.md section 2."
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 plugin missing. Install docker-compose-plugin."

TOTAL_RAM_MB=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo)
if (( TOTAL_RAM_MB < 22000 )); then
  warn "RAM ${TOTAL_RAM_MB}MB < 22GB recommended; OpenSearch heap may need lowering (OPENSEARCH_HEAP)."
fi

CPU_COUNT=$(nproc)
(( CPU_COUNT >= 8 )) || warn "only ${CPU_COUNT} cores detected; 8+ recommended."

DISK_ROOT_GB=$(df -BG / | awk 'NR==2 {print $4}' | tr -dc '0-9')
info "root free: ${DISK_ROOT_GB}GB, RAM: ${TOTAL_RAM_MB}MB, CPUs: ${CPU_COUNT}"

# kernel settings required by OpenSearch
sysctl -w vm.max_map_count=262144 >/dev/null
if ! grep -q "vm.max_map_count" /etc/sysctl.conf 2>/dev/null; then
  echo "vm.max_map_count=262144" >> /etc/sysctl.conf
fi

# ---------------------------------------------------------------- 2. env file
if [[ ! -f .env ]]; then
  info "generating .env from .env.example with random secrets..."
  cp .env.example .env
  sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=')|" .env
  sed -i "s|^JWT_SECRET=.*|JWT_SECRET=$(openssl rand -hex 32)|" .env
  sed -i "s|^ADMIN_PASSWORD=.*|ADMIN_PASSWORD=$(openssl rand -base64 18 | tr -d '/+=')|" .env
  sed -i "s|^ARKIME_PASSWORD_SECRET=.*|ARKIME_PASSWORD_SECRET=$(openssl rand -hex 16)|" .env
  chmod 600 .env
  info ".env created (600). Review CAPTURE_IFACE and NDR_DATA_ROOT before starting."
else
  info ".env already exists - keeping it."
fi

# shellcheck disable=SC1091
source .env

CAPTURE_IFACE="${CAPTURE_IFACE:-}"
[[ -n "$CAPTURE_IFACE" ]] || fail "CAPTURE_IFACE empty in .env"
if ! ip link show "$CAPTURE_IFACE" >/dev/null 2>&1; then
  warn "interface '$CAPTURE_IFACE' does not exist on this host - fix CAPTURE_IFACE in .env"
  warn "interfaces with an IP are management ports; the SPAN port usually has NO IPv4:"
  for i in $(ip -o link show | awk -F': ' '{print $2}'); do
    if ip -4 addr show dev "$i" 2>/dev/null | grep -q inet; then
      echo "    $i (has IP - management)"
    else
      echo "    $i (no IP  <- likely SPAN/TAP candidate)"
    fi
  done
  $WITH_SENSOR && fail "cannot start sensor profile with a missing interface"
fi

# ---------------------------------------------------------------- 3. data dirs
info "creating data layout under ${NDR_DATA_ROOT:-/var/lib/ndr} ..."
DATA_ROOT="${NDR_DATA_ROOT:-/var/lib/ndr}"
mkdir -p "$DATA_ROOT"/{opensearch,postgres,pcap,pcap-exports,backup/opensearch-snapshots} \
         "$DATA_ROOT"/zeek/logs "$DATA_ROOT"/suricata/logs
# v0.13.0: 711 (not 750) - the API container (uid 10002) must TRAVERSE
# $DATA_ROOT to reach pcap-exports/PCAP subdirs; group perms would block it
chmod 711 "$DATA_ROOT"
# snapshot dir must be writable by the API for backup/snapshot flows
mkdir -p "$DATA_ROOT/backup/opensearch-snapshots"
chown 10002:10002 "$DATA_ROOT/backup/opensearch-snapshots" 2>/dev/null || true

# OpenSearch container runs as uid 1000
chown -R 1000:1000 "$DATA_ROOT/opensearch" 2>/dev/null || true
# A1 (report 0.15.0): NEVER hardcode the postgres uid. compose uses
# postgres:16-alpine (uid 70) while Debian images use 999 - a hardcoded
# chown 999:999 broke fresh installs with "could not open file
# global/pg_filenode.map: Permission denied" (hit twice in production).
PG_IMAGE="$(grep -E '^POSTGRES_IMAGE=' .env 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '\"' || true)"
PG_IMAGE="${PG_IMAGE:-postgres:16-alpine}"
PG_UID="$(docker run --rm --entrypoint sh "$PG_IMAGE" -c 'id -u postgres' 2>/dev/null || echo 999)"
PG_GID="$(docker run --rm --entrypoint sh "$PG_IMAGE" -c 'id -g postgres' 2>/dev/null || echo 999)"
echo "[install] postgres uid/gid detected from ${PG_IMAGE}: ${PG_UID}:${PG_GID}"
chown -R "$PG_UID:$PG_GID" "$DATA_ROOT/postgres" 2>/dev/null || true
# API container (uid 10002) stages PCAP export bundles here
chown 10002:10002 "$DATA_ROOT/pcap-exports" 2>/dev/null || true

df -h "$DATA_ROOT" | tail -1 | awk -v dr="$DATA_ROOT" '{printf "[install] %s: total %s used %s avail %s\n", dr, $2, $3, $4}'

# ---------------------------------------------------------------- 4. build+up
# Build base and sensor SEPARATELY so a broken sensor image can never
# prevent the base stack (api/ui/pipeline/opensearch/postgres) from running.
info "building base images (first run downloads base images)..."
docker compose build ndr-pipeline ndr-api ndr-ui

info "starting base stack..."
docker compose up -d opensearch init-opensearch postgres init-rules ndr-pipeline ndr-api ndr-ui

if $WITH_SENSOR; then
  info "building sensor images (zeek, suricata, arkime)..."
  if docker compose --profile sensor build zeek suricata arkime; then
    info "starting sensor profile (zeek, suricata, arkime)..."
    docker compose --profile sensor up -d
  else
    warn "sensor image build FAILED - base stack stays up without sensors."
    warn "fix the build error, then re-run: sudo ./install.sh --sensor"
  fi
else
  warn "sensor profile NOT started. When SPAN/TAP is ready:"
  warn "  sudo ./install.sh --sensor   # or: docker compose --profile sensor up -d"
fi

# ---------------------------------------------------------------- 5. wait+verify
info "waiting for services to become healthy..."
sleep 20
for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:${OPENSEARCH_HTTP_PORT:-9200}/_cluster/health >/dev/null 2>&1; then
    break
  fi
  sleep 5
done

docker compose ps --format 'table {{.Name}}\t{{.Status}}' || true

# ---------------------------------------------------------------- 6. summary
ADMIN_PW=$(grep '^ADMIN_PASSWORD=' .env | cut -d= -f2-)
UI_PORT=$(grep '^UI_PORT=' .env | cut -d= -f2-)
HOST_IP=$(ip -4 addr show scope global | awk '/inet/ {print $2; exit}' | cut -d/ -f1)

cat <<SUMMARY

============================================================
 NDR Platform (Phase 0-2) is starting
============================================================
 Web UI        : http://${HOST_IP:-<vm-ip>}:${UI_PORT}
 API (local)   : http://127.0.0.1:${API_PORT:-8080}/api/meta
 OpenSearch    : http://127.0.0.1:${OPENSEARCH_HTTP_PORT:-9200} (SSH tunnel only)

 First login   : admin / ${ADMIN_PW}
               (you will be asked to change it)

 Useful commands
   make status        service overview
   make logs S=ndr-pipeline   tail one service
   ./scripts/healthcheck.sh   full health probe
   ./scripts/sensor-precheck.sh ${CAPTURE_IFACE}   verify SPAN visibility
============================================================
SUMMARY

info "done."
