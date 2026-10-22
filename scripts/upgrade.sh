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
# v0.16.2 (BUG-0161-03): build EKSPLISIT dengan profil sensor. Dulu
# `docker compose build` polos tidak membangun image zeek/suricata/arkime
# (profile sensor), sehingga `up -d --force-recreate` di bawah membuat
# ulang container sensor dengan IMAGE LAMA - "upgrade" sensor fiktif
# (dikonfirmasi di verifikasi 0.16.1; operator harus build manual).
# Fallback ke build dasar untuk deployment base-only.
if docker compose --profile sensor build 2>/dev/null; then
  echo "[upgrade] build OK (termasuk profil sensor)"
else
  echo "[upgrade] profil sensor tidak tersedia - build dasar saja"
  docker compose build
fi

# v0.16.2 (BUG-0161-06): rotasi OTOMATIS JWT_SECRET lemah/placeholder.
# .env buatan installer lama berisi 9 char; guard API 0.16.1 menolaknya
# lalu tiap worker memakai secret ephemeral berbeda -> 401 acak.
# Installer baru (v0.16.x) sudah generate otomatis; skrip ini menutup
# .env lama yang belum dirotasi (backup dibuat sebelum perubahan).
_jwt=$(grep -E '^JWT_SECRET=' .env 2>/dev/null | cut -d= -f2- || true)
if [ -z "${_jwt}" ] || [ "${#_jwt}" -lt 32 ] || [ "${_jwt}" = "change-me-32-bytes-min" ]; then
  if command -v openssl >/dev/null 2>&1; then
    cp .env ".env.bak-jwt-$(date +%Y%m%dT%H%M%S)" 2>/dev/null || true
    sed -i "s|^JWT_SECRET=.*|JWT_SECRET=$(openssl rand -hex 32)|" .env
    echo "[upgrade] JWT_SECRET lemah/placeholder dirotasi otomatis (backup .env.bak-jwt-*)"
  else
    echo "[upgrade] WARNING: JWT_SECRET lemah tetapi openssl tidak ada - set manual: openssl rand -hex 32"
  fi
fi

echo "[upgrade] running idempotent schema init (postgres/init is applied on first boot; changes are handled by API startup create_all)..."
# SQLAlchemy create_all runs on API start; destructive migrations are manual.

echo "[upgrade] restarting application layer..."
# v0.16.1 (P2-5): --force-recreate pada aplikasi memastikan container
# benar-benar memakai image baru (kasus lapangan: suricata tetap jalan
# dengan image lama setelah build karena container tidak di-recreate).
docker compose up -d --force-recreate ndr-api ndr-ui ndr-pipeline

echo "[upgrade] recreating sensor layer (image may have changed)..."
# v0.16.1 (P2-5): sensor TIDAK lagi andal pada perilaku default
# `up -d` - wajib --force-recreate agar image baru benar-benar dipakai.
# v0.16.2 (BUG-0161-04, koreksi dokumen): perilaku checkpoint saat inode
# log berubah ADALAH membaca file baru dari AWAL (offset 0), BUKAN dari
# EOF seperti klaim catatan lama. Artinya: (1) file log yang benar-benar
# baru diproses dari awal - benar dan tanpa duplikat berkat dedup; (2)
# file SAMA yang tumbuh selama downtime (mis. eve.json +297 MB) akan
# dimainkan ulang dari checkpoint - itu memang desain no-loss; banjir
# indexing akibatnya kini diredam pacing catch-up + sink cooldown +
# replay deadletter, bukan diabaikan.
docker compose --profile sensor up -d --force-recreate zeek suricata arkime 2>/dev/null \
  || docker compose up -d --force-recreate zeek suricata arkime 2>/dev/null \
  || echo "[upgrade] sensor services not present (base-only deployment)"

echo "[upgrade] waiting 15s and probing health..."
sleep 15
# v0.16.1 (P2-7): /api/version; fallback /api/meta untuk upgrade lama
if curl -sf http://127.0.0.1:${API_PORT:-8080}/api/version >/dev/null 2>&1 \
   || curl -sf http://127.0.0.1:${API_PORT:-8080}/api/meta >/dev/null 2>&1; then
  echo "[upgrade] API healthy"
else
  echo "[upgrade] ERROR: API not healthy - roll back with:"
  echo "   docker compose down && git checkout <previous-release> && docker compose up -d --build"
  exit 1
fi

echo "[upgrade] done $(date -u +%FT%TZ)"
