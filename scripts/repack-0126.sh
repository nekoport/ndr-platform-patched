#!/usr/bin/env bash
# ============================================================================
# repack-0126.sh - verifikasi kontrak rilis 0.12.6 + bangun arsip tar.gz/zip
# Jalankan dari root repo:  bash scripts/repack-0126.sh
# Output: /home/z/my-project/download/ndr-platform-0.12.6.tar.gz + sourcecode.zip
# ============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"
OUT="/home/z/my-project/download"
VERSION="0.12.6"

C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m'; C_RED='\033[0;31m'; C_OFF='\033[0m'
info() { echo -e "${C_GREEN}[repack]${C_OFF} $*"; }
warn() { echo -e "${C_YELLOW}[repack]${C_OFF} $*"; }
fail() { echo -e "${C_RED}[repack]${C_OFF} $*"; exit 1; }

# ------------------------------------------------------------------ kontrak
# [v0.12.3] Suricata: repo image yang benar-benar ada + ethtool
grep -q 'ARG SURICATA_IMAGE=jasonish/suricata:8.0' sensor/suricata/Dockerfile \
  || fail "kontrak: suricata Dockerfile default image jasonish/suricata:8.0"
grep -q 'apt-get install -y --no-install-recommends ethtool' sensor/suricata/Dockerfile \
  || fail "kontrak: suricata Dockerfile memasang ethtool"
grep -q 'SURICATA_IMAGE:-jasonish/suricata:8.0' docker-compose.yml \
  || fail "kontrak: compose default SURICATA_IMAGE jasonish/suricata:8.0"

# [v0.12.3] Arkime: pola nama deb ubuntu2404 + ARG ARKIME_DEB
grep -q 'ARG ARKIME_DEB=' sensor/arkime/Dockerfile \
  || fail "kontrak: arkime Dockerfile punya ARG ARKIME_DEB"
grep -q '1.ubuntu2404_amd64.deb' sensor/arkime/Dockerfile \
  || fail "kontrak: arkime deb pattern -1.ubuntu2404_amd64.deb"

# [v0.12.3] pipeline deps: sqlalchemy + psycopg
grep -qi 'sqlalchemy' pipeline/requirements.txt \
  || fail "kontrak: pipeline/requirements.txt memuat sqlalchemy"
grep -qi 'psycopg' pipeline/requirements.txt \
  || fail "kontrak: pipeline/requirements.txt memuat psycopg"

# [v0.12.3] skema Postgres tanpa UUID PK
if grep -E 'UUID PRIMARY KEY|UUID +PRIMARY' postgres/init/001_schema.sql >/dev/null; then
  fail "kontrak: 001_schema.sql masih punya UUID PRIMARY KEY (bug 0.12.2)"
fi
grep -q 'id                   TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text' \
  postgres/init/001_schema.sql \
  || fail "kontrak: users.id TEXT di 001_schema.sql"

# [v0.12.3] installer: build base & sensor terpisah
grep -q 'docker compose build opensearch init-opensearch postgres ndr-pipeline ndr-api ndr-ui' install.sh \
  || fail "kontrak: install.sh build base eksplisit"
grep -q 'docker compose --profile sensor build zeek suricata arkime' install.sh \
  || fail "kontrak: install.sh build sensor terpisah"

# [v0.12.3] .env.example lengkap + dok SPAN
[[ -f .env.example ]] || fail "kontrak: .env.example ada"
for v in CAPTURE_IFACE OPENSEARCH_HEAP POSTGRES_PASSWORD JWT_SECRET \
         ADMIN_PASSWORD SURICATA_IMAGE ARKIME_VERSION NDR_DATA_ROOT SENSOR_ID; do
  grep -q "^${v}=" .env.example || fail "kontrak: .env.example punya ${v}"
done

# [v0.12.4] zeek Dockerfile TANPA COPY scripts/ (baris komentar diabaikan)
if grep -v '^\s*#' sensor/zeek/Dockerfile | grep -q 'COPY scripts/'; then
  fail "kontrak: zeek Dockerfile masih COPY scripts/ (bug 0.12.3)"
fi

# [v0.12.4] reset Postgres yang benar di DEPLOYMENT.md
grep -q 'sudo env NDR_DATA_ROOT=' docs/DEPLOYMENT.md \
  || fail "kontrak: DEPLOYMENT.md reset command sudo env NDR_DATA_ROOT"

# [v0.12.4] migrasi inspector-guarded (API + pipeline)
grep -q 'inspect(engine).get_columns("incident_evidence")' api/app/main.py \
  || fail "kontrak: main.py _migrate_doc11_columns inspector-guarded"
grep -q 'inspect(engine).get_columns("incidents")' api/app/main.py \
  || fail "kontrak: main.py _migrate_v012_columns inspector-guarded"
grep -q 'sa_inspect(self.engine)' pipeline/app/correlation/store.py \
  || fail "kontrak: pipeline store.py ensure_schema inspector-guarded"
if grep -v '^\s*#' api/app/main.py | grep -q 'except Exception:  # noqa: BLE001 - column already exists'; then
  fail "kontrak: main.py masih exception-driven migration"
fi

# [v0.12.5] Alert Center: flatten hits + fallback lookup + panel gabungan
grep -q '{"id": h\["_id"\], \*\*(h.get("_source") or {})}' api/app/routers/alerts.py \
  || fail "kontrak: alerts.py search hits di-flatten"
grep -q 'find_by_term' api/app/routers/evidence.py \
  || fail "kontrak: evidence.py fallback find_by_term"
grep -q 'def find_by_term' api/app/os_client.py \
  || fail "kontrak: os_client.py punya find_by_term"
grep -q 'Evidence & sessions (doc 15)' ui/components/ndr/alerts.tsx \
  || fail "kontrak: alerts.tsx panel gabungan Evidence & sessions"
grep -q 'sampleEvents' ui/components/ndr/evidence.tsx \
  || fail "kontrak: evidence.tsx menerima sampleEvents"
grep -q 'SampleEventsBlock' ui/components/ndr/evidence.tsx \
  || fail "kontrak: evidence.tsx punya SampleEventsBlock"
if grep -n "Evidence (\${selected" ui/components/ndr/alerts.tsx >/dev/null 2>&1; then
  fail "kontrak: alerts.tsx masih punya section Evidence terpisah"
fi

# [v0.12.6] Fix 1: sidebar bisa discroll di layar pendek
grep -q 'min-h-0 flex-1 px-2 py-3' ui/app/page.tsx \
  || fail "kontrak: sidebar ScrollArea min-h-0 flex-1"
grep -q 'shrink-0 border-t border-zinc-800/70 p-3' ui/app/page.tsx \
  || fail "kontrak: sidebar footer shrink-0"

# [v0.12.6] Fix 2: Alert Center paginasi server-side + endpoint stats
grep -q 'router.post("/stats")' api/app/routers/alerts.py \
  || fail "kontrak: endpoint /api/alerts/stats"
grep -q 'from: filters.from ?? 0' ui/lib/ndr/api.ts \
  || fail "kontrak: searchAlerts kirim offset server-side"
grep -q 'export async function getAlertStats' ui/lib/ndr/api.ts \
  || fail "kontrak: getAlertStats tersedia"
grep -q 'matches (server-side)' ui/components/ndr/alerts.tsx \
  || fail "kontrak: alerts.tsx total server-side"
grep -q 'size: 500,' ui/components/ndr/alerts.tsx \
  && fail "kontrak: alerts.tsx masih fetch size 500"

# [v0.12.6] Fix 3: threat map ringan
grep -q 'max_pairs=limit' api/app/routers/graph.py \
  || fail "kontrak: geo router limit param"
grep -q 'const ARC_BUDGET = 40' ui/components/ndr/threat-map.tsx \
  || fail "kontrak: threat-map ARC_BUDGET"
grep -q 'MAX_RENDER_NODES = 140' ui/components/ndr/relationship-graph.tsx \
  || fail "kontrak: relationship-graph render cap"

# [v0.12.6] Fix 4: attack graph spesifik (caps + relevance ketat)
grep -q 'RECON_MAX_NODES\", 48' pipeline/app/config.py \
  || fail "kontrak: pipeline config RECON_MAX_NODES 48"
grep -q 'RECON_MAX_EDGES\", 72' pipeline/app/config.py \
  || fail "kontrak: pipeline config RECON_MAX_EDGES 72"
grep -q 'RECON_MAX_CONTEXT\", 60' pipeline/app/config.py \
  || fail "kontrak: pipeline config RECON_MAX_CONTEXT 60"
grep -q 'MAX_NODES = 48' pipeline/app/correlation/story.py \
  || fail "kontrak: story MAX_NODES 48"
grep -q 'self.context_count >= self.max_context' pipeline/app/correlation/story.py \
  || fail "kontrak: story context budget"
grep -q 'force=True' pipeline/app/correlation/story.py \
  || fail "kontrak: signal structure force=True"
grep -q 'RECON_MAX_NODES=48' .env.example \
  || fail "kontrak: .env.example RECON_MAX_NODES"

# [v0.12.6] Fix 5+6: rules paginasi + pembedaan sumber
grep -q 'source: str = Query(default="all",' api/app/routers/rules.py \
  || fail "kontrak: rules list source param"
grep -q '@router.get("/zeek")' api/app/routers/rules.py \
  || fail "kontrak: endpoint /api/rules/zeek"
grep -q 'zeek_local_path' api/app/config.py \
  || fail "kontrak: api config zeek_local_path"
grep -q './sensor/zeek/local.zeek:/etc/ndr/zeek/local.zeek:ro' docker-compose.yml \
  || fail "kontrak: compose mount local.zeek ke ndr-api"
grep -q 'export async function getZeekScripts' ui/lib/ndr/api.ts \
  || fail "kontrak: getZeekScripts api"
grep -q 'Lokal (custom)' ui/components/ndr/rules.tsx \
  || fail "kontrak: rules.tsx filter sumber"
grep -q 'Paginator page={page} pageSize={pageSize} total={list?.total ?? 0}' \
  ui/components/ndr/rules.tsx \
  || fail "kontrak: rules.tsx Paginator"

# [v0.12.6] Fix 7: tema menu biru glossy
grep -q 'ndr-menu-active' ui/app/globals.css \
  || fail "kontrak: globals.css .ndr-menu-active"
grep -q 'ndr-menu-active' ui/app/page.tsx \
  || fail "kontrak: page.tsx pakai .ndr-menu-active"

# [versi]
grep -q '__version__ = "0.12.6"' api/app/__init__.py \
  || fail "kontrak: api __version__ 0.12.6"
grep -q '"version": "0.12.6"' ui/package.json \
  || fail "kontrak: ui package.json 0.12.6"
grep -q 'v0.12.6' README.md \
  || fail "kontrak: README changelog v0.12.6"
info "semua kontrak statis LULUS"

# ------------------------------------------- simulasi installer (env-check)
# Proses terpisah TANPA export: membuktikan .env.example cukup untuk
# mengisi semua ${VAR} docker-compose.yml (kegagalan lama: file hilang).
ENV_CHECK="$(mktemp /tmp/ndr-envcheck-XXXX.py)"
cat > "$ENV_CHECK" << 'PYEOF'
import re, sys, pathlib
repo = pathlib.Path(sys.argv[1])
example = repo / ".env.example"
compose = repo / "docker-compose.yml"
vals = {}
for line in example.read_text().splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, _, v = line.partition("=")
    vals[k.strip()] = v.strip()
# simulasi 3 penggantian secret installer
import secrets
for k in ("POSTGRES_PASSWORD", "JWT_SECRET", "ADMIN_PASSWORD", "ARKIME_PASSWORD_SECRET"):
    vals[k] = secrets.token_urlsafe(24)
missing, placeholder = [], []
text = compose.read_text()
for m in re.finditer(r"\$\{([A-Z_][A-Z0-9_]*)(:-[^}]*)?\}", text):
    var, default = m.group(1), m.group(2)
    if var in vals and vals[var] != "":
        continue
    if default is not None and var not in vals:
        continue  # kompose punya default, var opsional
    if default is None and var in vals and vals[var] == "":
        placeholder.append(var)
    if var not in vals:
        missing.append(var)
if missing:
    print("VAR TANPA DEFAULT TIDAK TERDEFINISI:", missing); sys.exit(1)
if placeholder:
    print("VAR WAJIB KOSONG (placeholder):", placeholder); sys.exit(1)
print("env-check OK: semua ${VAR} compose terlayani oleh .env")
PYEOF
python3 "$ENV_CHECK" "$REPO_DIR"
rm -f "$ENV_CHECK"

# ------------------------------------------------------------- regresi cepat
info "pytest repo: api + pipeline..."
PASS_RE='[1-9][0-9]* passed'
( cd api && python -m pytest 2>&1 | grep -E "$PASS_RE" | tail -1 \
  | grep -qE "$PASS_RE" || fail "pytest api repo gagal" )
API_N=$( cd api && python -m pytest 2>&1 | grep -oE "$PASS_RE" | tail -1 )
( cd pipeline && python -m pytest 2>&1 | grep -E "$PASS_RE" | tail -1 \
  | grep -qE "$PASS_RE" || fail "pytest pipeline repo gagal" )
info "regresi repo LULUS (api ${API_N} + pipeline)"

# --------------------------------------------------------------- arsip tar.gz
rm -rf /tmp/ndr-repack && mkdir -p /tmp/ndr-repack
STAGE="/tmp/ndr-repack/ndr-platform-${VERSION}"
mkdir -p "$STAGE"
tar --exclude='./.git' --exclude='./ui/node_modules' --exclude='./ui/.next' \
    --exclude='./node_modules' --exclude='./.next' \
    --exclude='__pycache__' --exclude='*.pyc' --exclude='.pytest_cache' \
    --exclude='*.tar.gz' --exclude='*.zip' \
    -cf - . | tar -xf - -C "$STAGE"
info "tree distage: $(du -sh "$STAGE" | cut -f1)"

TARBALL="${OUT}/ndr-platform-${VERSION}.tar.gz"
mkdir -p "$OUT"
tar -czf "$TARBALL" -C /tmp/ndr-repack "ndr-platform-${VERSION}"

ZIPFILE="${OUT}/sourcecode.zip"
# PENTING: `zip -qr` MENAMBAH ke arsip yang sudah ada (entri lama yang tidak
# ada di tree baru ikut terbawa - bug repack). Hapus dulu.
rm -f "$ZIPFILE"
( cd "$STAGE" && rm -rf api/.pytest_cache pipeline/.pytest_cache \
    && zip -qr "$ZIPFILE" . -x 'node_modules/*' -x '*.pyc' )

# ------------------------------------- verifikasi arsip: identik + test hijau
EXTRACT_T="/tmp/ndr-repack/from-tar"
EXTRACT_Z="/tmp/ndr-repack/from-zip"
mkdir -p "$EXTRACT_T" "$EXTRACT_Z"
tar -xzf "$TARBALL" -C "$EXTRACT_T"
( cd "$EXTRACT_Z" && unzip -q "$ZIPFILE" )
if diff -r "$EXTRACT_T/ndr-platform-${VERSION}" "$EXTRACT_Z" > /tmp/ndr-repack/diff.txt 2>&1; then
  info "tar.gz vs zip: IDENTICAL"
else
  warn "PERBEDAAN terdeteksi:"; head -20 /tmp/ndr-repack/diff.txt
  fail "arsip tar dan zip tidak identik"
fi

info "pytest DI DALAM arsip..."
( cd "$EXTRACT_T/ndr-platform-${VERSION}/api" && python -m pytest 2>&1 | grep -E "$PASS_RE" | tail -1 )
( cd "$EXTRACT_T/ndr-platform-${VERSION}/pipeline" && python -m pytest 2>&1 | grep -E "$PASS_RE" | tail -1 )
grep -q '__version__ = "0.12.6"' "$EXTRACT_T/ndr-platform-${VERSION}/api/app/__init__.py" \
  || fail "versi dalam arsip salah"
[[ -f "$EXTRACT_T/ndr-platform-${VERSION}/.env.example" ]] \
  || fail ".env.example hilang dari arsip"

# ------------------------------------------------- pensiunkan arsip lama
for old in "$OUT"/ndr-platform-*.tar.gz; do
  [[ -e "$old" ]] || continue
  [[ "$old" == "$TARBALL" ]] && continue
  rm -f "$old" && info "pensiun: $(basename "$old")"
done

info "SELESAI"
sha256sum "$TARBALL" "$ZIPFILE"
ls -la "$TARBALL" "$ZIPFILE"
