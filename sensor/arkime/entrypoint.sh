#!/usr/bin/env bash
# Arkime container entrypoint
#  1. render config.ini from env
#  2. initialize OpenSearch indices once (arkime_users marker)
#  3. ensure the admin user exists
#  4. start capture + viewer, supervise both; container exits if either dies
#
# v0.12.5 layout notes (validated against the Arkime 5.6.2 deb, real VM):
#   * db.pl lives in /opt/arkime/db/db.pl (was /opt/arkime/bin/db.pl in
#     older releases) - both probed, ARG override possible.
#   * the bundled node runtime lives under /opt/arkime/node-v<ver>-linux-<arch>/bin
#     - auto-detected into PATH (version-tolerant, no rebuild per bump).
#   * capture must run with CWD=/opt/arkime (loads ./parsers); viewer must
#     run with CWD=/opt/arkime/viewer (loads ./views) - each process gets
#     its own (cd ... && exec ...) subshell.
set -euo pipefail

IFACE="${CAPTURE_IFACE:?CAPTURE_IFACE is required}"
ES_URL="${OPENSEARCH_URL:?OPENSEARCH_URL is required}"
SECRET="${ARKIME_PASSWORD_SECRET:?ARKIME_PASSWORD_SECRET is required}"
PROXYSECRET="${ARKIME_PROXY_SECRET:?ARKIME_PROXY_SECRET is required}"
ADMINPW="${ARKIME_ADMIN_PASSWORD:?ARKIME_ADMIN_PASSWORD is required}"
FREEG="${ARKIME_FREESPACE_G:-40}"
VPORT="${ARKIME_WEB_PORT:-8005}"

# --- locate version-dependent binaries (ARG-overridable) -------------
DBPL="${ARKIME_DBPL:-}"
if [ -z "${DBPL}" ]; then
  if [ -x /opt/arkime/db/db.pl ]; then
    DBPL=/opt/arkime/db/db.pl                     # Arkime >= 5.x layout
  elif [ -x /opt/arkime/bin/db.pl ]; then
    DBPL=/opt/arkime/bin/db.pl                    # legacy layout
  else
    echo "[ndr-arkime] FATAL: db.pl not found (set ARKIME_DBPL)" >&2
    exit 1
  fi
fi
NODE_BIN="${ARKIME_NODE_BIN:-}"
if [ -z "${NODE_BIN}" ]; then
  NODE_BIN="$(ls -d /opt/arkime/node-v*/bin 2>/dev/null | sort -V | tail -1 || true)"
fi
if [ -n "${NODE_BIN}" ] && [ -d "${NODE_BIN}" ]; then
  export PATH="${NODE_BIN}:${PATH}"
fi

# --- render config ------------------------------------------------
sed -e "s|@OPENSEARCH_URL@|${ES_URL}|g" \
    -e "s|@CAPTURE_IFACE@|${IFACE}|g" \
    -e "s|@PASSWORD_SECRET@|${SECRET}|g" \
    -e "s|@FREESPACE_G@|${FREEG}|g" \
     -e "s|@VIEW_PORT@|${VPORT}|g" \
     -e "s|@PROXY_SECRET@|${PROXYSECRET}|g" \
     /opt/arkime/etc/config.ini.template > /opt/arkime/etc/config.ini

ip link set "${IFACE}" up || true
ip link set "${IFACE}" promisc on || true

# --- one-time index initialization --------------------------------
if ! curl -sf "${ES_URL}/_cat/indices/arkime_users" >/dev/null 2>&1; then
  echo "[ndr-arkime] initializing Arkime OpenSearch indices..."
  "${DBPL}" "${ES_URL}" init --nodropshards
fi

# --- ensure admin user --------------------------------------------
if ! "${DBPL}" "${ES_URL}" user admin >/dev/null 2>&1; then
  echo "[ndr-arkime] creating admin user..."
  /opt/arkime/bin/arkime_add_user.sh admin "NDR Admin" "${ADMINPW}" --admin --packetSearch
fi

# --- keep the SSO header-auth flag on admin (B4, v0.15.0) -----------
# db.pl / arkime_add_user.sh provisions admin WITHOUT headerAuthEnabled,
# and (re)provisioning on container recreation silently resets it -> the
# NDR SSO proxy got 403 until the flag was re-set by hand on
# arkime_users_v30 (2026.10.17 + 2026.10.19 incidents). Idempotent on
# every boot:
ARKIME_USERS_IDX="$(curl -sf "${ES_URL}/_cat/indices/arkime_users*?h=index" 2>/dev/null | head -n1 | tr -d '[:space:]' || true)"
if [ -n "$ARKIME_USERS_IDX" ]; then
  if curl -s -o /dev/null -X POST "${ES_URL}/${ARKIME_USERS_IDX}/_update/admin" \
      -H 'Content-Type: application/json' \
      -d '{"doc":{"headerAuthEnabled":true}}'; then
    echo "[ndr-arkime] admin headerAuthEnabled=true pada ${ARKIME_USERS_IDX} (idempoten, B4)"
  else
    echo "[ndr-arkime] WARN: gagal set headerAuthEnabled - SSO proxy akan 403 utk admin" >&2
  fi
else
  echo "[ndr-arkime] WARN: indeks arkime_users* belum ada - headerAuthEnabled dilewati" >&2
fi

# --- start both processes, supervise in foreground -----------------
# capture: CWD=/opt/arkime so ./parsers resolves
#          (uses the viewer-less capture binary directly)
(cd /opt/arkime && exec /opt/arkime/bin/capture -c /opt/arkime/etc/config.ini) &
CAPTURE_PID=$!

# viewer: CWD=/opt/arkime/viewer so ./views resolves; started via the
# bundled node runtime (`viewer` shim path changed across releases)
(cd /opt/arkime/viewer && exec node viewer.js \
    -c /opt/arkime/etc/config.ini --host 0.0.0.0 -n ndr-arkime) &
VIEWER_PID=$!

trap 'kill -TERM "${CAPTURE_PID}" "${VIEWER_PID}" 2>/dev/null || true' TERM INT

echo "[ndr-arkime] capture pid=${CAPTURE_PID}, viewer pid=${VIEWER_PID} (port ${VPORT})"

while true; do
  sleep 15
  if ! kill -0 "${CAPTURE_PID}" 2>/dev/null; then
    echo "[ndr-arkime] FATAL: capture exited - restarting container" >&2
    exit 1
  fi
  if ! kill -0 "${VIEWER_PID}" 2>/dev/null; then
    echo "[ndr-arkime] FATAL: viewer exited - restarting container" >&2
    exit 1
  fi
done
