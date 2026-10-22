#!/usr/bin/env bash
# Zeek container entrypoint:
#   1. render node.cfg from the capture interface env
#   2. bring the capture interface up + promiscuous
#   3. zeekctl deploy (starts worker, generates logs/current/*)
#   4. supervisory loop: zeekctl cron every 60s (log rotation/archive),
#      exit(1) if the worker dies so Docker restarts it
set -euo pipefail

IFACE="${CAPTURE_IFACE:?CAPTURE_IFACE is required}"
LOGDIR=/usr/local/zeek/logs
mkdir -p "$LOGDIR"

sed "s/@CAPTURE_IFACE@/${IFACE}/g" /templates/node.cfg.tmpl \
  > /usr/local/zeek/etc/node.cfg

# SpoolDir is a zeekctl.cfg GLOBAL option - a SpoolDir inside node.cfg is
# silently IGNORED by zeekctl. Put the spool INSIDE the mounted log volume
# and re-create the `current` symlink RELATIVELY so it resolves on all
# three sides at once (v0.12.5; absolute symlink = pipeline stayed blind):
#   zeek container : /usr/local/zeek/logs/current
#   host bind      : <NDR_DATA_ROOT>/zeek/logs/current
#   pipeline (ro)  : /input/zeek/current
SPOOL=/usr/local/zeek/logs/spool
mkdir -p "$SPOOL"
if grep -q '^SpoolDir' /usr/local/zeek/etc/zeekctl.cfg 2>/dev/null; then
  sed -i "s|^SpoolDir.*|SpoolDir = ${SPOOL}|" /usr/local/zeek/etc/zeekctl.cfg
else
  echo "SpoolDir = ${SPOOL}" >> /usr/local/zeek/etc/zeekctl.cfg
fi

echo "[ndr-zeek] capture interface: ${IFACE}"
ip link set "${IFACE}" up || true
ip link set "${IFACE}" promisc on || true
# Reduce offload artifacts that corrupt checksums in captured streams
ethtool -K "${IFACE}" gro off lro off 2>/dev/null || true

echo "[ndr-zeek] deploying zeekctl..."
zeekctl deploy

# v0.16.1 (P0-2): zeekctl menulis log live ke $SPOOL/<node>/ yaitu
# spool/zeek/ (LANGSUNG, tanpa subdir 'current'). Symlink lama
# "spool/zeek/current" SELALU dangling sehingga pipeline tidak pernah
# membaca satu pun log Zeek (DNS/conn/TLS/HTTP buta total). Target yang
# benar adalah direktori node itu sendiri, relatif terhadap $LOGDIR:
#   zeek container : /usr/local/zeek/logs/current -> spool/zeek
#   host bind      : <NDR_DATA_ROOT>/zeek/logs/current -> spool/zeek
#   pipeline (ro)  : /input/zeek/current -> spool/zeek
ln -sfn "spool/zeek" "$LOGDIR/current"
if [ ! -e "$LOGDIR/current" ]; then
  echo "[ndr-zeek] WARNING: $LOGDIR/current masih dangling setelah deploy" >&2
fi

LAST_ARCHIVE="$(date +%s)"
while true; do
  sleep 60

  # v0.16.1 (P0-2): self-heal symlink - zeekctl deploy/cron dapat
  # membuat ulang symlink 'current' (absolut) miliknya; kalau target
  # kita hilang atau tidak lagi menunjuk spool/zeek, buat ulang.
  if [ ! -e "$LOGDIR/current" ] \
     || [ "$(readlink "$LOGDIR/current" 2>/dev/null)" != "spool/zeek" ]; then
    ln -sfn "spool/zeek" "$LOGDIR/current"
  fi

  # Archive + rotate logs (zeekctl cron handles this safely)
  zeekctl cron >/dev/null 2>&1 || true

  # Health check: worker process must be running
  if ! zeekctl status 2>/dev/null | grep -q '.*zeek.*running'; then
    echo "[ndr-zeek] FATAL: zeek worker not running, exiting for restart" >&2
    exit 1
  fi

  # Fallback rotation check (in case cron config drifts)
  NOW="$(date +%s)"
  if [ $((NOW - LAST_ARCHIVE)) -ge 3600 ]; then
    LAST_ARCHIVE="$NOW"
  fi
done
