#!/usr/bin/env bash
# Suricata container entrypoint
# The compose command supplies: -c /etc/suricata/suricata.yaml -i <iface>
set -euo pipefail

IFACE="unset"
ARGS=("$@")

# Best-effort: pick the interface from -i so we can tune it
for ((i=0; i<${#ARGS[@]}; i++)); do
  if [[ "${ARGS[$i]}" == "-i" ]]; then
    IFACE="${ARGS[$((i+1))]:-unset}"
  fi
done

echo "[ndr-suricata] capture interface: ${IFACE}"
if [[ "${IFACE}" != "unset" ]]; then
  ip link set "${IFACE}" up || true
  ip link set "${IFACE}" promisc on || true
  # Avoid capturing bogus offloaded checksums and fragmented segments
  ethtool -K "${IFACE}" gro off lro off tso off 2>/dev/null || true
fi

RULES=/var/lib/suricata/rules/suricata.rules
if [[ ! -s "${RULES}" ]]; then
  echo "[ndr-suricata] no rules found - running suricata-update..."
  suricata-update || echo "[ndr-suricata] WARN: rule fetch failed; IDS runs with 0 rules"
fi

# v0.13.0: hand the socket + rules dir to the API container uid (10002).
# Without this the API's live-reload write failed with EACCES SILENTLY -
# rule toggles never reached the IDS.
API_UID="${SURICATA_API_UID:-10002}"
chown -R "${API_UID}:${API_UID}" /var/lib/suricata/rules 2>/dev/null || true
mkdir -p /var/run/suricata 2>/dev/null || true
chown "${API_UID}:${API_UID}" /var/run/suricata 2>/dev/null || true
chmod o+r /var/run/suricata 2>/dev/null || true

echo "[ndr-suricata] starting suricata: $*"
exec suricata "$@"
