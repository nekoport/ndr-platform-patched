#!/usr/bin/env bash
# System + sensor precheck. Run BEFORE enabling the sensor profile.
#   sudo ./scripts/sensor-precheck.sh [iface]
set -euo pipefail

IFACE="${1:-${CAPTURE_IFACE:-}}"
if [[ -z "$IFACE" ]]; then
  echo "usage: $0 <capture-interface>   (e.g. ens160)"
  ip -o link show | awk -F': ' '{print "  available: " $2}'
  exit 1
fi

pass() { echo "  [ OK ] $*"; }
warn() { echo "  [WARN] $*"; }
fail() { echo "  [FAIL] $*"; }

echo "== NDR sensor precheck: $IFACE =="

# 1. interface exists and is up
if ip link show "$IFACE" >/dev/null 2>&1; then
  STATE=$(cat "/sys/class/net/$IFACE/operstate" 2>/dev/null || echo unknown)
  [[ "$STATE" == "up" ]] && pass "interface up" || warn "interface state: $STATE"
else
  fail "interface does not exist"; exit 1
fi

# 2. driver / speed
 DRIVER=$(readlink "/sys/class/net/$IFACE/device/driver" 2>/dev/null | xargs basename 2>/dev/null || echo "virtio/unknown")
echo "         driver: $DRIVER"
SPEED=$(cat "/sys/class/net/$IFACE/speed" 2>/dev/null || echo "?")
echo "         link speed: ${SPEED} Mb/s"

# 3. promiscuous mode
PROMISC=$(cat "/sys/class/net/$IFACE/promisc" 2>/dev/null || echo 0)
[[ "$PROMISC" == "1" ]] && pass "promiscuous mode on" || warn "promiscuous OFF - sensor engines enable it at start, verify after deploy"

# 4. offload settings (bogus checksums with SPAN)
for f in gro lro tso; do
  V=$(ethtool -k "$IFACE" 2>/dev/null | awk -v f="$f" '$1 == f"-on" {print $2}')
  [[ "$V" == "off" ]] && pass "$f off" || warn "$f is ${V:-unknown} - run: ethtool -K $IFACE $f off"
done

# 5. SPAN traffic visibility sample (5s)
echo "         sampling traffic on $IFACE for 5 seconds..."
if command -v timeout >/dev/null && command -v tcpdump >/dev/null; then
  PKTS=$(timeout 5 tcpdump -i "$IFACE" -c 200 -nn 2>/dev/null | wc -l || true)
  if (( PKTS > 0 )); then
    pass "SPAN traffic visible ($PKTS packets in 5s)"
  else
    fail "no packets observed - check SPAN/TAP config, VLAN direction, monitoring session"
  fi
else
  warn "tcpdump not installed - install tcpdump to verify SPAN visibility"
fi

# 6. NIC counters
if [[ -d "/sys/class/net/$IFACE/statistics" ]]; then
  RX=$(cat "/sys/class/net/$IFACE/statistics/rx_packets")
  RXDROP=$(cat "/sys/class/net/$IFACE/statistics/rx_dropped")
  RXFIFO=$(cat "/sys/class/net/$IFACE/statistics/rx_fifo_errors")
  pass "rx_packets=$RX rx_dropped=$RXDROP rx_fifo=$RXFIFO"
  (( RXDROP < 1000 )) || warn "high rx_dropped - ring buffer or CPU saturation"
fi

# 7. NTP sync
if command -v timedatectl >/dev/null; then
  if timedatectl show 2>/dev/null | grep -q "NTPSynchronized=yes"; then
    pass "NTP synchronized"
  else
    warn "NTP not synchronized - timestamp accuracy at risk (timedatectl set-ntp true)"
  fi
fi

# 8. kernel requirements
MMC=$(sysctl -n vm.max_map_count)
(( MMC >= 262144 )) && pass "vm.max_map_count=$MMC" || fail "vm.max_map_count=$MMC (need >= 262144)"

echo "== precheck done =="
