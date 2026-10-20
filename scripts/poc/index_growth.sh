#!/usr/bin/env bash
# PoC Day 2-3 helper: daily index growth snapshot (append to CSV).
# Cron suggestion: 0 6 * * * /opt/ndr/scripts/poc/index_growth.sh
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f .env ]] && set -a && source .env && set +a

OS="http://127.0.0.1:${OPENSEARCH_HTTP_PORT:-9200}"
CSV="${NDR_DATA_ROOT:-/var/lib/ndr}/backup/index-growth.csv"
mkdir -p "$(dirname "$CSV")"

[[ -f "$CSV" ]] || echo "date,indices_count,total_gb,docs" > "$CSV"

ROW=$(curl -sf "$OS/_cat/indices/ndr-*?format=json&bytes=b" | python3 -c '
import json, sys, datetime
rows = json.load(sys.stdin)
store = sum(int(r.get("store", "0").split(".")[0] or 0) if isinstance(r.get("store"), str) else int(r.get("store", 0) or 0) for r in rows)
docs = sum(int(r.get("docs.count", "0").replace(",", "") or 0) for r in rows)
print(f"{datetime.datetime.utcnow().isoformat()},{len(rows)},{store/1e9:.2f},{docs}")
')
echo "$ROW" >> "$CSV"
echo "[index-growth] appended: $ROW"
