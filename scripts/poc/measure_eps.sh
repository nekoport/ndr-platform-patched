#!/usr/bin/env bash
# PoC Day 2-3 helper: measure EPS per source from OpenSearch counters.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f .env ]] && set -a && source .env && set +a

OS="http://127.0.0.1:${OPENSEARCH_HTTP_PORT:-9200}"
NOW_MS=$(date +%s%3N)
FROM_MS=$((NOW_MS - 3600000))

echo "== EPS per engine (last 60 min, sampled at 1h date histogram) =="
curl -sf "$OS/ndr-events-read/_search" -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": { "range": { "@timestamp": { "gte": "now-1h" } } },
  "aggs": {
    "per_engine": {
      "terms": { "field": "source_engine", "size": 10 },
      "aggs": { "per_minute": { "date_histogram": { "field": "@timestamp", "fixed_interval": "1m" } } }
    }
  }
}' | python3 -c '
import json, sys
data = json.load(sys.stdin)
total = data["hits"]["total"]["value"]
print(f"events last 1h: {total} (~{total/3600:.1f} eps overall)")
for b in data["aggregations"]["per_engine"]["buckets"]:
    mins = [m["doc_count"] for m in b["per_minute"]["buckets"] if m["doc_count"] > 0]
    avg = sum(mins)/60 if mins else 0
    print(f"  {b[chr(107)+chr(101)+chr(121)]:<10} {b['doc_count']:>10} events  ~{avg:.1f} eps")
'
echo
echo "== index sizes on disk =="
curl -sf "$OS/_cat/indices/ndr-*?format=json&bytes=gb" | python3 -c '
import json, sys
rows = json.load(sys.stdin)
rows.sort(key=lambda r: r.get("store.size", "0"), reverse=True)
for r in rows[:15]:
    print(f"  {r['index']:<40} {r.get('store.size','?'):>8} {r.get('docs.count','?'):>12} docs")
'
