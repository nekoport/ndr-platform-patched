#!/usr/bin/env python3
"""Deadletter replay tool (v0.15.0, action report B2).

Reads pipeline deadletter JSONL files (deadletter-YYYYMMDD.jsonl.gz in
<state-dir>/deadletter/), optionally filters them, and re-indexes the
documents into OpenSearch with their ORIGINAL _id - idempotent by design
(same _id -> document replaced, never duplicated).

Usage:
  # dry-run (default): per-reason + per-index summary, no writes
  python3 scripts/deadletter-replay.py --state-dir /data/state

  # filter and show what WOULD be replayed
  python3 scripts/deadletter-replay.py --state-dir /data/state \
      --reason sink_timeout,index_error --prefix ndr-alerts- --limit 1000

  # actually replay (bulk batches of 200, original _id)
  python3 scripts/deadletter-replay.py --state-dir /data/state \
      --reason sink_timeout --execute --url http://opensearch:9200

Exit codes: 0 ok, 2 usage error, 3 nothing to replay (with --execute).
"""

from __future__ import annotations

import argparse
import glob
import gzip
import json
import os
import sys
from collections import Counter

BULK_BATCH = 200
KNOWN_REASONS = ("sink_timeout", "sink_failure", "index_error")


# ------------------------------------------------------------------ collect
def collect(state_dir: str, reasons: list[str] | None = None,
            prefix: str | None = None, limit: int | None = None):
    """Yield (reason, index, doc_id, source, raw_line) candidates.

    Doc records look like: {"ts","reason","doc_id","doc"|"raw"}; for
    sink-reason entries `doc` is the original (index, _id, _source) shape
    written by the sink dead-letter path.
    """
    files = sorted(glob.glob(os.path.join(state_dir, "deadletter",
                                          "deadletter-*.jsonl.gz")))
    want = set(reasons or KNOWN_REASONS)
    n = 0
    for path in files:
        try:
            fh = gzip.open(path, "rt", encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"  [skip] {path}: {exc}", file=sys.stderr)
            continue
        with fh:
            for line in fh:
                if limit is not None and n >= limit:
                    return
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                reason = rec.get("reason", "")
                if reason not in want:
                    continue
                doc = rec.get("doc")
                if not isinstance(doc, dict):
                    continue
                index = doc.get("_index") or doc.get("index") or ""
                if prefix and not index.startswith(prefix):
                    continue
                doc_id = str(doc.get("_id") or rec.get("doc_id") or "")
                source = doc.get("_source") if isinstance(
                    doc.get("_source"), dict) else doc
                yield reason, index, doc_id, source, line.rstrip("\n")
                n += 1


def summarize(state_dir: str) -> None:
    by_reason: Counter[str] = Counter()
    by_index: Counter[str] = Counter()
    files = sorted(glob.glob(os.path.join(state_dir, "deadletter",
                                          "deadletter-*.jsonl.gz")))
    for path in files:
        try:
            fh = gzip.open(path, "rt", encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                reason = rec.get("reason", "?")
                by_reason[reason] += 1
                doc = rec.get("doc") or {}
                if isinstance(doc, dict):
                    ix = doc.get("_index") or doc.get("index") or "?"
                    by_index[f"{reason} -> {ix}"] += 1
    print(f"files: {len(files)}  total records: {sum(by_reason.values())}")
    print("per reason:")
    for reason, count in by_reason.most_common():
        print(f"  {reason:<14} {count}")
    if by_index:
        print("per reason -> index (top 10):")
        for key, count in by_index.most_common(10):
            print(f"  {key}: {count}")


# ------------------------------------------------------------------ replay
def reindex(url: str, candidates) -> tuple[int, int, int]:
    """Bulk-reindex candidates with their original _id. Idempotent."""
    from opensearchpy import OpenSearch, helpers  # lazy: dry-run w/o client

    client = OpenSearch(hosts=[url], use_ssl=False, verify_certs=False,
                        timeout=120, max_retries=0, retry_on_timeout=False,
                        maxsize=10, pool_maxsize=10)
    ok = fail = skipped = 0
    batch: list[dict] = []

    def flush(actions):
        nonlocal ok, fail
        if not actions:
            return
        success, errors = helpers.bulk(client, actions, raise_on_error=False,
                                       raise_on_exception=False,
                                       stats_only=True)
        ok += success or 0
        fail += errors or 0

    for reason, index, doc_id, source, _raw in candidates:
        if not index or not doc_id or not isinstance(source, dict):
            skipped += 1
            continue
        batch.append({"_index": index, "_id": doc_id, "_source": source})
        if len(batch) >= BULK_BATCH:
            flush(batch)
            batch = []
    flush(batch)
    return ok, fail, skipped


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state-dir", default="/data/state",
                    help="pipeline state dir containing deadletter/ (default /data/state)")
    ap.add_argument("--reason", default=",".join(KNOWN_REASONS),
                    help=f"comma list of reasons to include ({', '.join(KNOWN_REASONS)})")
    ap.add_argument("--prefix", default=None,
                    help="only replay docs whose target index starts with this (e.g. ndr-alerts-)")
    ap.add_argument("--limit", type=int, default=None, help="max docs to process")
    ap.add_argument("--url", default=os.environ.get("OPENSEARCH_URL",
                                                    "http://127.0.0.1:9200"),
                    help="OpenSearch base URL for --execute")
    ap.add_argument("--execute", action="store_true",
                    help="actually replay (default is dry-run)")
    args = ap.parse_args(argv)

    reasons = [r.strip() for r in args.reason.split(",") if r.strip()]
    unknown = [r for r in reasons if r not in KNOWN_REASONS]
    if unknown:
        print(f"reason tidak dikenal: {unknown} (pilih dari {KNOWN_REASONS})",
              file=sys.stderr)
        return 2
    if not os.path.isdir(os.path.join(args.state_dir, "deadletter")):
        print(f"tidak ada deadletter/ di {args.state_dir} - tidak ada yang diputar ulang")
        return 0

    print(f"== dry-run {'(TIDAK menulis)' if not args.execute else '--execute'} ==")
    summarize(args.state_dir)

    candidates = list(collect(args.state_dir, reasons, args.prefix, args.limit))
    by_reason: Counter[str] = Counter(r for r, *_ in candidates)
    print(f"kandidat (reason={reasons} prefix={args.prefix or '-'} "
          f"limit={args.limit or '-'}): {len(candidates)}")
    for reason, count in by_reason.most_common():
        print(f"  {reason}: {count}")

    if not args.execute:
        print("dry-run selesai - jalankan ulang dengan --execute utk memutar ulang")
        return 0
    if not candidates:
        print("tidak ada kandidat - selesai")
        return 0
    ok, fail, skipped = reindex(args.url, candidates)
    print(f"replay selesai: {ok} sukses, {fail} error, {skipped} dilewati "
          f"(idempoten via _id asli)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
