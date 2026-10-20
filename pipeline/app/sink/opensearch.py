"""OpenSearch bulk sink with bounded queue and anti-wedge retry policy.

v0.15.0 (action report A2 + B1):
- consumes (index, doc_id, doc) triples
- flushes every `flush_seconds` or when `max_items` are pending
- client level: NO HTTP resend (`max_retries=0`, `retry_on_timeout=False`)
  a timed-out request MAY still be processed by the server; resending the
  same bulk doubled write pressure on a single shard and wedged Lucene
  DWPT in production (2026.10.15 / 10.18 / 10.19: 12 write threads stuck
  in BytesRefHash.findHash, queue 20000/20000, eps 0)
- app level policy:
    ConnectionTimeout / TimeoutError -> dead-letter "sink_timeout" and
      return WITHOUT retry (server may still finish attempt #1)
    other exceptions (429/5xx/network) -> exponential backoff, at most
      `max_retries` attempts, then dead-letter "sink_failure"
    per-item errors (mapping rejects etc.) -> dead-letter "index_error"
- B1 ensure-index: before the first bulk to a target index, PUT the index
  (idempotent). `index.auto_create_index=true` proved unreliable under
  wedge conditions - on 2026.10.17 the daily alert index was never created
  and analysts had to PUT `ndr-alerts-<today>` by hand.
"""

from __future__ import annotations

import logging
import threading
import time

from opensearchpy import OpenSearch, ConnectionTimeout, helpers

from app.metrics import Metrics

log = logging.getLogger("ndr.sink")


class OpenSearchSink(threading.Thread):
    def __init__(self, url: str, in_queue, cfg, metrics: Metrics,
                 deadletter=None, flush_seconds: float = 5.0,
                 max_items: int = 500, max_retries: int = 8):
        super().__init__(daemon=True, name="os-sink")
        # A2: max_retries=0 + retry_on_timeout=False -> urllib3 never
        # resends a request on its own; every failure surfaces here once.
        self.client = OpenSearch(
            hosts=[url], use_ssl=False, verify_certs=False,
            timeout=120, max_retries=0, retry_on_timeout=False,
            maxsize=50, pool_maxsize=50,
        )
        self.in_queue = in_queue
        self.cfg = cfg
        self.metrics = metrics
        self.deadletter = deadletter
        self.flush_seconds = flush_seconds
        self.max_items = max_items
        self.max_retries = max_retries
        self._stop = threading.Event()
        self._sleep = time.sleep          # injectable for unit tests
        self._ensured: set[str] = set()   # B1: indexes verified this run

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------ B1
    def _ensure_index(self, index: str) -> None:
        """Idempotent daily-index creation before the first bulk.

        The index templates installed by bootstrap (ndr-events-*/ndr-alerts-*)
        then apply automatically, including the read aliases. Success is
        cached; a failure is NOT cached so the next batch retries.
        """
        if index in self._ensured:
            return
        try:
            if not self.client.indices.exists(index=index):
                self.client.indices.create(index=index)
                log.info("[sink] ensure-index: %s dibuat (template berlaku)", index)
            self._ensured.add(index)
        except Exception as exc:  # noqa: BLE001 - never block the sink here
            if "resource_already_exists" in str(exc):
                self._ensured.add(index)
                return
            # explicit, visible failure (criteria B1) - retried next batch
            log.warning("[sink] ensure-index gagal utk %s: %s", index, exc)

    # ------------------------------------------------------------ A2
    def _flush(self, batch: list[tuple[str, str, dict]]) -> None:
        if not batch:
            return
        for index in {b[0] for b in batch}:
            self._ensure_index(index)
        actions = [
            {"_index": index, "_id": doc_id, "_source": doc}
            for index, doc_id, doc in batch
        ]
        delay = 1.0
        for attempt in range(self.max_retries):
            try:
                success, errors = helpers.bulk(
                    self.client, actions, raise_on_error=False,
                    raise_on_exception=True, refresh=False, stats_only=False,
                )
                # per-item errors (mapping rejections etc.) -> dead-letter
                if errors:
                    for item_err in errors:
                        self.metrics.inc("index_errors")
                        if self.deadletter:
                            self.deadletter.write(
                                "index_error", doc=item_err.get("index", {}))
                self.metrics.inc("events_indexed", len(actions) - len(errors or []))
                self.metrics.inc("batches")
                return
            except Exception as exc:  # noqa: BLE001
                self.metrics.inc("sink_retries")
                if isinstance(exc, (ConnectionTimeout, TimeoutError)):
                    # server MIGHT still be processing attempt #1 -
                    # resending duplicates work and wedged Lucene (A2).
                    self.metrics.inc("sink_failures")
                    if self.deadletter:
                        for _, doc_id, doc in batch:
                            self.deadletter.write("sink_timeout", doc_id, doc)
                    return  # NO sleep, NO retry
                if attempt == self.max_retries - 1:
                    self.metrics.inc("sink_failures")
                    if self.deadletter:
                        for _, doc_id, doc in batch:
                            self.deadletter.write("sink_failure", doc_id, doc)
                    return
                self._sleep(min(delay, 30.0))
                delay *= 2

    def run(self) -> None:
        batch: list[tuple[str, str, dict]] = []
        last_flush = time.monotonic()
        while not self._stop.is_set() or not self.in_queue.empty():
            try:
                item = self.in_queue.get(timeout=0.5)
                batch.append(item)
                self.in_queue.task_done()
            except Exception:
                item = None
            now = time.monotonic()
            if batch and (len(batch) >= self.max_items
                          or now - last_flush >= self.flush_seconds):
                self._flush(batch)
                self.metrics.set_gauge("sink_pending", 0)
                batch = []
                last_flush = now
        if batch:
            self._flush(batch)
