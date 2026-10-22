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

_CTRL_MAP = {i: None for i in list(range(0, 9)) + [11, 12] + list(range(14, 32)) + list(range(127, 160))}


def _sanitize(value):
    """Buang karakter kontrol (NUL/GS/dll) yang membuat bulk Lucene menggantung."""
    if isinstance(value, str):
        return value.translate(_CTRL_MAP)
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items()}
    return value


class OpenSearchSink(threading.Thread):
    def __init__(self, url: str, in_queue, cfg, metrics: Metrics,
                 deadletter=None, flush_seconds: float = 5.0,
                 max_items: int = 500, max_retries: int = 8,
                 cooldown_max_seconds: float = 60.0,
                 batch_min_items: int = 50):
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
        # v0.16.2 (BUG-0161-04): breaker adaptif anti-saturasi.
        self.cooldown_max = max(0.0, float(cooldown_max_seconds))
        self.batch_min = max(1, int(batch_min_items))
        self._cooldown = 0.0
        self._batch_size = max_items
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
        # v0.16.2 (BUG-0161-04): batch efektif menyusut saat breaker aktif.
        # Full batch dipecah jadi chunk - TIDAK ADA item yang hilang;
        # sisa yang belum terkirim saat breaker trip masuk deadletter
        # (replayable) oleh _flush_one.
        effective = max(self.batch_min, int(self._batch_size))
        pos = 0
        while pos < len(batch):
            chunk = batch[pos:pos + effective]
            if not self._flush_one(chunk):
                # breaker trip di chunk ini - sisa batch belum terkirim,
                # deadletter-kan agar direplay nanti (tanpa data loss).
                if self.deadletter:
                    for index, doc_id, doc in batch[pos + len(chunk):]:
                        self.deadletter.write("sink_timeout", doc_id, doc,
                                              index=index)
                return
            pos += len(chunk)

    def _flush_one(self, batch: list[tuple[str, str, dict]]) -> bool:
        """Kirim satu chunk. True = sukses, False = breaker trip."""
        for index in {b[0] for b in batch}:
            self._ensure_index(index)
        actions = [
            {"_index": index, "_id": doc_id, "_source": _sanitize(doc)}
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
                            info = item_err.get("index", {}) if isinstance(item_err, dict) else {}
                            self.deadletter.write(
                                "index_error",
                                doc_id=str(info.get("_id", "")),
                                doc=info.get("data"),
                                index=str(info.get("_index", "")))
                self.metrics.inc("events_indexed", len(actions) - len(errors or []))
                self.metrics.inc("batches")
                # v0.16.2: pemulihan bertahap - cooldown halving, batch tumbuh
                if self._cooldown > 0:
                    self._cooldown = max(0.0, self._cooldown / 2.0)
                    self.metrics.set_gauge("sink_cooldown_s",
                                           round(self._cooldown, 2))
                if self._batch_size < self.max_items:
                    self._batch_size = min(
                        self.max_items, max(self.batch_min,
                                            int(self._batch_size * 1.5)))
                return True
            except Exception as exc:  # noqa: BLE001
                log.warning("[sink] bulk gagal n=%d idx=%s: %r", len(batch),
                            sorted({b[0] for b in batch}), exc)
                self.metrics.inc("sink_retries")
                if isinstance(exc, (ConnectionTimeout, TimeoutError)):
                    # server MIGHT still be processing attempt #1 -
                    # resending duplicates work and wedged Lucene (A2).
                    self.metrics.inc("sink_failures")
                    if self.deadletter:
                        for index, doc_id, doc in batch:
                            self.deadletter.write("sink_timeout", doc_id, doc,
                                                  index=index)
                    # v0.16.2 (BUG-0161-04): breaker - tidur eksponensial
                    # sebelum batch berikutnya (batas atas config) dan
                    # perkecil batch; record deadletter direplay berkala
                    # oleh DeadLetterReplayer begitu OS pulih.
                    self._cooldown = min(
                        self.cooldown_max,
                        max(2.0, self._cooldown * 2.0 if self._cooldown
                            else 2.0))
                    self._batch_size = max(
                        self.batch_min, int(self._batch_size / 2))
                    self.metrics.set_gauge("sink_cooldown_s",
                                           round(self._cooldown, 2))
                    self.metrics.set_gauge("sink_batch_size", self._batch_size)
                    return False
                if attempt == self.max_retries - 1:
                    self.metrics.inc("sink_failures")
                    if self.deadletter:
                        for index, doc_id, doc in batch:
                            self.deadletter.write("sink_failure", doc_id, doc,
                                                  index=index)
                    return False
                self._sleep(min(delay, 30.0))
                delay *= 2
        return False

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
            if batch and (len(batch) >= max(self.batch_min, self._batch_size)
                          or now - last_flush >= self.flush_seconds):
                try:
                    self._flush(batch)
                except Exception:
                    log.exception("[sink] flush fatal (n=%d)", len(batch))
                self.metrics.set_gauge("sink_pending", 0)
                batch = []
                last_flush = now
                # v0.16.2 (BUG-0161-04): breaker - hening singkat setelah
                # timeout sebelum menulis lagi (melindungi OpenSearch).
                if self._cooldown > 0:
                    self._sleep(self._cooldown)
        if batch:
            self._flush(batch)
