"""Dead-letter replayer (v0.16.2, BUG-0161-04).

Riwayat lapangan (verifikasi 0.16.1): restart dengan backlog eve.json
297 MB membanjiri OpenSearch; 4.807 dokumen masuk deadletter `sink_timeout`
dan TIDAK PERNAH di-retry - data hilang dari index meski event mentah
masih ada di deadletter.

Desain replay yang AMAN:
  * HANYA record dengan reason replayable: `sink_timeout` dan
    `sink_failure` (batch yang tidak pasti terkirim / gagal terkirim).
    `parse_error`/`validation:*`/`index_error` TIDAK direplay (data
    memang invalid/mapping reject - replay hanya mengulang error).
  * doc _id deterministik (uuid5 dari dedup key / iocmatch id) -> index
    ulang dokumen yang sama = overwrite idempoten, tidak ada duplikat.
  * record `index_error` lama punya `doc._index` + `doc._id` dari body
    error bulk (format helpers.bulk stats_only=False) - tidak direplay,
    hanya dihitung.
  * state retry PERSISTEN di <state_dir>/deadletter_replay_state.json:
    {line_hash: {"attempts": n, "ts": iso}} - siklus berikutnya tidak
    mengulang record yang sudah melewati batas percobaan.
  * backoff: percobaan pertama setelah record berumur >= interval siklus;
    maksimum `dlq_replay_max_attempts` percobaan per proses hidup.
  * kill switch: PIPELINE_DLQ_REPLAY=0 mematikan thread ini sepenuhnya.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
from datetime import datetime, timedelta, timezone

log = logging.getLogger("ndr.dlq-replay")

REPLAYABLE_REASONS = {"sink_timeout", "sink_failure"}
STATE_FILENAME = "deadletter_replay_state.json"
# simpan state ringkas: buang entri lebih tua dari nilai ini
STATE_MAX_AGE_HOURS = 72


class DeadLetterReplayer(threading.Thread):
    def __init__(self, cfg, sink_queue: queue.Queue, metrics,
                 deadletter, poll_seconds: float = 30.0):
        super().__init__(daemon=True, name="dlq-replayer")
        self.cfg = cfg
        self.sink_queue = sink_queue
        self.metrics = metrics
        self.deadletter = deadletter
        self.poll_seconds = poll_seconds
        self.interval = max(60, int(cfg.dlq_replay_interval_seconds))
        self.max_age_hours = max(1, int(cfg.dlq_replay_max_age_hours))
        self.max_per_cycle = max(1, int(cfg.dlq_replay_max_per_cycle))
        self.max_attempts = max(1, int(cfg.dlq_replay_max_attempts))
        self.state_path = os.path.join(cfg.state_dir, STATE_FILENAME)
        self._state: dict[str, dict] = {}
        self._stop = threading.Event()
        self._load_state()

    # ------------------------------------------------------------- state
    def _load_state(self) -> None:
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self._state = {k: v for k, v in data.items()
                               if isinstance(v, dict)}
        except (OSError, ValueError):
            self._state = {}

    def _save_state(self) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(
            hours=STATE_MAX_AGE_HOURS)
        fresh: dict[str, dict] = {}
        for k, v in self._state.items():
            try:
                if datetime.fromisoformat(str(v.get("ts"))) >= cutoff:
                    fresh[k] = v
            except ValueError:
                continue
        self._state = fresh
        try:
            os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
            tmp = f"{self.state_path}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._state, fh)
            os.replace(tmp, self.state_path)
        except OSError as exc:
            log.warning("[replay] gagal menyimpan state: %s", exc)

    # -------------------------------------------------------------- core
    def replay_once(self) -> int:
        """Satu siklus replay. Returns jumlah dokumen yang diantrekan."""
        now = datetime.now(timezone.utc)
        min_age = now - timedelta(seconds=self.interval)
        max_age = now - timedelta(hours=self.max_age_hours)
        queued = 0
        for line_hash, rec in self.deadletter.records():
            if queued >= self.max_per_cycle:
                break
            if rec.get("reason") not in REPLAYABLE_REASONS:
                continue
            try:
                ts = datetime.fromisoformat(str(rec.get("ts")))
            except ValueError:
                continue
            # backoff: biarkan record berumur >= satu interval sebelum
            # percobaan pertama (server mungkin masih memproses bulk #1)
            if ts > min_age or ts < max_age:
                continue
            info = self._state.get(line_hash) or {}
            attempts = int(info.get("attempts", 0))
            if attempts >= self.max_attempts:
                continue
            doc = rec.get("doc")
            doc_id = str(rec.get("doc_id") or "")
            index = str(rec.get("index") or "")
            if not isinstance(doc, dict) or not doc_id or not index:
                # record lama (pra-0.16.2) tanpa field index -> tidak bisa
                # direplay dengan aman; dihitung sebagai skipped.
                self.metrics.inc("dlq_skipped")
                continue
            try:
                # blocking put: backpressure penuh bila sink queue penuh
                self.sink_queue.put((index, doc_id, doc), timeout=30.0)
            except queue.Full:
                log.warning("[replay] sink queue penuh - sisa siklus dilewati")
                break
            self._state[line_hash] = {"attempts": attempts + 1,
                                      "ts": now.isoformat()}
            queued += 1
        if queued:
            log.info("[replay] %d dokumen deadletter dimainkan ulang "
                     "(idempoten by _id)", queued)
            self.metrics.inc("dlq_replayed", queued)
        return queued

    def run(self) -> None:
        log.info("[replay] deadletter replayer aktif (interval %ds, "
                 "max_age %dh, max_attempts %d)", self.interval,
                 self.max_age_hours, self.max_attempts)
        # siklus pertama menunggu satu interval penuh - beri waktu pipeline
        # menstabilkan backlog live sebelum memutar ulang deadletter.
        waited = 0.0
        while waited < self.interval and not self._stop.wait(self.poll_seconds):
            waited += self.poll_seconds
        while not self._stop.is_set():
            try:
                self.replay_once()
            except Exception as exc:  # noqa: BLE001 - replay gagal mulus
                log.warning("[replay] siklus gagal: %s", exc)
            self._save_state()
            if self._stop.wait(self.interval):
                break

    def stop(self) -> None:
        self._stop.set()
