"""Dead-letter / quarantine writer (doc section 7.3).

Malformed or rejected events are appended to rotated JSONL files with a
reason - nothing is dropped silently. Files rotate daily and are cleaned
up after `retention_hours`.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Iterator

log = logging.getLogger("ndr.deadletter")


class DeadLetterWriter(threading.Thread):
    def __init__(self, state_dir: str, retention_hours: int = 72):
        super().__init__(daemon=True, name="deadletter")
        self.dir = os.path.join(state_dir, "deadletter")
        os.makedirs(self.dir, exist_ok=True)
        self.retention_hours = retention_hours
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.count = 0

    def write(self, reason: str, doc_id: str = "", doc=None, raw: str = "",
              index: str = "") -> None:
        """Tulis satu record deadletter.

        v0.16.2 (BUG-0161-04): record kini membawa `index` tujuan sehingga
        replayer bisa memainkan ulang dokumen sink_timeout/sink_failure ke
        index yang benar TANPA merekonstruksi nama index (dulu index hilang
        dari record, replay mustahil dilakukan dengan aman).
        """
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
        path = os.path.join(self.dir, f"deadletter-{stamp}.jsonl.gz")
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "doc_id": doc_id,
        }
        if index:
            record["index"] = index
        if doc is not None:
            record["doc"] = doc if isinstance(doc, (dict, list)) else str(doc)[:4096]
        if raw:
            record["raw"] = raw[:4096]
        line = json.dumps(record, separators=(",", ":"), default=str)
        with self._lock:
            with gzip.open(path, "at", encoding="utf-8") as fh:
                fh.write(line + "\n")
            self.count += 1

    def records(self) -> Iterator[tuple[str, dict]]:
        """Iterasi SEMUA record deadletter (v0.16.2, dipakai replayer).

        Yields (line_hash, record); line_hash = sha256 baris persis
        sehingga state retry tetap stabil lintas siklus & restart.
        Penyaringan umur record dilakukan replayer (field `ts`).
        """
        for name in sorted(os.listdir(self.dir)):
            if not name.startswith("deadletter-") or not name.endswith(".jsonl.gz"):
                continue
            path = os.path.join(self.dir, name)
            try:
                with gzip.open(path, "rt", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except ValueError:
                            continue
                        yield hashlib.sha256(line.encode("utf-8")).hexdigest(), rec
            except (OSError, EOFError) as exc:
                log.warning("[deadletter] gagal membaca %s: %s", path, exc)

    # ------------------------------------------------------------- cleanup
    def _cleanup(self) -> None:
        cutoff = time.time() - self.retention_hours * 3600
        try:
            for name in os.listdir(self.dir):
                path = os.path.join(self.dir, name)
                if os.path.getmtime(path) < cutoff:
                    os.remove(path)
        except OSError:
            pass

    def run(self) -> None:
        while not self._stop.wait(3600):
            self._cleanup()

    def stop(self) -> None:
        self._stop.set()
