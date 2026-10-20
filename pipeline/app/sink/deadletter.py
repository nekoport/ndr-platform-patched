"""Dead-letter / quarantine writer (doc section 7.3).

Malformed or rejected events are appended to rotated JSONL files with a
reason - nothing is dropped silently. Files rotate daily and are cleaned
up after `retention_hours`.
"""

from __future__ import annotations

import gzip
import json
import os
import threading
import time
from datetime import datetime, timezone


class DeadLetterWriter(threading.Thread):
    def __init__(self, state_dir: str, retention_hours: int = 72):
        super().__init__(daemon=True, name="deadletter")
        self.dir = os.path.join(state_dir, "deadletter")
        os.makedirs(self.dir, exist_ok=True)
        self.retention_hours = retention_hours
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.count = 0

    def write(self, reason: str, doc_id: str = "", doc=None, raw: str = "") -> None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
        path = os.path.join(self.dir, f"deadletter-{stamp}.jsonl.gz")
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "doc_id": doc_id,
        }
        if doc is not None:
            record["doc"] = doc if isinstance(doc, (dict, list)) else str(doc)[:4096]
        if raw:
            record["raw"] = raw[:4096]
        line = json.dumps(record, separators=(",", ":"), default=str)
        with self._lock:
            with gzip.open(path, "at", encoding="utf-8") as fh:
                fh.write(line + "\n")
            self.count += 1

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
