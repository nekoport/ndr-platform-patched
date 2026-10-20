"""Raw evidence archive (doc principle 4: preserve raw evidence).

Every accepted raw line (EVE/Zeek JSON) is appended to hourly gzip files
under <state>/raw/YYYYMMDDHH-<engine>.jsonl.gz. Retention defaults to 72h;
metadata events keep a sha256 reference (raw_event_ref) to this archive.
"""

from __future__ import annotations

import gzip
import hashlib
import os
import threading
import time
from datetime import datetime, timezone


class RawArchive:
    def __init__(self, state_dir: str, retention_hours: int = 72):
        self.dir = os.path.join(state_dir, "raw")
        os.makedirs(self.dir, exist_ok=True)
        self.retention_hours = retention_hours
        self._lock = threading.Lock()
        self._current_hour: str = ""
        # v0.13.0 BLOCKER fix: ONE handle per ENGINE. The old single handle
        # meant a Suricata line arriving after a Zeek line was appended to
        # the ZEEK archive (and vice versa) - silent raw-evidence corruption.
        self._handles: dict[str, "gzip.GzipFile"] = {}

    def store(self, engine: str, line: str) -> str:
        """Store one raw line; returns its sha256 reference."""
        digest = hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()
        hour = datetime.now(timezone.utc).strftime("%Y%m%d%H")
        path = os.path.join(self.dir, f"{hour}-{engine}.jsonl.gz")
        with self._lock:
            if self._current_hour != hour:
                # hourly rotation closes EVERY engine handle at once
                for fh in self._handles.values():
                    try:
                        fh.close()
                    except OSError:
                        pass
                self._handles.clear()
                self._current_hour = hour
            fh = self._handles.get(engine)
            if fh is None:
                fh = gzip.open(path, "at", encoding="utf-8")
                self._handles[engine] = fh
            fh.write(line.rstrip("\n") + "\n")
        return digest

    def cleanup(self) -> None:
        cutoff = time.time() - self.retention_hours * 3600
        try:
            for name in os.listdir(self.dir):
                path = os.path.join(self.dir, name)
                if os.path.getmtime(path) < cutoff:
                    os.remove(path)
        except OSError:
            pass

    def close(self) -> None:
        with self._lock:
            for fh in self._handles.values():
                try:
                    fh.close()
                except OSError:
                    pass
            self._handles.clear()


class RawArchiveMaintainer(threading.Thread):
    def __init__(self, archive: RawArchive, interval: float = 1800.0):
        super().__init__(daemon=True, name="raw-archive-maint")
        self.archive = archive
        self.interval = interval
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.wait(self.interval):
            self.archive.cleanup()

    def stop(self) -> None:
        self._stop.set()
