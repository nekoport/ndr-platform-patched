"""File tailer: follows one or more glob patterns, tolerating rotation.

- discovers files by pattern (e.g. /input/zeek/current/*.log)
- tracks files by (inode, device) so rotation moves don't cause re-reads
- persists checkpoints to survive restarts
- when an output queue is full, blocks (backpressure by design, doc 7.3)

v0.15.0 (action report B3) - checkpoint format hardened:
    {"version": 2, "saved_at": <iso>, "checksum": <sha256 of body>,
     "offsets": {path: int}, "inodes": {path: [st_ino, st_dev]}}
- checksum over the offsets/inodes body; a corrupted/truncated file is
  ignored as a WHOLE (no half-adopted offsets)
- inode entries must be exactly [ino, dev]; malformed entries are dropped
- saved [dev, ino] (the 2026.10.19 operator near-miss on the 18 GB
  eve.json) is DETECTED at use time: warn + keep the offset instead of
  silently treating it as rotation and re-reading the file from 0
- to genuinely force a re-read, delete the checkpoint file (explicit
  operator action; there is no implicit reset path)
"""

from __future__ import annotations

import glob
import hashlib
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Iterator

CHECKPOINT_SAVE_EVERY = 10.0
CHECKPOINT_VERSION = 2

log = logging.getLogger("ndr.tailer")


class Tailer(threading.Thread):
    def __init__(
        self,
        patterns: list[str],
        out_queue,
        checkpoint_path: str | None,
        line_handler: Callable[[str, str], None] | None = None,
        poll_seconds: float = 1.0,
        name: str = "tailer",
    ):
        super().__init__(daemon=True, name=name)
        self.patterns = patterns
        self.out_queue = out_queue
        self.checkpoint_path = checkpoint_path
        self.line_handler = line_handler  # optional per-file transform
        self.poll_seconds = poll_seconds
        self._stop = threading.Event()
        self._offsets: dict[str, int] = {}
        self._inodes: dict[str, tuple[int, int]] = {}
        self.files_seen: set[str] = set()
        self.last_event_monotonic: float | None = None
        self._load_checkpoints()

    # ------------------------------------------------------------ control
    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------ state
    @staticmethod
    def _body_checksum(offsets: dict, inodes: dict) -> str:
        body = json.dumps({"offsets": offsets, "inodes": inodes},
                          sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode("utf-8")).hexdigest()

    def _load_checkpoints(self) -> None:
        if not self.checkpoint_path or not os.path.exists(self.checkpoint_path):
            return
        try:
            with open(self.checkpoint_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            log.warning("[tailer] checkpoint rusak/tak terbaca (%s) - diabaikan: %s",
                        self.checkpoint_path, exc)
            self._offsets, self._inodes = {}, {}
            return
        offsets = data.get("offsets", {})
        inodes_raw = data.get("inodes", {})
        # B3: checksum verification (v2) - ignore the WHOLE file on mismatch
        version = int(data.get("version", 1))
        if version >= 2 and "checksum" in data:
            if self._body_checksum(offsets, inodes_raw) != data["checksum"]:
                log.warning(
                    "[tailer] checksum checkpoint TIDAK COCOK (%s) - file "
                    "diabaikan utuh (jangan edit manual; hapus file utk reset)",
                    self.checkpoint_path)
                return
        # shape validation: offsets must be non-negative ints
        clean_offsets: dict[str, int] = {}
        for k, v in offsets.items():
            if isinstance(v, int) and v >= 0 and not isinstance(v, bool):
                clean_offsets[k] = v
            else:
                log.warning("[tailer] offset tak valid utk %s (%r) - entri dibuang", k, v)
        # shape validation: inodes must be exactly [ino, dev], 2 ints >= 0
        clean_inodes: dict[str, tuple[int, int]] = {}
        for k, v in inodes_raw.items():
            if (isinstance(v, (list, tuple)) and len(v) == 2
                    and all(isinstance(x, int) and x >= 0 and not isinstance(x, bool)
                            for x in v)):
                clean_inodes[k] = (v[0], v[1])
            else:
                log.warning("[tailer] entri inode tak valid utk %s (%r) - "
                            "dibuang (format wajib [st_ino, st_dev])", k, v)
        self._offsets = clean_offsets
        self._inodes = clean_inodes

    def _save_checkpoints(self) -> None:
        if not self.checkpoint_path:
            return
        os.makedirs(os.path.dirname(self.checkpoint_path), exist_ok=True)
        tmp = f"{self.checkpoint_path}.tmp"
        body_offsets = dict(self._offsets)
        body_inodes = {k: list(v) for k, v in self._inodes.items()}
        doc = {"version": CHECKPOINT_VERSION,
               "saved_at": datetime.now(timezone.utc).isoformat(),
               "checksum": self._body_checksum(body_offsets, body_inodes),
               "offsets": body_offsets,
               "inodes": body_inodes}
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        os.replace(tmp, self.checkpoint_path)

    # ------------------------------------------------------------ scan
    def _discover(self) -> list[str]:
        found: list[str] = []
        for pattern in self.patterns:
            for path in glob.glob(pattern):
                if os.path.isfile(path):
                    found.append(path)
        return sorted(set(found))

    def _iter_new_lines(self, path: str) -> Iterator[str]:
        """Yield lines appended since the last checkpointed offset."""
        try:
            st = os.stat(path)
        except OSError:
            return
        inode = (st.st_ino, st.st_dev)
        saved_inode = self._inodes.get(path)
        offset = self._offsets.get(path, 0)
        if saved_inode is not None and tuple(saved_inode) != inode:
            # B3: detect the [dev, ino] hand-edit mistake first (2026.10.19
            # near-miss: operator wrote the pair swapped, the tailer would
            # treat it as rotation and re-read the whole file from 0).
            if tuple(saved_inode) == (st.st_dev, st.st_ino):
                log.warning(
                    "[tailer] checkpoint %s menyimpan [dev, ino] TERBALIK "
                    "(%s vs aktual [ino, dev] %s) - offset DIPERTAHANKAN "
                    "(bukan rotasi); entri dikoreksi di memori",
                    path, list(saved_inode), list(inode))
                self._inodes[path] = inode  # correct in memory; keep offset
            else:
                # rotated/truncated: start from beginning of the new file
                offset = 0
        if offset > st.st_size:
            offset = 0  # truncated in place
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(offset)
                while True:
                    line = fh.readline()
                    if not line:
                        break
                    self.files_seen.add(path)
                    self.last_event_monotonic = time.monotonic()
                    yield line
                new_offset = fh.tell()
        except OSError:
            return
        self._offsets[path] = new_offset
        self._inodes[path] = inode

    # ------------------------------------------------------------ loop
    def run(self) -> None:
        last_save = 0.0
        while not self._stop.is_set():
            scanned_any = False
            for path in self._discover():
                scanned_any = True
                for line in self._iter_new_lines(path):
                    if self.line_handler is not None:
                        line = self.line_handler(path, line)
                    if line is None:
                        continue
                    # blocks when the queue is full -> backpressure upstream
                    self.out_queue.put((path, line.rstrip("\n")))
            if time.monotonic() - last_save > CHECKPOINT_SAVE_EVERY:
                self._save_checkpoints()
                last_save = time.monotonic()
            if not scanned_any:
                time.sleep(self.poll_seconds)
            else:
                # brief idle read to keep CPU low on quiet links
                time.sleep(0.05)
        self._save_checkpoints()
