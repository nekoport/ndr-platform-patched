"""In-process deduplication (doc sections 6.2, 7.1, 8.1).

Deduplication = the SAME event arriving more than once (replay, retry,
duplicate source delivery). Distinct-but-similar events must NOT be merged
here; that is aggregation and lives in the detection stage.

Memory-bounded: keeps the most recent `capacity` keys in an LRU structure.
"""

from __future__ import annotations

import threading
from collections import OrderedDict


class DedupStore:
    def __init__(self, capacity: int = 200_000):
        self.capacity = capacity
        self._keys: OrderedDict[str, None] = OrderedDict()
        self._lock = threading.Lock()

    def seen_before(self, key: str) -> bool:
        """True if key was seen recently (within the LRU window)."""
        with self._lock:
            if key in self._keys:
                self._keys.move_to_end(key)
                return True
            self._keys[key] = None
            if len(self._keys) > self.capacity:
                self._keys.popitem(last=False)
            return False

    def __len__(self) -> int:
        with self._lock:
            return len(self._keys)
