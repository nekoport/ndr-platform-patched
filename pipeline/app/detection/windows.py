"""Sliding-window aggregation state used by detection rules.

Memory-bounded: keys are evicted LRU-style beyond `max_keys`; per-key
buffers are pruned to `window_seconds` on every touch/sweep.
"""


from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque


class WindowBuffer:
    def __init__(self, window_seconds: int, max_keys: int = 100_000):
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._buffers: OrderedDict[str, deque] = OrderedDict()
        self._lock = threading.Lock()

    def add(self, key: str, ts_epoch: float, payload) -> None:
        with self._lock:
            buf = self._buffers.get(key)
            if buf is None:
                buf = deque()
                self._buffers[key] = buf
            buf.append((ts_epoch, payload))
            self._buffers.move_to_end(key)
            self._prune(key, buf)
            while len(self._buffers) > self.max_keys:
                self._buffers.popitem(last=False)

    def prune_key(self, key: str, now: float | None = None) -> deque | None:
        """Return the window contents for key (already pruned)."""
        with self._lock:
            buf = self._buffers.get(key)
            if buf is None:
                return None
            self._prune(key, buf, now)
            return buf

    def drop_key(self, key: str) -> None:
        with self._lock:
            self._buffers.pop(key, None)

    def keys(self) -> list[str]:
        with self._lock:
            return list(self._buffers.keys())

    def _prune(self, key: str, buf: deque, now: float | None = None) -> None:
        cutoff = (now if now is not None else time.time()) - self.window_seconds
        while buf and buf[0][0] < cutoff:
            buf.popleft()
        if not buf:
            self._buffers.pop(key, None)


def jitter(intervals: list[float]) -> float:
    """Coefficient of variation of intervals (stdev/mean); 0.0 if undefined."""
    if len(intervals) < 2:
        return 1.0
    mean = sum(intervals) / len(intervals)
    if mean <= 0:
        return 1.0
    variance = sum((x - mean) ** 2 for x in intervals) / (len(intervals) - 1)
    return (variance ** 0.5) / mean
