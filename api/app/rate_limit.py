"""Rate limiting (in-memory sliding window) for expensive endpoints."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException


class SlidingWindowLimiter:
    def __init__(self, max_events: int, window_seconds: float = 60.0):
        self.max_events = max_events
        self.window = window_seconds
        self._events: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            q = self._events[key]
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= self.max_events:
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded ({self.max_events}/min). "
                           f"Slow down and refine your query.")
            q.append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)
