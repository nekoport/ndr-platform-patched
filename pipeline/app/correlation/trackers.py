"""Context trackers: DNS answer + SNI/HTTP-host caches (doc 10.3).

These caches give the reconstruction engine its cross-log entity
correlation power:

  * AnswerTracker - domain <-> resolved IP mappings learned from Zeek/
    Suricata DNS events. Lets a beaconing alert on IP X attach the C2
    domain that X resolved minutes earlier.
  * SniTracker    - destination IP -> TLS SNI / HTTP host mappings.
    Lets a connection alert attach the hostname the endpoint really
    talked to.

Memory-bounded LRU caches; thread-safe (processor thread writes,
reconstruction thread reads).
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict

MAX_TTL_SECONDS = 6 * 3600          # answers older than this are stale


class _LruTtl:
    """Generic bounded LRU with per-entry timestamp pruning."""

    def __init__(self, max_entries: int):
        self.max_entries = max_entries
        self._data: OrderedDict[str, tuple[float, object]] = OrderedDict()

    def get(self, key: str):
        item = self._data.get(key)
        if item is None:
            return None
        ts, value = item
        if time.time() - ts > MAX_TTL_SECONDS:
            self._data.pop(key, None)
            return None
        self._data.move_to_end(key)
        return value

    def put(self, key: str, value) -> None:
        self._data[key] = (time.time(), value)
        self._data.move_to_end(key)
        while len(self._data) > self.max_entries:
            self._data.popitem(last=False)

    def __len__(self) -> int:
        return len(self._data)


class _BaseTracker:
    def __init__(self, max_entries: int = 50_000):
        self._lock = threading.Lock()
        self._forward = _LruTtl(max_entries)   # domain -> {ips}
        self._reverse = _LruTtl(max_entries)   # ip -> {domains}

    @staticmethod
    def _add_to_set(existing: set | None, value) -> set:
        s = existing if existing is not None else set()
        s.add(value)
        return s

    def domains_for_ip(self, ip: str) -> set[str]:
        with self._lock:
            return set(self._reverse.get(ip) or ())

    def ips_for_domain(self, domain: str) -> set[str]:
        with self._lock:
            return set(self._forward.get(domain) or ())

    def size(self) -> tuple[int, int]:
        with self._lock:
            return len(self._forward), len(self._reverse)


class AnswerTracker(_BaseTracker):
    """domain <-> resolved-IP knowledge base from DNS events."""

    def record(self, query: str | None, answers: list[dict],
               ts_epoch: float) -> None:
        if not query or not answers:
            return
        with self._lock:
            ips = self._forward.get(query) or set()
            for a in answers:
                data = str(a.get("data") or "").strip()
                if data:
                    ips.add(data)
            if ips:
                self._forward.put(query, ips)
                for ip in ips:
                    domains = self._reverse.get(ip) or set()
                    domains.add(query)
                    self._reverse.put(ip, domains)


class SniTracker(_BaseTracker):
    """destination-IP -> hostname knowledge base from TLS/HTTP events."""

    def record(self, dst_ip: str | None, domain: str,
               ts_epoch: float) -> None:
        if not dst_ip or not domain:
            return
        with self._lock:
            domains = self._reverse.get(dst_ip) or set()
            domains.add(domain)
            self._reverse.put(dst_ip, domains)
            ips = self._forward.get(domain) or set()
            ips.add(dst_ip)
            self._forward.put(domain, ips)
