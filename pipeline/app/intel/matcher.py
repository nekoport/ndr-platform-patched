"""In-memory IOC matcher with atomic snapshot reload (doc 9.2 step 6-7).

Design:
  * an immutable `_Snapshot` is built from the store, then swapped in
    atomically - matching never blocks on reloads and never sees a
    half-built index
  * ip: exact set; domain: exact + parent-suffix walk; url: exact;
    hash: per-algorithm sets; allowlist: suppressed before reporting
  * match(ev) inspects source/destination IP, dns.query, tls.sni,
    http.host, http.url and file hashes; max 3 enrichments per event
    to bound document growth
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

MATCH_FIELDS_IP = (("source_ip", "source"), ("destination_ip", "destination"))
MATCH_FIELDS_DOMAIN = (("dns_query", "dns.query"), ("tls_sni", "tls.sni"),
                       ("http_host", "http.host"))
MATCH_FIELDS_HASH = (("file_md5", "file.hash.md5"),
                     ("file_sha1", "file.hash.sha1"),
                     ("file_sha256", "file.hash.sha256"))


def domain_parents(name: str) -> list[str]:
    """qname plus all its parents: a.b.evil.com -> [a.b.evil.com,
    b.evil.com, evil.com]."""
    parts = name.lower().rstrip(".").split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


@dataclass(frozen=True)
class IocEntry:
    ioc_type: str
    value: str
    confidence: str
    malware: str | None
    first_seen: str | None
    last_seen: str | None
    expires_at: str | None


@dataclass(frozen=True)
class _Snapshot:
    ips: dict[str, IocEntry] = field(default_factory=dict)
    domains: dict[str, IocEntry] = field(default_factory=dict)
    urls: dict[str, IocEntry] = field(default_factory=dict)
    hashes: dict[str, dict[str, IocEntry]] = field(default_factory=dict)
    allowlist: set[tuple[str, str]] = field(default_factory=set)

    def size(self) -> int:
        return (len(self.ips) + len(self.domains) + len(self.urls)
                + sum(len(v) for v in self.hashes.values()))


class IntelMatcher:
    def __init__(self, store, reload_seconds: int = 60):
        self._store = store
        self._reload_seconds = max(10, reload_seconds)
        self._lock = threading.Lock()
        self._snapshot = _Snapshot()
        self._wake = threading.Event()

    # ------------------------------------------------------------- build
    def reload(self) -> int:
        """Rebuild snapshot from store + allowlist. Returns snapshot size."""
        entries: dict[tuple[str, str], IocEntry] = {}
        for row in self._store.active_iocs():
            key = (row["ioc_type"], row["ioc_value"])
            entries[key] = IocEntry(
                ioc_type=row["ioc_type"], value=row["ioc_value"],
                confidence=row.get("confidence") or "medium",
                malware=row.get("malware"),
                first_seen=row.get("first_seen"),
                last_seen=row.get("last_seen"),
                expires_at=row.get("expires_at"))
        allowed = self._store.allowlisted_keys()
        # v0.13.0: allowlist suppression is CASE-INSENSITIVE for
        # url/hash/domain values (feeds mix case; an allowlisted
        # "Malware.EXAMPLE.com/url" must still suppress the lowercase hit)
        def _norm(ioc_type, value):
            if ioc_type in ("domain", "url", "md5", "sha1", "sha256"):
                return str(value).lower()
            return value
        allowed_norm = {_norm(ti, vi) for ti, vi in allowed}
        snap = _Snapshot(allowlist=allowed)
        for (ioc_type, value), entry in entries.items():
            if _norm(ioc_type, value) in allowed_norm:
                continue
            if ioc_type == "ip":
                snap.ips[value] = entry
            elif ioc_type == "domain":
                snap.domains[value] = entry
            elif ioc_type == "url":
                snap.urls[value] = entry
            elif ioc_type in ("md5", "sha1", "sha256"):
                snap.hashes.setdefault(ioc_type, {})[value] = entry
        with self._lock:
            self._snapshot = snap
        return snap.size()

    def request_reload(self) -> None:
        self._wake.set()

    def reload_if_requested(self) -> bool:
        """Consume the wake event and rebuild when set."""
        if self._wake.is_set():
            self._wake.clear()
            self.reload()
            return True
        return False

    # ------------------------------------------------------------- match
    def _domain_lookup(self, snap: _Snapshot, qname: str | None) -> IocEntry | None:
        if not qname:
            return None
        for candidate in domain_parents(qname)[:4]:
            entry = snap.domains.get(candidate)
            if entry is not None:
                return entry
        return None

    def match(self, ev) -> list[dict]:
        """Return up to 3 IOC enrichments for a CommonEvent."""
        snap = self._snapshot
        if snap.size() == 0:
            return []
        found: list[tuple[str, IocEntry]] = []

        def _add(field_name: str, entry: IocEntry | None) -> None:
            if entry is not None and (field_name, entry) not in found:
                found.append((field_name, entry))

        for attr, field_name in MATCH_FIELDS_IP:
            ip = getattr(ev, attr, None)
            if ip and ip in snap.ips:
                _add(field_name, snap.ips[ip])
        for attr, field_name in MATCH_FIELDS_DOMAIN:
            entry = self._domain_lookup(snap, getattr(ev, attr, None))
            if entry is not None:
                _add(field_name, entry)
        url = getattr(ev, "http_url", None)
        if url and url in snap.urls:
            _add("http.url", snap.urls[url])
        for attr, field_name in MATCH_FIELDS_HASH:
            h = getattr(ev, attr, None)
            if h and h.lower() in snap.hashes.get(
                    {"file_md5": "md5", "file_sha1": "sha1",
                     "file_sha256": "sha256"}[attr], {}):
                _add(field_name, snap.hashes[
                    {"file_md5": "md5", "file_sha1": "sha1",
                     "file_sha256": "sha256"}[attr]][h.lower()])
        out = []
        for field_name, entry in found[:3]:
            out.append({
                "ioc_type": entry.ioc_type,
                "ioc_value": entry.value,
                "ioc_source": entry.malware or "threat-intel",
                "confidence": entry.confidence,
                "match_field": field_name,
                "first_seen": entry.first_seen,
                "last_seen": entry.last_seen,
                "expires_at": entry.expires_at,
            })
        return out

    def snapshot_size(self) -> int:
        return self._snapshot.size()


class MatcherRefresher(threading.Thread):
    """Periodically rebuilds the matcher snapshot from the store."""

    def __init__(self, matcher: IntelMatcher, reload_seconds: int = 60):
        super().__init__(daemon=True, name="intel-refresher")
        self.matcher = matcher
        self.reload_seconds = max(10, reload_seconds)
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self.matcher.reload()
            except Exception:  # noqa: BLE001 - refresher must not die
                pass
            self._stop.wait(self.reload_seconds)


def now_monotonic() -> float:
    return time.monotonic()
