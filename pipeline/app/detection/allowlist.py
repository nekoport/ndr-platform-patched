"""v0.14.0 Alert whitelist (allowlist) provider for the detection engine.

Loads ACTIVE entries from the Postgres ``alert_allowlist`` table (owned by
the API), matches emitted alert docs against them and reports hits back.

Two enforcement layers (per entry, decided by the API):
  * ``L0`` - the alert is NEVER indexed into ``ndr-alerts-*``; the doc is
    still fanned out to the reconstruction hook so the attack story stays
    intact (governance decision: a whitelist silences ALERTS, it never
    cuts correlation), and only the hit counter increments.
  * ``L1`` - the alert IS indexed but tagged ``suppressed=True`` +
    ``suppressed_by=<entry id>`` so the UI can keep it out of the default
    triage queue while preserving the full record.

Failure policy: detection must NEVER die because of the whitelist. Any
DB error keeps the last known snapshot and logs once per reload cycle.
"""

from __future__ import annotations

import ipaddress
import sys
import threading
import time
from datetime import datetime, timezone

from sqlalchemy import create_engine, text

from app.models import PARSER_VERSION  # noqa: F401 - keeps import parity

RELOAD_SECONDS = 30.0
FLUSH_SECONDS = 30.0


class _Entry:
    __slots__ = ("id", "alert_type", "signature", "entity_field",
                 "entity_value", "layer", "net")

    def __init__(self, row):
        self.id = int(row["id"])
        self.alert_type = row["alert_type"]
        self.signature = row["signature"] or None
        self.entity_field = row["entity_field"]
        self.entity_value = row["entity_value"]
        if self.entity_field == "dst_domain":
            # API canonicalizes to a lowercase dotted suffix; be defensive
            # anyway (hand-edited rows must not silently break matching)
            self.entity_value = self.entity_value.lower()
            if not self.entity_value.startswith("."):
                self.entity_value = f".{self.entity_value}"
        self.layer = row["layer"] if row["layer"] in ("L0", "L1") else "L1"
        self.net: ipaddress._BaseNetwork | None = None
        if self.entity_field in ("src_ip", "dst_ip"):
            try:
                self.net = ipaddress.ip_network(self.entity_value,
                                                strict=False)
            except ValueError:
                self.net = None


class AlertAllowlistProvider:
    """DB-backed snapshot + matcher. Owned by the DetectionEngine thread."""

    def __init__(self, db_url: str, reload_seconds: float = RELOAD_SECONDS,
                 flush_seconds: float = FLUSH_SECONDS):
        self._db_url = db_url
        self._reload_seconds = reload_seconds
        self._flush_seconds = flush_seconds
        self._engine = create_engine(db_url, pool_pre_ping=True, future=True)
        self._lock = threading.Lock()
        self._entries: list[_Entry] = []
        self._hits: dict[int, int] = {}
        self._last_reload = 0.0
        self._last_flush = time.time()
        self._db_ok = True
        self._warned_at = 0.0
        self.load(force=True)

    # ------------------------------------------------------------ load
    def load(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._last_reload < self._reload_seconds:
            return
        self._last_reload = now
        try:
            with self._engine.connect() as conn:
                # status filter in SQL (portable); expiry filter in Python
                # (SQLite has no now() and stored timestamps are ISO text
                # in both dialects)
                rows = conn.execute(text(
                    "SELECT id, alert_type, signature, entity_field, "
                    "entity_value, layer, expires_at FROM alert_allowlist "
                    "WHERE status = 'active'")).mappings()
                entries = [_Entry(r) for r in rows
                           if _not_expired(r["expires_at"])]
            with self._lock:
                self._entries = entries
            if not self._db_ok:
                print("[detection] allowlist DB recovered", file=sys.stderr)
            self._db_ok = True
        except Exception as e:  # noqa: BLE001 - keep the last snapshot
            self._db_ok = False
            if now - self._warned_at > 300.0:
                self._warned_at = now
                print(f"[detection] allowlist reload failed "
                      f"(keeping {len(self._entries)} cached entries): {e}",
                      file=sys.stderr)

    # ------------------------------------------------------------ match
    def check(self, doc: dict) -> tuple[str, int] | None:
        """Return ('L0'|'L1', entry_id) for the first matching entry.

        Preference: an L0 match wins over L1 (strictest outcome); within a
        layer the most specific entry (signature-pinned) wins.
        """
        entries = self._entries
        if not entries:
            return None
        alert_type = doc.get("alert_type")
        if not alert_type:
            return None
        sig = None
        top_rules = doc.get("top_rules") or []
        if top_rules:
            sig = (top_rules[0] or {}).get("signature")
        src = (doc.get("source") or {}).get("ip")
        dst = (doc.get("destination") or {}).get("ip")
        domains = list(doc.get("dns_domains") or [])
        for mi in doc.get("matched_iocs") or []:
            if isinstance(mi, dict) and mi.get("ioc_type") == "domain":
                v = mi.get("ioc_value")
                if v and v not in domains:
                    domains.append(str(v).lower())

        best: tuple[str, int] | None = None
        best_sig_match = False
        for entry in entries:
            if entry.alert_type != alert_type:
                continue
            if entry.signature is not None and entry.signature != sig:
                continue
            if not self._entity_matches(entry, src, dst, domains):
                continue
            sig_specific = entry.signature is not None
            if best is None or (entry.layer == "L0" and best[0] == "L1") \
                    or (sig_specific and not best_sig_match
                        and entry.layer == best[0]):
                best = (entry.layer, entry.id)
                best_sig_match = sig_specific
        return best

    @staticmethod
    def _entity_matches(entry: _Entry, src: str | None, dst: str | None,
                        domains: list[str]) -> bool:
        if entry.entity_field == "src_ip":
            if not src or entry.net is None:
                return False
            try:
                return ipaddress.ip_address(src) in entry.net
            except ValueError:
                return False
        if entry.entity_field == "dst_ip":
            if not dst or entry.net is None:
                return False
            try:
                return ipaddress.ip_address(dst) in entry.net
            except ValueError:
                return False
        # dst_domain: suffix match (entry value starts with a dot),
        # case-insensitive (lesson from the v0.13.0 suppress FP fix)
        suffix = entry.entity_value
        return any(str(d).lower() == suffix or str(d).lower().endswith(suffix)
                   for d in domains)

    # ------------------------------------------------------------ hits
    def bump(self, entry_id: int) -> None:
        with self._lock:
            self._hits[entry_id] = self._hits.get(entry_id, 0) + 1

    def maybe_flush(self, now: float | None = None) -> None:
        now = now or time.time()
        if now - self._last_flush < self._flush_seconds:
            return
        self._last_flush = now
        self.flush()

    def flush(self) -> None:
        with self._lock:
            pending = dict(self._hits)
            self._hits.clear()
        if not pending:
            return
        now_iso = datetime_utc_iso()
        try:
            with self._engine.begin() as conn:
                conn.execute(text(
                    "UPDATE alert_allowlist SET "
                    "hit_count = hit_count + :n, last_hit_at = :ts "
                    "WHERE id = :id"),
                    [{"id": eid, "n": n, "ts": now_iso}
                     for eid, n in pending.items()])
        except Exception:  # noqa: BLE001 - re-queue, never lose counts
            with self._lock:
                for eid, n in pending.items():
                    self._hits[eid] = self._hits.get(eid, 0) + n

    def close(self) -> None:
        self.flush()
        try:
            self._engine.dispose()
        except Exception:  # noqa: BLE001
            pass


def _not_expired(expires_raw) -> bool:
    """True when the entry has no TTL or its expiry is still in the future.
    Tolerates 'Z', '+00:00' and naive ISO strings (SQLite stores text)."""
    if expires_raw is None:
        return True
    raw = str(expires_raw).strip()
    if not raw:
        return True
    try:
        exp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return True  # unparsable TTL: fail OPEN (keep the entry live)
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return exp > datetime.now(timezone.utc)


def datetime_utc_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
