"""Arkime PCAP telemetry integration (v0.12).

The evidence workflow (doc 15) already resolves sessions from the
normalized event store and exports rolling capture files. This module
completes the loop with ARKIME, the actual packet capture engine:

  * reachability probe of the Arkime viewer (honest status: reachable
    vs unreachable - never fabricated)
  * deterministic deep-link URLs into the Arkime session viewer with
    EXPRESSION injection protection (every value is sanitized; the
    expression language is never built from raw user-controlled data)
  * per-session and per-scope links (alert/incident window + entities)

Design note: Arkime owns packet-level inspection; the platform links
to it instead of duplicating it. Deep links are pure URL builders -
they never touch capture storage themselves.
"""

from __future__ import annotations

import re
import time
from urllib.parse import quote

import httpx

from app.config import config

# values that may legally appear inside an Arkime expression value:
# IPv4, IPv6 (basic), domains, hostnames, ports. Anything else is
# dropped - the expression degrades gracefully instead of breaking.
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")


def _safe(value: str | None) -> str | None:
    v = str(value or "").strip()
    if not v or not _SAFE_VALUE.match(v):
        return None
    return v


def probe(timeout: float = 2.0) -> dict:
    """Probe the Arkime viewer. Never raises; status is honest."""
    base = config.arkime_viewer_url.rstrip("/")
    t0 = time.monotonic()
    try:
        r = httpx.get(base, timeout=timeout, follow_redirects=False)
        latency = int((time.monotonic() - t0) * 1000)
        # Arkime answers 200 (UI) or 302 (auth redirect) when alive
        reachable = r.status_code < 500
        return {"reachable": reachable, "http_status": r.status_code,
                "latency_ms": latency, "error": None if reachable
                else f"viewer answered HTTP {r.status_code}"}
    except Exception as exc:  # noqa: BLE001 - degradation by design
        latency = int((time.monotonic() - t0) * 1000)
        return {"reachable": False, "http_status": None,
                "latency_ms": latency, "error": f"{type(exc).__name__}"}


def build_expression(ips: list[str], domains: list[str],
                     ports: list[str | int] | None = None) -> str:
    """Build an Arkime expression for the given entities.

    Each value is sanitized; unsafe values are silently dropped. The
    result ORs the entity conditions - Arkime applies it to the session
    list. Returns "" when nothing usable remains.

    v0.16.0 (quirk Arkime 5.6.2, fix live §27c-4): nilai IP dan PORT
    TIDAK boleh diberi tanda kutip ('ip == "10.0.0.1"' -> "not a valid
    ip"); field string (host) tetap di-quote.
    """
    conds: list[str] = []
    for ip in ips or []:
        v = _safe(ip)
        if v:
            conds.append(f"ip == {v}")
    for d in domains or []:
        v = _safe(d)
        if v:
            conds.append(f'host == "{v}"')
    for p in ports or []:
        v = _safe(str(p))
        if v and v.isdigit():
            conds.append(f"port == {v}")
    # group into ORs; Arkime accepts parentheses around alternatives
    return " || ".join(conds)


def session_viewer_url(expression: str, t_from_epoch: int,
                       t_to_epoch: int) -> str:
    """Deep link into the Arkime session list for the expression+window.

    v0.16.0: URL mengarah ke PUBLIC BASE (site-relative melalui proxy
    API, mis. /backend/api/arkime/sessions) - fallback internal viewer
    bila ARKIME_PUBLIC_BASE tidak diset.
    """
    base = (config.arkime_public_base
            or config.arkime_viewer_url).rstrip("/")
    return (f"{base}/sessions"
            f"?expression={quote(expression, safe='')}"
            f"&startTime={t_from_epoch}&stopTime={t_to_epoch}")


def viewer_base_url() -> str:
    """Public viewer base (site-relative) untuk deep-link dari browser.
    Fallback: URL internal viewer (perilaku lama) bila public base kosong."""
    return ((config.arkime_public_base
             or config.arkime_viewer_url).rstrip("/"))


def epoch_of(iso_ts: str | None, fallback_epoch: int) -> int:
    """Parse an ISO-Z timestamp into epoch seconds (best effort)."""
    if not iso_ts:
        return fallback_epoch
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(str(iso_ts).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except ValueError:
        return fallback_epoch
