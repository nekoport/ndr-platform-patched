"""Validation stage (doc section 7.1 step 5).

Events that fail hard checks go to the quarantine/dead-letter path instead
of being silently dropped (doc section 7.3).
"""

from __future__ import annotations

import ipaddress
from datetime import timedelta

from app.models import CommonEvent, utcnow

HARD_LIMITS = {
    "dns_query": 512,
    "http_url": 2048,
    "http_user_agent": 512,
    "tls_subject": 512,
    "tls_issuer": 512,
}


def validate_event(ev: CommonEvent, max_clock_skew_seconds: int = 300,
                   max_event_age_days: int = 7) -> tuple[bool, str]:
    """Return (ok, reason). ok=False means quarantine."""
    now = utcnow()

    # --- timestamp sanity (doc 7.2) --------------------------------
    if ev.event_time is None:
        return False, "missing event_time"
    if ev.event_time > now + timedelta(seconds=max_clock_skew_seconds):
        return False, f"event_time too far in future (> {max_clock_skew_seconds}s skew)"
    if ev.event_time < now - timedelta(days=max_event_age_days):
        return False, f"event_time older than {max_event_age_days} days"

    # --- ip / port sanity -------------------------------------------
    for ip_field in ("source_ip", "destination_ip"):
        ip = getattr(ev, ip_field)
        if ip in (None, ""):
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return False, f"invalid {ip_field}: {ip!r}"

    for port_field in ("source_port", "destination_port"):
        port = getattr(ev, port_field)
        if port is None:
            continue
        if not isinstance(port, int) or not (0 <= port <= 65535):
            return False, f"invalid {port_field}: {port!r}"

    # --- identifier completeness -------------------------------------
    if not ev.event_id or not ev.source_engine or not ev.event_type:
        return False, "missing required identity fields (event_id/engine/type)"

    # --- field truncation markers ------------------------------------
    ev.parse_status = "ok"
    for field, limit in HARD_LIMITS.items():
        value = getattr(ev, field)
        if value and len(value) >= limit:
            ev.parse_status = "partial"

    return True, "ok"


def quarantine_reason(ev: CommonEvent) -> str:
    ok, reason = validate_event(ev)
    return reason
