"""Live metrics stream (v0.16.0 - requirement 19).

SSE (Server-Sent Events) 2 detik per tick - sengaja SSE, bukan WebSocket:
lebih tahan proxy/reverse-proxy dan tanpa dep baru. Data per tick:
  * eps + eps_by_engine + queue_depth + backlog_seconds dari dokumen
    health terakhir pipeline (jalur ndr-health yang sudah terbukti);
  * tiap 5 tick (10 dtk): alert_count_5m + events_5m (count query ringan).

Koneksi di-cap (default 20) supaya stream tidak menghabiskan worker.
Client menutup koneksi -> generator StopIteration -> bersih.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.audit import audit
from app.config import config
from app.db import get_db
from app.models import User
from app.os_client import get_os
from app.security import require_permission

router = APIRouter(prefix="/api/metrics", tags=["metrics"])

_active_connections = 0
MAX_CONNECTIONS = 20
TICK_SECONDS = 2


def _latest_health() -> dict:
    os = get_os()
    try:
        res = os.client.search(
            index=os.validate_alias("ndr-health-read"), body={
                "size": 1,
                "query": {"bool": {"filter": [{"match_all": {}}]}},
                "sort": [{"@timestamp": {"order": "desc"}}],
            }, request_timeout=config.search_timeout_seconds)
        hits = (res.get("hits") or {}).get("hits") or []
        return (hits[0].get("_source") or {}) if hits else {}
    except Exception:  # noqa: BLE001 - stream harus tetap hidup
        return {}


def _count_5m(alias: str) -> int | None:
    os = get_os()
    try:
        since = (datetime.now(timezone.utc)
                 - timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        res = os.client.search(
            index=os.validate_alias(alias), body={
                "size": 0,
                "track_total_hits": True,
                "query": {"bool": {"filter": [
                    {"range": {"@timestamp": {"gte": since}}}],
                    "must_not": [{"exists": {"field": "suppressed"}}]}},
            }, request_timeout=config.search_timeout_seconds)
        total = (res.get("hits") or {}).get("total") or {}
        return int(total.get("value", 0)) if isinstance(total, dict) else int(total)
    except Exception:  # noqa: BLE001
        return None


def _event_stream(username: str, max_ticks: int | None = None):
    """max_ticks: hook testability (None = produksi, stream terus)."""
    global _active_connections
    tick = 0
    try:
        while _active_connections <= MAX_CONNECTIONS \
                and (max_ticks is None or tick < max_ticks):
            health = _latest_health()
            point: dict = {
                "ts": datetime.now(timezone.utc)
                .isoformat().replace("+00:00", "Z"),
                "eps": health.get("eps"),
                "eps_by_engine": health.get("eps_by_engine") or {},
                "queue_depth": health.get("queue_depth"),
                "queue_capacity": health.get("queue_capacity"),
                "backlog_seconds": health.get("backlog_seconds"),
            }
            if tick % 5 == 0:
                point["alerts_5m"] = _count_5m("ndr-alerts-read")
                point["events_5m"] = _count_5m("ndr-events-read")
            yield f"data: {json.dumps(point)}\n\n"
            tick += 1
            time.sleep(TICK_SECONDS)
    finally:
        _active_connections = max(0, _active_connections - 1)


@router.get("/live")
def metrics_live(request: Request,
                 user: User = Depends(require_permission("search")),
                 db: Session = Depends(get_db)):
    """Stream realtime trafik (req 19): pps-like EPS per engine + antrean."""
    global _active_connections
    if _active_connections >= MAX_CONNECTIONS:
        raise HTTPException(429, "too many live metric streams")
    _active_connections += 1
    audit(db, request, action="metrics.live", target_type="stream",
          target_id="ndr-health-read", actor=user)
    return StreamingResponse(
        _event_stream(user.username),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                 "Connection": "keep-alive"})
