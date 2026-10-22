"""Preset aktivitas Judi Online (v0.16.0 - requirement 18).

Pipeline (GamblingWatchlist) menandai event dengan campaign="judi-online"
(GAMBLING_KEYWORDS / GAMBLING_DOMAINS_FILE) dan detector gambling_access
memancarkan alert berkampanye. API ini adalah LENS A presets-nya:
agregasi + daftar event/alert ber-campaign, siap diekspor.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.audit import audit
from app.config import config
from app.db import get_db
from app.models import User
from app.os_client import DSLValidationError, get_os
from app.security import require_permission

router = APIRouter(prefix="/api/gambling", tags=["gambling"])

_CAMPAIGN_TERM = {"term": {"campaign": "judi-online"}}


@router.get("/summary")
def gambling_summary(request: Request,
                     hours: int = Query(default=24, ge=1, le=720),
                     user: User = Depends(require_permission("search")),
                     db: Session = Depends(get_db)):
    """Ringkasan aktivitas Judi Online: event, klien, domain, timeline."""
    os = get_os()
    aggs = {
        "top_clients": {"terms": {"field": "source.ip", "size": 15}},
        "top_domains": {"terms": {"field": "dns.query", "size": 20}},
        "top_hosts": {"terms": {"field": "http.host", "size": 20}},
        "by_engine": {"terms": {"field": "source_engine", "size": 4}},
        "timeline": {"date_histogram": {"field": "@timestamp",
                                        "calendar_interval": "1h",
                                        "min_doc_count": 0}},
    }
    time_from = (datetime.now(timezone.utc)
                 - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")
    try:
        result = os.guarded_aggregate(
            alias="ndr-events-read", query=_CAMPAIGN_TERM, aggs=aggs,
            time_from=time_from, time_to=None)
    except DSLValidationError as e:
        raise HTTPException(400, f"Query rejected: {e}")
    except Exception as e:  # noqa: BLE001 - degrade
        raise HTTPException(502, f"Search backend unavailable: {e}")

    def buckets(name: str) -> list[dict]:
        return sorted(
            ({"key": b.get("key"), "count": b.get("doc_count", 0)}
             for b in result.get("aggregations", {})
             .get(name, {}).get("buckets", []) if b.get("key") is not None),
            key=lambda x: -x["count"])

    total = result["hits"]["total"]
    audit(db, request, action="gambling.summary", target_type="index",
          target_id="ndr-events-read", actor=user)
    return {
        "hours": hours,
        "campaign": "judi-online",
        "total_events": total.get("value", 0)
        if isinstance(total, dict) else int(total),
        "top_clients": buckets("top_clients"),
        "top_domains": buckets("top_domains"),
        "top_hosts": buckets("top_hosts"),
        "by_engine": buckets("by_engine"),
        "timeline_hourly": [
            {"ts": b.get("key_as_string"), "count": b.get("doc_count", 0)}
            for b in result.get("aggregations", {})
            .get("timeline", {}).get("buckets", [])],
        "keywords": list(config.gambling_keywords),
        "note": "keyword matcher GAMBLING_KEYWORDS + GAMBLING_DOMAINS_FILE "
                "(pipeline); PCAP tiap sesi tersedia via Arkime SSO",
    }


@router.get("/events")
def gambling_events(request: Request,
                    size: int = Query(default=100, ge=1, le=500),
                    hours: int = Query(default=24, ge=1, le=720),
                    user: User = Depends(require_permission("search")),
                    db: Session = Depends(get_db)):
    """Event terbaru ber-tag campaign judi-online (raw records untuk tabel)."""
    os = get_os()
    time_from = (datetime.now(timezone.utc)
                 - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")
    try:
        result = os.client.search(
            index=os.validate_alias("ndr-events-read"), body={
                "size": min(size, config.search_max_size),
                "track_total_hits": True,
                "query": {"bool": {"filter": [
                    {"range": {"@timestamp": {"gte": time_from}}},
                    _CAMPAIGN_TERM]}},
                "sort": [{"@timestamp": {"order": "desc"}}],
                "_source": {"excludes": ["raw_line"]},
            }, request_timeout=config.search_timeout_seconds)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"Search backend unavailable: {e}")
    audit(db, request, action="gambling.events", target_type="index",
          target_id="ndr-events-read", actor=user)
    hits = []
    for h in result["hits"]["hits"]:
        src = h.get("_source") or {}
        dns = src.get("dns") or {}
        hits.append({
            "id": h.get("_id"),
            "@timestamp": src.get("@timestamp"),
            "event_type": src.get("event_type"),
            "client": (src.get("source") or {}).get("ip"),
            "destination": (src.get("destination") or {}).get("ip"),
            "domain": dns.get("query") or (src.get("http") or {}).get("host")
            or (src.get("tls") or {}).get("sni"),
            "rcode": dns.get("rcode"),
            "resolved": dns.get("rcode") == "NOERROR",
            "bytes": ((src.get("network") or {}).get("bytes")),
        })
    total = result["hits"]["total"]
    return {"total": total.get("value", 0)
            if isinstance(total, dict) else int(total), "hits": hits}
