"""Events router - guarded DSL search proxy (doc section 4.5)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.audit import audit
from app.config import config
from app.db import get_db
from app.models import User
from app.os_client import DSLValidationError, get_os
from app.rate_limit import SlidingWindowLimiter
from app.schemas import SearchRequest
from app.security import require_permission

router = APIRouter(prefix="/api/events", tags=["events"])
search_limiter = SlidingWindowLimiter(max_events=config.search_rate_limit_per_min)


@router.post("/search")
def search_events(body: SearchRequest, request: Request,
                  user: User = Depends(require_permission("search")),
                  db: Session = Depends(get_db)):
    search_limiter.check(user.username)
    try:
        result = get_os().guarded_search(
            alias=body.index, query=body.query, size=body.size,
            from_=body.from_, sort=body.sort,
            time_from=body.time_from, time_to=body.time_to)
    except DSLValidationError as e:
        audit(db, request, action="events.search", result="failure",
              target_type="index", target_id=body.index,
              detail={"error": str(e)}, actor=user)
        raise HTTPException(400, f"Query rejected: {e}")
    except Exception as e:
        raise HTTPException(502, f"Search backend unavailable: {e}")

    audit(db, request, action="events.search", target_type="index",
          target_id=body.index,
          detail={"size": body.size, "hits": result["hits"]["total"]},
          actor=user)
    hits = [{"id": h["_id"], "index": h["_index"],
             "score": h.get("_score"), "source": h["_source"]}
            for h in result["hits"]["hits"]]
    total = result["hits"]["total"]
    return {"total": total.get("value", 0),
            "relation": total.get("relation", "eq"),
            "hits": hits}


@router.get("/{index}/{doc_id}")
def get_event(index: str, doc_id: str,
              user: User = Depends(require_permission("search"))):
    doc = get_os().get_by_id(index, doc_id)
    if doc is None:
        raise HTTPException(404, "Event not found or index not allowed")
    return {"id": doc["_id"], "index": doc["_index"],
            "source": doc["_source"]}


@router.get("/timeline")
def events_timeline(hours: int = Query(default=24, ge=1, le=336),
                    user: User = Depends(require_permission("search")),
                    db: Session = Depends(get_db)):
    """REAL per-interval event histogram (v0.13.0, anti-fabrication).

    The dashboard timeline used to be FABRICATED from a constant EPS -
    numbers that looked plausible but described nothing. This endpoint
    aggregates ndr-events-read server-side (guarded, size 0, docs never
    returned) so the chart reflects actually indexed events.
    """
    now = datetime.now(timezone.utc)
    frm = (now - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")
    interval = "1h" if hours <= 48 else "1d"
    query = {"bool": {"filter": [{"range": {"@timestamp": {"gte": frm}}}]}}
    aggs = {
        "by_ts": {"date_histogram": {
            "field": "@timestamp", "fixed_interval": interval,
            "min_doc_count": 0, "format": "strict_date_optional_time"}},
        "engines": {"terms": {"field": "source_engine", "size": 8}},
    }
    try:
        result = get_os().guarded_aggregate(
            alias="ndr-events-read", query=query, aggs=aggs,
            time_from=frm, time_to=None)
    except DSLValidationError as e:
        raise HTTPException(400, f"Query rejected: {e}")
    except Exception as e:  # noqa: BLE001 - honest 502 like /search
        raise HTTPException(502, f"Search backend unavailable: {e}")

    audit(db, request=None, action="events.timeline",
          target_type="index", target_id="ndr-events-read", actor=user)

    points = []
    for b in (result.get("aggregations", {}).get("by_ts", {})
              .get("buckets", [])):
        engines = {e.get("key"): e.get("doc_count", 0)
                   for e in b.get("engines", {}).get("buckets", [])}
        points.append({"ts": b.get("key_as_string") or b.get("key"),
                       "count": b.get("doc_count", 0), "engines": engines})
    return {"hours": hours, "interval": interval,
            "total": sum(p["count"] for p in points), "points": points}
