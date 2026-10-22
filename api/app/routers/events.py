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
        # v0.16.1 (P0-5): mode simple dibangun SERVER dari query_text
        # (dulu client mengirim term teks ke field ip -> parsing gagal,
        # hasil selalu 0). query DSL mentah tetap hanya utk mode advanced.
        query = body.query
        if body.query_text:
            built = get_os().build_free_text_query(body.query_text)
            if built:
                query = built
        result = get_os().guarded_search(
            alias=body.index, query=query, size=body.size,
            from_=body.from_, sort=body.sort,
            time_from=body.time_from, time_to=body.time_to,
            exact_total=body.exact_total)
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

    v0.16.2 (BUG-0161-01): sub-agregasi `engines` kini benar-benar
    DI-NEST di dalam `by_ts` (dulu sejajar dengan by_ts di level atas,
    sehingga pembacaan `b.get("engines")` per bucket selalu kosong ->
    KPI "Events (24h)" Dashboard dan "Events processed" Reports = 0
    meski data 10 juta+ event ada).

    v0.16.2 (BUG-0161-05): `engines` tidak lagi diagregasi langsung pada
    alias campuran. Index lama (mis. 2026.10.14) memetakan source_engine
    sebagai `text` tanpa fielddata -> shard gagal -> hasil parsial bisu.
    Kini:
      1. by_ts utama tetap dijalankan pada ALIAS (tanpa agg berisiko)
         sehingga `count` per interval selalu EKSAK;
      2. split engine dihitung per kelompok index dengan varian field
         yang siap-agregasi (keyword langsung, atau sub-field .keyword
         pada index dinamis lama) lalu digabung per bucket;
      3. index yang sama sekali tidak bisa diagregasi dilaporkan
         transparan di `warnings` (tidak pernah silent partial).
    """
    now = datetime.now(timezone.utc)
    frm = (now - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")
    interval = "1h" if hours <= 48 else "1d"
    query = {"bool": {"filter": [{"range": {"@timestamp": {"gte": frm}}}]}}
    by_ts_agg = {"date_histogram": {
        "field": "@timestamp", "fixed_interval": interval,
        "min_doc_count": 0, "format": "strict_date_optional_time"}}
    warnings: list[str] = []
    try:
        # 1) jumlah per interval - EKSAK, di seluruh alias (strict)
        result = get_os().guarded_aggregate(
            alias="ndr-events-read", query=query,
            aggs={"by_ts": by_ts_agg},
            time_from=frm, time_to=None)
    except DSLValidationError as e:
        raise HTTPException(400, f"Query rejected: {e}")
    except Exception as e:  # noqa: BLE001 - honest 502 like /search
        raise HTTPException(502, f"Search backend unavailable: {e}")

    points: dict[str, dict] = {}
    order: list[str] = []
    for b in (result.get("aggregations", {}).get("by_ts", {})
              .get("buckets", [])):
        # kunci gabung: epoch millis (key) dengan fallback key_as_string -
        # keduanya selalu ada di date_histogram OpenSearch
        key = str(b.get("key") or b.get("key_as_string") or "")
        if key not in points:
            order.append(key)
        points[key] = {"ts": b.get("key_as_string") or b.get("key"),
                       "count": b.get("doc_count", 0), "engines": {}}

    # 2) split engine per kelompok mapping (keyword / .keyword legacy)
    try:
        groups, excluded = get_os().keyword_aggregation_groups(
            "ndr-events-read", "source_engine")
        if excluded:
            warnings.append(
                f"{len(excluded)} index lama tidak ikut split engine "
                f"(mapping text tanpa sub-field keyword): "
                f"{', '.join(excluded)}")
        for agg_field, indices in groups:
            aggs_e = {"by_ts": dict(by_ts_agg, aggs={
                "engines": {"terms": {"field": agg_field, "size": 8}}})}
            try:
                res_e = get_os().guarded_aggregate(
                    alias="ndr-events-read", query=query, aggs=aggs_e,
                    time_from=frm, time_to=None,
                    concrete=indices or None)
            except DSLValidationError as e:
                warnings.append(f"split engine dilewati: {e}")
                continue
            for b in (res_e.get("aggregations", {}).get("by_ts", {})
                      .get("buckets", [])):
                key = str(b.get("key") or b.get("key_as_string") or "")
                if key not in points:
                    continue
                for e in b.get("engines", {}).get("buckets", []):
                    k = e.get("key")
                    points[key]["engines"][k] = (
                        points[key]["engines"].get(k, 0)
                        + e.get("doc_count", 0))
    except Exception as e:  # noqa: BLE001 - split engine boleh gagal mulus
        warnings.append(f"split engine tidak tersedia: {e}")

    audit(db, request=None, action="events.timeline",
          target_type="index", target_id="ndr-events-read", actor=user)

    out_points = [points[k] for k in order]
    resp = {"hours": hours, "interval": interval,
            "total": sum(p["count"] for p in out_points),
            "points": out_points}
    if warnings:
        resp["warnings"] = warnings
    return resp
