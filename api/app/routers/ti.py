"""Threat Intelligence router (doc section 9 - Phase 3).

Endpoints:
  GET    /api/ti/overview                 counts + 24h match stats (view)
  GET    /api/ti/feeds                    feed list (view)
  POST   /api/ti/feeds                    create feed (ti_admin)
  PATCH  /api/ti/feeds/{id}               update feed (ti_admin)
  POST   /api/ti/feeds/{id}/update        enqueue manual job (ti_admin)
  GET    /api/ti/jobs                     job history (view)
  GET    /api/ti/iocs                     IOC store search (view)
  GET    /api/ti/matches                  guarded search over matches (search)
  GET    /api/ti/allowlist                allowlist (view)
  POST   /api/ti/allowlist                add allowlist entry (ti_admin)
  DELETE /api/ti/allowlist/{id}           remove entry (ti_admin)

Feed credentials in `config` are masked on every read path and never
logged (doc 9.3). All mutations are audited.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func
from sqlalchemy import text as _text
from sqlalchemy.orm import Session

from app.audit import audit
from app.config import config
from app.db import get_db
from app.models import IocAllowlist, IocRecord, TIFeed, TIUpdateJob, User
from app.os_client import DSLValidationError, get_os
from app.schemas import (AllowlistCreate, MASK, TIFeedCreate, TIFeedOut,
                         TIFeedUpdate, TIJobOut)
from app.security import require_permission

router = APIRouter(prefix="/api/ti", tags=["threat-intelligence"])

SENSITIVE_CONFIG_KEYS = {"api_key", "apikey", "token", "password", "secret",
                         "credential", "auth"}


def _mask_config(cfg: dict) -> dict:
    out = copy.deepcopy(cfg or {})
    for key in list(out):
        if key.lower() in SENSITIVE_CONFIG_KEYS:
            out[key] = MASK
    return out


def _feed_out(feed: TIFeed) -> dict:
    data = TIFeedOut.model_validate(feed).model_dump(mode="json")
    data["config"] = _mask_config(feed.config or {})
    return data


def _job_out(job: TIUpdateJob) -> dict:
    return TIJobOut.model_validate(job).model_dump(mode="json")


# ------------------------------------------------------------- overview
@router.get("/overview")
def ti_overview(user: User = Depends(require_permission("view")),
                db: Session = Depends(get_db)):
    by_status = dict(db.query(IocRecord.status, func.count())
                     .group_by(IocRecord.status).all())
    by_type = dict(db.query(IocRecord.ioc_type, func.count())
                   .filter(IocRecord.status == "active")
                   .group_by(IocRecord.ioc_type).all())
    feeds = db.query(TIFeed).all()
    enabled = sum(1 for f in feeds if f.enabled)
    degraded = sum(1 for f in feeds
                   if f.enabled and f.last_status in ("failed", None))
    matches_24h = 0
    by_match_type: dict = {}
    by_source: dict = {}
    try:
        os = get_os()
        now = datetime.now(timezone.utc)
        frm = (now - timedelta(hours=24)).isoformat().replace("+00:00", "Z")
        time_q = {"range": {"@timestamp": {"gte": frm}}}
        matches_24h = os.count("ndr-ioc-matches-read", {"bool": {
            "filter": [time_q]}})
        res = os.aggregate("ndr-ioc-matches-read", {
            "size": 0, "query": {"bool": {"filter": [time_q]}},
            "aggs": {
                "by_type": {"terms": {"field": "ioc_type", "size": 10}},
                "by_source": {"terms": {"field": "ioc_source", "size": 10}},
            }})
        aggs = res.get("aggregations", {})
        by_match_type = {b["key"]: b["doc_count"]
                         for b in aggs.get("by_type", {}).get("buckets", [])}
        by_source = {b["key"]: b["doc_count"]
                     for b in aggs.get("by_source", {}).get("buckets", [])}
    except Exception:
        pass  # search backend down: overview degrades gracefully
    expiring = db.query(IocRecord).filter(
        IocRecord.status == "active",
        IocRecord.expires_at.isnot(None),
        IocRecord.expires_at < datetime.now(timezone.utc)
        + timedelta(days=3)).count()
    return {
        "iocs_total": sum(by_status.values()),
        "iocs_active": by_status.get("active", 0),
        "iocs_expired": by_status.get("expired", 0),
        "by_type_active": by_type,
        "feeds_total": len(feeds),
        "feeds_enabled": enabled,
        "feeds_degraded": degraded,
        "iocs_expiring_3d": expiring,
        "matches_24h": matches_24h,
        "matches_by_type": by_match_type,
        "matches_by_source": by_source,
    }


# ---------------------------------------------------------------- feeds
@router.get("/feeds")
def list_feeds(user: User = Depends(require_permission("view")),
               db: Session = Depends(get_db)):
    feeds = db.query(TIFeed).order_by(TIFeed.name).all()
    return [_feed_out(f) for f in feeds]


@router.post("/feeds", status_code=201)
def create_feed(body: TIFeedCreate, request: Request,
                user: User = Depends(require_permission("ti_admin")),
                db: Session = Depends(get_db)):
    if db.query(TIFeed).filter(TIFeed.name == body.name).first():
        raise HTTPException(409, f"feed '{body.name}' already exists")
    if body.adapter != "file" and not body.url:
        raise HTTPException(400, f"adapter '{body.adapter}' requires a url")
    feed = TIFeed(name=body.name, adapter=body.adapter, url=body.url,
                  config=body.config, enabled=body.enabled,
                  schedule_min=body.schedule_min, ttl_days=body.ttl_days)
    db.add(feed)
    db.commit()
    db.refresh(feed)
    audit(db, request, action="ti.feed.create", target_type="ti_feed",
          target_id=feed.id, detail={"name": feed.name,
                                     "adapter": feed.adapter}, actor=user)
    return _feed_out(feed)


@router.patch("/feeds/{feed_id}")
def update_feed(feed_id: str, body: TIFeedUpdate, request: Request,
                user: User = Depends(require_permission("ti_admin")),
                db: Session = Depends(get_db)):
    feed = db.query(TIFeed).filter(TIFeed.id == feed_id).first()
    if feed is None:
        raise HTTPException(404, "feed not found")
    changed = {}
    if body.enabled is not None:
        feed.enabled = body.enabled
        changed["enabled"] = body.enabled
    if body.schedule_min is not None:
        feed.schedule_min = body.schedule_min
        changed["schedule_min"] = body.schedule_min
    if body.ttl_days is not None:
        feed.ttl_days = body.ttl_days
        changed["ttl_days"] = body.ttl_days
    if body.url is not None:
        feed.url = body.url
        changed["url"] = body.url
    if body.config is not None:
        # merge; masked values coming back from the UI never overwrite
        # stored credentials (doc 9.3)
        merged = dict(feed.config or {})
        for k, v in body.config.items():
            if v == MASK:
                continue
            merged[k] = v
        feed.config = merged
        changed["config_keys"] = sorted(merged)
    db.commit()
    audit(db, request, action="ti.feed.update", target_type="ti_feed",
          target_id=feed.id, detail=changed, actor=user)
    return _feed_out(feed)


@router.delete("/feeds/{feed_id}", status_code=204)
def delete_feed(feed_id: str, request: Request,
                user: User = Depends(require_permission("ti_admin")),
                db: Session = Depends(get_db)):
    """v0.13.0 (audit B4): DELETE a feed - previously 405, leaving dead
    feeds stuck in the table forever."""
    feed = db.query(TIFeed).filter(TIFeed.id == feed_id).first()
    if feed is None:
        raise HTTPException(404, "feed not found")
    detail = {"name": feed.name, "url": feed.url}
    db.delete(feed)
    db.commit()
    audit(db, request, action="ti.feed.delete", target_type="ti_feed",
          target_id=feed_id, detail=detail, actor=user)
    return None


@router.post("/feeds/{feed_id}/update", status_code=202)
def update_now(feed_id: str, request: Request,
               user: User = Depends(require_permission("ti_admin")),
               db: Session = Depends(get_db)):
    """Manual 'Update Now' - queues a job the pipeline collector runs."""
    feed = db.query(TIFeed).filter(TIFeed.id == feed_id).first()
    if feed is None:
        raise HTTPException(404, "feed not found")
    running = db.query(TIUpdateJob).filter(
        TIUpdateJob.feed_id == feed_id,
        TIUpdateJob.status.in_(("queued", "running"))).first()
    if running is not None:
        raise HTTPException(409, "an update job is already queued or running")
    job = TIUpdateJob(feed_id=feed.id, feed_name=feed.name, trigger="manual",
                      status="queued", counts={}, created_by=user.username)
    db.add(job)
    db.commit()
    db.refresh(job)
    audit(db, request, action="ti.feed.update_now", target_type="ti_feed",
          target_id=feed.id, detail={"job_id": job.id}, actor=user)
    return {"job_id": job.id, "status": job.status,
            "feed": feed.name, "queued_at": job.created_at.isoformat()}


# ----------------------------------------------------------------- jobs
@router.get("/jobs")
def list_jobs(limit: int = Query(default=20, ge=1, le=200),
              user: User = Depends(require_permission("view")),
              db: Session = Depends(get_db)):
    jobs = (db.query(TIUpdateJob).order_by(TIUpdateJob.created_at.desc())
            .limit(min(limit, config.ti_jobs_history_limit)).all())
    return [_job_out(j) for j in jobs]


# ----------------------------------------------------------------- iocs
@router.get("/iocs")
def list_iocs(type: str | None = Query(default=None),
              status: str = Query(default="active"),
              q: str | None = Query(default=None, max_length=128),
              limit: int = Query(default=100, ge=1, le=500),
              offset: int = Query(default=0, ge=0),
              user: User = Depends(require_permission("view")),
              db: Session = Depends(get_db)):
    query = db.query(IocRecord)
    if type:
        query = query.filter(IocRecord.ioc_type == type)
    if status in ("active", "expired"):
        query = query.filter(IocRecord.status == status)
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(_text(
            "lower(ioc_value) LIKE :like OR lower(coalesce(malware,'')) "
            "LIKE :like").bindparams(like=like))
    total = query.count()
    rows = (query.order_by(IocRecord.last_seen.desc())
            .offset(offset).limit(limit).all())
    return {"total": total,
            "items": [
                {"id": r.id, "ioc_type": r.ioc_type, "ioc_value": r.ioc_value,
                 "status": r.status, "confidence": r.confidence,
                 "malware": r.malware, "tags": r.tags or [],
                 "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                 "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                 "expires_at": r.expires_at.isoformat() if r.expires_at else None}
                for r in rows]}


# ------------------------------------------------- ioc activity (v0.12.9)
@router.get("/iocs/activity")
def ioc_activity(value: str = Query(min_length=1, max_length=512),
                 ioc_type: str | None = Query(default=None, max_length=16),
                 hours: int = Query(default=168, ge=1, le=24 * 30),
                 user: User = Depends(require_permission("view")),
                 db: Session = Depends(get_db)):
    """Per-IOC detail feed for the Threat Intel IOC sheet (v0.12.9).

    User report: 'IOC detail kurang rinci'. This closes the gap honestly:
    it joins the STORE record (incl. structured provenance) with what
    actually happened on THIS network - match count, unique source hosts,
    first/last sighting, top hosts, recent matches and the ioc_match
    alerts the detector raised for this indicator. Nothing is guessed:
    matches come from the ndr-ioc-matches index, alerts are matched by
    their recorded top_rules signature `ioc:<value>`.
    """
    row_q = db.query(IocRecord).filter(IocRecord.ioc_value == value)
    if ioc_type:
        row_q = row_q.filter(IocRecord.ioc_type == ioc_type)
    row = row_q.order_by(IocRecord.last_seen.desc()).first()
    if row is None:
        raise HTTPException(404, "IOC not found")

    now = datetime.now(timezone.utc)
    frm = (now - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")
    match_query = {"bool": {"filter": [
        {"term": {"ioc_value": value}},
        {"range": {"@timestamp": {"gte": frm}}},
    ]}}
    aggs = {
        "hosts": {"terms": {"field": "source_ip", "size": 8}},
        "fields": {"terms": {"field": "match_field", "size": 6}},
        "host_card": {"cardinality": {"field": "source_ip"}},
        "first_match": {"min": {"field": "@timestamp"}},
        "last_match": {"max": {"field": "@timestamp"}},
    }
    try:
        os = get_os()
        agg_res = os.aggregate("ndr-ioc-matches-read", {
            "size": 0, "track_total_hits": 10000,
            "query": match_query, "aggs": aggs})
        recent_res = os.aggregate("ndr-ioc-matches-read", {
            "size": 10, "sort": [{"@timestamp": {"order": "desc"}}],
            "query": match_query})
        # ioc_match alerts carry top_rules.signature == "ioc:<value>"
        # (keyword-mapped) - that is the honest alert-side linkage
        alerts_res = os.aggregate("ndr-alerts-read", {
            "size": 10, "track_total_hits": 10000,
            "sort": [{"last_seen": {"order": "desc"}}],
            "query": {"bool": {"filter": [
                {"term": {"top_rules.signature": f"ioc:{value}"}},
                {"range": {"last_seen": {"gte": frm}}},
            ]}}})
    except DSLValidationError as e:
        raise HTTPException(400, f"Query rejected: {e}")
    except Exception as e:
        raise HTTPException(502, f"Search backend unavailable: {e}")

    audit(db, request=None, action="ti.ioc_activity", target_type="ioc",
          target_id=value, actor=user)

    aggs_out = agg_res.get("aggregations", {})
    total = agg_res["hits"]["total"]

    def buckets(name: str) -> list[dict]:
        return [{"key": b.get("key"), "count": b.get("doc_count", 0)}
                for b in aggs_out.get(name, {}).get("buckets", [])]

    provenance = row.provenance
    if not isinstance(provenance, list):
        try:
            import json as _json
            provenance = _json.loads(provenance or "[]")
        except (TypeError, ValueError):
            provenance = []

    alert_total = alerts_res["hits"]["total"]
    recent = []
    for h in recent_res.get("hits", {}).get("hits", []):
        s = h.get("_source", {})
        recent.append({
            "id": h.get("_id"),
            "@timestamp": s.get("@timestamp"),
            "event_id": s.get("event_id"),
            "event_index": s.get("event_index"),
            "source_ip": s.get("source_ip"),
            "destination_ip": s.get("destination_ip"),
            "match_field": s.get("match_field"),
            "zone": s.get("zone"),
        })
    alert_items = []
    for h in alerts_res.get("hits", {}).get("hits", []):
        s = h.get("_source", {})
        alert_items.append({
            "alert_id": s.get("alert_id"),
            "title": s.get("title"),
            "severity": s.get("severity"),
            "alert_type": s.get("alert_type"),
            "status": s.get("status"),
            "first_seen": s.get("first_seen"),
            "last_seen": s.get("last_seen"),
            "source_ip": (s.get("source") or {}).get("ip"),
            "destination_ip": (s.get("destination") or {}).get("ip"),
        })

    return {
        "ioc": {
            "id": row.id, "ioc_type": row.ioc_type, "ioc_value": row.ioc_value,
            "status": row.status, "confidence": row.confidence,
            "malware": row.malware, "tags": row.tags or [],
            "first_seen": row.first_seen.isoformat() if row.first_seen
            else None,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            "expires_at": row.expires_at.isoformat() if row.expires_at
            else None,
            "provenance": provenance,
        },
        "hours": hours,
        "activity": {
            "matches_total": total.get("value", 0),
            "relation": total.get("relation", "eq"),
            "unique_source_hosts": (aggs_out.get("host_card", {})
                                    .get("value", 0)),
            "first_match": (aggs_out.get("first_match", {})
                            .get("value_as_string")),
            "last_match": (aggs_out.get("last_match", {})
                           .get("value_as_string")),
            "top_source_hosts": buckets("hosts"),
            "match_fields": buckets("fields"),
        },
        "recent_matches": recent,
        "related_alerts": {"total": alert_total.get("value", 0),
                           "items": alert_items},
    }


# -------------------------------------------------------------- matches
@router.get("/matches")
def list_matches(size: int = Query(default=50, ge=1, le=200),
                 hours: int = Query(default=24, ge=1, le=24 * 90),
                 ioc_type: str | None = Query(default=None),
                 user: User = Depends(require_permission("search"))):
    """Guarded read over the ndr-ioc-matches-read alias (API-built query,
    user input is limited to pagination + a whitelisted term filter)."""
    now = datetime.now(timezone.utc)
    frm = (now - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")
    filters = [{"range": {"@timestamp": {"gte": frm}}}]
    if ioc_type:
        filters.append({"term": {"ioc_type": ioc_type}})
    try:
        result = get_os().aggregate("ndr-ioc-matches-read", {
            "size": size, "track_total_hits": 10000,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": {"filter": filters}}})
    except DSLValidationError as e:
        raise HTTPException(400, f"Query rejected: {e}")
    except Exception as e:
        raise HTTPException(502, f"Search backend unavailable: {e}")
    total = result["hits"]["total"]
    return {"total": total.get("value", 0),
            "hits": [{"id": h["_id"], "source": h["_source"]}
                     for h in result["hits"]["hits"]]}


# ------------------------------------------------------------ allowlist
@router.get("/allowlist")
def list_allowlist(user: User = Depends(require_permission("view")),
                   db: Session = Depends(get_db)):
    rows = db.query(IocAllowlist).order_by(IocAllowlist.created_at.desc()).all()
    return [{"id": r.id, "ioc_type": r.ioc_type, "ioc_value": r.ioc_value,
             "reason": r.reason, "created_by": r.created_by,
             "created_at": r.created_at.isoformat()} for r in rows]


@router.post("/allowlist", status_code=201)
def add_allowlist(body: AllowlistCreate, request: Request,
                  user: User = Depends(require_permission("ti_admin")),
                  db: Session = Depends(get_db)):
    existing = db.query(IocAllowlist).filter(
        IocAllowlist.ioc_type == body.ioc_type,
        IocAllowlist.ioc_value == body.ioc_value).first()
    if existing is not None:
        raise HTTPException(409, "entry already allowlisted")
    entry = IocAllowlist(ioc_type=body.ioc_type, ioc_value=body.ioc_value,
                         reason=body.reason, created_by=user.username)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    audit(db, request, action="ti.allowlist.add", target_type="ioc",
          target_id=f"{body.ioc_type}:{body.ioc_value}",
          detail={"reason": body.reason}, actor=user)
    return {"id": entry.id, "ioc_type": entry.ioc_type,
            "ioc_value": entry.ioc_value, "reason": entry.reason,
            "created_by": entry.created_by,
            "created_at": entry.created_at.isoformat()}


@router.delete("/allowlist/{entry_id}", status_code=204)
def delete_allowlist(entry_id: int, request: Request,
                     user: User = Depends(require_permission("ti_admin")),
                     db: Session = Depends(get_db)):
    entry = db.query(IocAllowlist).filter(IocAllowlist.id == entry_id).first()
    if entry is None:
        raise HTTPException(404, "allowlist entry not found")
    detail = {"ioc_type": entry.ioc_type, "ioc_value": entry.ioc_value}
    db.delete(entry)
    db.commit()
    audit(db, request, action="ti.allowlist.remove", target_type="ioc",
          target_id=f"{detail['ioc_type']}:{detail['ioc_value']}",
          detail=detail, actor=user)
    return None
