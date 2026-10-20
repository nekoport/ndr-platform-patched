"""Health & stats routers - overview dashboard data (doc sections 11.2, 19.3)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import config
from app.db import get_db
from app.models import Sensor, User
from app.os_client import get_os
from app.routers.admin import effective_sensor_status
from app.security import require_permission

router = APIRouter(prefix="/api", tags=["health"])


def _db_ok(db: Session) -> bool:
    try:
        db.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


@router.get("/health")
def health(user: User = Depends(require_permission("view")),
           db: Session = Depends(get_db)):
    os = get_os()
    result: dict = {"time": datetime.now(timezone.utc).isoformat(),
                    "retention_days": config.retention_days}

    # PostgreSQL
    result["postgres"] = {"ok": _db_ok(db)}

    # OpenSearch cluster
    try:
        ch = os.cluster_health()
        result["opensearch"] = {
            "ok": ch.get("status") in ("green", "yellow"),
            "status": ch.get("status"),
            "number_of_nodes": ch.get("number_of_nodes"),
            "unassigned_shards": ch.get("unassigned_shards"),
        }
    except Exception as e:
        result["opensearch"] = {"ok": False, "error": str(e)[:200]}

    # Pipeline freshness from ndr-health docs
    doc = os.latest_health_doc()
    if doc:
        backlog = doc.get("backlog_seconds")
        result["pipeline"] = {
            "ok": backlog is not None and backlog < 300,
            "sensor_id": doc.get("sensor_id"),
            "eps": doc.get("eps"),
            "eps_by_engine": doc.get("eps_by_engine"),
            "events_indexed": doc.get("events_indexed"),
            "parse_errors": doc.get("parse_errors"),
            "duplicates": doc.get("duplicates"),
            "queue_depth": doc.get("queue_depth"),
            "last_event_time": doc.get("last_event_time"),
            "backlog_seconds": backlog,
        }
    else:
        result["pipeline"] = {"ok": False, "error": "no health data yet"}

    # Disk usage of the OpenSearch data node
    try:
        stats = os.nodes_fs_stats()
        for _node, nd in stats.get("nodes", {}).items():
            fs = nd.get("fs", {}).get("total", {})
            total_in = fs.get("total_in_bytes", 0)
            free_in = fs.get("free_in_bytes", 0)
            if total_in:
                result["disk"] = {
                    "total_gb": round(total_in / 1e9, 1),
                    "free_gb": round(free_in / 1e9, 1),
                    "used_pct": round(100 * (1 - free_in / total_in), 1),
                }
                break
    except Exception:
        pass

    # Sensor freshness (registered sensors + pipeline heartbeat).
    # v0.12.5: status is derived from last_seen_at freshness (5 min window)
    # so a dead pipeline cannot keep a stale row 'online' forever.
    sensors = db.query(Sensor).all()
    result["sensors"] = [{
        "id": s.id, "hostname": s.hostname,
        "status": effective_sensor_status(s.last_seen_at, s.status),
        "last_seen_at": s.last_seen_at.isoformat() if s.last_seen_at else None,
    } for s in sensors]

    overall = all(result.get(k, {}).get("ok", False)
                  for k in ("postgres", "opensearch", "pipeline"))
    result["status"] = "healthy" if overall else "degraded"
    return result


@router.get("/stats/overview")
def stats_overview(user: User = Depends(require_permission("view"))):
    os = get_os()
    now = datetime.now(timezone.utc)
    day_ago = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    hour_ago = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")

    out: dict = {"time": now.isoformat()}

    # alerts by severity (24h)
    try:
        res = os.aggregate("ndr-alerts-read", {
            "size": 0,
            "query": {"range": {"last_seen": {"gte": day_ago}}},
            "aggs": {
                "by_severity": {"terms": {"field": "severity", "size": 5}},
                "by_status": {"terms": {"field": "status", "size": 8}},
                "top_rules": {"terms": {"field": "title", "size": 10}},
            },
        })
        out["alerts_24h"] = res["hits"]["total"]["value"]
        out["alerts_by_severity"] = [
            {"key": b["key"], "count": b["doc_count"]}
            for b in res["aggregations"]["by_severity"]["buckets"]]
        out["alerts_by_status"] = [
            {"key": b["key"], "count": b["doc_count"]}
            for b in res["aggregations"]["by_status"]["buckets"]]
        out["top_alert_titles"] = [
            {"key": b["key"], "count": b["doc_count"]}
            for b in res["aggregations"]["top_rules"]["buckets"]]
    except Exception as e:
        out["alerts_24h"] = 0
        out["alerts_error"] = str(e)[:200]

    # events indexed last hour + last 24h
    try:
        out["events_24h"] = os.count("ndr-events-read", {
            "range": {"@timestamp": {"gte": day_ago}}})
        out["events_1h"] = os.count("ndr-events-read", {
            "range": {"@timestamp": {"gte": hour_ago}}})
    except Exception:
        out["events_24h"] = 0
        out["events_1h"] = 0

    # pipeline EPS from latest health doc
    doc = os.latest_health_doc()
    out["eps"] = doc.get("eps") if doc else None
    out["eps_by_engine"] = doc.get("eps_by_engine") if doc else None
    out["pipeline_last_event_time"] = doc.get("last_event_time") if doc else None

    # alert trend per hour (24 buckets)
    try:
        res = os.aggregate("ndr-alerts-read", {
            "size": 0,
            "query": {"range": {"last_seen": {"gte": day_ago}}},
            "aggs": {"trend": {"date_histogram": {
                "field": "last_seen", "calendar_interval": "hour"}}}})
        out["alert_trend"] = [
            {"ts": b["key_as_string"], "count": b["doc_count"]}
            for b in res["aggregations"]["trend"]["buckets"]]
    except Exception:
        out["alert_trend"] = []

    return out
