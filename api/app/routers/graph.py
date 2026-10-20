"""Threat-map graph router (Phase 5).

Endpoints (all read-only, `view` permission):
  GET /api/graph/relationships   merged entity graph across campaigns
  GET /api/graph/geo             geographic external<->internal flows
  GET /api/graph/entity/{key}    evidence pivot + blast radius per entity

The relationship graph and the geographic map consume the SAME
correlation data: an external IP clicked on the geo map resolves to the
`ip:<address>` node key of the relationship graph.
"""

from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app import graph as graphsvc
from app.audit import audit
from app.config import config
from app.db import get_db
from app.os_client import get_os
from app.security import require_permission

router = APIRouter(prefix="/api/graph", tags=["graph"])


# ------------------------------------------------------- relationships
@router.get("/relationships")
def relationships(
        status: str = Query(default="open,confirmed"),
        severity_min: str | None = Query(default=None),
        q: str | None = Query(default=None, max_length=128),
        limit: int = Query(default=60, ge=1, le=200),
        # v0.12.7: render caps - the merged graph is trimmed to the most
        # significant entities so the browser never draws thousands of
        # SVG elements (meta.full_counts keeps the original numbers)
        max_nodes: int = Query(default=140, ge=20, le=400),
        max_edges: int = Query(default=500, ge=50, le=1200),
        user=Depends(require_permission("view")),
        db: Session = Depends(get_db)):
    statuses = [s.strip() for s in status.split(",") if s.strip()]
    graph = graphsvc.load_graph(db, statuses=statuses,
                                severity_min=severity_min, q=q,
                                limit=limit)
    payload = graph.to_payload()
    payload = graphsvc.prune_relationship_payload(
        payload, max_nodes=max_nodes, max_edges=max_edges)
    payload["meta"].update({
        "generated_at": _now(),
        "node_count": len(payload["nodes"]),
        "edge_count": len(payload["edges"]),
        "campaign_count": len(payload["campaigns"]),
        "basis": "merged reconstructed incidents (evidence-backed); "
                 "solid edges = observed relations, dashed = inferred "
                 "from entity/temporal context; cross-campaign links "
                 "exist only on shared checkable infrastructure",
        "disclaimer": "Graph relationships are correlations with cited "
                      "evidence, not proof of compromise.",
    })
    if payload["meta"]["pruned"]:
        payload["meta"]["note"] = (
            "graph trimmed for rendering: the most significant entities "
            "(TI-matched, cross-campaign, highest evidence) are kept - "
            "full counts in meta.full_counts; raise ?max_nodes/?max_edges "
            "to inspect more")
    return payload


# ---------------------------------------------------------------- geo
@router.get("/geo")
def geo_map(
        hours: int = Query(default=24, ge=1, le=24 * 60),
        # v0.12.7: top-volume pair cap - the map only needs the most
        # significant external<->internal pairs; the aggregation itself
        # stays broad but the RESPONSE is trimmed to the top pairs by
        # connection count (meta counts stay honest in the UI matrix)
        max_pairs: int = Query(default=120, ge=10, le=400),
        user=Depends(require_permission("view")),
        db: Session = Depends(get_db)):
    os = get_os()

    def aggregate(body: dict) -> dict:
        # API-constructed aggregation (never user DSL) with enforced
        # alias + timeout, mirroring os_client.aggregate
        os.validate_alias("ndr-events-read")
        return os.client.search(index="ndr-events-read", body=body,
                                request_timeout=config
                                .search_timeout_seconds)

    try:
        result = graphsvc.geo_flows_from_events(aggregate, db, hours=hours,
                                                max_pairs=max_pairs)
    except Exception as exc:  # OS down / index missing -> graceful empty
        result = {
            "hours": hours, "geo_enabled": False, "flows": [],
            "unmapped": [],
            "note": "events index unavailable: geographic aggregation "
                    f"disabled ({type(exc).__name__})",
            "generated_at": _now(),
        }
    return result


# ---------------------------------------------------------------- pivot
@router.get("/entity/{entity_key}")
def entity_pivot(entity_key: str, request: Request,
                 hours: int = Query(default=48, ge=1, le=24 * 60),
                 user=Depends(require_permission("view")),
                 db: Session = Depends(get_db)):
    key = _decode_key(entity_key)
    pivot = graphsvc.entity_pivot(db, key)
    if pivot is None:
        raise HTTPException(404, f"entity '{key}' not found in any "
                                 f"reconstructed campaign")
    pivot["alerts"] = _recent_alerts(key, hours)
    pivot["events_sample"] = _recent_events(key, hours)
    audit(db, request, action="graph.entity_pivot",
          target_type="entity", target_id=key, actor=user)
    return pivot


# ------------------------------------------------------------- helpers
def _decode_key(raw: str) -> str:
    """Accept URL-encoded `ip:1.2.3.4` style keys."""
    key = raw.replace("%3A", ":").replace("%3a", ":")
    if ":" not in key:
        raise HTTPException(400, "entity key must look like "
                                 "'ip:1.2.3.4' or 'domain:example.test'")
    return key


def _recent_alerts(key: str, hours: int) -> list[dict]:
    """Recent alerts involving this entity (evidence pivot)."""
    kind, _, value = key.partition(":")
    if kind not in ("ip", "domain") or not value:
        return []
    os = get_os()
    field = "source.ip" if kind == "ip" else "matched_ioc.ioc_value"
    alt_field = "destination.ip" if kind == "ip" else None
    should: list[dict] = [{"term": {field: value}}]
    if alt_field:
        should.append({"term": {alt_field: value}})
    body = {
        "size": 10,
        "sort": [{"last_seen": {"order": "desc"}}],
        "query": {"bool": {"filter": [
            {"range": {"last_seen": {"gte": _since(hours)}}},
            {"bool": {"should": should}},
        ]}},
        "_source": {"excludes": ["raw_line"]},
    }
    try:
        res = os.aggregate("ndr-alerts-read", body)
    except Exception:
        return []
    out = []
    for hit in res.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        out.append({
            "index": hit.get("_index"),
            "alert_id": src.get("alert_id"),
            "title": src.get("title"),
            "severity": src.get("severity"),
            "alert_type": src.get("alert_type"),
            "last_seen": src.get("last_seen"),
            "source_ip": (src.get("source") or {}).get("ip"),
            "destination_ip": (src.get("destination") or {}).get("ip"),
        })
    return out


def _recent_events(key: str, hours: int) -> list[dict]:
    """Compact session metadata sample for the pivot (Arkime-style)."""
    kind, _, value = key.partition(":")
    if kind not in ("ip", "domain") or not value:
        return []
    os = get_os()
    if kind == "ip":
        should = [{"term": {"source.ip": value}},
                  {"term": {"destination.ip": value}}]
    else:
        should = [{"term": {"dns.query": value}},
                  {"term": {"tls.sni": value}},
                  {"term": {"http.host": value}}]
    body = {
        "size": 8,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": _since(hours)}}},
            {"bool": {"should": should}},
        ]}},
        "_source": {"excludes": ["raw_line"]},
    }
    try:
        res = os.aggregate("ndr-events-read", body)
    except Exception:
        return []
    out = []
    for hit in res.get("hits", {}).get("hits", []):
        s = hit.get("_source", {})
        out.append({
            "index": hit.get("_index"),
            "doc_id": hit.get("_id"),
            "@timestamp": s.get("@timestamp"),
            "event_type": s.get("event_type"),
            "source_engine": s.get("source_engine"),
            "source_ip": (s.get("source") or {}).get("ip"),
            "destination_ip": (s.get("destination") or {}).get("ip"),
            "destination_port": (s.get("destination") or {}).get("port"),
            "network_transport": (s.get("network") or {})
            .get("transport"),
            "network_bytes": (s.get("network") or {}).get("bytes"),
            "dns_query": (s.get("dns") or {}).get("query"),
            "tls_sni": (s.get("tls") or {}).get("sni"),
            "http_host": (s.get("http") or {}).get("host"),
            "session_id": s.get("session_id"),
        })
    return out


def _since(hours: int) -> str:
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc)
            - timedelta(hours=hours)).isoformat() \
        .replace("+00:00", "Z")


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat() \
        .replace("+00:00", "Z")
