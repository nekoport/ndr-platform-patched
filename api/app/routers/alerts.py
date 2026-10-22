"""Alerts router - search, detail, analyst updates, manual escalation
(doc sections 8.1, 10, 11.3)."""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit import audit
from app.config import config
from app.db import get_db
from app.filters import (ALERT_FILTER_FIELDS, FilterError, build_query,
                         combine)
from app.graph import MergedGraph, is_internal_ip, prune_relationship_payload
from app.killchain import phase_for_stage
from app.models import (Incident, IncidentEdge, IncidentEvidence,
                        IncidentHistory, IncidentNode, IncidentNote, User)
from app.os_client import DSLValidationError, get_os
from app.routers.assets import asset_name_map
from app.schemas import AlertUpdate, EscalateRequest, SearchRequest
from app.security import require_permission

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

RFC1918_PREFIXES = ("192.168.", "10.",
                    "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.",
                    "172.24.", "172.25.", "172.26.", "172.27.",
                    "172.28.", "172.29.", "172.30.", "172.31.")


def _is_internal(ip: str | None) -> bool:
    return bool(ip) and str(ip).startswith(RFC1918_PREFIXES)


@router.post("/search")
def search_alerts(body: SearchRequest, request: Request,
                  user: User = Depends(require_permission("search")),
                  db: Session = Depends(get_db)):
    if body.index != "ndr-alerts-read":
        body.index = "ndr-alerts-read"
    try:
        # v0.16.0 (req 5): custom filter DSL digabung dengan query lama
        filter_query = build_query(body.filter, ALERT_FILTER_FIELDS)
        combined = combine(body.query or None, filter_query)
        result = get_os().guarded_search(
            alias=body.index, query=combined, size=body.size,
            from_=body.from_, sort=body.sort,
            time_from=body.time_from, time_to=body.time_to)
    except FilterError as e:
        raise HTTPException(400, f"Filter rejected: {e}")
    except DSLValidationError as e:
        raise HTTPException(400, f"Query rejected: {e}")
    except Exception as e:
        raise HTTPException(502, f"Search backend unavailable: {e}")

    audit(db, request, action="alerts.search", target_type="index",
          target_id="ndr-alerts-read", actor=user)
    hits = [{"id": h["_id"], "source": h["_source"]}
            for h in result["hits"]["hits"]]
    # v0.10 asset-name enrichment: label source/destination with the
    # registered asset hostname so alerts on known machines are
    # immediately recognizable
    ips: list[str] = []
    for h in hits:
        src = h["source"]
        for side in ("source", "destination"):
            ip = (src.get(side) or {}).get("ip")
            if ip:
                ips.append(ip)
    names = asset_name_map(db, ips)
    if names:
        for h in hits:
            src = h["source"]
            src_ip = (src.get("source") or {}).get("ip")
            dst_ip = (src.get("destination") or {}).get("ip")
            if src_ip and src_ip in names:
                src["source_asset_name"] = names[src_ip]
            if dst_ip and dst_ip in names:
                src["destination_asset_name"] = names[dst_ip]
    total = result["hits"]["total"]
    return {"total": total.get("value", 0),
            "relation": total.get("relation", "eq"), "hits": hits}


# v0.16.1 (P2-6): GET /api/alerts/search tadinya jatuh ke route
# /{alert_id} (alert_id="search") lalu 502. Sekarang eksplisit 405
# dengan petunjuk method yang benar.
@router.get("/search")
def alerts_search_wrong_method():
    raise HTTPException(405, "Gunakan POST /api/alerts/search")


@router.post("/stats")
def alert_stats(body: SearchRequest, request: Request,
                user: User = Depends(require_permission("search")),
                db: Session = Depends(get_db)):
    """Aggregation-only chart feed for the Alert Center header.

    Runs against the SAME guarded filter as /search (alias whitelist,
    query guard, time window) with size 0 - the response carries ONLY
    exact bucket counts (severity/status/outcome + MITRE rollup), so the
    charts stay accurate for result sets of ANY size. A bounded
    newest-first scatter sample (max 300, server-side sort) feeds the
    scatter plot and supplies technique names for the MITRE rollup.
    """
    if body.index != "ndr-alerts-read":
        body.index = "ndr-alerts-read"
    os = get_os()
    try:
        # v0.16.0 (req 5): filter DSL ikut berlaku pada agregasi header
        filter_query = build_query(body.filter, ALERT_FILTER_FIELDS)
        combined = combine(body.query or None, filter_query)
        aggs = {
            "by_severity": {"terms": {"field": "severity", "size": 8}},
            "by_status": {"terms": {"field": "status", "size": 10}},
            "by_outcome": {"terms": {"field": "outcome", "size": 8}},
            "by_attack_status": {"terms": {"field": "attack_status", "size": 8}},
            "by_kill_chain": {"terms": {"field": "kill_chain.stage", "size": 10}},
            "by_mitre": {"terms": {"field": "mitre.technique_id", "size": 12}},
        }
        if combined:
            os.validate_query(combined)
        time_filter = os.build_time_filter(body.time_from, body.time_to)
        filters = [time_filter] + ([combined] if combined else [])
        result = os.aggregate(alias=body.index, body={
            "size": 0,
            "track_total_hits": 10000,
            "query": {"bool": {"filter": filters}},
            "aggs": aggs,
        })
    except DSLValidationError as e:
        raise HTTPException(400, f"Query rejected: {e}")
    except Exception as e:  # noqa: BLE001 - degrade, never 500 the header
        return {"total": 0, "relation": "eq", "severity": [], "status": [],
                "outcome": [], "attack_status": [], "kill_chain": [],
                "new_count": 0, "critical_count": 0,
                "mitre": [], "scatter": [], "sample_size": 0,
                "aggregations": {},
                "note": f"stats unavailable: {e}"}

    def bucket_dict(name: str) -> dict:
        return {b.get("key"): b.get("doc_count", 0)
                for b in result.get("aggregations", {})
                .get(name, {}).get("buckets", [])}

    def bucket_list(name: str) -> list[dict]:
        """v0.16.0 (bug A6 fix): kontrak UI mengharapkan LIST {key,count}
        (AlertStatBucket[]); bentuk dict vendor 0.15.0 dipindah ke key
        'aggregations.*' agar dua generasi kontrak aman berdampingan.
        Urutan: count desc - sama seperti normalisasi live 2026-10-20.
        """
        buckets = [{"key": k, "count": c}
                   for k, c in bucket_dict(name).items()]
        return sorted(buckets, key=lambda b: -b["count"])

    severity = bucket_dict("by_severity")
    status = bucket_dict("by_status")
    outcome = bucket_dict("by_outcome")
    attack_status = bucket_dict("by_attack_status")
    kill_chain = bucket_dict("by_kill_chain")
    mitre_buckets = [(b.get("key"), b.get("doc_count", 0))
                     for b in result.get("aggregations", {})
                     .get("by_mitre", {}).get("buckets", [])]

    # bounded scatter sample: newest-first, never the full set
    scatter: list[dict] = []
    names: dict[str, str] = {}
    try:
        sres = os.guarded_search(
            alias=body.index, query=combined, size=300, from_=0,
            sort=[{"last_seen": {"order": "desc"}}],
            time_from=body.time_from, time_to=body.time_to)
        for h in sres["hits"]["hits"]:
            src = h.get("_source") or {}
            scatter.append({
                "id": h.get("_id"),
                "title": src.get("title"),
                "severity": src.get("severity"),
                "last_seen": src.get("last_seen"),
                "risk_score": src.get("risk_score"),
                "mitre": src.get("mitre") or [],
            })
            for m in src.get("mitre") or []:
                if isinstance(m, dict) and m.get("technique_id"):
                    names.setdefault(str(m["technique_id"]),
                                     str(m.get("technique")
                                         or m["technique_id"]))
    except Exception:  # noqa: BLE001 - scatter is best-effort
        scatter = []

    total = result["hits"]["total"]
    audit(db, request, action="alerts.stats", target_type="index",
          target_id="ndr-alerts-read", actor=user)
    return {"total": total.get("value", 0),
            "relation": total.get("relation", "eq"),
            # list {key,count} - kontrak UI (bug A6 fix)
            "severity": bucket_list("by_severity"),
            "status": bucket_list("by_status"),
            "outcome": bucket_list("by_outcome"),
            "attack_status": bucket_list("by_attack_status"),
            "kill_chain": bucket_list("by_kill_chain"),
            "new_count": status.get("new", 0),
            "critical_count": severity.get("critical", 0),
            "mitre": [[tid, names.get(tid, tid), cnt]
                      for tid, cnt in mitre_buckets],
            "scatter": scatter,
            "sample_size": len(scatter),
            # bentuk dict vendor 0.15.0 tetap tersedia di sini
            "aggregations": {"severity": severity, "status": status,
                             "outcome": outcome,
                             "attack_status": attack_status,
                             "kill_chain": kill_chain}}


# ------------------------------------------- DGA focus view (v0.12.8)
# The pipeline emits TWO DGA-family detections: dga_suspected (entropy
# burst, Phase 4) and dns_nxdomain_burst (weak DGA signal, doc 8.7).
# The dedicated "DGA Activity" menu is a FOCUS VIEW over exactly these
# two alert types - no new detector, just a pre-filtered lens.
DGA_ALERT_TYPES = ("dga_suspected", "dns_nxdomain_burst")


@router.get("/dga/summary")
def dga_summary(hours: int = Query(default=24, ge=1, le=336),
                user: User = Depends(require_permission("search")),
                db: Session = Depends(get_db)):
    """Aggregation-only feed for the DGA Activity menu (v0.12.8).

    Same guarded-aggregation pattern as /stats: alias whitelist, query
    guard, bounded time window, size 0 - documents are NEVER returned
    here. Returns the total alert count for the two DGA-family types,
    the top querying source hosts and an hourly timeline bucket.
    """
    frm = (datetime.now(timezone.utc)
           - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")
    query = {"bool": {"filter": [
        {"terms": {"alert_type": list(DGA_ALERT_TYPES)}},
    ]}}
    # hourly buckets up to 48h, daily beyond - keeps the bucket count
    # bounded (<= 48) regardless of the requested window
    interval = "1h" if hours <= 48 else "1d"
    aggs = {
        "by_source": {"terms": {"field": "source.ip", "size": 10}},
        "timeline": {"date_histogram": {
            "field": "@timestamp", "fixed_interval": interval,
            "format": "yyyy-MM-dd'T'HH:mm:ss'Z'",
            "min_doc_count": 0}},
        "newest": {"max": {"field": "@timestamp"}},
    }
    try:
        result = get_os().guarded_aggregate(
            alias="ndr-alerts-read", query=query, aggs=aggs,
            time_from=frm, time_to=None)
    except DSLValidationError as e:
        raise HTTPException(400, f"Query rejected: {e}")
    except Exception as e:
        raise HTTPException(502, f"Search backend unavailable: {e}")

    audit(db, request=None, action="alerts.dga_summary",
          target_type="index", target_id="ndr-alerts-read", actor=user)

    aggs_out = result.get("aggregations", {})
    total = result["hits"]["total"]
    return {
        "hours": hours,
        "total": total.get("value", 0),
        "relation": total.get("relation", "eq"),
        "alert_types": list(DGA_ALERT_TYPES),
        "sources": [{"key": b.get("key"), "count": b.get("doc_count", 0)}
                    for b in aggs_out.get("by_source", {}).get("buckets", [])],
        "timeline": [{"ts": b.get("key_as_string"), "count": b.get("doc_count", 0)}
                     for b in aggs_out.get("timeline", {}).get("buckets", [])],
        "last_seen": (aggs_out.get("newest", {}) or {}).get("value_as_string")
                     or (aggs_out.get("newest", {}) or {}).get("value"),
    }


@router.get("/{alert_id}")
def get_alert(alert_id: str,
              user: User = Depends(require_permission("search"))):
    # v0.12.6: resilient resolution (_id get + alert_id-field fallback);
    # backend failures surface as 502, not a misleading 404.
    try:
        doc = get_os().get_alert_doc(alert_id)
    except Exception as e:  # noqa: BLE001 - backend down -> honest 502
        raise HTTPException(502, f"Search backend unavailable: {e}")
    if doc is None:
        raise HTTPException(404, "Alert not found")
    return {"id": doc["_id"], "source": doc["_source"]}


@router.patch("/{alert_id}")
def update_alert(alert_id: str, body: AlertUpdate, request: Request,
                 user: User = Depends(require_permission("alert_update")),
                 db: Session = Depends(get_db)):
    os = get_os()
    # v0.12.6: resilient resolution; the partial update below must target
    # the RESOLVED _id (a doc whose _id differs from its alert_id field
    # would otherwise 404 on write too).
    try:
        doc = os.get_alert_doc(alert_id)
    except Exception as e:  # noqa: BLE001 - backend down -> honest 502
        raise HTTPException(502, f"Search backend unavailable: {e}")
    if doc is None:
        raise HTTPException(404, "Alert not found")
    resolved_id = doc["_id"]

    before = {k: doc["_source"].get(k)
              for k in ("status", "assignee", "notes")}
    updates: dict = {"updated_at": datetime.now(timezone.utc)
                     .isoformat().replace("+00:00", "Z"),
                     "updated_by": user.username}
    if body.status is not None:
        updates["status"] = body.status
    if body.assignee is not None:
        updates["assignee"] = body.assignee
    if body.notes is not None:
        updates["notes"] = body.notes

    # scripted-free partial update via doc merge
    try:
        # v0.13.0 (backport fix VM): a busy cluster can hold this write
        # longer than the client-level 15 s default -> 502 while the
        # update actually lands. 90 s absorbs the spike; refresh stays
        # wait_for so the UI reads its own write.
        os.client.update(index="ndr-alerts-read", id=resolved_id,
                         body={"doc": updates}, refresh="wait_for",
                         request_timeout=90)
    except Exception as e:
        audit(db, request, action="alerts.update", result="failure",
              target_type="alert", target_id=alert_id,
              detail={"error": str(e)}, actor=user)
        raise HTTPException(502, f"Update failed: {e}")

    audit(db, request, action="alerts.update", target_type="alert",
          target_id=alert_id, actor=user,
          detail={"before": before, "after": updates})
    return {"ok": True, "updated": updates}


@router.get("/{alert_id}/related-incident")
def related_incident(alert_id: str,
                     user: User = Depends(require_permission("view")),
                     db: Session = Depends(get_db)):
    """Incidents whose recorded EVIDENCE references this alert (v0.12.8).

    Closes the Alert Center -> Incidents loop honestly: an alert is
    linked ONLY when the correlation engine (or a manual escalation)
    actually recorded it as incident evidence - no similarity guessing.
    """
    rows = (db.query(Incident)
            .join(IncidentEvidence,
                  IncidentEvidence.incident_id == Incident.id)
            .filter(IncidentEvidence.ref_id == alert_id)
            .order_by(Incident.last_seen.desc().nullslast())
            .limit(5).all())
    return {"items": [{
        "incident_id": r.id,
        "title": r.title,
        "status": r.status,
        "severity": r.severity,
        "outcome_label": (r.outcome or {}).get("label", "indeterminate"),
    } for r in rows]}


# ------------------------------------------------ alert relationship (v0.12.9)
# User report: the Alert Center "jump to threat map" button landed on the
# GLOBAL view (geographic map when the IP had no graph node) - heavy and
# off-target. The fix keeps the jump FOCUSED: it renders the attack
# relationship of THIS alert only (its incident subgraph when the alert is
# recorded as incident evidence, otherwise an honest single-alert graph),
# never the global campaign graph.
ALERT_REL_MAX_NODES = 60
ALERT_REL_MAX_EDGES = 200


def _phase_of(src: dict) -> str:
    stage = ((src.get("kill_chain") or {}).get("stage")
             if isinstance(src.get("kill_chain"), dict) else None)
    phase = phase_for_stage(stage)
    return phase or "unknown"


def _alert_only_graph(src: dict, alert_id: str) -> tuple[dict, str, str]:
    """Honest minimal graph built ONLY from one alert's own fields.

    Every node/edge cites the alert as its single source - checkable via
    the alert id, its evidence refs and "Verify in Event Search". Nothing
    is inferred: when the alert has no source/destination the graph is
    intentionally EMPTY (basis "none") rather than decorated.
    """
    src_ip = (src.get("source") or {}).get("ip")
    dst_ip = (src.get("destination") or {}).get("ip")
    first_seen = src.get("first_seen")
    last_seen = src.get("last_seen")
    title = str(src.get("title") or alert_id)
    phase = _phase_of(src)
    confidence = int(src.get("risk_score") or src.get("severity_score") or 60)

    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def node(ip: str | None, role: str) -> dict | None:
        if not ip:
            return None
        key = f"ip:{ip}"
        n = nodes.get(key)
        if n is None:
            n = {
                "key": key, "kind": "ip", "label": ip,
                "roles": [role], "phase": phase,
                "confidence": confidence,
                "first_seen": first_seen, "last_seen": last_seen,
                "evidence_count": 1, "incident_ids": [],
                "ti_match": False,
                "attrs": {"via": f"alert {alert_id}"},
                "internal": is_internal_ip(ip), "degree": 0,
            }
            nodes[key] = n
        elif role not in n["roles"]:
            n["roles"].append(role)
        return n

    src_node = node(src_ip,
                    "compromised_host" if is_internal_ip(src_ip)
                    else "attacker")
    dst_node = node(dst_ip,
                    "target_range" if is_internal_ip(dst_ip)
                    else "c2_infra")

    # ioc_match alerts record the matched indicator - surface it as its
    # own node so the focused view shows what the host actually touched
    matched = (src.get("matched_iocs") or [{}])[0] \
        if isinstance(src.get("matched_iocs"), list) else {}
    ioc_value = matched.get("ioc_value")
    if ioc_value:
        ioc_key = f"{matched.get('ioc_type', 'ioc')}:{ioc_value}"
        ioc_node = {
            "key": ioc_key,
            "kind": matched.get("ioc_type") if matched.get("ioc_type") in (
                "domain", "hash", "url") else "ioc",
            "label": ioc_value, "roles": ["threat_intel"], "phase": phase,
            "confidence": confidence, "first_seen": first_seen,
            "last_seen": last_seen, "evidence_count": 1,
            "incident_ids": [], "ti_match": True,
            "attrs": {"via": f"alert {alert_id}",
                      "feed_confidence": matched.get("confidence")},
            "internal": False, "degree": 0,
        }
        nodes[ioc_key] = ioc_node
        if src_node:
            relation = ("connected_to" if matched.get("match_field")
                        == "destination" else "queried")
            ioc_node["degree"] += 1
            src_node["degree"] += 1
            edges.append({
                "src": src_node["key"], "dst": ioc_key,
                "relation": relation, "phase": phase, "inferred": False,
                "first_seen": first_seen, "last_seen": last_seen,
                "evidence_count": 1, "confidence": confidence,
                "incident_ids": [],
                "reasons": [f"alert {alert_id}: IOC match recorded by the "
                            f"detection pipeline (contextual evidence, "
                            f"doc 9.2)"],
            })

    if src_node and dst_node:
        src_node["degree"] += 1
        dst_node["degree"] += 1
        edges.append({
            "src": src_node["key"], "dst": dst_node["key"],
            "relation": "alerted_activity", "phase": phase,
            "inferred": False,
            "first_seen": first_seen, "last_seen": last_seen,
            "evidence_count": 1, "confidence": confidence,
            "incident_ids": [],
            "reasons": [f"alert {alert_id}: '{title}' observed "
                        f"{first_seen} to {last_seen} "
                        f"({src.get('event_count', '?')} events)"],
        })

    if not nodes:
        basis = "none"
        note = ("This alert carries no source/destination entities, so "
                "there is nothing to draw yet. Use its evidence and "
                "'Verify in Event Search' instead - the correlation "
                "engine may still link it into an incident later.")
    else:
        basis = "alert"
        note = ("Showing what THIS alert alone proves - its own source, "
                "destination and IOC entities with the alert as the "
                "single cited source. No correlation is guessed. When "
                "the correlation engine records this alert as incident "
                "evidence, the full incident chain replaces this view.")
    return {"nodes": list(nodes.values()), "edges": edges, "campaigns": []}, \
        basis, note


def _incident_subgraph(db: Session, incidents: list[Incident]) -> dict:
    """Merged mini-graph from the incidents that cite this alert (same
    node/edge shapes as the global relationship graph - MergedGraph -
    so the focused view renders with the identical component)."""
    g = MergedGraph()
    inc_ids = [i.id for i in incidents]
    node_rows: dict[str, list] = {i: [] for i in inc_ids}
    edge_rows: dict[str, list] = {i: [] for i in inc_ids}
    for n in db.query(IncidentNode).filter(
            IncidentNode.incident_id.in_(inc_ids)).all():
        node_rows[n.incident_id].append(n)
    for e in db.query(IncidentEdge).filter(
            IncidentEdge.incident_id.in_(inc_ids)).all():
        edge_rows[e.incident_id].append(e)
    for inc in incidents:
        touched = [n.key for n in node_rows[inc.id]]
        for e in edge_rows[inc.id]:
            for endpoint in (e.src_key, e.dst_key):
                nd = g.nodes.get(endpoint)
                if nd is None:
                    kind, _, label = endpoint.partition(":")
                    g.add_node(IncidentNode(
                        incident_id=inc.id, kind=kind or "ioc",
                        key=endpoint, label=label or endpoint,
                        first_seen=e.first_seen, last_seen=e.last_seen,
                        attrs={}), inc.id)
                    touched.append(endpoint)
                elif inc.id not in nd["incident_ids"]:
                    nd["incident_ids"].append(inc.id)
                    touched.append(endpoint)
            g.add_edge(e, inc.id)
        g.add_campaign(inc, touched)
    return g.to_payload()


@router.get("/{alert_id}/relationship")
def alert_relationship(alert_id: str,
                       user: User = Depends(require_permission("view")),
                       db: Session = Depends(get_db)):
    """FOCUSED attack relationship for ONE alert (v0.12.9).

    The Alert Center 'threat map' jump lands HERE - not on the global
    campaign graph or the geographic map. Priority order, honestly
    labeled in `basis`:
      1. incident  - the alert is recorded evidence of reconstructed
                     incident(s); returns that incident subgraph only.
      2. alert     - not yet correlated; returns an honest minimal graph
                     built from the alert's own entities.
      3. none      - the alert has no source/destination; empty graph.
    """
    try:
        doc = get_os().get_alert_doc(alert_id)
    except Exception as e:  # noqa: BLE001 - backend down -> honest 502
        raise HTTPException(502, f"Search backend unavailable: {e}")
    if doc is None:
        raise HTTPException(404, "Alert not found")
    src = doc["_source"]

    incidents = (db.query(Incident)
                 .join(IncidentEvidence,
                       IncidentEvidence.incident_id == Incident.id)
                 .filter(IncidentEvidence.ref_id == alert_id)
                 .order_by(Incident.last_seen.desc().nullslast())
                 .limit(3).all())

    if incidents:
        payload = _incident_subgraph(db, incidents)
        basis = "incident"
        note = (f"This alert is recorded evidence of {len(incidents)} "
                f"reconstructed incident(s) - showing the incident "
                f"attack chain(s) it belongs to, trimmed for focus. "
                f"Every edge cites checkable evidence.")
    else:
        graph_payload, basis, note = _alert_only_graph(src, alert_id)
        payload = graph_payload

    payload = prune_relationship_payload(
        payload, max_nodes=ALERT_REL_MAX_NODES, max_edges=ALERT_REL_MAX_EDGES)
    payload["meta"].update({
        "generated_at": datetime.now(timezone.utc).isoformat()
                        .replace("+00:00", "Z"),
        "node_count": len(payload["nodes"]),
        "edge_count": len(payload["edges"]),
        "campaign_count": len(payload["campaigns"]),
        "basis": note,
        "disclaimer": "Focused relationship view - correlations carry "
                      "cited evidence, not proof of compromise.",
    })
    audit(db, request=None, action="alerts.relationship",
          target_type="alert", target_id=alert_id, actor=user)
    return {
        "alert": {
            "id": doc["_id"],
            "alert_id": src.get("alert_id") or alert_id,
            "title": src.get("title"),
            "alert_type": src.get("alert_type"),
            "severity": src.get("severity"),
            "status": src.get("status"),
            "source_ip": (src.get("source") or {}).get("ip"),
            "destination_ip": (src.get("destination") or {}).get("ip"),
            "first_seen": src.get("first_seen"),
            "last_seen": src.get("last_seen"),
            "event_count": src.get("event_count"),
        },
        "basis": basis,
        "note": note,
        "incidents": [{
            "incident_id": r.id, "title": r.title, "status": r.status,
            "severity": r.severity,
            "outcome_label": (r.outcome or {}).get("label",
                                                   "indeterminate"),
        } for r in incidents],
        "graph": payload,
    }


# ------------------------------------------------- manual escalation (v0.10)
@router.post("/{alert_id}/escalate")
def escalate_alert(alert_id: str, body: EscalateRequest, request: Request,
                   user: User = Depends(require_permission("incident_update")),
                   db: Session = Depends(get_db)):
    """Raise ONE alert into a NEW open incident (analyst decision).

    The incident honestly carries exactly what the alert proves: its own
    entities and a single evidence item. NO edges are invented - relations
    only ever come from the automatic correlation engine, which may merge
    this incident with related chains later.
    """
    # v0.12.6: resilient resolution (_id get + alert_id-field fallback).
    try:
        doc = get_os().get_alert_doc(alert_id)
    except Exception as e:  # noqa: BLE001 - backend down -> honest 502
        raise HTTPException(502, f"Search backend unavailable: {e}")
    if doc is None:
        raise HTTPException(404, "Alert not found")
    src = doc["_source"]

    # deterministic id -> natural idempotency guard
    incident_id = f"inc-esc-{alert_id}"[:64]
    if db.get(Incident, incident_id) is not None:
        raise HTTPException(409,
                            f"Alert already escalated to incident {incident_id}")

    clean_title = str(src.get("title") or alert_id).strip()
    severity = src.get("severity", "medium")
    confidence = int(src.get("risk_score") or src.get("severity_score") or 50)
    first_seen = src.get("first_seen")
    last_seen = src.get("last_seen")
    kc = src.get("kill_chain") or {}
    stage = kc.get("stage") if isinstance(kc, dict) else None
    phase = phase_for_stage(stage)
    outcome_label = src.get("outcome", "indeterminate")

    src_ip = (src.get("source") or {}).get("ip")
    dst_ip = (src.get("destination") or {}).get("ip")

    incident = Incident(
        id=incident_id,
        title=f"Manual escalation: {clean_title}"[:512],
        status="open",
        severity=severity,
        confidence=confidence,
        first_seen=first_seen,
        last_seen=last_seen,
        outcome={
            "label": outcome_label,
            "proven": [f"Alert '{clean_title}' observed {first_seen} to "
                       f"{last_seen} ({src.get('event_count', '?')} events)"],
            "suspected": [],
            "unknown": ["Whether this single alert is part of a wider chain - "
                        "the correlation engine will merge this incident if "
                        "related evidence appears",
                        "Host state after the observed activity (needs "
                        "endpoint/server logs)"],
            "markers": ["manual escalation"],
            "disclaimer": "Manually raised by an analyst from a single alert. "
                          "No relations are inferred without corroborating evidence.",
        },
        phases=[{"phase": phase, "status": "observed",
                 "evidence_count": 1, "signal_count": 1,
                 "context_count": 0}],
        entity_count=(1 if src_ip else 0) + (1 if dst_ip else 0),
        edge_count=0,
        evidence_count=1,
        signal_count=1,
        analyst=user.username,
    )
    db.add(incident)

    if src_ip:
        db.add(IncidentNode(
            incident_id=incident_id, kind="ip", key=f"ip:{src_ip}",
            label=src_ip,
            role="compromised_host" if _is_internal(src_ip) else "attacker",
            phase=phase, confidence=confidence,
            first_seen=first_seen, last_seen=last_seen,
            attrs={"via": "manual escalation", "alert_type": src.get("alert_type")}))
    if dst_ip:
        db.add(IncidentNode(
            incident_id=incident_id, kind="ip", key=f"ip:{dst_ip}",
            label=dst_ip,
            role="target_range" if _is_internal(dst_ip) else "c2_infra",
            phase=phase, confidence=confidence,
            first_seen=first_seen, last_seen=last_seen,
            attrs={"via": "manual escalation", "alert_type": src.get("alert_type")}))

    db.add(IncidentEvidence(
        incident_id=incident_id, ts=last_seen, kind="alert_ref",
        source=str(src.get("alert_type") or "alert"),
        ref_index="ndr-alerts-read", ref_id=alert_id,
        title=clean_title, severity=severity, phase=phase,
        summary=src.get("rationale"),
        detail={"group_key": src.get("group_key"),
                "event_count": src.get("event_count"),
                "escalation_reason": body.reason or None}))

    db.add(IncidentHistory(
        incident_id=incident_id, actor=user.username,
        action="created_by_manual_escalation",
        detail={"alert_id": alert_id, "reason": body.reason or None}))
    if body.reason:
        db.add(IncidentNote(incident_id=incident_id, author=user.username,
                            body=body.reason))

    db.commit()
    audit(db, request, action="alert.escalate", target_type="incident",
          target_id=incident_id, actor=user,
          detail={"alert_id": alert_id, "reason": body.reason or None})
    return {"incident_id": incident_id,
            "title": incident.title}


# ------------------------------------------- Alert export (v0.16.0, req 6)
EXPORT_COLUMNS = [
    "alert_id", "@timestamp", "first_seen", "last_seen", "severity",
    "status", "attack_status", "outcome", "kill_chain.stage",
    "detection_engine", "alert_type", "title", "source.ip",
    "destination.ip", "network.protocol", "network.transport",
    "event_count", "campaign", "cve", "dns_domains",
    "top_rules.signature", "mitre.techniques", "explanation",
]


class ExportRequest(BaseModel):
    """Body export alert (req 6). Query/filter sama dengan /search."""
    format: str = "csv"  # csv | xlsx
    query: dict[str, Any] = Field(default_factory=dict)
    filter: dict[str, Any] | None = None
    time_from: str | None = None
    time_to: str | None = None
    columns: list[str] | None = None
    max_rows: int = Field(default=50000, ge=1, le=200000)

    model_config = {"populate_by_name": True}


def _flatten(value: Any) -> str:
    """Nilai nested/list -> sel tunggal yang terbaca di csv/xlsx."""
    if value is None:
        return ""
    if isinstance(value, dict):
        if "stage" in value and value.get("stage") is not None:
            return str(value["stage"])
        if "ip" in value:
            return str(value["ip"])
        if "technique_id" in value:
            return str(value["technique_id"])
        if "signature" in value:
            return str(value["signature"])
        return "; ".join(f"{k}={_flatten(v)}" for k, v in value.items())
    if isinstance(value, list):
        return "; ".join(_flatten(v) for v in value)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _cell(doc: dict, column: str) -> Any:
    # v0.16.0: kolom rollup ditangani SEBELUM traversal dot (list tidak
    # bisa di-walk pakai dict.get - dulu selalu return kosong).
    if column == "mitre.techniques":
        mitre = doc.get("mitre") or []
        if isinstance(mitre, list):
            return "; ".join(
                sorted({str(m.get("technique_id"))
                        for m in mitre if isinstance(m, dict)}))
    if column == "top_rules.signature":
        rules = doc.get("top_rules") or []
        if isinstance(rules, list):
            return "; ".join(
                sorted({str(r.get("signature"))
                        for r in rules if isinstance(r, dict)}))
    cur: Any = doc
    for part in column.split("."):
        if not isinstance(cur, dict):
            return ""
        cur = cur.get(part)
    if isinstance(cur, (dict, list)):
        return _flatten(cur)
    return cur


@router.post("/export")
def export_alerts(body: ExportRequest, request: Request,
                  user: User = Depends(require_permission("search")),
                  db: Session = Depends(get_db)):
    """Export alert ke .csv / .xlsx (requirement 6).

    Streaming dengan search_after pagination (bukan from+size, aman untuk
    hasil besar), window time WAJIB (guard yang sama dengan /search),
    baris di-cap config.export_max_rows. File dibangun di memori dengan
    batas baris; audit mencatat setiap permintaan export.
    """
    fmt = (body.format or "csv").lower()
    if fmt not in ("csv", "xlsx"):
        raise HTTPException(400, "format must be csv or xlsx")
    columns = body.columns or EXPORT_COLUMNS
    # v0.16.0: whitelist PENUH - kolom harus exact EXPORT_COLUMNS atau
    # dot-prefixed di bawah root yang sama (menutup celah kolom tanpa
    # titik seperti 'raw_event' yang dulu lolos ke backend).
    allowed_exact = set(EXPORT_COLUMNS)
    allowed_roots = {c.split(".")[0] for c in EXPORT_COLUMNS}
    bad = [c for c in columns
           if not isinstance(c, str)
           or (c not in allowed_exact
               and ("." not in c or c.split(".")[0] not in allowed_roots))]
    if bad:
        raise HTTPException(400, f"unknown columns: {bad[:5]}")

    os = get_os()
    try:
        filter_query = build_query(body.filter, ALERT_FILTER_FIELDS)
        combined = combine(body.query or None, filter_query)
        alias = os.validate_alias("ndr-alerts-read")
        if combined:
            os.validate_query(combined)
        time_filter = os.build_time_filter(body.time_from, body.time_to)
        filters = [time_filter] + ([combined] if combined else [])
    except FilterError as e:
        raise HTTPException(400, f"Filter rejected: {e}")
    except DSLValidationError as e:
        raise HTTPException(400, f"Query rejected: {e}")

    audit(db, request, action="alerts.export", target_type="index",
          target_id="ndr-alerts-read", actor=user,
          detail={"format": fmt, "max_rows": body.max_rows})

    batch_size = 1000
    cap = min(body.max_rows, config.export_max_rows)
    search_body: dict[str, Any] = {
        "size": batch_size,
        "track_total_hits": False,
        "query": {"bool": {"filter": filters}},
        "sort": [{"@timestamp": {"order": "desc"}},
                 {"alert_id": {"order": "asc"}}],
        "_source": {"excludes": ["raw_line"]},
    }

    rows: list[list[Any]] = []
    after: Any = None
    try:
        while len(rows) < cap:
            body_page = dict(search_body)
            if after is not None:
                body_page["search_after"] = after
            page = os.client.search(index=alias, body=body_page,
                                    request_timeout=30)
            hits = (page.get("hits") or {}).get("hits") or []
            if not hits:
                break
            for h in hits:
                rows.append([_cell(h.get("_source") or {}, c)
                             for c in columns])
            after = hits[-1].get("sort")
            if after is None:
                break
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"Export backend unavailable: {e}")
    rows = rows[:cap]

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(columns)
        writer.writerows(rows)
        data = buf.getvalue().encode("utf-8-sig")
        media = "text/csv; charset=utf-8"
        filename = f"ndr-alerts-{stamp}.csv"
    else:
        # v0.16.1 (P0-1): import openpyxl LAZY di titik pakai. Import
        # top-level dulu bikin SELURUH API crash saat dependency tidak
        # terpasang (fresh deploy tanpa openpyxl = platform mati total).
        # Kini: API tetap hidup, export xlsx saja yang menjawab 503.
        try:
            from openpyxl import Workbook  # noqa: deferred import
        except ModuleNotFoundError as exc:
            raise HTTPException(
                503, "Export XLSX tidak tersedia: dependency 'openpyxl' "
                     f"belum terpasang di image API ({exc}). Jalankan "
                     "'pip install -r api/requirements.txt' atau pakai "
                     "format csv.")
        wb = Workbook(write_only=True)
        ws = wb.create_sheet("alerts")
        ws.append(columns)
        for r in rows:
            ws.append([c if isinstance(c, (int, float)) else str(c)
                       for c in r])
        bio = io.BytesIO()
        wb.save(bio)
        data = bio.getvalue()
        media = ("application/vnd.openxmlformats-officedocument"
                 ".spreadsheetml.sheet")
        filename = f"ndr-alerts-{stamp}.xlsx"

    return StreamingResponse(
        io.BytesIO(data), media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"',
                 "X-Export-Rows": str(len(rows))})
