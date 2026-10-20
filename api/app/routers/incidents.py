"""Attack reconstruction router (doc section 10 - Phase 4).

Endpoints:
  GET   /api/incidents               list reconstructed incidents (view)
  GET   /api/incidents/summary       KPI counts for dashboards (view)
  GET   /api/incidents/{id}          full reconstruction detail (view)
  PATCH /api/incidents/{id}/status   analyst triage (incident_update)
  POST  /api/incidents/{id}/notes    analyst note (incident_update)
  GET   /api/incidents/{id}/report   Markdown incident report (view)

Story data is produced by the pipeline's reconstruction engine; this
router never fabricates incidents. All triage actions are audited and
appended to the incident history.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.audit import audit
from app.db import get_db
from app.killchain import (deepest_stage, stage_assessment_for_incident,
                           stage_for_phase)
from app.models import (Campaign, Incident, IncidentEdge, IncidentEvidence,
                        IncidentHistory, IncidentNote, IncidentNode,
                        IncidentReportVersion, User)
from app.report import build_report
from app.schemas import (IncidentNoteCreate, IncidentOut,
                         IncidentStatusUpdate)
from app.security import require_permission

router = APIRouter(prefix="/api/incidents", tags=["incidents"])

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1,
                 "informational": 0}
STATUS_VALUES = {"open", "confirmed", "benign", "closed"}


def _campaign_map(db: Session, campaign_ids: set[str | None]) -> dict:
    ids = {c for c in campaign_ids if c}
    if not ids:
        return {}
    rows = db.query(Campaign).filter(Campaign.id.in_(ids)).all()
    return {c.id: c.title for c in rows}


def _incident_out(inc: Incident, campaign_titles: dict | None = None) -> dict:
    data = IncidentOut.model_validate(inc).model_dump(mode="json")
    data["outcome_label"] = (inc.outcome or {}).get("label", "indeterminate")
    outcome = inc.outcome or {}
    data["deepest_stage"] = outcome.get("deepest_stage") \
        or deepest_stage(outcome.get("stage_progression"))
    if inc.campaign_id:
        data["campaign_title"] = (campaign_titles or {}).get(
            inc.campaign_id) or inc.campaign_id
    else:
        data["campaign_title"] = None
    return data


def _detail_out(inc: Incident, db: Session) -> dict:
    titles = _campaign_map(db, {inc.campaign_id})
    nodes = db.query(IncidentNode).filter(
        IncidentNode.incident_id == inc.id).all()
    edges = db.query(IncidentEdge).filter(
        IncidentEdge.incident_id == inc.id).all()
    evidence = db.query(IncidentEvidence).filter(
        IncidentEvidence.incident_id == inc.id).all()
    notes = db.query(IncidentNote).filter(
        IncidentNote.incident_id == inc.id).order_by(
        IncidentNote.created_at).all()
    history = db.query(IncidentHistory).filter(
        IncidentHistory.incident_id == inc.id).order_by(
        IncidentHistory.occurred_at.desc()).limit(50).all()
    evidence_out = [{
        "ts": ev.ts, "kind": ev.kind, "source": ev.source,
        "ref_index": ev.ref_index, "ref_id": ev.ref_id,
        "title": ev.title, "severity": ev.severity,
        "phase": ev.phase, "summary": ev.summary,
        "detail": ev.detail or {}, "stage": ev.stage or None,
        "attck": ev.attck or [],
    } for ev in evidence]
    stage_progression, stage_history = stage_assessment_for_incident(
        inc.outcome, evidence_out)
    return {
        **_incident_out(inc, titles),
        "outcome": inc.outcome or {},
        "phase_progression": inc.phases or [],
        "stage_progression": stage_progression,
        "stage_history": stage_history,
        "deepest_stage": deepest_stage(stage_progression),
        "nodes": [{
            "key": n.key, "kind": n.kind, "label": n.label,
            "role": n.role, "phase": n.phase,
            "kill_chain_stage": stage_for_phase(n.phase),
            "confidence": n.confidence, "first_seen": n.first_seen,
            "last_seen": n.last_seen, "attrs": n.attrs or {},
            "evidence_count": 0,
        } for n in nodes],
        "edges": [{
            "src": e.src_key, "dst": e.dst_key,
            "relation": e.relation, "phase": e.phase,
            "inferred": bool(e.inferred), "first_seen": e.first_seen,
            "last_seen": e.last_seen,
            "evidence_count": e.evidence_count,
            "confidence": e.confidence,
        } for e in edges],
        "evidence": evidence_out,
        "notes": [{
            "author": n.author, "body": n.body,
            "created_at": n.created_at.isoformat() if n.created_at else None,
        } for n in notes],
        "history": [{
            "occurred_at": h.occurred_at.isoformat() if h.occurred_at
            else None,
            "actor": h.actor, "action": h.action,
            "detail": h.detail or {},
        } for h in history],
    }


# --------------------------------------------------------------- list
@router.get("")
def list_incidents(
        status: str | None = Query(default=None),
        severity: str | None = Query(default=None),
        outcome: str | None = Query(default=None),
        q: str | None = Query(default=None, max_length=128),
        time_from: str | None = Query(default=None),
        time_to: str | None = Query(default=None),
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        user: User = Depends(require_permission("view")),
        db: Session = Depends(get_db)):
    query = db.query(Incident)
    if status:
        wanted = {s.strip() for s in status.split(",") if s.strip()
                  in STATUS_VALUES}
        if wanted:
            query = query.filter(Incident.status.in_(wanted))
    if severity:
        wanted = {s.strip() for s in severity.split(",")
                  if s.strip() in SEVERITY_RANK}
        if wanted:
            query = query.filter(Incident.severity.in_(wanted))
    # time-range filter (v0.10): ISO-Z strings compare lexicographically
    # the same as chronologically, so plain string comparison is correct
    if time_from:
        query = query.filter(Incident.last_seen >= time_from)
    if time_to:
        query = query.filter(Incident.first_seen <= time_to)
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(or_(
            Incident.title.ilike(like), Incident.id.ilike(like)))
    total = query.count()
    rows = query.order_by(Incident.last_seen.desc().nullslast(),
                          Incident.created_at.desc()) \
        .offset(offset).limit(limit).all()
    titles = _campaign_map(db, {r.campaign_id for r in rows})
    items = [_incident_out(r, titles) for r in rows]
    if outcome:
        items = [i for i in items if i.get("outcome_label") == outcome]
    return {"total": total, "items": items}


# --------------------------------------------------------------- summary
@router.get("/summary")
def incidents_summary(user: User = Depends(require_permission("view")),
                      db: Session = Depends(get_db)):
    rows = db.query(Incident).all()
    by_status: dict[str, int] = {}
    open_by_severity: dict[str, int] = {}
    by_outcome: dict[str, int] = {}
    for r in rows:
        by_status[r.status] = by_status.get(r.status, 0) + 1
        if r.status in ("open", "confirmed"):
            open_by_severity[r.severity] = \
                open_by_severity.get(r.severity, 0) + 1
        label = (r.outcome or {}).get("label", "indeterminate")
        by_outcome[label] = by_outcome.get(label, 0) + 1
    return {
        "total": len(rows),
        "by_status": by_status,
        "open_by_severity": open_by_severity,
        "by_outcome": by_outcome,
        "open_total": by_status.get("open", 0) + by_status.get("confirmed", 0),
    }


# --------------------------------------------------------------- detail
@router.get("/{incident_id}")
def incident_detail(incident_id: str,
                    user: User = Depends(require_permission("view")),
                    db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "incident not found")
    return _detail_out(inc, db)


# --------------------------------------------------------------- triage
@router.patch("/{incident_id}/status")
def update_status(incident_id: str, body: IncidentStatusUpdate,
                  request: Request,
                  user: User = Depends(require_permission("incident_update")),
                  db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "incident not found")
    previous = inc.status
    inc.status = body.status
    inc.analyst = user.username
    if body.note:
        db.add(IncidentNote(incident_id=incident_id,
                            author=user.username, body=body.note))
    db.add(IncidentHistory(
        incident_id=incident_id, actor=user.username,
        action="status_change",
        detail={"from": previous, "to": body.status,
                "note": body.note or None}))
    db.commit()
    audit(db, request, action="incident.status_change",
          target_type="incident", target_id=incident_id,
          detail={"from": previous, "to": body.status,
                  "note": body.note or None}, actor=user)
    return {"ok": True, "id": incident_id, "status": body.status}


@router.post("/{incident_id}/notes")
def add_note(incident_id: str, body: IncidentNoteCreate, request: Request,
             user: User = Depends(require_permission("incident_update")),
             db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "incident not found")
    note = IncidentNote(incident_id=incident_id, author=user.username,
                        body=body.body)
    db.add(note)
    db.add(IncidentHistory(incident_id=incident_id, actor=user.username,
                           action="note_added", detail={}))
    db.commit()
    audit(db, request, action="incident.note_add",
          target_type="incident", target_id=incident_id, actor=user)
    return {"ok": True, "id": incident_id}


# --------------------------------------------------------------- report
@router.get("/{incident_id}/report")
def incident_report(incident_id: str, request: Request,
                    user: User = Depends(require_permission("view")),
                    db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "incident not found")
    detail = _detail_out(inc, db)
    markdown = build_report(detail)
    audit(db, request, action="incident.report_download",
          target_type="incident", target_id=incident_id, actor=user)
    return Response(content=markdown, media_type="text/markdown",
                    headers={"Content-Disposition":
                             f'inline; filename="incident-{incident_id}.md"'})


# -------------------------------------------------- report versions (v0.12)
def _report_version_meta(v: IncidentReportVersion) -> dict:
    return {
        "version": v.version,
        "generated_by": v.generated_by,
        "incident_status": v.incident_status,
        "severity": v.severity,
        "outcome_label": v.outcome_label,
        "evidence_count": v.evidence_count,
        "signal_count": v.signal_count,
        "created_at": v.created_at.isoformat() if v.created_at else None,
    }


@router.post("/{incident_id}/reports")
def save_report_version(incident_id: str, request: Request,
                        user: User = Depends(
                            require_permission("incident_update")),
                        db: Session = Depends(get_db)):
    """Freeze the CURRENT report as the next version (v0.12).

    The snapshot is immutable afterwards: it records what the platform
    claimed at save time (status/severity/outcome/evidence counts), so
    later reconstruction or triage changes never rewrite history.
    """
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "incident not found")
    detail = _detail_out(inc, db)
    markdown = build_report(detail)
    last = db.query(IncidentReportVersion).filter(
        IncidentReportVersion.incident_id == incident_id).order_by(
        IncidentReportVersion.version.desc()).first()
    version = (last.version + 1) if last else 1
    rec = IncidentReportVersion(
        incident_id=incident_id, version=version, markdown=markdown,
        generated_by=user.username, incident_status=inc.status,
        severity=inc.severity,
        outcome_label=(inc.outcome or {}).get("label", "indeterminate"),
        evidence_count=inc.evidence_count,
        signal_count=inc.signal_count)
    db.add(rec)
    _history_entry(db, incident_id, user.username, "report_version_saved",
                   {"version": version})
    db.commit()
    audit(db, request, action="incident.report_version_save",
          target_type="incident", target_id=incident_id,
          detail={"version": version}, actor=user)
    return _report_version_meta(rec)


def _history_entry(db: Session, incident_id: str, actor: str, action: str,
                   detail: dict) -> None:
    db.add(IncidentHistory(incident_id=incident_id, actor=actor,
                           action=action, detail=detail))


@router.get("/{incident_id}/reports")
def list_report_versions(incident_id: str,
                         user: User = Depends(require_permission("view")),
                         db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "incident not found")
    rows = db.query(IncidentReportVersion).filter(
        IncidentReportVersion.incident_id == incident_id).order_by(
        IncidentReportVersion.version.desc()).all()
    return {"items": [_report_version_meta(r) for r in rows],
            "total": len(rows)}


@router.get("/{incident_id}/reports/{version}")
def get_report_version(incident_id: str, version: int, request: Request,
                       user: User = Depends(require_permission("view")),
                       db: Session = Depends(get_db)):
    rec = db.query(IncidentReportVersion).filter(
        IncidentReportVersion.incident_id == incident_id,
        IncidentReportVersion.version == version).first()
    if rec is None:
        raise HTTPException(404, "report version not found")
    audit(db, request, action="incident.report_version_download",
          target_type="incident", target_id=incident_id,
          detail={"version": version}, actor=user)
    return Response(content=rec.markdown, media_type="text/markdown",
                    headers={"Content-Disposition":
                             f'inline; filename="incident-{incident_id}-'
                             f'v{version}.md"'})
