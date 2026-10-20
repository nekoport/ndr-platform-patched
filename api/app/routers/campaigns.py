"""Campaign router (v0.12 - analyst grouping of incidents).

Endpoints:
  GET    /api/campaigns                          list campaigns (view)
  GET    /api/campaigns/{id}                     detail + member incidents (view)
  POST   /api/campaigns                          create + merge members (incident_update)
  PATCH  /api/campaigns/{id}                     rename / describe / close (incident_update)
  POST   /api/campaigns/{id}/incidents           merge more incidents in (incident_update)
  DELETE /api/campaigns/{id}/incidents/{iid}     split one incident out (incident_update)
  DELETE /api/campaigns/{id}                    dissolve: detach all + delete (incident_update)

Design rules (in the spirit of the reconstruction contract):
  * Campaigns are analyst bookkeeping ONLY. Merging or splitting never
    rewrites incident evidence, entities, edges, outcome or confidence -
    the correlation engine remains the single source of relations.
  * Rollup fields (severity, first_seen, last_seen, incident_count) are
    recomputed from current members on every membership change.
  * Attaching an incident that already belongs to another campaign MOVES
    it (last-write-wins) and leaves an incident-history trail on both
    campaigns' sides.
  * Every mutation is audited.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.audit import audit
from app.db import get_db
from app.models import Campaign, Incident, IncidentHistory, User
from app.schemas import (CampaignCreate, CampaignMembership, CampaignUpdate)
from app.security import require_permission

router = APIRouter(prefix="/api/campaigns", tags=["campaigns"])

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1,
                 "informational": 0}
RANK_TO_SEVERITY = {v: k for k, v in SEVERITY_RANK.items()}


def _campaign_out(c: Campaign) -> dict:
    return {
        "id": c.id,
        "title": c.title,
        "description": c.description or "",
        "status": c.status,
        "created_by": c.created_by,
        "incident_count": c.incident_count,
        "severity": c.severity,
        "first_seen": c.first_seen,
        "last_seen": c.last_seen,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


def _recompute_rollup(db: Session, campaign: Campaign) -> None:
    # the app session runs with autoflush=False: membership changes made
    # in this request must be flushed before the rollup query, otherwise
    # it counts the PREVIOUS membership state
    db.flush()
    members = db.query(Incident).filter(
        Incident.campaign_id == campaign.id).all()
    campaign.incident_count = len(members)
    if not members:
        campaign.severity = "low"
        campaign.first_seen = None
        campaign.last_seen = None
        return
    worst = max(members, key=lambda i: SEVERITY_RANK.get(i.severity, 0))
    campaign.severity = worst.severity
    seen_first = [i.first_seen for i in members if i.first_seen]
    seen_last = [i.last_seen for i in members if i.last_seen]
    campaign.first_seen = min(seen_first) if seen_first else None
    campaign.last_seen = max(seen_last) if seen_last else None


def _history(db: Session, incident_id: str, actor: str, action: str,
             detail: dict) -> None:
    db.add(IncidentHistory(incident_id=incident_id, actor=actor,
                           action=action, detail=detail))


def _validate_members(db: Session, incident_ids: list[str]) -> list[Incident]:
    rows = db.query(Incident).filter(
        Incident.id.in_(incident_ids)).all()
    found = {r.id for r in rows}
    missing = [i for i in incident_ids if i not in found]
    if missing:
        raise HTTPException(400, "unknown incident ids: "
                                 f"{', '.join(missing[:10])}")
    return rows


# --------------------------------------------------------------- list
@router.get("")
def list_campaigns(
        status: str | None = Query(default=None),
        q: str | None = Query(default=None, max_length=128),
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        user: User = Depends(require_permission("view")),
        db: Session = Depends(get_db)):
    query = db.query(Campaign)
    if status in ("open", "closed"):
        query = query.filter(Campaign.status == status)
    if q:
        query = query.filter(Campaign.title.ilike(f"%{q.lower()}%"))
    total = query.count()
    rows = query.order_by(Campaign.updated_at.desc()) \
        .offset(offset).limit(limit).all()
    return {"total": total, "items": [_campaign_out(c) for c in rows]}


# ------------------------------------------------------------- detail
@router.get("/{campaign_id}")
def campaign_detail(campaign_id: str,
                    user: User = Depends(require_permission("view")),
                    db: Session = Depends(get_db)):
    c = db.get(Campaign, campaign_id)
    if c is None:
        raise HTTPException(404, "campaign not found")
    members = db.query(Incident).filter(
        Incident.campaign_id == campaign_id).order_by(
        Incident.last_seen.desc().nullslast()).all()
    from app.routers.incidents import _incident_out
    return {**_campaign_out(c),
            "incidents": [_incident_out(i) for i in members]}


# ------------------------------------------------------------- create
@router.post("")
def create_campaign(body: CampaignCreate, request: Request,
                    user: User = Depends(require_permission("incident_update")),
                    db: Session = Depends(get_db)):
    rows = _validate_members(db, body.incident_ids)
    # incidents already in another campaign move here (last-write-wins)
    previous: dict[str, str | None] = {}
    for r in rows:
        previous[r.id] = r.campaign_id
    campaign = Campaign(
        id=f"cmp-{uuid.uuid4().hex[:12]}",
        title=body.title.strip(),
        description=(body.description or "").strip(),
        status="open",
        created_by=user.username)
    db.add(campaign)
    for r in rows:
        r.campaign_id = campaign.id
        _history(db, r.id, user.username, "campaign_merge", {
            "campaign_id": campaign.id, "campaign_title": campaign.title,
            "previous_campaign_id": previous[r.id]})
    _recompute_rollup(db, campaign)
    # campaigns the incidents were moved OUT OF need a rollup refresh too
    old_ids = {v for v in previous.values() if v and v != campaign.id}
    for oid in old_ids:
        old = db.get(Campaign, oid)
        if old is not None:
            _recompute_rollup(db, old)
    db.commit()
    audit(db, request, action="campaign.create",
          target_type="campaign", target_id=campaign.id,
          detail={"title": campaign.title,
                  "incident_ids": [r.id for r in rows]}, actor=user)
    return _campaign_out(campaign)


# ------------------------------------------------------------- update
@router.patch("/{campaign_id}")
def update_campaign(campaign_id: str, body: CampaignUpdate, request: Request,
                    user: User = Depends(require_permission("incident_update")),
                    db: Session = Depends(get_db)):
    c = db.get(Campaign, campaign_id)
    if c is None:
        raise HTTPException(404, "campaign not found")
    changes: dict = {}
    if body.title is not None and body.title.strip() != c.title:
        changes["title"] = {"from": c.title, "to": body.title.strip()}
        c.title = body.title.strip()
    if body.description is not None and body.description.strip() != \
            (c.description or ""):
        changes["description"] = {"from": c.description or "",
                                  "to": body.description.strip()}
        c.description = body.description.strip()
    if body.status is not None and body.status != c.status:
        changes["status"] = {"from": c.status, "to": body.status}
        c.status = body.status
    if changes:
        members = db.query(Incident).filter(
            Incident.campaign_id == c.id).all()
        for m in members:
            _history(db, m.id, user.username, "campaign_update",
                     {"campaign_id": c.id, **changes})
        db.commit()
        audit(db, request, action="campaign.update",
              target_type="campaign", target_id=c.id,
              detail=changes, actor=user)
    return _campaign_out(c)


# ------------------------------------------------------------- merge
@router.post("/{campaign_id}/incidents")
def attach_incidents(campaign_id: str, body: CampaignMembership,
                     request: Request,
                     user: User = Depends(require_permission("incident_update")),
                     db: Session = Depends(get_db)):
    c = db.get(Campaign, campaign_id)
    if c is None:
        raise HTTPException(404, "campaign not found")
    rows = _validate_members(db, body.incident_ids)
    previous: dict[str, str | None] = {}
    for r in rows:
        previous[r.id] = r.campaign_id
        r.campaign_id = c.id
        _history(db, r.id, user.username, "campaign_merge", {
            "campaign_id": c.id, "campaign_title": c.title,
            "previous_campaign_id": previous[r.id]})
    _recompute_rollup(db, c)
    # campaigns the incidents were moved OUT OF need a rollup refresh too
    old_ids = {v for v in previous.values() if v and v != c.id}
    for oid in old_ids:
        old = db.get(Campaign, oid)
        if old is not None:
            _recompute_rollup(db, old)
    db.commit()
    audit(db, request, action="campaign.merge",
          target_type="campaign", target_id=c.id,
          detail={"incident_ids": [r.id for r in rows],
                  "previous": previous}, actor=user)
    return _campaign_out(c)


# ------------------------------------------------------------- split
@router.delete("/{campaign_id}/incidents/{incident_id}")
def detach_incident(campaign_id: str, incident_id: str, request: Request,
                    user: User = Depends(require_permission("incident_update")),
                    db: Session = Depends(get_db)):
    c = db.get(Campaign, campaign_id)
    if c is None:
        raise HTTPException(404, "campaign not found")
    inc = db.get(Incident, incident_id)
    if inc is None or inc.campaign_id != c.id:
        raise HTTPException(404, "incident is not a member of this campaign")
    inc.campaign_id = None
    _history(db, incident_id, user.username, "campaign_split",
             {"campaign_id": c.id, "campaign_title": c.title})
    _recompute_rollup(db, c)
    db.commit()
    audit(db, request, action="campaign.split",
          target_type="campaign", target_id=c.id,
          detail={"incident_id": incident_id}, actor=user)
    return _campaign_out(c)


# ----------------------------------------------------------- dissolve
@router.delete("/{campaign_id}")
def dissolve_campaign(campaign_id: str, request: Request,
                      user: User = Depends(require_permission("incident_update")),
                      db: Session = Depends(get_db)):
    c = db.get(Campaign, campaign_id)
    if c is None:
        raise HTTPException(404, "campaign not found")
    members = db.query(Incident).filter(
        Incident.campaign_id == c.id).all()
    detached = [m.id for m in members]
    for m in members:
        m.campaign_id = None
        _history(db, m.id, user.username, "campaign_split",
                 {"campaign_id": c.id, "campaign_title": c.title,
                  "campaign_dissolved": True})
    db.delete(c)
    db.commit()
    audit(db, request, action="campaign.dissolve",
          target_type="campaign", target_id=campaign_id,
          detail={"detached": detached}, actor=user)
    return {"ok": True, "detached": detached}
