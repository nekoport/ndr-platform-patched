"""v0.14.0 Alert Whitelist (allowlist) - recurring false-positive control.

Governance model (agreed with the user, 2026-10):
  * analyst (soc_analyst/soc_lead) SUBMITS an entry -> status "pending";
  * administrator/security_engineer APPROVEs -> "active" (two-man rule);
  * admin/security_engineer creating an entry is self-approved instantly
    (small-team practicality) and IS audited with approved_by = creator;
  * mandatory reason, optional TTL (24h/30d/90d), guard against
    universe-wide entries, duplicate -> 409;
  * optional RETROACTIVE tagging of matching alerts (7 days, best-effort);
  * raw events and the attack story are NEVER touched.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.audit import audit
from app.db import get_db
from app.models import AlertAllowlist, User
from app.os_client import get_os
from app.security import require_permission

router = APIRouter(prefix="/api/allowlist", tags=["allowlist"])

# every alert_type the pipeline can emit (detection engine, doc 8)
ALLOWED_ALERT_TYPES = {
    "suricata_alert_group", "portscan_suspected", "beaconing_possible",
    "dns_nxdomain_burst", "dga_suspected", "dns_tunneling_suspected",
    "file_transfer_suspected", "internal_lateral_suspected", "ioc_match",
}
ALLOWED_ENTITY_FIELDS = {"src_ip", "dst_ip", "dst_domain"}
ALLOWED_LAYERS = {"L0", "L1"}
TTL_CHOICES_HOURS = {None, 24, 720, 2160}  # permanent / 24h / 30d / 90d

_UNIVERSE_VALUES = {"*", "0.0.0.0/0", "::/0", "::", "0.0.0.0/0 "}

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _normalize_entity(entity_field: str, raw: str) -> str:
    """Validate + canonicalize an entity value. Raises HTTPException 422."""
    value = (raw or "").strip()
    if not value:
        raise HTTPException(422, "entity_value must not be empty")
    if value.lower() in _UNIVERSE_VALUES:
        raise HTTPException(
            422, "universe-wide whitelist entries are not allowed "
                 "(this would disable detection entirely)")
    if entity_field in ("src_ip", "dst_ip"):
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise HTTPException(422, f"invalid IP or CIDR: {value!r}")
        if net.prefixlen == 0:
            raise HTTPException(422, "/0 CIDR is not allowed")
        if net.version == 4 and net.prefixlen < 8:
            raise HTTPException(
                422, "CIDR too broad (min /8 for IPv4) - split it into "
                     "more precise entries")
        return str(net)
    # dst_domain: store as a lowercase suffix with a leading dot
    d = value.lower().lstrip(".")
    if d.startswith("*."):
        d = d[2:]
    if len(d) < 3 or not _DOMAIN_RE.match(d):
        raise HTTPException(422, f"invalid domain: {value!r}")
    return f".{d}"


def _aware(dt: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; PostgreSQL returns aware ones.
    Comparisons must always happen in UTC-aware space."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _expires_at(hours: int | None) -> datetime | None:
    if hours is None:
        return None
    return datetime.now(timezone.utc) + timedelta(hours=int(hours))


def _expire_sweep(db: Session) -> None:
    """Lazily flip active entries past their TTL to 'expired' (kept in the
    UI for one-click renewal, per the agreed TTL design)."""
    now = datetime.now(timezone.utc)
    candidates = db.query(AlertAllowlist).filter(
        AlertAllowlist.status == "active",
        AlertAllowlist.expires_at.isnot(None)).all()
    stale = [e for e in candidates if _aware(e.expires_at) < now]
    for entry in stale:
        entry.status = "expired"
    if stale:
        db.commit()


def _entry_dto(entry: AlertAllowlist) -> dict:
    return {
        "id": entry.id,
        "alert_type": entry.alert_type,
        "signature": entry.signature,
        "entity_field": entry.entity_field,
        "entity_value": entry.entity_value,
        "layer": entry.layer,
        "status": entry.status,
        "reason": entry.reason,
        "retroactive": bool(entry.retroactive),
        "created_by": entry.created_by,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
        "approved_by": entry.approved_by,
        "approved_at": entry.approved_at.isoformat() if entry.approved_at else None,
        "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
        "hit_count": entry.hit_count,
        "last_hit_at": entry.last_hit_at.isoformat() if entry.last_hit_at else None,
    }


# ---------------------------------------------------------------- list
@router.get("")
def list_entries(status: str | None = None, alert_type: str | None = None,
                 user: User = Depends(require_permission("view")),
                 db: Session = Depends(get_db)):
    _expire_sweep(db)
    q = db.query(AlertAllowlist)
    if status:
        q = q.filter(AlertAllowlist.status == status)
    if alert_type:
        q = q.filter(AlertAllowlist.alert_type == alert_type)
    rows = q.order_by(AlertAllowlist.created_at.desc()).limit(500).all()
    return [_entry_dto(r) for r in rows]


# ---------------------------------------------------------------- summary
@router.get("/summary")
def summary(user: User = Depends(require_permission("view")),
            db: Session = Depends(get_db)):
    """Overview card feed: how much noise the whitelist is eating."""
    _expire_sweep(db)
    rows = db.query(AlertAllowlist).all()
    active = [r for r in rows if r.status == "active"]
    pending = [r for r in rows if r.status == "pending"]
    expired = [r for r in rows if r.status == "expired"]
    rejected = [r for r in rows if r.status == "rejected"]
    top = sorted(active, key=lambda r: r.hit_count, reverse=True)[:5]
    return {
        "active": len(active),
        "pending": len(pending),
        "expired": len(expired),
        "rejected": len(rejected),
        "total_hits": sum(r.hit_count for r in active),
        "l0": sum(1 for r in active if r.layer == "L0"),
        "l1": sum(1 for r in active if r.layer == "L1"),
        "top": [{"id": r.id, "alert_type": r.alert_type,
                 "entity_field": r.entity_field,
                 "entity_value": r.entity_value, "layer": r.layer,
                 "hit_count": r.hit_count,
                 "last_hit_at": r.last_hit_at.isoformat()
                 if r.last_hit_at else None} for r in top],
    }


# ---------------------------------------------------------------- create
from pydantic import BaseModel, Field  # noqa: E402 - keep router self-contained


class AllowlistCreate(BaseModel):
    alert_type: str
    signature: str | None = None
    entity_field: str
    entity_value: str
    layer: str = "L1"
    reason: str = Field(min_length=5, max_length=2000)
    ttl_hours: int | None = None
    retroactive: bool = False


def _apply_retroactive(db: Session, entry: AlertAllowlist) -> int:
    """Best-effort by design: a cluster hiccup must never fail the
    whitelist write itself (entry stays usable; hit counter unaffected)."""
    try:
        tagged = get_os().suppress_alert_docs(
            alert_type=entry.alert_type, signature=entry.signature,
            entity_field=entry.entity_field, entity_value=entry.entity_value,
            suppressed_by=entry.id)
    except Exception:  # noqa: BLE001 - retro is an optimization, not a gate
        return 0
    if tagged:
        entry.hit_count = (entry.hit_count or 0) + tagged
        db.commit()
    return int(tagged or 0)


@router.post("", status_code=201)
def create_entry(body: AllowlistCreate, request: Request,
                 user: User = Depends(require_permission("whitelist_create")),
                 db: Session = Depends(get_db)):
    if body.alert_type not in ALLOWED_ALERT_TYPES:
        raise HTTPException(422, f"unknown alert_type: {body.alert_type}")
    if body.entity_field not in ALLOWED_ENTITY_FIELDS:
        raise HTTPException(422, f"unknown entity_field: {body.entity_field}")
    if body.layer not in ALLOWED_LAYERS:
        raise HTTPException(422, f"layer must be one of {sorted(ALLOWED_LAYERS)}")
    if body.ttl_hours not in TTL_CHOICES_HOURS:
        raise HTTPException(422, "ttl_hours must be one of: null, 24, 720, 2160")
    signature = (body.signature or "").strip() or None
    if signature and len(signature) > 255:
        raise HTTPException(422, "signature too long (max 255)")
    entity_value = _normalize_entity(body.entity_field, body.entity_value)

    existing = db.query(AlertAllowlist).filter(
        AlertAllowlist.alert_type == body.alert_type,
        AlertAllowlist.entity_field == body.entity_field,
        AlertAllowlist.entity_value == entity_value,
        AlertAllowlist.signature == signature).first()
    if existing is not None and existing.status in ("pending", "active"):
        raise HTTPException(409, "an entry with this scope already exists")

    is_admin = user.role in ("administrator", "security_engineer")
    entry = AlertAllowlist(
        alert_type=body.alert_type, signature=signature,
        entity_field=body.entity_field, entity_value=entity_value,
        layer=body.layer,
        status="active" if is_admin else "pending",
        reason=body.reason.strip(), retroactive=body.retroactive,
        created_by=user.username,
        approved_by=user.username if is_admin else None,
        approved_at=datetime.now(timezone.utc) if is_admin else None,
        expires_at=_expires_at(body.ttl_hours))
    db.add(entry)
    db.commit()
    db.refresh(entry)

    retro_tagged = 0
    if entry.status == "active" and body.retroactive:
        retro_tagged = _apply_retroactive(db, entry)

    audit(db, request, action="whitelist.create", target_type="allowlist",
          target_id=str(entry.id),
          detail={"alert_type": entry.alert_type, "signature": signature,
                  "entity_field": entry.entity_field,
                  "entity_value": entry.entity_value, "layer": entry.layer,
                  "status": entry.status, "ttl_hours": body.ttl_hours,
                  "retro_tagged": retro_tagged}, actor=user)
    dto = _entry_dto(entry)
    dto["retro_tagged"] = retro_tagged
    return dto


# ---------------------------------------------------------------- approve
@router.post("/{entry_id}/approve")
def approve_entry(entry_id: int, request: Request,
                  user: User = Depends(require_permission("whitelist_admin")),
                  db: Session = Depends(get_db)):
    entry = db.query(AlertAllowlist).filter(
        AlertAllowlist.id == entry_id).first()
    if entry is None:
        raise HTTPException(404, "whitelist entry not found")
    if entry.status == "active":
        raise HTTPException(409, "entry is already active")
    if entry.status in ("rejected", "expired"):
        entry.status = "active"
    else:  # pending
        entry.status = "active"
    entry.approved_by = user.username
    entry.approved_at = datetime.now(timezone.utc)
    db.commit()

    retro_tagged = 0
    if entry.retroactive:
        retro_tagged = _apply_retroactive(db, entry)

    audit(db, request, action="whitelist.approve", target_type="allowlist",
          target_id=str(entry.id),
          detail={"entity_value": entry.entity_value,
                  "layer": entry.layer, "retro_tagged": retro_tagged},
          actor=user)
    dto = _entry_dto(entry)
    dto["retro_tagged"] = retro_tagged
    return dto


@router.post("/{entry_id}/reject")
def reject_entry(entry_id: int, request: Request,
                 user: User = Depends(require_permission("whitelist_admin")),
                 db: Session = Depends(get_db)):
    entry = db.query(AlertAllowlist).filter(
        AlertAllowlist.id == entry_id).first()
    if entry is None:
        raise HTTPException(404, "whitelist entry not found")
    if entry.status != "pending":
        raise HTTPException(409, "only pending entries can be rejected")
    entry.status = "rejected"
    entry.approved_by = user.username
    entry.approved_at = datetime.now(timezone.utc)
    db.commit()
    audit(db, request, action="whitelist.reject", target_type="allowlist",
          target_id=str(entry.id),
          detail={"entity_value": entry.entity_value}, actor=user)
    return _entry_dto(entry)


# ---------------------------------------------------------------- extend
class ExtendBody(BaseModel):
    days: int = Field(ge=1, le=365)


@router.post("/{entry_id}/extend")
def extend_entry(entry_id: int, body: ExtendBody, request: Request,
                 user: User = Depends(require_permission("whitelist_admin")),
                 db: Session = Depends(get_db)):
    entry = db.query(AlertAllowlist).filter(
        AlertAllowlist.id == entry_id).first()
    if entry is None:
        raise HTTPException(404, "whitelist entry not found")
    now = datetime.now(timezone.utc)
    exp = _aware(entry.expires_at)
    base = exp if (exp is not None and exp > now) else now
    entry.expires_at = base + timedelta(days=int(body.days))
    if entry.status == "expired":
        entry.status = "active"
    db.commit()
    audit(db, request, action="whitelist.extend", target_type="allowlist",
          target_id=str(entry.id),
          detail={"days": body.days,
                  "new_expires_at": entry.expires_at.isoformat()}, actor=user)
    return _entry_dto(entry)


# ---------------------------------------------------------------- delete
@router.delete("/{entry_id}", status_code=204)
def delete_entry(entry_id: int, request: Request,
                 user: User = Depends(require_permission("whitelist_admin")),
                 db: Session = Depends(get_db)):
    entry = db.query(AlertAllowlist).filter(
        AlertAllowlist.id == entry_id).first()
    if entry is None:
        raise HTTPException(404, "whitelist entry not found")
    detail = {"alert_type": entry.alert_type, "signature": entry.signature,
              "entity_field": entry.entity_field,
              "entity_value": entry.entity_value, "layer": entry.layer}
    db.delete(entry)
    db.commit()
    audit(db, request, action="whitelist.delete", target_type="allowlist",
          target_id=str(entry_id), detail=detail, actor=user)
    return None
