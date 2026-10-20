"""Sensors, users, audit routers (doc sections 12, 13, 14)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.audit import audit
from app.db import get_db
from app.models import AuditRecord, Sensor, User
from app.os_client import get_os
from app.schemas import (SensorCreate, SensorUpdate, UserCreate, UserUpdate,
                         UserOut)
from app.security import ROLES, hash_password, require_permission

router = APIRouter(prefix="/api", tags=["administration"])

# role display metadata for GET /api/roles (the capability matrix itself is
# security.PERMISSIONS - code-enforced, exposed here as read-only truth)
ROLE_META: dict[str, dict[str, str]] = {
    "administrator": {
        "label": "Administrator",
        "description": "Full platform control: users, sensors, rules, feeds, evidence export."},
    "security_engineer": {
        "label": "Security Engineer",
        "description": "Detection engineering: Suricata rules, TI feeds, sensors, asset registry."},
    "soc_lead": {
        "label": "SOC Lead",
        "description": "Triage oversight: confirms/closes incidents, assigns analysts."},
    "soc_analyst": {
        "label": "SOC Analyst",
        "description": "Day-to-day triage: works alerts and incidents, escalates, requests PCAP."},
    "auditor": {
        "label": "Auditor",
        "description": "Read-only compliance access: dashboard and audit log, no response actions."},
}

CAPABILITY_META: dict[str, str] = {
    "view": "View dashboards and entity detail",
    "search": "Search events, alerts, incidents",
    "alert_update": "Change alert status / assignee / notes",
    "incident_update": "Triage incidents (confirm, benign, close, notes)",
    "evidence_export": "Export PCAP / evidence bundles",
    "rule_admin": "Enable/disable Suricata rules, run rule updates",
    "ti_admin": "Manage TI feeds, IOC allowlist",
    "sensor_admin": "Register/modify capture sensors and assets",
    "user_admin": "Create, edit, delete users",
    "audit_read": "Read the audit log",
}


# ------------------------------------------------------------------ sensors

# v0.12.5: the pipeline heartbeats the sensors table (metrics.py), but a
# dead pipeline would leave the row 'online' forever. Status shown to the
# UI is therefore DERIVED from last_seen_at freshness, never trusted from
# the stored column.
SENSOR_FRESH_WINDOW = timedelta(minutes=5)


def effective_sensor_status(last_seen_at, stored_status: str | None) -> str:
    """Derive the displayed sensor status from heartbeat freshness."""
    if last_seen_at is None:
        return stored_status or "unknown"
    last = last_seen_at
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    age = datetime.now(timezone.utc) - last
    if age <= SENSOR_FRESH_WINDOW:
        return "online"
    if age <= SENSOR_FRESH_WINDOW * 3:
        return "degraded"
    return "offline"


@router.get("/sensors")
def list_sensors(user: User = Depends(require_permission("view")),
                 db: Session = Depends(get_db)):
    sensors = db.query(Sensor).order_by(Sensor.id).all()
    health_doc = get_os().latest_health_doc()
    fresh = {}
    if health_doc:
        fresh = {"sensor_id": health_doc.get("sensor_id"),
                 "last_event_time": health_doc.get("last_event_time"),
                 "eps": health_doc.get("eps")}
    return [{"id": s.id, "hostname": s.hostname,
             "capture_iface": s.capture_iface,
             "software_versions": s.software_versions,
             "status": effective_sensor_status(s.last_seen_at, s.status),
             "last_seen_at": s.last_seen_at.isoformat() if s.last_seen_at else None,
             "notes": s.notes,
             "pipeline": fresh if fresh.get("sensor_id") == s.id else None}
            for s in sensors]


@router.post("/sensors")
def create_sensor(body: SensorCreate, request: Request,
                  user: User = Depends(require_permission("sensor_admin")),
                  db: Session = Depends(get_db)):
    if db.query(Sensor).filter(Sensor.id == body.id).first():
        raise HTTPException(409, f"Sensor '{body.id}' already exists")
    sensor = Sensor(id=body.id, hostname=body.hostname,
                    capture_iface=body.capture_iface, notes=body.notes)
    db.add(sensor)
    db.commit()
    audit(db, request, action="sensor.create", target_type="sensor",
          target_id=body.id, actor=user, detail=body.model_dump())
    return {"ok": True, "id": body.id}


@router.patch("/sensors/{sensor_id}")
def update_sensor(sensor_id: str, body: SensorUpdate, request: Request,
                  user: User = Depends(require_permission("sensor_admin")),
                  db: Session = Depends(get_db)):
    sensor = db.query(Sensor).filter(Sensor.id == sensor_id).first()
    if sensor is None:
        raise HTTPException(404, "Sensor not found")
    before = {"hostname": sensor.hostname, "capture_iface": sensor.capture_iface,
              "status": sensor.status, "notes": sensor.notes}
    for field in ("hostname", "capture_iface", "status", "notes"):
        value = getattr(body, field)
        if value is not None:
            setattr(sensor, field, value)
    db.commit()
    audit(db, request, action="sensor.update", target_type="sensor",
          target_id=sensor_id, actor=user,
          detail={"before": before,
                  "after": body.model_dump(exclude_none=True)})
    return {"ok": True}


# ------------------------------------------------------------------ users
@router.get("/users", response_model=list[UserOut])
def list_users(user: User = Depends(require_permission("user_admin")),
               db: Session = Depends(get_db)):
    return db.query(User).order_by(User.username).all()


@router.post("/users", response_model=UserOut)
def create_user(body: UserCreate, request: Request,
                user: User = Depends(require_permission("user_admin")),
                db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(409, "Username already exists")
    created = User(username=body.username,
                   password_hash=hash_password(body.password),
                   role=body.role, full_name=body.full_name,
                   must_change_password=True)
    db.add(created)
    db.commit()
    db.refresh(created)
    # never audit plaintext passwords
    audit(db, request, action="user.create", target_type="user",
          target_id=body.username, actor=user,
          detail={"role": body.role})
    return created


@router.patch("/users/{username}", response_model=UserOut)
def update_user(username: str, body: UserUpdate, request: Request,
                user: User = Depends(require_permission("user_admin")),
                db: Session = Depends(get_db)):
    target = db.query(User).filter(User.username == username).first()
    if target is None:
        raise HTTPException(404, "User not found")
    before = {"role": target.role, "is_active": target.is_active}
    # last-admin guard (v0.10): disabling or demoting the only active
    # administrator would lock the platform out
    demotes = (body.role is not None and body.role != "administrator"
               and target.role == "administrator")
    disables = (body.is_active is False and target.role == "administrator"
                and target.is_active)
    if (demotes or disables) and target.is_active:
        other_admins = db.query(User).filter(
            User.role == "administrator", User.is_active.is_(True),
            User.username != username).count()
        if not other_admins:
            raise HTTPException(
                409, "Cannot disable or demote the last active administrator")
    if body.role is not None:
        target.role = body.role
    if body.is_active is not None:
        target.is_active = body.is_active
    if body.full_name is not None:
        target.full_name = body.full_name
    if body.new_password:
        target.password_hash = hash_password(body.new_password)
        target.must_change_password = True
    # force re-login everywhere after role/password changes
    target.token_version += 1
    db.commit()
    audit(db, request, action="user.update", target_type="user",
          target_id=username, actor=user,
          detail={"before": before,
                  "after": body.model_dump(exclude_none=True,
                                           exclude={"new_password"})})
    return target


# ------------------------------------------------------------------ audit
@router.get("/roles")
def list_roles(user: User = Depends(require_permission("view"))):
    """RBAC capability matrix as enforced by the backend (v0.10).

    Read-only on purpose: the matrix is code (doc section 12). Role
    assignment happens per user via POST/PATCH /api/users.
    """
    from app.security import PERMISSIONS
    return {
        "roles": [{"role": r,
                   "label": ROLE_META.get(r, {}).get("label", r),
                   "description": ROLE_META.get(r, {}).get("description", "")}
                  for r in ROLES],
        "capabilities": [{"capability": cap,
                          "description": CAPABILITY_META.get(cap, cap),
                          "roles": sorted(roles)}
                         for cap, roles in PERMISSIONS.items()],
    }


@router.delete("/users/{username}")
def delete_user(username: str, request: Request,
                user: User = Depends(require_permission("user_admin")),
                db: Session = Depends(get_db)):
    if username == user.username:
        raise HTTPException(400, "You cannot delete your own account")
    target = db.query(User).filter(User.username == username).first()
    if target is None:
        raise HTTPException(404, "User not found")
    if target.role == "administrator" and target.is_active:
        other_admins = db.query(User).filter(
            User.role == "administrator", User.is_active.is_(True),
            User.username != username).count()
        if not other_admins:
            raise HTTPException(409, "Cannot delete the last active administrator")
    db.delete(target)
    db.commit()
    audit(db, request, action="user.delete", target_type="user",
          target_id=username, actor=user,
          detail={"role": target.role})
    return {"ok": True}


@router.get("/audit")
def query_audit(request: Request,
                user: User = Depends(require_permission("audit_read")),
                db: Session = Depends(get_db),
                limit: int = 100, offset: int = 0,
                action: str | None = None, actor: str | None = None):
    limit = min(max(limit, 1), 500)
    query = db.query(AuditRecord)
    if action:
        query = query.filter(AuditRecord.action == action)
    if actor:
        query = query.filter(AuditRecord.actor == actor)
    total = query.count()
    rows = (query.order_by(AuditRecord.occurred_at.desc())
            .offset(offset).limit(limit).all())
    return {"total": total, "records": [{
        "id": r.id, "occurred_at": r.occurred_at.isoformat(),
        "actor": r.actor, "actor_role": r.actor_role, "action": r.action,
        "target_type": r.target_type, "target_id": r.target_id,
        "result": r.result, "source_ip": r.source_ip,
        "request_id": r.request_id, "detail": r.detail,
    } for r in rows]}
