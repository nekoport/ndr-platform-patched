"""Manual asset registry router (v0.10).

The registry complements traffic-derived host profiles: machines the SOC
explicitly registers. Alert enrichment joins on `ip`, so alerts touching a
registered asset carry its hostname in the Alert Center.

Capabilities: view = all roles; mutations = sensor_admin
(administrator + security_engineer), matching the asset-management trust
level from the design doc. Every mutation is audited.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.audit import audit
from app.db import get_db
from app.models import Asset, User
from app.schemas import AssetCreate, AssetOut, AssetUpdate
from app.security import require_permission

router = APIRouter(prefix="/api/assets", tags=["assets"])


@router.get("", response_model=list[AssetOut])
def list_assets(user: User = Depends(require_permission("view")),
                db: Session = Depends(get_db)):
    return db.query(Asset).order_by(Asset.created_at.desc()).all()


@router.post("", response_model=AssetOut)
def create_asset(body: AssetCreate, request: Request,
                 user: User = Depends(require_permission("sensor_admin")),
                 db: Session = Depends(get_db)):
    if db.query(Asset).filter(Asset.ip == body.ip).first():
        raise HTTPException(409, f"Asset with IP {body.ip} already registered")
    asset = Asset(ip=body.ip, hostname=body.hostname, zone=body.zone,
                  role=body.role, criticality=body.criticality,
                  notes=body.notes, created_by=user.username)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    audit(db, request, action="asset.create", target_type="asset",
          target_id=asset.id, actor=user,
          detail={"ip": body.ip, "hostname": body.hostname})
    return asset


@router.patch("/{asset_id}", response_model=AssetOut)
def update_asset(asset_id: str, body: AssetUpdate, request: Request,
                 user: User = Depends(require_permission("sensor_admin")),
                 db: Session = Depends(get_db)):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    before = {"hostname": asset.hostname, "zone": asset.zone,
              "role": asset.role, "criticality": asset.criticality}
    for field in ("hostname", "zone", "role", "criticality", "notes"):
        value = getattr(body, field)
        if value is not None:
            setattr(asset, field, value)
    db.commit()
    audit(db, request, action="asset.update", target_type="asset",
          target_id=asset_id, actor=user,
          detail={"before": before,
                  "after": body.model_dump(exclude_none=True)})
    return asset


@router.delete("/{asset_id}")
def delete_asset(asset_id: str, request: Request,
                 user: User = Depends(require_permission("sensor_admin")),
                 db: Session = Depends(get_db)):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    db.delete(asset)
    db.commit()
    audit(db, request, action="asset.delete", target_type="asset",
          target_id=asset_id, actor=user,
          detail={"ip": asset.ip, "hostname": asset.hostname})
    return {"ok": True}


def asset_name_map(db: Session, ips: list[str]) -> dict[str, str]:
    """ip -> hostname for the given IPs (used by alert enrichment)."""
    if not ips:
        return {}
    rows = db.query(Asset).filter(Asset.ip.in_(list(set(ips)))).all()
    return {r.ip: r.hostname for r in rows}
