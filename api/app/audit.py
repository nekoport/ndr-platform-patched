"""Audit helper (doc section 13.3 - minimum audit fields)."""

from __future__ import annotations

import uuid

from fastapi import Request
from sqlalchemy.orm import Session

from app.config import config
from app.models import AuditRecord, User


def client_ip(request: Request) -> str:
    # v0.13.0: X-Forwarded-For is attacker-controlled when the API is
    # exposed directly - only trust it behind the gateway (TRUST_PROXY=1)
    fwd = request.headers.get("X-Forwarded-For")
    if fwd and config.trust_proxy:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def audit(db: Session, request: Request | None, *, action: str,
          target_type: str | None = None, target_id: str | None = None,
          result: str = "success", detail: dict | None = None,
          actor: User | None = None) -> None:
    """Persist one audit record. Never raises into the request path."""
    try:
        record = AuditRecord(
            actor=actor.username if actor else (getattr(request.state, "user", None).username
                                                if request is not None and hasattr(request.state, "user")
                                                else "anonymous"),
            actor_role=actor.role if actor else None,
            action=action,
            target_type=target_type,
            target_id=target_id,
            result=result,
            source_ip=client_ip(request) if request else None,
            request_id=str(getattr(request.state, "request_id", ""))[:64] if request else None,
            detail=detail or {},
        )
        db.add(record)
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass


def new_request_id() -> str:
    return str(uuid.uuid4())
