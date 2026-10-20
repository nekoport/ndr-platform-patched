"""Security: password hashing, JWT, RBAC dependencies (doc section 12)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Callable

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, Response, status

from app.config import config
from app.db import get_db
from app.models import User

ROLES = ("administrator", "security_engineer", "soc_analyst",
         "soc_lead", "auditor")

# endpoint capability -> roles allowed (doc 12.2 baseline)
PERMISSIONS: dict[str, set[str]] = {
    "view": set(ROLES),
    "search": set(ROLES) - set(),           # all roles may search (auditor read-only)
    "alert_update": {"administrator", "security_engineer", "soc_analyst", "soc_lead"},
    "sensor_admin": {"administrator", "security_engineer"},
    "user_admin": {"administrator"},
    "audit_read": {"administrator", "auditor"},
    "ti_admin": {"administrator", "security_engineer"},   # doc 9.3 feed admin
    "incident_update": {"administrator", "security_engineer",
                        "soc_analyst", "soc_lead"},       # doc 10 triage
    "rule_admin": {"administrator", "security_engineer"},  # suricata rules
    # v0.11 system settings (rename, branding, NTP, network) - admin only
    "system_admin": {"administrator"},
    # doc 15.3: export access is role-limited; auditor is read-only
    # (AT-18/AT-28 - PCAP export denied without the right permission)
    "evidence_export": {"administrator", "security_engineer",
                        "soc_analyst", "soc_lead"},
    # v0.14.0 alert whitelist (allowlist): analysts may SUBMIT entries
    # (two-man rule -> pending); approve/reject/delete/extend is
    # restricted to the same trust level as TI/rule admin.
    "whitelist_create": {"administrator", "security_engineer",
                         "soc_analyst", "soc_lead"},
    "whitelist_admin": {"administrator", "security_engineer"},
}


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=10)).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:
        return False


def create_access_token(user: User) -> str:
    payload = {
        "sub": user.username,
        "role": user.role,
        "ver": user.token_version,
        "jti": str(uuid.uuid4()),
        "exp": datetime.utcnow() + timedelta(minutes=config.access_token_minutes),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, config.jwt_secret, algorithm=config.jwt_algorithm)


def decode_token(token: str) -> dict:
    return jwt.decode(token, config.jwt_secret, algorithms=[config.jwt_algorithm])


def set_session_cookie(response: Response, token: str) -> None:
    # v0.12: Secure flag follows config.tls_enabled (TLS_ENABLED=1) so
    # the session cookie is never sent over plain HTTP in TLS deploys.
    response.set_cookie(
        config.session_cookie, token,
        httponly=True, samesite="lax", secure=config.tls_enabled,
        max_age=config.access_token_minutes * 60, path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(config.session_cookie, path="/")


def _extract_token(request: Request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.cookies.get(config.session_cookie)


def get_current_user(request: Request, db=Depends(get_db)) -> User:
    token = _extract_token(request)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid session")

    user = db.query(User).filter(User.username == payload["sub"]).first()
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account disabled")
    if payload.get("ver") != user.token_version:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session revoked")
    request.state.user = user
    request.state.request_id = request.headers.get("X-Request-ID",
                                                   str(uuid.uuid4()))
    return user


def require_permission(capability: str) -> Callable:
    """Backend-enforced RBAC per endpoint (doc: never rely on hidden buttons)."""
    allowed = PERMISSIONS.get(capability, set())

    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Role '{user.role}' lacks permission '{capability}'")
        return user

    return dependency
