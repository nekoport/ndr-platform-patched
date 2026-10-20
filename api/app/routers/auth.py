"""Auth router: login/logout/me/change-password (doc sections 12.1, 13.2)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.audit import audit, client_ip
from app.config import config
from app.db import get_db
from app.models import User
from app.rate_limit import SlidingWindowLimiter
from app.schemas import ChangePasswordRequest, LoginRequest
from app.security import (clear_session_cookie, create_access_token,
                          decode_token, get_current_user, hash_password,
                          set_session_cookie, verify_password)

router = APIRouter(prefix="/api/auth", tags=["auth"])

login_limiter = SlidingWindowLimiter(max_events=10, window_seconds=300)


def _aware(dt: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; PG returns aware. Normalize to UTC."""
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _lock_check(user: User) -> None:
    locked_until = _aware(user.locked_until)
    if locked_until and locked_until > datetime.now(timezone.utc):
        raise HTTPException(423, "Account temporarily locked; try again later")


@router.post("/login")
def login(body: LoginRequest, request: Request, response: Response,
          db: Session = Depends(get_db)):
    ip = client_ip(request)
    login_limiter.check(f"login:{ip}")

    user = db.query(User).filter(User.username == body.username).first()
    if user is None:
        audit(db, request, action="auth.login", result="failure",
              target_type="user", target_id=body.username,
              detail={"reason": "unknown user"})
        raise HTTPException(401, "Invalid credentials")

    _lock_check(user)
    if not user.is_active:
        audit(db, request, action="auth.login", result="denied",
              target_type="user", target_id=user.username,
              detail={"reason": "disabled"})
        raise HTTPException(401, "Invalid credentials")

    if not verify_password(body.password, user.password_hash):
        user.failed_attempts += 1
        if user.failed_attempts >= config.login_max_failed:
            user.locked_until = (datetime.now(timezone.utc)
                                 + timedelta(minutes=config.login_lockout_minutes))
            user.failed_attempts = 0
        db.commit()
        audit(db, request, action="auth.login", result="failure",
              target_type="user", target_id=user.username,
              detail={"failed_attempts": user.failed_attempts})
        raise HTTPException(401, "Invalid credentials")

    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    token = create_access_token(user)
    set_session_cookie(response, token)
    audit(db, request, action="auth.login", target_type="user",
          target_id=user.username, actor=user)
    return {"access_token": token, "token_type": "bearer",
            "must_change_password": user.must_change_password,
            "role": user.role, "username": user.username}


@router.post("/logout")
def logout(request: Request, response: Response,
           user: User = Depends(get_current_user),
           db: Session = Depends(get_db)):
    clear_session_cookie(response)
    audit(db, request, action="auth.logout", target_type="user",
          target_id=user.username, actor=user)
    return {"ok": True}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"username": user.username, "role": user.role,
            "full_name": user.full_name,
            "must_change_password": user.must_change_password}


@router.post("/change-password")
def change_password(body: ChangePasswordRequest, request: Request,
                    user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    if not verify_password(body.current_password, user.password_hash):
        audit(db, request, action="auth.change_password", result="failure",
              target_type="user", target_id=user.username, actor=user)
        raise HTTPException(400, "Current password is incorrect")
    if verify_password(body.new_password, user.password_hash):
        raise HTTPException(400, "New password must differ from current")
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    user.token_version += 1  # revoke all existing sessions
    db.commit()
    audit(db, request, action="auth.change_password", target_type="user",
          target_id=user.username, actor=user)
    return {"ok": True}


def bootstrap_admin(db: Session) -> None:
    """Create the first admin if the users table is empty (install flow)."""
    if db.query(User).count() > 0:
        return
    admin = User(username=config.admin_username,
                 password_hash=hash_password(config.admin_password),
                 role="administrator",
                 full_name="Bootstrap Administrator",
                 must_change_password=True)
    db.add(admin)
    db.commit()
    print(f"[ndr-api] bootstrap admin '{config.admin_username}' created "
          f"(must change password on first login)", flush=True)
