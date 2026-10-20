"""System settings router (v0.11).

Endpoints:
  GET  /api/settings              everything the UI needs in one call (view)
  PATCH /api/settings/system      rename the console (system_admin)
  PATCH /api/settings/branding    custom logo / favicon data URLs (system_admin)
  PATCH /api/settings/ntp         NTP servers + timezone (system_admin)
  POST /api/settings/ntp/status   best-effort NTP sync state (system_admin)
  GET  /api/settings/network      interfaces / hostname / resolvers (view)
  PATCH /api/settings/network     hostname + resolvers (system_admin, honest
                                  about what a container may change)
  POST /api/settings/diagnosis    ping / traceroute / dns / port check
                                  (sensor_admin; fixed argv, no shell)

Settings persist in the system_settings table (JSON per key). Everything
mutating is audited. The diagnosis tools never touch a shell: argv lists
plus a strict target regex (validated twice - schema + here).
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.audit import audit
from app import __version__
from app.db import get_db
from app.models import SystemSetting, User
from app.schemas import (BrandingPatch, DiagnoseRequest, NetworkPatch,
                         NtpPatch, SystemPatch)
from app.security import require_permission

router = APIRouter(prefix="/api/settings", tags=["system-settings"])

DEFAULTS = {
    "system": {"name": "NDR Console",
               "tagline": "network detection & response"},
    "branding": {"logo": None, "favicon": None},
    "ntp": {"servers": ["time.google.com", "id.pool.ntp.org"],
            "timezone": "Asia/Jakarta", "enabled": True},
    "network": {"hostname": socket.gethostname(),
                "dns_servers": ["1.1.1.1", "8.8.8.8"]},
}
KEYS = tuple(DEFAULTS)

TARGET_RE = re.compile(r"^[a-zA-Z0-9._:-]{1,253}$")
MAX_LOG = 4000


def _get(db: Session, key: str) -> dict:
    row = db.get(SystemSetting, key)
    base = dict(DEFAULTS[key])
    if row and isinstance(row.value, dict):
        base.update(row.value)
    return base


def _put(db: Session, key: str, value: dict, actor: User) -> None:
    row = db.get(SystemSetting, key)
    if row is None:
        row = SystemSetting(key=key, value=value)
        db.add(row)
    else:
        row.value = value
    row.updated_at = datetime.now(timezone.utc)
    row.updated_by = actor.username
    db.commit()


@router.get("")
def get_settings(user: User = Depends(require_permission("view")),
                 db: Session = Depends(get_db)):
    return {
        "version": __version__,
        "system": _get(db, "system"),
        "branding": _get(db, "branding"),
        "ntp": _get(db, "ntp"),
        "network": {**_get(db, "network"),
                    "interfaces": _interfaces()},
    }


# ---------------------------------------------------------------- system
@router.patch("/system")
def patch_system(body: SystemPatch, request: Request,
                 user: User = Depends(require_permission("system_admin")),
                 db: Session = Depends(get_db)):
    cur = _get(db, "system")
    changed = {}
    if body.name is not None:
        cur["name"] = body.name
        changed["name"] = body.name
    if body.tagline is not None:
        cur["tagline"] = body.tagline
        changed["tagline"] = body.tagline
    _put(db, "system", cur, user)
    audit(db, request, action="settings.system", target_type="settings",
          detail=changed, actor=user)
    return cur


# -------------------------------------------------------------- branding
@router.patch("/branding")
def patch_branding(body: BrandingPatch, request: Request,
                   user: User = Depends(require_permission("system_admin")),
                   db: Session = Depends(get_db)):
    cur = _get(db, "branding")
    changed = {}
    if body.reset_logo:
        cur["logo"] = None
        changed["logo"] = "reset"
    elif body.logo_data_url:
        cur["logo"] = body.logo_data_url
        changed["logo"] = f"{len(body.logo_data_url)} chars"
    if body.reset_favicon:
        cur["favicon"] = None
        changed["favicon"] = "reset"
    elif body.favicon_data_url:
        cur["favicon"] = body.favicon_data_url
        changed["favicon"] = f"{len(body.favicon_data_url)} chars"
    _put(db, "branding", cur, user)
    audit(db, request, action="settings.branding", target_type="settings",
          detail=changed, actor=user)
    return cur


# ------------------------------------------------------------------- ntp
TIMEZONES_FALLBACK = (
    "Asia/Jakarta", "Asia/Pontianak", "Asia/Makassar", "Asia/Jayapura",
    "Asia/Singapore", "Asia/Tokyo", "UTC", "Europe/London", "Europe/Berlin",
    "America/New_York", "America/Los_Angeles",
)


@router.patch("/ntp")
def patch_ntp(body: NtpPatch, request: Request,
              user: User = Depends(require_permission("system_admin")),
              db: Session = Depends(get_db)):
    cur = _get(db, "ntp")
    changed = {}
    if body.servers:
        cur["servers"] = body.servers
        changed["servers"] = body.servers
    if body.timezone is not None:
        try:
            from zoneinfo import ZoneInfo
            ZoneInfo(body.timezone)
        except Exception:  # noqa: BLE001 - unknown tz rejected honestly
            raise HTTPException(422, f"unknown timezone {body.timezone!r}")
        cur["timezone"] = body.timezone
        changed["timezone"] = body.timezone
    if body.enabled is not None:
        cur["enabled"] = body.enabled
        changed["enabled"] = body.enabled
    _put(db, "ntp", cur, user)
    audit(db, request, action="settings.ntp", target_type="settings",
          detail=changed, actor=user)
    return cur


@router.post("/ntp/status")
def ntp_status(request: Request,
               user: User = Depends(require_permission("system_admin")),
               db: Session = Depends(get_db)):
    """Best-effort NTP state: chrony -> timedatectl -> honest fallback."""
    cfg = _get(db, "ntp")
    for cmd in (["chronyc", "tracking"], ["timedatectl", "show"]):
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv
                cmd, capture_output=True, text=True, timeout=5)
            if proc.returncode == 0:
                return {"available": True, "tool": cmd[0],
                        "output": proc.stdout.strip()[:MAX_LOG],
                        "config": cfg}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    # last resort: can we even reach the first configured server?
    server = (cfg.get("servers") or [""])[0]
    reachable = False
    if server:
        try:
            reachable = socket.getaddrinfo(server, 123,
                                           type=socket.SOCK_DGRAM) is not None
        except OSError:
            reachable = False
    return {"available": False, "tool": None,
            "output": "no chronyc/timedatectl in this environment - "
                      "configure the host's NTP daemon (chrony/systemd-"
                      "timesyncd) and verify with 'chronyc tracking'",
            "first_server_resolvable": reachable, "config": cfg}


# --------------------------------------------------------------- network
def _interfaces() -> list[dict]:
    """Enumerate interfaces: `ip -j addr` when present, /sys fallback."""
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv
            ["ip", "-j", "addr"], capture_output=True, text=True, timeout=5)
        if proc.returncode == 0:
            import json as _json
            data = _json.loads(proc.stdout or "[]")
            out = []
            for it in data:
                addrs = [a.get("local") for a in it.get("addr_info", [])
                         if a.get("local")]
                out.append({"name": it.get("name"),
                            "state": "up" if it.get("operstate")
                            in ("UP", "UNKNOWN") else
                            str(it.get("operstate", "down")).lower(),
                            "mac": it.get("address"),
                            "addrs": addrs})
            return out
    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
        pass
    out = []
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            try:
                with open(f"/sys/class/net/{name}/operstate") as fh:
                    state = fh.read().strip()
            except OSError:
                state = "unknown"
            out.append({"name": name, "state": state, "mac": None,
                        "addrs": []})
    except OSError:
        pass
    return out


def _resolv_dns() -> list[str]:
    try:
        with open("/etc/resolv.conf") as fh:
            return [ln.split()[1] for ln in fh
                    if ln.startswith("nameserver")
                    and len(ln.split()) > 1][:4]
    except OSError:
        return []


@router.get("/network")
def network_info(user: User = Depends(require_permission("view")),
                 db: Session = Depends(get_db)):
    return {**_get(db, "network"),
            "system_dns": _resolv_dns(),
            "interfaces": _interfaces()}


@router.patch("/network")
def patch_network(body: NetworkPatch, request: Request,
                  user: User = Depends(require_permission("system_admin")),
                  db: Session = Depends(get_db)):
    cur = _get(db, "network")
    changed = {}
    applied = True
    notes: list[str] = []
    if body.hostname is not None and body.hostname != cur.get("hostname"):
        # attempt the host change; inside a container this is expected to
        # fail - report honestly instead of pretending
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv
                ["hostnamectl", "set-hostname", body.hostname],
                capture_output=True, text=True, timeout=5)
            if proc.returncode != 0:
                applied = False
                notes.append("hostnamectl failed: "
                             f"{(proc.stderr or '').strip()[:200] or 'no permission'}")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            applied = False
            notes.append("hostnamectl not available here - run on the NDR "
                         "host: sudo hostnamectl set-hostname "
                         f"{body.hostname}")
        cur["hostname"] = body.hostname
        changed["hostname"] = body.hostname
    if body.dns_servers is not None:
        cur["dns_servers"] = body.dns_servers
        changed["dns_servers"] = body.dns_servers
        notes.append("resolvers are persisted in settings; apply them in "
                     "your netplan/resolv.conf management for enforcement")
    _put(db, "network", cur, user)
    audit(db, request, action="settings.network", target_type="settings",
          detail={"changed": changed, "applied": applied}, actor=user)
    return {**cur, "applied": applied, "notes": notes,
            "interfaces": _interfaces()}


# ------------------------------------------------------------- diagnosis
def _run_tool(argv: list[str], timeout: int) -> tuple[bool, str]:
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, validated target
            argv, capture_output=True, text=True, timeout=timeout)
        out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        return proc.returncode == 0, out[:MAX_LOG]
    except FileNotFoundError:
        return False, f"{argv[0]} is not installed in this environment"
    except subprocess.TimeoutExpired:
        return False, f"{argv[0]} timed out after {timeout}s"


@router.post("/diagnosis")
def diagnosis(body: DiagnoseRequest, request: Request,
              user: User = Depends(require_permission("sensor_admin")),
              db: Session = Depends(get_db)):
    target = body.target.strip()
    if not TARGET_RE.match(target):
        raise HTTPException(422, "target must be a hostname or IP")
    tool = body.tool
    started = datetime.now(timezone.utc).isoformat()
    if tool == "ping":
        ok, output = _run_tool(
            ["ping", "-c", str(body.count), "-W", "2", target], 15)
    elif tool == "traceroute":
        ok, output = _run_tool(
            ["traceroute", "-n", "-w", "1", "-q", "1", "-m", "15", target],
            45)
    elif tool == "dns":
        try:
            infos = socket.getaddrinfo(target, None)
            addrs = sorted({i[4][0] for i in infos})
            ok, output = True, (
                f"{target} resolves to: {', '.join(addrs)}")
        except OSError as e:
            ok, output = False, f"DNS resolution failed: {e}"
    else:  # port
        port = body.port or 80
        try:
            with socket.create_connection((target, port), timeout=3):
                ok, output = True, f"TCP {target}:{port} open"
        except OSError as e:
            ok, output = False, f"TCP {target}:{port} not reachable: {e}"
    audit(db, request, action="settings.diagnosis", target_type="network",
          target_id=f"{tool}:{target}",
          detail={"ok": ok, "port": body.port}, actor=user)
    return {"tool": tool, "target": target, "ok": ok, "output": output,
            "at": started}
