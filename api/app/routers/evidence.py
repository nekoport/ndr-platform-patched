"""PCAP & evidence workflow router (doc section 15 - Phase 6).

Endpoints:
  GET  /api/evidence/pcap/storage                     capture storage stats (view)
  GET  /api/evidence/alerts/{alert_id}/sessions       resolve sessions + status (view)
  GET  /api/evidence/incidents/{id}/sessions          resolve sessions + status (view)
  POST /api/evidence/pcap/export                      selective export bundle (evidence_export)
  GET  /api/evidence/pcap/exports                     export register (view)
  GET  /api/evidence/pcap/exports/{id}/download       download export bundle (evidence_export)

What this implements, honestly:
  * doc 15.1 - sessions are resolved from the alert/incident entities and
    a bounded time window (with a configurable pre/post capture buffer);
    the analyst sees the sessions BEFORE any export and picks a subset;
    the backend re-resolves every selected session server-side and
    enforces size/duration limits before touching capture storage.
  * doc 15.2 - every session carries an evidence status (available /
    partially_available / expired / not_captured) derived from the
    rolling capture coverage window, so "no evidence" is distinguishable
    from "sensor did not capture" and "pruned by retention".
  * doc 15.3 - exports produce a zip bundle + manifest.json with SHA-256
    per file and for the bundle, and every export/download/expiry is
    recorded (pcap_exports table + audit log) with actor, reason, scope,
    sizes and hashes. Files are removed automatically after TTL.
  * Granularity is FILE-LEVEL for this PoC: a session is exported as the
    rolling pcap file(s) that cover its time window, not as a
    packet-precise slice. The manifest and the UI state this explicitly
    (doc 15.3: never overclaim chain of custody). For packet-precise
    inspection the UI deep-links to the Arkime viewer.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.arkime import (build_expression, probe, session_viewer_url,
                        viewer_base_url)

# v0.13.0 (backport fix VM): Arkime/zeek writers roll .pcap, .pcapng and
# compressed variants - the old ".pcap only" filter silently showed ZERO
# files on deployments that compress.
_PCAP_SUFFIXES = (".pcap", ".pcapng", ".pcap.zst", ".pcap.gz")
from app.audit import audit
from app.config import config
from app.db import get_db
from app.models import Incident, IncidentNode, PcapExport, User
from app.os_client import get_os
from app.schemas import PcapExportRequest
from app.security import require_permission

router = APIRouter(prefix="/api/evidence", tags=["evidence"])

GRANULARITY = "file-level"


# ---------------------------------------------------------------- time utils
def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ------------------------------------------------------------- capture window
def _capture_window() -> dict:
    """Stats + coverage window derived from the rolling capture directory.

    mtime of a finished Arkime 'simple' pcap file is its close time, so a
    file roughly covers [mtime - file_span, mtime]; the union of all
    files gives the retained capture coverage. This is an approximation
    by design - it never fabricates availability.
    """
    pcap_dir = Path(config.pcap_dir)
    span = timedelta(minutes=config.pcap_file_span_minutes)
    out: dict = {
        "pcap_dir": config.pcap_dir,
        "dir_exists": pcap_dir.is_dir(),
        "file_count": 0,
        "total_bytes": 0,
        "oldest_file": None,
        "newest_file": None,
        "coverage_from": None,
        "coverage_to": None,
        "free_bytes": None,
        "disk_total_bytes": None,
        "used_pct": None,
    }
    files: list[tuple[float, float, str]] = []  # (mtime, size, name)
    if out["dir_exists"]:
        try:
            for p in pcap_dir.iterdir():
                if p.is_file() and p.name.lower().endswith(_PCAP_SUFFIXES):
                    try:
                        st = p.stat()
                        files.append((st.st_mtime, st.st_size, p.name))
                    except OSError:
                        continue
        except OSError:
            out["dir_exists"] = False
    if files:
        files.sort()
        oldest, newest = files[0], files[-1]
        out["file_count"] = len(files)
        out["total_bytes"] = sum(f[1] for f in files)
        out["oldest_file"] = _iso(datetime.fromtimestamp(oldest[0],
                                                         timezone.utc))
        out["newest_file"] = _iso(datetime.fromtimestamp(newest[0],
                                                         timezone.utc))
        out["coverage_from"] = _iso(datetime.fromtimestamp(oldest[0],
                                                           timezone.utc)
                                    - span)
        out["coverage_to"] = _iso(datetime.fromtimestamp(newest[0],
                                                         timezone.utc)
                                  + span)
    try:
        du = shutil.disk_usage(pcap_dir if pcap_dir.is_dir() else "/")
        out["free_bytes"] = du.free
        out["disk_total_bytes"] = du.total
        out["used_pct"] = round(100 * du.used / du.total, 1) if du.total else None
    except (OSError, ValueError):
        pass
    return out


def _status_for(ts: datetime, cw: dict) -> tuple[str, str]:
    """doc 15.2 evidence status for one session time."""
    if not cw.get("dir_exists") or not cw.get("file_count"):
        return ("not_captured",
                "sensor PCAP storage has no capture files - nothing was "
                "recorded (or Arkime is not running)")
    span = timedelta(minutes=config.pcap_file_span_minutes)
    cov_from = _parse_iso(cw.get("coverage_from"))
    if cov_from is None:
        return ("not_captured", "capture coverage unknown")
    if ts < cov_from - span:
        return ("expired",
                "older than the retained capture window - pruned by "
                "rolling retention or before the sensor started")
    if ts < cov_from:
        return ("partially_available",
                "at the edge of the retained capture window - older "
                "packets may already be pruned")
    return ("available", "within the retained capture window")


# ------------------------------------------------------------ entity scoping
def _entities_from_alert(src: dict) -> tuple[list[str], list[str]]:
    ips: list[str] = []
    domains: list[str] = []
    for v in ((src.get("source") or {}).get("ip"),
              (src.get("destination") or {}).get("ip")):
        if v:
            ips.append(str(v))
    for lst in (src.get("top_sources") or [])[:10]:
        if lst.get("ip"):
            ips.append(str(lst["ip"]))
    for lst in (src.get("top_destinations") or [])[:10]:
        if lst.get("ip"):
            ips.append(str(lst["ip"]))
    for it in (src.get("matched_iocs") or [])[:20]:
        if it.get("ioc_type") == "domain" and it.get("ioc_value"):
            domains.append(str(it["ioc_value"]))
    seen: set[str] = set()
    ips = [i for i in ips if not (i in seen or seen.add(i))][:12]
    seen = set()
    domains = [d for d in domains if not (d in seen or seen.add(d))][:8]
    return ips, domains


def _entities_from_incident(db: Session, incident_id: int) -> \
        tuple[list[str], list[str]]:
    inc = db.get(Incident, str(incident_id))
    if inc is None:
        raise HTTPException(404, "Incident not found")
    nodes = db.query(IncidentNode).filter(
        IncidentNode.incident_id == inc.id).all()
    ips: list[str] = []
    domains: list[str] = []
    for n in nodes:
        value = n.key
        prefix = f"{n.kind}:"
        if value.startswith(prefix):
            value = value[len(prefix):]
        if n.kind == "ip" and value:
            ips.append(value)
        elif n.kind == "domain" and value:
            domains.append(value)
    seen: set[str] = set()
    ips = [i for i in ips if not (i in seen or seen.add(i))][:12]
    seen = set()
    domains = [d for d in domains if not (d in seen or seen.add(d))][:8]
    return ips, domains


def _window_from_bounds(first_seen: str | None, last_seen: str | None,
                        fallback_hours: int = 24) -> tuple[datetime, datetime]:
    buf = timedelta(minutes=config.pcap_session_buffer_minutes)
    now = _now()
    fs = _parse_iso(first_seen)
    ls = _parse_iso(last_seen)
    if fs is None and ls is None:
        return (now - timedelta(hours=fallback_hours), now)
    if fs is None:
        fs = ls
    if ls is None:
        ls = fs
    return (fs - buf, ls + buf)


# ----------------------------------------------------------- session lookup
def _query_sessions(ips: list[str], domains: list[str],
                    t_from: datetime, t_to: datetime) -> list[dict]:
    """Session metadata sample from the normalized event store
    (API-constructed query, never user DSL)."""
    should: list[dict] = []
    for v in ips:
        should.append({"term": {"source.ip": v}})
        should.append({"term": {"destination.ip": v}})
    for v in domains:
        should.append({"term": {"dns.query": v}})
        should.append({"term": {"tls.sni": v}})
        should.append({"term": {"http.host": v}})
    if not should:
        return []
    body = {
        "size": min(config.evidence_session_limit, 500),
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {
                "gte": _iso(t_from), "lte": _iso(t_to)}}},
            {"bool": {"should": should}},
        ]}},
        "_source": {"excludes": ["raw_line"]},
    }
    try:
        res = get_os().aggregate("ndr-events-read", body)
    except Exception:  # noqa: BLE001 - degrade to empty, status stays honest
        return []
    out = []
    for hit in res.get("hits", {}).get("hits", []):
        s = hit.get("_source", {})
        out.append({
            "doc_id": hit.get("_id"),
            "index": hit.get("_index"),
            "@timestamp": s.get("@timestamp"),
            "session_id": s.get("session_id"),
            "source_engine": s.get("source_engine"),
            "event_type": s.get("event_type"),
            "source_ip": (s.get("source") or {}).get("ip"),
            "destination_ip": (s.get("destination") or {}).get("ip"),
            "destination_port": (s.get("destination") or {}).get("port"),
            "network_transport": (s.get("network") or {}).get("transport"),
            "network_bytes": (s.get("network") or {}).get("bytes"),
            "dns_query": (s.get("dns") or {}).get("query"),
            "tls_sni": (s.get("tls") or {}).get("sni"),
            "http_host": (s.get("http") or {}).get("host"),
        })
    return out


def _arkime_block(ips: list[str], domains: list[str], t_from: datetime,
                  t_to: datetime) -> dict:
    """v0.12 PCAP telemetry: Arkime deep-link for the whole scope."""
    expression = build_expression(ips, domains)
    status = probe()
    out: dict = {
        "reachable": status["reachable"],
        "viewer_url": viewer_base_url(),
        "expression": expression,
        "error": status.get("error"),
    }
    if expression:
        out["url"] = session_viewer_url(
            expression, int(t_from.timestamp()), int(t_to.timestamp()))
    return out


def _sessions_response(scope: str, scope_id: str, ips: list[str],
                       domains: list[str], t_from: datetime,
                       t_to: datetime, cw: dict) -> dict:
    rows = _query_sessions(ips, domains, t_from, t_to)
    for r in rows:
        ts = _parse_iso(r.get("@timestamp")) or _now()
        status, note = _status_for(ts, cw)
        r["pcap_status"] = status
        r["pcap_note"] = note
        # v0.12: per-session Arkime deep link (5-tuple + bounded window)
        r["arkime_url"] = None
        s_ip = [v for v in (r.get("source_ip"), r.get("destination_ip"))
                if v]
        expr = build_expression(s_ip, [], [r.get("destination_port")]
                                if r.get("destination_port") else [])
        if expr:
            r["arkime_url"] = session_viewer_url(
                expr, int((ts - timedelta(minutes=2)).timestamp()),
                int((ts + timedelta(minutes=2)).timestamp()))
    return {
        "scope": scope,
        "scope_id": scope_id,
        "window": {"from": _iso(t_from), "to": _iso(t_to)},
        "entities": {"ips": ips, "domains": domains},
        "pcap": {**cw, "granularity": GRANULARITY,
                 "note": "PoC export granularity is file-level: the "
                         "rolling pcap file(s) covering the session "
                         "window are exported, not a packet-precise "
                         "slice. Use the Arkime viewer for packet "
                         "precision."},
        "arkime_viewer_url": viewer_base_url(),
        "arkime": _arkime_block(ips, domains, t_from, t_to),
        "capture_buffer_minutes": config.pcap_session_buffer_minutes,
        "sessions": rows,
        "total": len(rows),
    }


@router.get("/pcap/storage")
def pcap_storage(user: User = Depends(require_permission("view"))):
    return {**_capture_window(), "granularity": GRANULARITY,
            "arkime_viewer_url": viewer_base_url()}


@router.get("/arkime/status")
def arkime_status(user: User = Depends(require_permission("view"))):
    """v0.12 PCAP telemetry: honest Arkime reachability + base URL."""
    status = probe()
    return {**status, "viewer_url": viewer_base_url()}


@router.get("/alerts/{alert_id}/sessions")
def alert_sessions(alert_id: str, request: Request,
                   user: User = Depends(require_permission("view")),
                   db: Session = Depends(get_db)):
    # v0.12.6: resilient resolution (_id get + alert_id-field fallback).
    # A bare GET-by-id on the multi-index read alias / a doc whose _id
    # differs from its alert_id field used to surface as a lying 404.
    try:
        doc = get_os().get_alert_doc(alert_id)
    except Exception as e:  # noqa: BLE001 - backend down -> honest 502
        raise HTTPException(502, f"Search backend unavailable: {e}")
    if doc is None:
        raise HTTPException(404, "Alert not found")
    src = doc.get("_source") or {}
    ips, domains = _entities_from_alert(src)
    t_from, t_to = _window_from_bounds(src.get("first_seen"),
                                       src.get("last_seen"))
    out = _sessions_response("alert", alert_id, ips, domains,
                             t_from, t_to, _capture_window())
    audit(db, request, action="evidence.sessions", target_type="alert",
          target_id=alert_id,
          detail={"sessions": out["total"],
                  "entities": out["entities"]}, actor=user)
    return out


@router.get("/incidents/{incident_id}/sessions")
def incident_sessions(incident_id: str, request: Request,
                      user: User = Depends(require_permission("view")),
                      db: Session = Depends(get_db)):
    inc = db.get(Incident, str(incident_id))
    if inc is None:
        raise HTTPException(404, "Incident not found")
    ips, domains = _entities_from_incident(db, incident_id)
    t_from, t_to = _window_from_bounds(inc.first_seen, inc.last_seen)
    out = _sessions_response("incident", str(incident_id), ips, domains,
                             t_from, t_to, _capture_window())
    audit(db, request, action="evidence.sessions", target_type="incident",
          target_id=str(incident_id),
          detail={"sessions": out["total"],
                  "entities": out["entities"]}, actor=user)
    return out


# ------------------------------------------------------------------- exports
def _record_out(rec: PcapExport) -> dict:
    return {
        "id": rec.id,
        "actor": rec.actor,
        "actor_role": rec.actor_role,
        "alert_id": rec.alert_id,
        "incident_id": rec.incident_id,
        "reason": rec.reason,
        "session_count": rec.session_count,
        "sessions": rec.sessions or [],
        "window": {"from": rec.window_from, "to": rec.window_to},
        "files": rec.files or [],
        "total_bytes": rec.total_bytes,
        "bundle_name": rec.bundle_name,
        "bundle_sha256": rec.bundle_sha256,
        "status": rec.status,
        "error": rec.error,
        "created_at": _iso(rec.created_at),
        "expires_at": _iso(rec.expires_at),
    }


def _sweep_expired(db: Session) -> list[str]:
    """TTL for temporary export files (doc 15.1 step 8). Never raises."""
    expired: list[str] = []
    try:
        rows = db.query(PcapExport).filter(
            PcapExport.status == "ready",
            PcapExport.expires_at.isnot(None),
            PcapExport.expires_at < _now()).all()
    except Exception:  # noqa: BLE001
        return expired
    for rec in rows:
        try:
            if rec.bundle_name:
                (Path(config.pcap_export_dir)
                 / rec.bundle_name).unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            pass
        rec.status = "expired"
        expired.append(rec.id)
    if expired:
        try:
            db.commit()
            audit(db, None, action="evidence.pcap.expire",
                  target_type="pcap_export",
                  detail={"expired": expired, "ttl_minutes":
                          config.pcap_export_ttl_minutes})
        except Exception:  # noqa: BLE001
            db.rollback()
    return expired


def _select_pcap_files(t_min: datetime, t_max: datetime) -> list[dict]:
    """Rolling capture files overlapping the requested window."""
    span = timedelta(minutes=config.pcap_file_span_minutes)
    pcap_dir = Path(config.pcap_dir)
    if not pcap_dir.is_dir():
        return []
    picked: list[dict] = []
    for p in pcap_dir.iterdir():
        if not (p.is_file() and p.suffix.lower() == ".pcap"):
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        mtime = datetime.fromtimestamp(st.st_mtime, timezone.utc)
        file_start = mtime - span
        if file_start <= t_max and mtime >= t_min:
            picked.append({"path": p, "name": p.name, "bytes": st.st_size,
                           "mtime": mtime})
    picked.sort(key=lambda f: abs((f["mtime"] - (t_min + (t_max - t_min) / 2))
                                  .total_seconds()))
    return picked


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


@router.get("/pcap/exports")
def list_exports(limit: int = Query(default=20, ge=1, le=100),
                 user: User = Depends(require_permission("view")),
                 db: Session = Depends(get_db)):
    _sweep_expired(db)
    rows = db.query(PcapExport).order_by(
        PcapExport.created_at.desc()).limit(limit).all()
    return {"items": [_record_out(r) for r in rows],
            "ttl_minutes": config.pcap_export_ttl_minutes,
            "limits": {"max_files": config.pcap_export_max_files,
                       "max_bytes": config.pcap_export_max_bytes,
                       "max_sessions": config.pcap_export_max_sessions}}


@router.post("/pcap/export")
def create_export(body: PcapExportRequest, request: Request,
                  user: User = Depends(require_permission("evidence_export")),
                  db: Session = Depends(get_db)):
    _sweep_expired(db)

    doc_ids = list(dict.fromkeys(body.sessions))
    doc_ids = doc_ids[:config.pcap_export_max_sessions]
    if not doc_ids:
        raise HTTPException(400, "select at least one session to export")

    # 1. re-resolve every selected session server-side (doc 15.1 step 1)
    # v0.13.0 (backport fix VM): batch ids-query - per-id GET returned
    # nothing on multi-index day aliases (500 on export).
    os = get_os()
    resolved: list[dict] = []
    for hit in os.get_docs_by_ids("ndr-events-read", doc_ids):
        doc_id = hit.get("_id")
        src = hit.get("_source") or {}
        ts = _parse_iso(src.get("@timestamp"))
        if doc_id is None or ts is None:
            continue
        resolved.append({
            "doc_id": doc_id,
            "@timestamp": src.get("@timestamp"),
            "session_id": src.get("session_id"),
            "source_engine": src.get("source_engine"),
            "event_type": src.get("event_type"),
        })
    if not resolved:
        raise HTTPException(404, "none of the selected sessions could be "
                                 "resolved from the event store")

    times = [_parse_iso(r["@timestamp"]) for r in resolved]
    buf = timedelta(minutes=config.pcap_session_buffer_minutes)
    t_min, t_max = min(times) - buf, max(times) + buf

    # 2. limits BEFORE touching storage (doc 15.1 step 4)
    files = _select_pcap_files(t_min, t_max)
    total_bytes = sum(f["bytes"] for f in files)
    if files and (len(files) > config.pcap_export_max_files
                  or total_bytes > config.pcap_export_max_bytes):
        raise HTTPException(
            400,
            f"export exceeds policy limits: {len(files)} files / "
            f"{total_bytes} bytes requested, max "
            f"{config.pcap_export_max_files} files / "
            f"{config.pcap_export_max_bytes} bytes. Narrow the session "
            f"selection or ask an administrator to raise the limit.")

    export_id = str(uuid.uuid4())
    ttl = timedelta(minutes=config.pcap_export_ttl_minutes)
    expires = _now() + ttl

    if not files:
        # nothing covers this window - record it honestly (doc 15.1
        # step 9 + AT-11 spirit: explain, never fabricate)
        rec = PcapExport(
            id=export_id, actor=user.username, actor_role=user.role,
            alert_id=body.alert_id, incident_id=body.incident_id,
            reason=body.reason, session_count=len(resolved),
            sessions=resolved, window_from=_iso(t_min),
            window_to=_iso(t_max), files=[], total_bytes=0,
            status="failed",
            error="no capture files cover the selected session window - "
                  "the sensor was not capturing yet or the PCAP was "
                  "already pruned by rolling retention",
            expires_at=expires)
        db.add(rec)
        db.commit()
        audit(db, request, action="evidence.pcap.export", result="failure",
              target_type="pcap_export", target_id=export_id,
              detail={"error": rec.error, "sessions": len(resolved),
                      "window": [_iso(t_min), _iso(t_max)]}, actor=user)
        return _record_out(rec)

    # 3. build the bundle: copy files + manifest + zip with SHA-256
    export_dir = Path(config.pcap_export_dir)
    bundle_name = f"pcap-export-{export_id}.zip"
    bundle_path = export_dir / bundle_name
    file_entries: list[dict] = []
    try:
        with tempfile.TemporaryDirectory(dir=str(export_dir)) as tmp:
            work = Path(tmp)
            for f in files:
                dest = work / f["name"]
                shutil.copyfile(f["path"], dest)
                file_entries.append({"name": f["name"],
                                     "bytes": f["bytes"],
                                     "sha256": _sha256_file(dest)})
            manifest = {
                "export_id": export_id,
                "created_at": _iso(_now()),
                "expires_at": _iso(expires),
                "tool": "ndr-api evidence workflow",
                "granularity": GRANULARITY,
                "granularity_note": "files are the rolling capture files "
                                    "covering the window, not packet-"
                                    "precise slices",
                "actor": user.username,
                "actor_role": user.role,
                "reason": body.reason,
                "alert_id": body.alert_id,
                "incident_id": body.incident_id,
                "window": {"from": _iso(t_min), "to": _iso(t_max)},
                "sessions": resolved,
                "files": file_entries,
                "total_bytes": total_bytes,
                "limits": {"max_files": config.pcap_export_max_files,
                           "max_bytes": config.pcap_export_max_bytes,
                           "ttl_minutes": config.pcap_export_ttl_minutes},
                "integrity": {"algorithm": "sha256"},
            }
            (work / "manifest.json").write_text(
                json.dumps(manifest, indent=2), encoding="utf-8")
            with zipfile.ZipFile(bundle_path, "w",
                                 compression=zipfile.ZIP_DEFLATED) as zf:
                for f in files:
                    zf.write(work / f["name"], arcname=f["name"])
                zf.write(work / "manifest.json", arcname="manifest.json")
        bundle_sha256 = _sha256_file(bundle_path)
    except OSError as exc:
        raise HTTPException(500, f"export staging failed: {exc}")

    rec = PcapExport(
        id=export_id, actor=user.username, actor_role=user.role,
        alert_id=body.alert_id, incident_id=body.incident_id,
        reason=body.reason, session_count=len(resolved),
        sessions=resolved, window_from=_iso(t_min), window_to=_iso(t_max),
        files=file_entries, total_bytes=total_bytes,
        bundle_name=bundle_name, bundle_sha256=bundle_sha256,
        status="ready", expires_at=expires)
    db.add(rec)
    db.commit()
    audit(db, request, action="evidence.pcap.export",
          target_type="pcap_export", target_id=export_id,
          detail={"actor": user.username, "reason": body.reason,
                  "alert_id": body.alert_id,
                  "incident_id": body.incident_id,
                  "sessions": len(resolved),
                  "window": [_iso(t_min), _iso(t_max)],
                  "files": file_entries, "total_bytes": total_bytes,
                  "bundle_sha256": bundle_sha256}, actor=user)
    return _record_out(rec)


@router.get("/pcap/exports/{export_id}/download")
def download_export(export_id: str, request: Request,
                    user: User = Depends(require_permission("evidence_export")),
                    db: Session = Depends(get_db)):
    _sweep_expired(db)
    rec = db.get(PcapExport, export_id)
    if rec is None:
        raise HTTPException(404, "Export not found")
    if rec.status == "expired":
        raise HTTPException(410, "export expired (TTL) - create a new one")
    if rec.status == "failed":
        raise HTTPException(409, f"export failed: {rec.error}")
    path = Path(config.pcap_export_dir) / (rec.bundle_name or "")
    if not path.is_file():
        raise HTTPException(410, "export file is gone (expired or removed) "
                                 "- create a new export")
    audit(db, request, action="evidence.pcap.download",
          target_type="pcap_export", target_id=export_id,
          detail={"bundle_sha256": rec.bundle_sha256,
                  "total_bytes": rec.total_bytes}, actor=user)
    return FileResponse(path, media_type="application/zip",
                        filename=rec.bundle_name)
