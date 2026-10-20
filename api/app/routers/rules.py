"""Suricata rule manager router (Phase 6).

Endpoints:
  GET  /api/rules/summary         counts, categories, sensor state (view)
  GET  /api/rules                 rule list + 7d hit counts (view)
  POST /api/rules/update          regenerate rules + live reload (rule_admin)
  POST /api/rules/{sid}/toggle    enable/disable one rule (rule_admin)
  POST /api/rules/validate        syntax-check one rule text (rule_admin)
  GET  /api/rules/custom          operator-authored rules (view)
  POST /api/rules/custom          create custom rule (rule_admin)
  PUT  /api/rules/custom/{sid}    edit / enable-disable (rule_admin)
  DELETE /api/rules/custom/{sid}  remove custom rule (rule_admin)

Custom rules (v0.11) live in the reserved local SID range 1,000,000+
and are synced into the marker section of suricata.rules after every
change, so the engine - not just the UI - always sees them.

Disabling uses disable.conf on the shared rules volume - the exact
mechanism suricata-update documents for operators - so UI state, CLI
state (make rule-update) and the sensor itself can never diverge.
Every mutation is audited with before/after detail.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import rules_engine as re_mod
from app.audit import audit
from app.config import config
from app.db import get_db, SessionLocal
from app.models import CustomRule, SuricataRuleMeta, User
from app.os_client import get_os
from app.schemas import (CustomRuleCreate, CustomRuleOut, CustomRuleUpdate,
                         RuleToggle)
from app.security import require_permission

router = APIRouter(prefix="/api/rules", tags=["rule-manager"])


def _sync_meta(db: Session, items: list[dict], enabled_sids: set[int]) -> None:
    """Upsert last-known metadata for every rule present in suricata.rules.

    v0.12.8: loads existing rows ONCE into a dict instead of issuing one
    db.get() per rule (~53k round trips on every regeneration), and only
    writes rows whose state actually changed - the file regeneration sync
    drops from tens of thousands of statements to the small delta."""
    now = datetime.now(timezone.utc)
    rows = {r.sid: r for r in db.query(SuricataRuleMeta).all()}
    for it in items:
        row = rows.get(it["sid"])
        if row is None:
            row = SuricataRuleMeta(sid=it["sid"])
            db.add(row)
            rows[it["sid"]] = row
            changed = True
        else:
            changed = (row.gid != it["gid"] or row.rev != it["rev"]
                       or row.msg != it["msg"]
                       or row.classtype != it["classtype"]
                       or bool(row.enabled) != (it["sid"] in enabled_sids)
                       or row.last_seen_in_rules is None)
        row.gid = it["gid"]
        row.rev = it["rev"]
        row.action = it["action"]
        row.protocol = it["protocol"]
        row.msg = it["msg"]
        row.classtype = it["classtype"]
        row.priority = it["priority"]
        row.enabled = it["sid"] in enabled_sids
        if changed:
            row.last_seen_in_rules = now
    db.commit()


# ---- parse + meta-sync cache (v0.12.5) --------------------------------
# suricata.rules is ~45 MB with ~53k rules; summary AND list both fired a
# full re-parse + a 53k-row upsert on EVERY page open (two concurrent
# transactions) -> 47 s responses, 500s and lock contention on the live
# VM. Both now run only when the underlying files changed (mtime+size
# signature). Measured live: 47.3 s -> 1.4 s, toggle/rule-update paths
# keep working (they rewrite the files, which invalidates the signature).
#
# v0.12.8: the REMAINING cost was still paid on every request -
# _load_rules re-loaded all ~53k SuricataRuleMeta rows from Postgres and
# re-built + re-sorted the full item list per request, and a cold cache
# hit by summary+list simultaneously (exactly what the UI does on open)
# ran the 53k-row meta-sync TWICE in two transactions -> row-lock
# contention -> the intermittent 500 the user reported. Now:
#   1. a threading.Lock serializes the cache build (the second request
#      waits instead of duplicating the work),
#   2. the MERGED item list is cached too, keyed by file signature PLUS
#      a custom-rule signature (count/max-updated) - on a cache hit the
#      hot path runs ZERO SuricataRuleMeta queries; only the handful of
#      CustomRule rows is touched to compute the signature.
# Toggles re-write disable.conf (file sig changes), rule updates re-write
# suricata.rules, custom CRUD changes the custom sig - all invalidate
# exactly the caches they affect.
_PARSE_LOCK = threading.Lock()
_PARSED_CACHE: dict[str, Any] | None = None
_FILES_SIG: tuple | None = None
_ITEMS_LOCK = threading.Lock()
_ITEMS_CACHE: list[dict] | None = None
_ITEMS_SIG: tuple | None = None


def _files_sig() -> tuple:
    sig: list[Any] = []
    for path in (re_mod.rules_path(), re_mod.disable_path()):
        try:
            st = os.stat(path)
            sig.append((st.st_mtime_ns, st.st_size))
        except OSError:
            sig.append(None)
    return tuple(sig)


def _custom_sig(db: Session) -> tuple:
    """Cheap signature of the custom-rule table (a handful of rows)."""
    row = (db.query(func.count(CustomRule.sid),
                    func.max(CustomRule.updated_at),
                    func.max(CustomRule.sid)).one())
    return (int(row[0] or 0), str(row[1]), int(row[2] or 0))


def _parsed_rules(db: Session) -> dict:
    """Cached parse of suricata.rules + disable.conf.

    Returns {parsed, disabled, enabled_sids}; re-parses and re-syncs the
    meta table only when the file signature changed (or on first call).
    v0.12.8: build is serialized with a lock so concurrent summary+list
    requests can no longer run the 53k-row meta sync twice in parallel.
    """
    global _PARSED_CACHE, _FILES_SIG
    sig = _files_sig()
    if _PARSED_CACHE is None or sig != _FILES_SIG:
        with _PARSE_LOCK:
            sig = _files_sig()  # re-read under the lock (may have changed)
            if _PARSED_CACHE is None or sig != _FILES_SIG:
                parsed = re_mod.parse_rules_file()
                disabled = re_mod.read_disable_sids()
                enabled_sids = ({r["sid"] for r in parsed["items"]}
                                - disabled)
                if parsed["items"]:
                    _sync_meta(db, parsed["items"], enabled_sids)
                _PARSED_CACHE = {"parsed": parsed, "disabled": disabled,
                                 "enabled_sids": enabled_sids}
                _FILES_SIG = sig
    return _PARSED_CACHE


def _load_rules(db: Session) -> dict:
    """Merge suricata.rules (enabled) with disable.conf + meta cache
    (disabled) + operator custom rules into one coherent rule list.

    Custom rules enabled in the DB are ALSO inside suricata.rules (the
    marker section), so the parsed loop emits them (flagged custom, with
    their DB rule_text) and the DB loop only adds the ones not in the
    file (disabled) - never duplicates.

    v0.12.8: the merged list is CACHED by (file sig, custom sig). On a
    hit this runs zero SuricataRuleMeta queries - opening the Rule
    Manager no longer pulls ~53k rows out of Postgres per request.
    """
    global _ITEMS_CACHE, _ITEMS_SIG
    cache = _parsed_rules(db)
    c_sig = _custom_sig(db)
    sig = (_FILES_SIG, c_sig)
    if _ITEMS_CACHE is not None and sig == _ITEMS_SIG:
        return {"items": _ITEMS_CACHE, "skipped": cache["parsed"]["skipped"],
                "file_exists": cache["parsed"]["exists"]}
    with _ITEMS_LOCK:
        c_sig = _custom_sig(db)  # re-read under the lock
        sig = (_FILES_SIG, c_sig)
        if _ITEMS_CACHE is not None and sig == _ITEMS_SIG:
            return {"items": _ITEMS_CACHE,
                    "skipped": cache["parsed"]["skipped"],
                    "file_exists": cache["parsed"]["exists"]}

        parsed = cache["parsed"]
        disabled = cache["disabled"]
        enabled_sids = cache["enabled_sids"]

        custom_rows = {c.sid: c for c in db.query(CustomRule).all()}
        rows = {r.sid: r for r in db.query(SuricataRuleMeta).all()}
        items: list[dict] = []
        emitted: set[int] = set()
        for r in parsed["items"]:
            sid = r["sid"]
            if sid in disabled:
                continue  # listed but removed from file after regeneration
            is_custom = sid in custom_rows
            # v0.12.7: explicit source taxonomy - operator-authored LOCAL
            # rules vs subscribed ET SURICATA rules (UI filter "bedakan rule
            # lokal, rule suricata dan rule zeek")
            items.append({**r, "enabled": True, "changed_by": None,
                          "changed_at": None, "custom": is_custom,
                          "source": "local" if is_custom else "suricata",
                          "rule_text": custom_rows[sid].rule_text
                          if is_custom else None})
            emitted.add(sid)
        for sid, r in rows.items():
            # skip the custom SID range entirely - those rules are rendered
            # from the CustomRule table (ET SIDs sit ABOVE 1,999,999)
            if sid in emitted or sid in enabled_sids \
                    or (re_mod.CUSTOM_SID_BASE <= sid <= re_mod.CUSTOM_SID_MAX):
                continue
            items.append({
                "sid": sid, "gid": r.gid, "rev": r.rev,
                "action": r.action or "alert",
                "protocol": r.protocol or "any",
                "src": None, "sport": None, "dst": None, "dport": None,
                "msg": r.msg, "classtype": r.classtype,
                "priority": r.priority,
                "enabled": bool(r.enabled),
                "changed_by": r.changed_by,
                "changed_at": r.changed_at.isoformat()
                              if r.changed_at else None,
                "custom": False, "source": "suricata", "rule_text": None,
            })
        for sid, c in custom_rows.items():
            if sid in emitted:
                continue  # already listed from suricata.rules
            items.append({
                "sid": sid, "gid": 1, "rev": c.rev,
                "action": c.action, "protocol": c.protocol,
                "src": None, "sport": None, "dst": None, "dport": None,
                "msg": c.msg, "classtype": c.classtype,
                "priority": c.priority,
                "enabled": bool(c.enabled),
                "changed_by": c.updated_by or c.created_by,
                "changed_at": (c.updated_at or c.created_at).isoformat()
                              if (c.updated_at or c.created_at) else None,
                "custom": True, "source": "local", "rule_text": c.rule_text,
            })
        items.sort(key=lambda x: x["sid"])
        _ITEMS_CACHE = items
        _ITEMS_SIG = sig
        return {"items": items, "skipped": parsed["skipped"],
                "file_exists": parsed["exists"]}


def _apply_custom(db: Session) -> int:
    """Persist enabled custom rules to custom.rules + sync the section in
    suricata.rules. Best-effort: a read-only rules volume never breaks the
    DB mutation (the section re-syncs on the next successful update)."""
    rules = db.query(CustomRule).filter(CustomRule.enabled.is_(True)).all()
    texts = [r.rule_text for r in rules]
    try:
        re_mod.write_custom_file(texts)
        re_mod.sync_custom_section(texts)
    except OSError:
        pass  # volume not writable from this container - keep UI state
    return len(texts)


def _hit_counts(sids: list[int]) -> dict[int, int]:
    """7-day alert counts per signature_id (best-effort; 0 on any error)."""
    if not sids:
        return {}
    try:
        frm = (datetime.now(timezone.utc)
               - timedelta(days=7)).isoformat().replace("+00:00", "Z")
        res = get_os().aggregate("ndr-alerts-read", {
            "size": 0,
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": frm}}},
                {"terms": {"signature_id": [str(s) for s in sids]}},
            ]}},
            "aggs": {"by_sid": {"terms": {
                "field": "signature_id", "size": 1000}}}})
        return {int(b["key"]): b["doc_count"]
                for b in res.get("aggregations", {})
                .get("by_sid", {}).get("buckets", [])
                if str(b["key"]).isdigit()}
    except Exception:  # noqa: BLE001 - counts are decorative, never fatal
        return {}


@router.get("/summary")
def rules_summary(user: User = Depends(require_permission("view")),
                  db: Session = Depends(get_db)):
    data = _load_rules(db)
    items = data["items"]
    by_category: dict[str, int] = {}
    by_action: dict[str, int] = {}
    by_source: dict[str, int] = {"local": 0, "suricata": 0}
    for it in items:
        cat = it.get("classtype") or "unclassified"
        by_category[cat] = by_category.get(cat, 0) + 1
        act = it.get("action") or "alert"
        by_action[act] = by_action.get(act, 0) + 1
        src = it.get("source") or "suricata"
        by_source[src] = by_source.get(src, 0) + 1
    top_categories = dict(sorted(by_category.items(),
                                 key=lambda kv: kv[1],
                                 reverse=True)[:12])
    return {
        "total": len(items),
        "enabled": sum(1 for it in items if it["enabled"]),
        "disabled": sum(1 for it in items if not it["enabled"]),
        "actions": by_action,
        "by_source": by_source,
        "top_categories": top_categories,
        "rules_file_updated": re_mod.file_mtime(),
        "rules_file_exists": data["file_exists"],
        "skipped_lines": data["skipped"],
        "sensor_online": re_mod.sensor_online(),
        "update_tool": "suricata-update",
    }


@router.get("")
def list_rules(q: str | None = Query(default=None, max_length=128),
               category: str | None = Query(default=None, max_length=64),
               status: str = Query(default="all",
                                   pattern=r"^(all|enabled|disabled)$"),
               # v0.12.7: rule source filter (local = operator-authored,
               # suricata = subscribed ET ruleset)
               source: str = Query(default="all",
                                   pattern=r"^(all|local|suricata)$"),
               limit: int = Query(default=100, ge=1, le=500),
               offset: int = Query(default=0, ge=0),
               user: User = Depends(require_permission("view")),
               db: Session = Depends(get_db)):
    data = _load_rules(db)
    items = data["items"]
    if q:
        needle = q.lower()
        items = [it for it in items
                 if needle in (it.get("msg") or "").lower()
                 or needle in str(it["sid"])
                 or needle in (it.get("classtype") or "").lower()]
    if category:
        items = [it for it in items
                 if (it.get("classtype") or "unclassified") == category]
    if status != "all":
        items = [it for it in items
                 if it["enabled"] == (status == "enabled")]
    if source != "all":
        items = [it for it in items
                 if (it.get("source") or "suricata") == source]
    total = len(items)
    page = items[offset:offset + limit]
    hits = _hit_counts([it["sid"] for it in page])
    return {"total": total, "skipped_lines": data["skipped"],
            "rules_file_updated": re_mod.file_mtime(),
            "items": [{**it, "hits_7d": hits.get(it["sid"], 0)}
                      for it in page]}


# ------------------------------------------- zeek script view (v0.12.7)
@router.get("/zeek")
def zeek_scripts(user: User = Depends(require_permission("view"))):
    """READ-ONLY inventory of the Zeek policy loaded on the sensor.

    Zeek has no 'rules' in the Suricata sense - its detection logic
    lives in policy SCRIPTS activated from local.zeek. This endpoint
    parses that file (mounted read-only into the API container) so the
    Rule Manager can show all three rule sources side by side:
    local / suricata / zeek. Nothing here is editable by design.
    """
    path = config.zeek_local_conf
    try:
        raw = open(path, "r", encoding="utf-8", errors="replace").read()
    except OSError as exc:
        return {"exists": False, "path": path, "items": [],
                "note": f"local.zeek not readable from the API container "
                        f"({type(exc).__name__}) - check the docker "
                        "compose mount ./sensor/zeek/local.zeek"}
    items: list[dict] = []
    comments = 0
    for lineno, line in enumerate(raw.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            comments += 1
            continue
        kind = "other"
        if stripped.startswith("@load-sigs"):
            kind = "load-sigs"
        elif stripped.startswith("@load"):
            kind = "load"
        elif stripped.startswith("@"):
            kind = "directive"
        elif stripped.startswith("redef"):
            kind = "redef"
        items.append({"line": lineno, "kind": kind,
                      "text": stripped[:300]})
    loads = sum(1 for it in items if it["kind"] == "load")
    return {"exists": True, "path": path,
            "total_lines": len(raw.splitlines()),
            "comment_lines": comments,
            "load_count": loads,
            "items": items[:500],
            "note": "read-only inventory of the Zeek policy scripts "
                    "loaded on the sensor (local.zeek)"}


@router.post("/update")
def update_rules(request: Request,
                 user: User = Depends(require_permission("rule_admin")),
                 db: Session = Depends(get_db)):
    """Fetch the latest Emerging Threats rule set and regenerate
    suricata.rules, then attempt a live reload."""
    with re_mod.apply_lock:
        result = re_mod.run_update()
        parsed = re_mod.parse_rules_file()
        disabled = re_mod.read_disable_sids()
        enabled_sids = {r["sid"] for r in parsed["items"]} - disabled
        if parsed["items"]:
            _sync_meta(db, parsed["items"], enabled_sids)
        custom_count = _apply_custom(db)
        reload = re_mod.reload_via_socket() if result["ok"] else {
            "ok": False, "detail": "update failed - nothing to reload"}
    audit(db, request, action="rules.update",
          target_type="suricata_rules",
          detail={"ok": result["ok"], "reloaded": reload["ok"],
                  "rules_loaded": len(parsed["items"]),
                  "custom_rules": custom_count,
                  "error": result["error"]}, actor=user)
    return {"ok": result["ok"], "output": result["output"],
            "error": result["error"], "reloaded": reload["ok"],
            "reload_detail": reload["detail"],
            "rules_loaded": len(parsed["items"]),
            "custom_rules": custom_count,
            "rules_file_updated": re_mod.file_mtime()}


# v0.13.0 (B3): rule toggling runs suricata-update + a live reload, which
# can take MINUTES on a busy sensor. The endpoint now answers INSTANTLY
# with a job id; the UI polls GET /api/rules/jobs/{id} for progress.
# wait=1 keeps the legacy synchronous behaviour for tests and scripts.
_RULE_JOBS: dict[str, dict] = {}
_RULE_JOBS_LOCK = threading.Lock()


def _run_toggle_job(job_id: str, sid: int, enabled: bool, request: Request,
                    user: User, db_factory) -> None:
    db = db_factory()
    try:
        result = _toggle_now(sid, enabled, request, user, db)
        with _RULE_JOBS_LOCK:
            _RULE_JOBS[job_id].update(status="done", result=result)
    except HTTPException as e:
        with _RULE_JOBS_LOCK:
            _RULE_JOBS[job_id].update(status="failed", error=str(e.detail))
    except Exception as e:  # noqa: BLE001 - job surface must be honest
        with _RULE_JOBS_LOCK:
            _RULE_JOBS[job_id].update(status="failed", error=str(e))
    finally:
        db.close()
        with _RULE_JOBS_LOCK:
            # keep the registry bounded (last 200 jobs)
            if len(_RULE_JOBS) > 200:
                for k in sorted(_RULE_JOBS)[:len(_RULE_JOBS) - 200]:
                    _RULE_JOBS.pop(k, None)


@router.post("/{sid}/toggle")
def toggle_rule(sid: int, body: RuleToggle, request: Request,
                user: User = Depends(require_permission("rule_admin")),
                db: Session = Depends(get_db),
                wait: int = Query(default=1, ge=0, le=1)):
    if wait == 0:
        import uuid as _uuid
        job_id = str(_uuid.uuid4())
        with _RULE_JOBS_LOCK:
            _RULE_JOBS[job_id] = {"job_id": job_id, "sid": sid,
                                  "enabled": body.enabled,
                                  "status": "queued", "created_at":
                                  datetime.now(timezone.utc).isoformat(),
                                  "result": None, "error": None}
        worker_db = SessionLocal
        threading.Thread(
            target=_run_toggle_job, daemon=True, name=f"rule-toggle-{sid}",
            args=(job_id, sid, body.enabled, request, user,
                  worker_db)).start()
        return {"job_id": job_id, "sid": sid, "status": "queued"}
    return _toggle_now(sid, body.enabled, request, user, db)


@router.get("/jobs/{job_id}")
def get_rule_job(job_id: str,
                 user: User = Depends(require_permission("view"))):
    with _RULE_JOBS_LOCK:
        job = _RULE_JOBS.get(job_id)
        if job is None:
            raise HTTPException(404, "job not found (or registry restarted)")
        return dict(job)


def _toggle_now(sid: int, enabled: bool, request: Request,
                user: User, db: Session):
    with re_mod.apply_lock:
        parsed = re_mod.parse_rules_file()
        orig = next((r for r in parsed["items"] if r["sid"] == sid), None)
        known = {r["sid"] for r in parsed["items"]}
        known |= {r.sid for r in db.query(SuricataRuleMeta.sid).all()}
        if sid not in known:
            raise HTTPException(404, f"rule sid {sid} not found")

        if enabled:
            removed = re_mod.remove_disable_sid(sid)
        else:
            re_mod.add_disable_sid(
                sid, comment=(orig or {}).get("msg") or None)
            removed = 0

        result = re_mod.run_update()
        reload = re_mod.reload_via_socket() if result["ok"] else {
            "ok": False, "detail": "update failed - change is staged in "
            "disable.conf and applies on next successful update"}

        # refresh the cache from the regenerated file, then record the
        # toggle on the affected row (creating it from pre-update metadata
        # if the regeneration already removed the rule from the file)
        parsed_after = re_mod.parse_rules_file()
        disabled = re_mod.read_disable_sids()
        enabled_sids = {r["sid"] for r in parsed_after["items"]} - disabled
        if parsed_after["items"]:
            _sync_meta(db, parsed_after["items"], enabled_sids)
        _apply_custom(db)  # suricata-update wiped the custom section
        row = db.get(SuricataRuleMeta, sid)
        if row is None and orig is not None:
            row = SuricataRuleMeta(sid=sid, gid=orig["gid"], rev=orig["rev"],
                                   action=orig["action"],
                                   protocol=orig["protocol"], msg=orig["msg"],
                                   classtype=orig["classtype"],
                                   priority=orig["priority"])
            db.add(row)
        if row is not None:
            row.enabled = enabled
            row.changed_by = user.username
            row.changed_at = datetime.now(timezone.utc)
            db.commit()

    audit(db, request,
          action="rules.enable" if enabled else "rules.disable",
          target_type="suricata_rule", target_id=str(sid),
          detail={"enabled": enabled, "lines_removed": removed,
                  "reloaded": reload["ok"], "update_ok": result["ok"],
                  "error": result["error"]}, actor=user)
    return {"sid": sid, "enabled": enabled, "update_ok": result["ok"],
            "reloaded": reload["ok"], "reload_detail": reload["detail"],
            "error": result["error"]}


# ----------------------------------------------------- custom rules (v0.11)
@router.post("/validate")
def validate_rule_text(body: CustomRuleCreate,
                       user: User = Depends(require_permission("rule_admin"))):
    """Syntax-check a rule text WITHOUT saving (editor 'Check' button)."""
    try:
        parsed = re_mod.parse_rule_text(body.rule_text)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "error": None, "parsed": {
        k: v for k, v in parsed.items() if k != "rule_text"}}


@router.get("/custom")
def list_custom_rules(user: User = Depends(require_permission("view")),
                      db: Session = Depends(get_db)):
    rules = db.query(CustomRule).order_by(CustomRule.sid).all()
    return {"total": len(rules), "items": [
        CustomRuleOut.model_validate(r).model_dump(mode="json")
        for r in rules]}


@router.post("/custom", status_code=201)
def create_custom_rule(body: CustomRuleCreate, request: Request,
                       user: User = Depends(require_permission("rule_admin")),
                       db: Session = Depends(get_db)):
    try:
        parsed = re_mod.parse_rule_text(body.rule_text)
    except ValueError as e:
        raise HTTPException(422, str(e))
    sid = parsed["sid"]
    text = parsed["rule_text"]
    if body.sid and body.sid != sid:
        # the editor reserved a different local SID than the text declares
        import re as _re
        text = _re.sub(r"\bsid\s*:\s*\d+", f"sid:{body.sid}", text, count=1)
        sid = body.sid
    if db.get(CustomRule, sid) is not None \
            or db.get(SuricataRuleMeta, sid) is not None:
        raise HTTPException(409, f"rule sid {sid} already exists")
    row = CustomRule(
        sid=sid, rule_text=text, msg=parsed["msg"],
        action=parsed["action"], protocol=parsed["protocol"],
        classtype=parsed["classtype"], priority=parsed["priority"],
        rev=parsed["rev"], enabled=body.enabled, created_by=user.username)
    db.add(row)
    db.commit()
    db.refresh(row)
    with re_mod.apply_lock:
        applied = _apply_custom(db)
    audit(db, request, action="rules.custom.create",
          target_type="custom_rule", target_id=str(sid),
          detail={"msg": row.msg, "applied": applied,
                  "enabled": row.enabled}, actor=user)
    return CustomRuleOut.model_validate(row).model_dump(mode="json")


@router.put("/custom/{sid}")
def update_custom_rule(sid: int, body: CustomRuleUpdate, request: Request,
                       user: User = Depends(require_permission("rule_admin")),
                       db: Session = Depends(get_db)):
    row = db.get(CustomRule, sid)
    if row is None:
        raise HTTPException(404, "custom rule not found")
    changed = {}
    if body.enabled is not None and body.enabled != row.enabled:
        row.enabled = body.enabled
        changed["enabled"] = body.enabled
    if body.rule_text is not None and body.rule_text.strip() != row.rule_text:
        try:
            parsed = re_mod.parse_rule_text(body.rule_text)
        except ValueError as e:
            raise HTTPException(422, str(e))
        if parsed["sid"] != sid:
            raise HTTPException(
                422, f"rule text declares sid {parsed['sid']}, "
                     f"but this rule is {sid} - edit the text or delete "
                     "and recreate")
        row.rule_text = parsed["rule_text"]
        row.msg = parsed["msg"]
        row.action = parsed["action"]
        row.protocol = parsed["protocol"]
        row.classtype = parsed["classtype"]
        row.priority = parsed["priority"]
        row.rev = parsed["rev"]
        changed["rule_text"] = True
    if not changed:
        return CustomRuleOut.model_validate(row).model_dump(mode="json")
    row.updated_by = user.username
    db.commit()
    db.refresh(row)
    with re_mod.apply_lock:
        applied = _apply_custom(db)
    audit(db, request, action="rules.custom.update",
          target_type="custom_rule", target_id=str(sid),
          detail={**changed, "applied": applied}, actor=user)
    return CustomRuleOut.model_validate(row).model_dump(mode="json")


@router.delete("/custom/{sid}", status_code=204)
def delete_custom_rule(sid: int, request: Request,
                       user: User = Depends(require_permission("rule_admin")),
                       db: Session = Depends(get_db)):
    row = db.get(CustomRule, sid)
    if row is None:
        raise HTTPException(404, "custom rule not found")
    detail = {"msg": row.msg}
    db.delete(row)
    db.commit()
    with re_mod.apply_lock:
        applied = _apply_custom(db)
    audit(db, request, action="rules.custom.delete",
          target_type="custom_rule", target_id=str(sid),
          detail={**detail, "applied": applied}, actor=user)
    return None
