"""v0.13.0 re-construction tests (sandbox restored an older snapshot; these
pin the remediation contract permanently): TRUST_PROXY, events/timeline,
rules async toggle job, DELETE TI feed, schema validators."""

import time

import pytest

from tests.conftest import login

ADMIN = {"username": "admin", "password": "bootstrap-admin-pass-01"}


def _login(client):
    r = login(client, **ADMIN)
    assert r.status_code == 200


# ------------------------------------------------------------ TRUST_PROXY
def test_client_ip_ignores_xff_without_trust_proxy(client, users_seeded):
    """X-Forwarded-For is attacker-controlled: without TRUST_PROXY=1 the
    socket peer is recorded, so a spoofed header cannot poison audit."""
    from app import config as cfg_mod
    old = cfg_mod.config.trust_proxy
    cfg_mod.config.trust_proxy = False
    try:
        _login(client)
        r = client.post("/api/alerts/search", json={"index": "ndr-alerts-read"},
                        headers={"X-Forwarded-For": "6.6.6.6"})
        assert r.status_code == 200
        from app.db import SessionLocal
        from app.models import AuditRecord
        db = SessionLocal()
        row = (db.query(AuditRecord)
               .filter(AuditRecord.action == "alerts.search")
               .order_by(AuditRecord.id.desc()).first())
        db.close()
        assert row is not None
        assert row.source_ip != "6.6.6.6"
    finally:
        cfg_mod.config.trust_proxy = old


def test_client_ip_honours_xff_with_trust_proxy(client, users_seeded):
    from app import config as cfg_mod
    old = cfg_mod.config.trust_proxy
    cfg_mod.config.trust_proxy = True
    try:
        _login(client)
        client.post("/api/alerts/search", json={"index": "ndr-alerts-read"},
                    headers={"X-Forwarded-For": "6.6.6.6"})
        from app.db import SessionLocal
        from app.models import AuditRecord
        db = SessionLocal()
        row = (db.query(AuditRecord)
               .filter(AuditRecord.action == "alerts.search")
               .order_by(AuditRecord.id.desc()).first())
        db.close()
        assert row is not None
        assert row.source_ip == "6.6.6.6"
    finally:
        cfg_mod.config.trust_proxy = old


# --------------------------------------------------------- events timeline
def test_events_timeline_shape(client, _fake_os, monkeypatch):
    """GET /api/events/timeline returns REAL histogram points (size 0)."""
    def fake_agg(**kw):
        return {"hits": {"total": {"value": 7, "relation": "eq"}},
                "aggregations": {"by_ts": {"buckets": [
                    {"key_as_string": "2026-10-19T01:00:00Z",
                     "doc_count": 5,
                     "engines": {"buckets": [
                         {"key": "zeek", "doc_count": 3},
                         {"key": "suricata", "doc_count": 2}]}},
                    {"key_as_string": "2026-10-19T02:00:00Z",
                     "doc_count": 2, "engines": {"buckets": []}},
                ]}}}

    monkeypatch.setattr(_fake_os, "guarded_aggregate", fake_agg)
    _login(client)
    r = client.get("/api/events/timeline?hours=24")
    assert r.status_code == 200
    body = r.json()
    assert body["interval"] == "1h" and body["total"] == 7
    assert body["points"][0]["count"] == 5
    assert body["points"][0]["engines"]["zeek"] == 3


def test_events_timeline_backend_down_502(client, _fake_os, monkeypatch):
    def boom(**kw):
        raise RuntimeError("down")

    monkeypatch.setattr(_fake_os, "guarded_aggregate", boom)
    _login(client)
    r = client.get("/api/events/timeline")
    assert r.status_code == 502


# ----------------------------------------------------- rules async job (B3)
def test_toggle_async_job_and_poll(client, monkeypatch, tmp_path, _fake_os):
    from app.routers import rules as rules_mod
    monkeypatch.setattr(rules_mod, "_toggle_now",
                        lambda sid, enabled, req, user, db:
                        {"sid": sid, "enabled": enabled, "update_ok": True,
                         "reloaded": True, "reload_detail": "ok",
                         "error": None})
    _login(client)
    r = client.post("/api/rules/2027865/toggle?wait=0",
                    json={"enabled": False})
    assert r.status_code == 200
    job_id = r.json()["job_id"]
    assert r.json()["status"] == "queued"
    for _ in range(50):
        job = client.get(f"/api/rules/jobs/{job_id}").json()
        if job["status"] != "queued":
            break
        time.sleep(0.05)
    assert job["status"] == "done"
    assert job["result"]["update_ok"] is True


def test_toggle_sync_still_works(client, monkeypatch, tmp_path, _fake_os):
    from app.routers import rules as rules_mod
    monkeypatch.setattr(rules_mod, "_toggle_now",
                        lambda sid, enabled, req, user, db:
                        {"sid": sid, "enabled": enabled, "update_ok": True,
                         "reloaded": True, "reload_detail": "ok",
                         "error": None})
    _login(client)
    r = client.post("/api/rules/2027865/toggle", json={"enabled": True})
    assert r.status_code == 200
    assert r.json()["update_ok"] is True


def test_rule_job_404(client):
    _login(client)
    assert client.get("/api/rules/jobs/no-such-job").status_code == 404


# ------------------------------------------------------- DELETE TI feed (B4)
def test_delete_ti_feed_404_when_missing(client):
    _login(client)
    r = client.delete("/api/ti/feeds/999999")
    assert r.status_code == 404


# ---------------------------------------------------------- schema guards
def test_user_role_validator_rejects_unknown(client):
    _login(client)
    r = client.patch("/api/users/admin", json={"role": "superadmin"})
    assert r.status_code == 422


def test_sensor_status_validator_rejects_unknown(client):
    _login(client)
    r = client.patch("/api/sensors/sensor-01", json={"status": "exploded"})
    assert r.status_code == 422
