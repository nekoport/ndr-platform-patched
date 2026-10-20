"""v0.14.0 API tests: alert whitelist (allowlist) CRUD, two-man governance,
guards, TTL lifecycle, retroactive tagging and the Overview summary feed."""

import pytest

from tests.conftest import login

ADMIN = {"username": "admin", "password": "bootstrap-admin-pass-01"}
ENGINEER = {"username": "engineer", "password": "Password-123456"}
ANALYST = {"username": "analyst", "password": "Password-123456"}
VIEWER = {"username": "viewer", "password": "Password-123456"}

BODY = {"alert_type": "beaconing_possible", "entity_field": "dst_ip",
        "entity_value": "10.10.5.7", "layer": "L0",
        "reason": "internal backup server beacons nightly to NAS"}


def _login(client, who):
    r = login(client, who["username"], who["password"])
    assert r.status_code == 200, r.text
    return r


# ---------------------------------------------------------------- creation


def test_admin_create_is_self_approved_active(client):
    _login(client, ADMIN)
    r = client.post("/api/allowlist", json=BODY)
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["status"] == "active"
    assert data["approved_by"] == "admin"
    assert data["layer"] == "L0"
    assert data["hit_count"] == 0


def test_analyst_creates_pending_engineer_approves(client, users_seeded):
    _login(client, ANALYST)
    r = client.post("/api/allowlist", json=BODY)
    assert r.status_code == 201
    data = r.json()
    assert data["status"] == "pending"
    assert data["approved_by"] is None

    _login(client, ENGINEER)
    r = client.post(f"/api/allowlist/{data['id']}/approve")
    assert r.status_code == 200
    assert r.json()["status"] == "active"


def test_auditor_cannot_create(client, users_seeded):
    _login(client, VIEWER)
    r = client.post("/api/allowlist", json=BODY)
    assert r.status_code == 403


def test_analyst_cannot_approve_or_delete(client, users_seeded):
    _login(client, ANALYST)
    r = client.post("/api/allowlist", json=BODY)
    entry_id = r.json()["id"]
    assert client.post(f"/api/allowlist/{entry_id}/approve").status_code == 403
    assert client.delete(f"/api/allowlist/{entry_id}").status_code == 403


def test_reject_flow_and_reactivate(client, users_seeded):
    _login(client, ANALYST)
    entry_id = client.post("/api/allowlist", json=BODY).json()["id"]
    _login(client, ENGINEER)
    assert client.post(f"/api/allowlist/{entry_id}/reject").status_code == 200
    assert client.post(f"/api/allowlist/{entry_id}/reject").status_code == 409
    # a rejected entry can be re-activated by an explicit approve
    r = client.post(f"/api/allowlist/{entry_id}/approve")
    assert r.status_code == 200 and r.json()["status"] == "active"


# ---------------------------------------------------------------- guards


def test_universe_entries_rejected(client):
    _login(client, ADMIN)
    for bad in ("0.0.0.0/0", "::/0"):
        r = client.post("/api/allowlist", json={**BODY, "entity_value": bad})
        assert r.status_code == 422, bad
    r = client.post("/api/allowlist", json={
        **BODY, "entity_field": "dst_domain", "entity_value": "*"})
    assert r.status_code == 422
    # overly broad IPv4 CIDR (min /8)
    r = client.post("/api/allowlist", json={**BODY, "entity_value": "10.0.0.0/2"})
    assert r.status_code == 422


def test_unknown_alert_type_or_layer_rejected(client):
    _login(client, ADMIN)
    assert client.post("/api/allowlist", json={
        **BODY, "alert_type": "brand_new_detector"}).status_code == 422
    assert client.post("/api/allowlist", json={
        **BODY, "layer": "L9"}).status_code == 422


def test_duplicate_scope_conflict(client):
    _login(client, ADMIN)
    assert client.post("/api/allowlist", json=BODY).status_code == 201
    assert client.post("/api/allowlist", json=BODY).status_code == 409


def test_ttl_validation_and_expiry(client):
    _login(client, ADMIN)
    assert client.post("/api/allowlist", json={
        **BODY, "ttl_hours": 7}).status_code == 422
    r = client.post("/api/allowlist", json={**BODY, "ttl_hours": 720})
    assert r.status_code == 201
    assert r.json()["expires_at"] is not None
    r = client.post("/api/allowlist", json={**BODY, "entity_value": "10.10.9.9"})
    assert r.json()["expires_at"] is None      # permanent


# ---------------------------------------------------------------- retro


def test_retroactive_tagged_count(client, monkeypatch):
    from app.os_client import get_os
    _login(client, ADMIN)
    monkeypatch.setattr(type(get_os()), "suppress_alert_docs",
                        lambda self, **kw: 5, raising=True)
    r = client.post("/api/allowlist", json={**BODY, "retroactive": True})
    data = r.json()
    assert data["retro_tagged"] == 5
    assert data["hit_count"] == 5


def test_retroactive_deferred_until_approve(client, monkeypatch, users_seeded):
    from app.os_client import get_os
    _login(client, ANALYST)
    entry_id = client.post("/api/allowlist",
                           json={**BODY, "retroactive": True}).json()["id"]
    _login(client, ENGINEER)
    calls = []

    def fake(self, **kw):
        calls.append(kw)
        return 3

    monkeypatch.setattr(type(get_os()), "suppress_alert_docs", fake,
                        raising=True)
    r = client.post(f"/api/allowlist/{entry_id}/approve")
    assert r.status_code == 200
    assert r.json()["retro_tagged"] == 3
    assert calls and calls[0]["suppressed_by"] == entry_id


def test_retroactive_backend_failure_is_soft(client, monkeypatch):
    from app.os_client import get_os
    _login(client, ADMIN)

    def boom(self, **kw):
        raise RuntimeError("cluster down")

    monkeypatch.setattr(type(get_os()), "suppress_alert_docs", boom,
                        raising=True)
    # the real OSClient catches inside suppress_alert_docs; simulate the
    # failure surface the API would see anyway:
    r = client.post("/api/allowlist", json={**BODY, "retroactive": True})
    assert r.status_code == 201
    assert r.json()["retro_tagged"] == 0


# ---------------------------------------------------------------- lifecycle


def test_summary_shape_and_top(client):
    _login(client, ADMIN)
    client.post("/api/allowlist", json=BODY)
    client.post("/api/allowlist", json={
        **BODY, "entity_value": "10.10.5.0/24", "layer": "L1"})
    r = client.get("/api/allowlist/summary")
    assert r.status_code == 200
    data = r.json()
    assert data["active"] == 2 and data["pending"] == 0
    assert data["l0"] == 1 and data["l1"] == 1
    assert isinstance(data["top"], list) and len(data["top"]) <= 5


def test_extend_reactivates_expired(client):
    _login(client, ADMIN)
    entry_id = client.post("/api/allowlist",
                           json={**BODY, "ttl_hours": 24}).json()["id"]
    # force-expire the entry (simulate TTL elapsed)
    from app.db import SessionLocal
    from app.models import AlertAllowlist
    db = SessionLocal()
    row = db.query(AlertAllowlist).filter(
        AlertAllowlist.id == entry_id).first()
    from datetime import datetime, timedelta, timezone
    row.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db.commit()
    db.close()

    rows = client.get("/api/allowlist", params={"status": "expired"}).json()
    assert any(x["id"] == entry_id for x in rows)

    r = client.post(f"/api/allowlist/{entry_id}/extend", json={"days": 30})
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "active"
    assert data["expires_at"] is not None


def test_delete_removed_from_list(client):
    _login(client, ADMIN)
    entry_id = client.post("/api/allowlist", json=BODY).json()["id"]
    assert client.delete(f"/api/allowlist/{entry_id}").status_code == 204
    remaining = client.get("/api/allowlist").json()
    assert all(x["id"] != entry_id for x in remaining)


def test_audit_trail_recorded(client):
    _login(client, ADMIN)
    client.post("/api/allowlist", json=BODY)
    from app.db import SessionLocal
    from app.models import AuditRecord
    db = SessionLocal()
    actions = [r.action for r in db.query(AuditRecord).all()]
    db.close()
    assert "whitelist.create" in actions
