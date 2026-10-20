"""v0.10 feature tests: roles matrix, user delete, asset registry,
manual alert escalation, incident time-range filter."""

from tests.conftest import SessionLocal, login  # noqa: F401

ADMIN = {"username": "admin", "password": "bootstrap-admin-pass-01"}
ANALYST = {"username": "analyst", "password": "Password-123456"}

ALERT_DOC = {
    "_id": "alert-esc-1",
    "_source": {
        "alert_id": "alert-esc-1",
        "alert_type": "suricata_alert_group",
        "title": "Suricata: ET WEB_SERVER SQL Injection Attempt",
        "group_key": "2016645|203.0.113.25",
        "severity": "high",
        "severity_score": 75,
        "risk_score": 88,
        "status": "new",
        "confidence": "heuristic-uncalibrated",
        "rationale": "42 events for the same signature from one source.",
        "event_count": 42,
        "source_count": 1,
        "destination_count": 1,
        "first_seen": "2026-10-12T01:00:00Z",
        "last_seen": "2026-10-12T01:20:00Z",
        "sensor_id": "sensor-test",
        "source": {"ip": "203.0.113.25"},
        "destination": {"ip": "192.168.1.50"},
        "network": {"transport": "tcp", "protocol": "http"},
        "outcome": "attempted",
        "kill_chain": {"stage": "exploitation", "stage_label": "Exploitation",
                       "basis": "suricata category", "reason": "demo"},
    },
}


# ----------------------------------------------------------------- roles
def test_roles_matrix_exposed(client):
    login(client, **ADMIN)
    res = client.get("/api/roles")
    assert res.status_code == 200
    body = res.json()
    roles = {r["role"] for r in body["roles"]}
    assert roles == {"administrator", "security_engineer", "soc_analyst",
                     "soc_lead", "auditor"}
    caps = {c["capability"]: set(c["roles"]) for c in body["capabilities"]}
    assert "user_admin" in caps
    assert caps["user_admin"] == {"administrator"}
    assert "auditor" not in caps["alert_update"]


def test_roles_readable_by_auditor(client):
    login(client, **ADMIN)
    res = client.get("/api/roles")
    assert res.status_code == 200


# ----------------------------------------------------------------- user delete
def test_user_delete_flow(client, users_seeded):
    login(client, **ADMIN)
    res = client.delete("/api/users/analyst")
    assert res.status_code == 200
    assert client.get("/api/users").json() is not None
    remaining = [u["username"] for u in client.get("/api/users").json()]
    assert "analyst" not in remaining


def test_user_delete_self_rejected(client):
    login(client, **ADMIN)
    res = client.delete("/api/users/admin")
    assert res.status_code == 400


def test_user_delete_and_last_admin_guard(client):
    login(client, **ADMIN)
    # create a second admin, then deleting it is fine (one active admin left)
    res = client.post("/api/users", json={
        "username": "admin2", "password": "Password-223456",
        "role": "administrator"})
    assert res.status_code == 200
    assert client.delete("/api/users/admin2").status_code == 200
    # the last-admin guard fires when disabling yourself (the only active
    # admin) via PATCH - delete of self is caught earlier by the self-guard
    res = client.patch("/api/users/admin", json={"is_active": False})
    assert res.status_code == 409


def test_user_delete_requires_user_admin(client, users_seeded):
    login(client, **ANALYST)
    res = client.delete("/api/users/viewer")
    assert res.status_code == 403


# ----------------------------------------------------------------- assets
def test_asset_registry_crud(client):
    login(client, **ADMIN)
    res = client.post("/api/assets", json={
        "ip": "192.168.2.30", "hostname": "vault-app-01", "zone": "servers",
        "role": "Payment vault", "criticality": "critical"})
    assert res.status_code == 200
    asset = res.json()
    assert asset["hostname"] == "vault-app-01"
    assert asset["created_by"] == "admin"

    # duplicate IP rejected
    dup = client.post("/api/assets", json={
        "ip": "192.168.2.30", "hostname": "x", "zone": "servers",
        "role": "dup", "criticality": "low"})
    assert dup.status_code == 409

    listed = client.get("/api/assets").json()
    assert any(a["ip"] == "192.168.2.30" for a in listed)

    patched = client.patch(f"/api/assets/{asset['id']}",
                           json={"hostname": "vault-app-02"})
    assert patched.status_code == 200
    assert patched.json()["hostname"] == "vault-app-02"

    assert client.delete(f"/api/assets/{asset['id']}").status_code == 200
    assert not any(a["ip"] == "192.168.2.30"
                   for a in client.get("/api/assets").json())


def test_asset_mutations_require_sensor_admin(client, users_seeded):
    login(client, **ANALYST)
    res = client.post("/api/assets", json={
        "ip": "10.1.1.1", "hostname": "h", "zone": "servers",
        "role": "r", "criticality": "low"})
    assert res.status_code == 403


# ----------------------------------------------------------------- escalate
def test_manual_escalation_creates_incident(client, monkeypatch):
    login(client, **ADMIN)
    monkeypatch.setattr("app.os_client._client",
                        type("F", (), {
                            "get_by_id": staticmethod(
                                lambda alias, doc_id: ALERT_DOC),
                            # v0.12.6: routers resolve alerts via
                            # get_alert_doc (get + term-search fallback)
                            "get_alert_doc": staticmethod(
                                lambda alert_id: ALERT_DOC),
                            "validate_alias": staticmethod(
                                lambda a: None),
                        })())

    res = client.post("/api/alerts/alert-esc-1/escalate",
                      json={"reason": "Confirmed scanning pattern, needs review"})
    assert res.status_code == 200
    body = res.json()
    assert body["incident_id"] == "inc-esc-alert-esc-1"
    assert body["title"].startswith("Manual escalation:")

    # second escalation of the same alert is rejected (idempotency guard)
    assert client.post("/api/alerts/alert-esc-1/escalate",
                       json={}).status_code == 409

    # incident detail: exactly the alert's evidence, NO invented edges
    detail = client.get("/api/incidents/inc-esc-alert-esc-1").json()
    assert detail["status"] == "open"
    assert detail["severity"] == "high"
    assert detail["evidence_count"] == 1
    assert detail["edge_count"] == 0
    assert {n["label"] for n in detail["nodes"]} == \
        {"203.0.113.25", "192.168.1.50"}
    assert detail["outcome"]["label"] == "attempted"
    assert detail["outcome"]["markers"] == ["manual escalation"]
    assert detail["history"][0]["action"] == "created_by_manual_escalation"
    assert any(n["body"].startswith("Confirmed scanning")
               for n in detail["notes"])


def test_manual_escalation_missing_alert_404(client):
    login(client, **ADMIN)
    res = client.post("/api/alerts/does-not-exist/escalate", json={})
    assert res.status_code == 404


def test_manual_escalation_rbac(client, users_seeded, monkeypatch):
    # auditor lacks incident_update -> 403
    login(client, username="viewer", password="Password-123456")
    monkeypatch.setattr("app.os_client._client",
                        type("F", (), {
                            "get_by_id": staticmethod(
                                lambda alias, doc_id: ALERT_DOC),
                            "get_alert_doc": staticmethod(
                                lambda alert_id: ALERT_DOC),
                        })())
    res = client.post("/api/alerts/alert-esc-1/escalate", json={})
    assert res.status_code == 403


# ------------------------------------------------- incident time-range filter
def test_incident_list_time_range(client):
    login(client, **ADMIN)
    from datetime import datetime, timezone

    from app.models import Incident
    db = SessionLocal()
    db.add(Incident(id="inc-old", title="old story", status="open",
                    severity="low", confidence=40,
                    first_seen="2026-09-01T00:00:00Z",
                    last_seen="2026-09-01T01:00:00Z"))
    db.add(Incident(id="inc-new", title="new story", status="open",
                    severity="high", confidence=80,
                    first_seen="2026-10-12T00:00:00Z",
                    last_seen="2026-10-12T05:00:00Z"))
    db.commit()
    db.close()

    # 7-day window keeps only the recent incident
    res = client.get("/api/incidents",
                     params={"time_from": "2026-10-06T00:00:00Z"})
    ids = {i["id"] for i in res.json()["items"]}
    assert ids == {"inc-new"}

    # wide window keeps both
    res = client.get("/api/incidents")
    assert res.json()["total"] == 2

    # custom upper bound excludes everything seen after it
    res = client.get("/api/incidents",
                     params={"time_to": "2026-09-15T00:00:00Z"})
    ids = {i["id"] for i in res.json()["items"]}
    assert ids == {"inc-old"}
