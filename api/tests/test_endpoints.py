"""Endpoint behavior tests: search guard wiring, health, sensors, audit."""

from tests.conftest import login

ADMIN = {"username": "admin", "password": "bootstrap-admin-pass-01"}


def test_events_search_uses_guard_and_aliases(client):
    login(client, **ADMIN)
    res = client.post("/api/events/search", json={
        "index": "ndr-suricata-2026.10.12",  # raw index must be rejected
        "size": 10})
    assert res.status_code == 400
    assert "not an allowed read alias" in res.json()["detail"]


def test_events_search_valid_query_ok(client):
    login(client, **ADMIN)
    res = client.post("/api/events/search", json={
        "index": "ndr-events-read", "size": 10,
        "query": {"term": {"source.ip": "203.0.113.25"}},
        "time_from": "2026-10-11T00:00:00Z"})
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 0 and body["hits"] == []


def test_events_search_oversize_rejected(client):
    login(client, **ADMIN)
    res = client.post("/api/events/search", json={
        "index": "ndr-events-read", "size": 5000})
    assert res.status_code == 422  # schema cap at 500


def test_audit_records_searches(client):
    login(client, **ADMIN)
    client.post("/api/events/search", json={"index": "ndr-events-read"})
    res = client.get("/api/audit?action=events.search")
    assert res.status_code == 200
    body = res.json()
    assert body["total"] >= 1
    assert body["records"][0]["action"] == "events.search"
    assert body["records"][0]["actor"] == "admin"


def test_health_endpoint_shape(client):
    login(client, **ADMIN)
    res = client.get("/api/health")
    assert res.status_code == 200
    body = res.json()
    assert body["postgres"]["ok"] is True
    assert body["opensearch"]["status"] == "green"
    assert body["pipeline"]["eps"] == 12.5
    assert body["status"] in ("healthy", "degraded")


def test_sensor_crud_audited(client):
    login(client, **ADMIN)
    res = client.post("/api/sensors", json={
        "id": "sensor-01", "hostname": "ndr-sensor-01",
        "capture_iface": "ens160"})
    assert res.status_code == 200
    # duplicate rejected
    assert client.post("/api/sensors", json={
        "id": "sensor-01", "hostname": "x"}).status_code == 409
    res = client.get("/api/sensors")
    assert any(s["id"] == "sensor-01" for s in res.json())
    # visible in audit trail
    res = client.get("/api/audit?action=sensor.create")
    assert res.json()["total"] == 1


def test_user_create_flow(client, users_seeded):
    login(client, **ADMIN)
    res = client.post("/api/users", json={
        "username": "soc.lead", "password": "Lead-Passw0rd-01",
        "role": "soc_lead", "full_name": "SOC Lead"})
    assert res.status_code == 200
    # plaintext password never appears in audit
    res = client.get("/api/audit?action=user.create")
    assert "Lead-Passw0rd-01" not in str(res.json())
