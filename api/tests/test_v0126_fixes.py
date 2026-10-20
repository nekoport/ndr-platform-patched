"""v0.12.6 fix tests: resilient alert resolution + honest backend errors.

Regression for the live-deployment report: the Alert Center detail's
"PCAP & sessions (doc 15)" panel answered 404 "Alert not found" for an
alert that was clearly listable, because alert resolution relied on a
bare GET-by-id against the multi-index ndr-alerts-read alias (and every
backend error was swallowed into that same 404).

Covers:
  * get_alert_doc fallback -> docs resolvable by the alert_id FIELD when
    the _id differs (older writers / multi-index alias fan-out quirks)
  * get_alert, PATCH update and escalate all follow the resolved _id
  * backend failures surface as 502 instead of a lying 404
"""

from __future__ import annotations

import pytest

from tests.conftest import login

ADMIN = {"username": "admin", "password": "bootstrap-admin-pass-01"}

# doc stored under an OpenSearch _id that DIFFERS from its alert_id field
RESOLVED_ID = "opensearch-doc-id-1"
FIELD_ID = "alert-field-id-1"
ALERT_DOC = {
    "_id": RESOLVED_ID,
    "_index": "ndr-alerts-2026.10.10",
    "_source": {
        "alert_id": FIELD_ID,
        "alert_type": "portscan_suspected",
        "title": "Port scan suspected from 198.51.100.7",
        "severity": "medium",
        "severity_score": 50,
        "status": "new",
        "first_seen": "2026-10-10T01:00:00Z",
        "last_seen": "2026-10-10T01:10:00Z",
        "sensor_id": "sensor-test",
        "source": {"ip": "198.51.100.7"},
        "destination": {"ip": "192.168.1.50"},
        "outcome": "indeterminate",
    },
}


@pytest.fixture()
def field_id_alert(_fake_os, monkeypatch):
    """Alert resolvable ONLY through the alert_id-field fallback."""
    monkeypatch.setattr(_fake_os, "search_alert_doc",
                        lambda alert_id: ALERT_DOC
                        if alert_id == FIELD_ID else None)
    return _fake_os


# ------------------------------------------------------------------ fallback
def test_alert_sessions_via_field_fallback(client, field_id_alert):
    login(client, **ADMIN)
    res = client.get(f"/api/evidence/alerts/{FIELD_ID}/sessions")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["scope"] == "alert"
    assert body["scope_id"] == FIELD_ID
    assert body["entities"]["ips"] == ["198.51.100.7", "192.168.1.50"]


def test_get_alert_via_field_fallback(client, field_id_alert):
    login(client, **ADMIN)
    res = client.get(f"/api/alerts/{FIELD_ID}")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["id"] == RESOLVED_ID          # the real OpenSearch _id
    assert body["source"]["alert_id"] == FIELD_ID


def test_escalate_via_field_fallback(client, field_id_alert):
    login(client, **ADMIN)
    res = client.post(f"/api/alerts/{FIELD_ID}/escalate",
                      json={"reason": "Escalated via fallback resolution"})
    assert res.status_code == 200, res.text
    assert res.json()["incident_id"] == f"inc-esc-{FIELD_ID}"


def test_update_alert_targets_resolved_id(client, field_id_alert):
    login(client, **ADMIN)
    recorded: list[dict] = []

    class _Client:
        @staticmethod
        def update(**kw):
            recorded.append(kw)
            return {"result": "updated"}

    field_id_alert.client = _Client()  # capture the partial-update target

    res = client.patch(f"/api/alerts/{FIELD_ID}", json={"status": "closed"})
    assert res.status_code == 200, res.text
    assert recorded and recorded[0]["id"] == RESOLVED_ID


# ------------------------------------------------------- honest error codes
def test_backend_failure_is_502_not_lying_404(client, _fake_os, monkeypatch):
    def _boom(alert_id):
        raise RuntimeError("opensearch connection reset")

    monkeypatch.setattr(_fake_os, "get_alert_doc", _boom)
    login(client, **ADMIN)
    assert client.get("/api/evidence/alerts/A1/sessions").status_code == 502
    assert client.get("/api/alerts/A1").status_code == 502


def test_missing_alert_still_404(client, _fake_os):
    login(client, **ADMIN)
    assert client.get("/api/evidence/alerts/missing/sessions"
                      ).status_code == 404
    assert client.get("/api/alerts/missing").status_code == 404
    assert client.post("/api/alerts/missing/escalate", json={}
                       ).status_code == 404
