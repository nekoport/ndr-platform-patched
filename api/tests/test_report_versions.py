"""Report versioning API tests (v0.12).

A report version is an IMMUTABLE snapshot of the generated incident
report plus the incident state at save time. Later triage changes must
never alter an existing version.
"""

import pytest

from sqlalchemy.orm import sessionmaker

from app.db import engine
from app.models import Incident, IncidentReportVersion
from tests.conftest import login

TestSession = sessionmaker(bind=engine, autoflush=False,
                           expire_on_commit=False)


@pytest.fixture()
def db():
    db = TestSession()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture()
def seeded(db, users_seeded):
    db.add(Incident(id="inc-rep", title="Report story",
                    status="open", severity="high", confidence=61,
                    first_seen="2026-10-12T10:00:00Z",
                    last_seen="2026-10-12T10:05:00Z",
                    outcome={"label": "attempted"}, phases=[],
                    entity_count=2, edge_count=1, evidence_count=3,
                    signal_count=3))
    db.commit()
    return db


def _as_analyst(client):
    assert login(client, "analyst", "Password-123456").status_code == 200


def test_save_version_increments_and_freezes(client, seeded):
    _as_analyst(client)
    r1 = client.post("/api/incidents/inc-rep/reports")
    assert r1.status_code == 200, r1.text
    v1 = r1.json()
    assert v1["version"] == 1
    assert v1["generated_by"] == "analyst"
    assert v1["incident_status"] == "open"
    assert v1["severity"] == "high"
    assert v1["outcome_label"] == "attempted"
    assert v1["evidence_count"] == 3

    r2 = client.post("/api/incidents/inc-rep/reports")
    assert r2.json()["version"] == 2

    # gapless, ordered desc
    r = client.get("/api/incidents/inc-rep/reports")
    assert r.json()["total"] == 2
    assert [v["version"] for v in r.json()["items"]] == [2, 1]


def test_version_markdown_is_immutable(client, seeded, db):
    _as_analyst(client)
    client.post("/api/incidents/inc-rep/reports")
    r = client.get("/api/incidents/inc-rep/reports/1")
    assert r.status_code == 200
    md_v1 = r.text
    assert "Incident Report - inc-rep" in md_v1
    assert "Status:** Open" in md_v1

    # triage the incident AFTER the snapshot
    r = client.patch("/api/incidents/inc-rep/status",
                     json={"status": "confirmed", "note": "verified"})
    assert r.status_code == 200

    # the saved version still claims the OLD state
    md_v1b = client.get("/api/incidents/inc-rep/reports/1").text
    assert md_v1b == md_v1
    assert "Status:** Open" in md_v1b

    # ...but a NEW snapshot records the new state
    v2 = client.post("/api/incidents/inc-rep/reports").json()
    assert v2["incident_status"] == "confirmed"
    md_v2 = client.get("/api/incidents/inc-rep/reports/2").text
    assert "Status:** Confirmed" in md_v2


def test_report_version_history_entry(client, seeded):
    _as_analyst(client)
    client.post("/api/incidents/inc-rep/reports")
    r = client.get("/api/incidents/inc-rep")
    actions = [h["action"] for h in r.json()["history"]]
    assert "report_version_saved" in actions


def test_report_version_rbac(client, seeded, users_seeded):
    # anonymous
    assert client.post("/api/incidents/inc-rep/reports").status_code == 401
    assert login(client, "viewer", "Password-123456").status_code == 200
    # auditor can read but not save
    assert client.get("/api/incidents/inc-rep/reports").status_code == 200
    r = client.post("/api/incidents/inc-rep/reports")
    assert r.status_code == 403


def test_report_version_not_found(client, seeded):
    _as_analyst(client)
    assert client.get("/api/incidents/inc-rep/reports/9").status_code == 404
    assert client.get("/api/incidents/inc-missing/reports").status_code == 404
    assert client.post("/api/incidents/inc-missing/reports").status_code == 404


def test_report_version_audit(client, seeded):
    _as_analyst(client)
    client.post("/api/incidents/inc-rep/reports")
    client.get("/api/incidents/inc-rep/reports/1")
    db2 = seeded
    from app.models import AuditRecord
    actions = {a.action for a in db2.query(AuditRecord)
               .filter(AuditRecord.target_type == "incident").all()}
    assert "incident.report_version_save" in actions
    assert "incident.report_version_download" in actions


def test_versions_table_unique_constraint(client, seeded, db):
    _as_analyst(client)
    client.post("/api/incidents/inc-rep/reports")
    rows = db.query(IncidentReportVersion).all()
    assert len(rows) == 1 and rows[0].version == 1
