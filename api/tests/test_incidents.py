"""Incident reconstruction API tests (doc section 10 - Phase 4).

Covers: list/detail/triage/report flows, RBAC (auditor read-only),
persistence boundary between pipeline-written story data and
analyst-written triage data.
"""

from app.models import (Incident, IncidentEdge, IncidentEvidence,
                        IncidentHistory, IncidentNode, IncidentNote)
from app.security import hash_password


import pytest

from sqlalchemy.orm import sessionmaker

from app.db import engine
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


def _seed_incident(db, incident_id="inc-test-1", status="open",
                   outcome_label="suspected_success"):
    outcome = {
        "label": outcome_label,
        "proven": ["Reconnaissance activity was observed"],
        "suspected": ["Periodic patterns are consistent with C2"],
        "unknown": ["Process execution on host"],
        "markers": ["recon_observed", "c2_observed"],
        "disclaimer": "Network-only assessment.",
    }
    phases = [
        {"phase": "recon", "status": "observed", "evidence_count": 2,
         "signal_count": 2, "context_count": 0},
        {"phase": "initial_access", "status": "observed",
         "evidence_count": 1, "signal_count": 1, "context_count": 0},
        {"phase": "c2", "status": "observed", "evidence_count": 1,
         "signal_count": 1, "context_count": 0},
    ]
    inc = Incident(id=incident_id, title="203.0.113.25 -> 10.0.0.50 "
                   "(Recon > Initial Access > C2)",
                   status=status, severity="high", confidence=72,
                   first_seen="2026-10-12T10:00:01Z",
                   last_seen="2026-10-12T10:05:00Z",
                   outcome=outcome, phases=phases, entity_count=3,
                   edge_count=2, evidence_count=4, signal_count=4)
    db.add(inc)
    db.add(IncidentNode(incident_id=incident_id, kind="ip",
                        key="ip:203.0.113.25", label="203.0.113.25",
                        role="attacker", phase="recon", confidence=60,
                        first_seen="2026-10-12T10:00:01Z",
                        last_seen="2026-10-12T10:05:00Z", attrs={}))
    db.add(IncidentNode(incident_id=incident_id, kind="ip",
                        key="ip:10.0.0.50", label="10.0.0.50",
                        role="entity", phase="c2", confidence=60,
                        first_seen="2026-10-12T10:00:01Z",
                        last_seen="2026-10-12T10:05:00Z", attrs={}))
    db.add(IncidentNode(incident_id=incident_id, kind="domain",
                        key="domain:c2.evil.test", label="c2.evil.test",
                        role="c2_infra", phase="c2", confidence=70,
                        first_seen="2026-10-12T10:01:15Z",
                        last_seen="2026-10-12T10:01:15Z",
                        attrs={"via": "dns/tls context"}))
    db.add(IncidentEdge(incident_id=incident_id, src_key="ip:203.0.113.25",
                        dst_key="ip:10.0.0.50", relation="probed",
                        phase="recon", inferred=False,
                        first_seen="2026-10-12T10:00:01Z",
                        last_seen="2026-10-12T10:00:01Z",
                        evidence_count=1, confidence=55))
    db.add(IncidentEdge(incident_id=incident_id, src_key="ip:10.0.0.50",
                        dst_key="domain:c2.evil.test",
                        relation="contacted", phase="c2", inferred=True,
                        first_seen="2026-10-12T10:01:15Z",
                        last_seen="2026-10-12T10:01:15Z",
                        evidence_count=1, confidence=45))
    for i, (ts, title, phase) in enumerate([
            ("2026-10-12T10:00:01Z", "Port scan suspected", "recon"),
            ("2026-10-12T10:00:08Z", "ET exploit attempt",
             "initial_access"),
            ("2026-10-12T10:01:15Z", "Possible beaconing", "c2"),
            ("2026-10-12T10:01:15Z", "DNS resolution: c2.evil.test",
             "c2")]):
        db.add(IncidentEvidence(
            incident_id=incident_id, ts=ts, kind="alert" if i < 3
            else "context", source="pipeline" if i < 3 else "zeek",
            ref_index="ndr-alerts-x", ref_id=f"ref-{i}", title=title,
            severity="high" if i == 1 else "medium", phase=phase,
            summary="heuristic evidence", detail={}))
    db.commit()
    return inc


def _login(client, users_seeded, username):
    r = login(client, username, "Password-123456")
    assert r.status_code == 200, r.text
    return r


def test_list_and_detail(client, db, users_seeded):
    _seed_incident(db)
    _login(client, users_seeded, "analyst")
    r = client.get("/api/incidents")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["outcome_label"] == "suspected_success"
    assert any(p["phase"] == "recon" for p in item["phases"])

    r = client.get(f"/api/incidents/{item['id']}")
    assert r.status_code == 200
    detail = r.json()
    assert len(detail["nodes"]) == 3
    assert len(detail["edges"]) == 2
    assert len(detail["evidence"]) == 4
    assert detail["outcome"]["label"] == "suspected_success"
    assert detail["outcome"]["unknown"]


def test_filters_and_summary(client, db, users_seeded):
    _seed_incident(db)
    _seed_incident(db, incident_id="inc-benign", status="benign",
                   outcome_label="indeterminate")
    _login(client, users_seeded, "analyst")
    r = client.get("/api/incidents", params={"status": "open"})
    assert r.json()["total"] == 1
    r = client.get("/api/incidents", params={"severity": "high"})
    assert r.json()["total"] == 2
    r = client.get("/api/incidents", params={"q": "203.0.113.25"})
    assert r.json()["total"] == 2
    r = client.get("/api/incidents/summary")
    body = r.json()
    assert body["total"] == 2
    assert body["open_total"] == 1
    assert body["by_outcome"]["suspected_success"] == 1


def test_triage_status_and_note(client, db, users_seeded):
    _seed_incident(db)
    _login(client, users_seeded, "analyst")
    r = client.patch("/api/incidents/inc-test-1/status",
                     json={"status": "confirmed",
                           "note": "Confirmed via server logs"})
    assert r.status_code == 200
    r = client.post("/api/incidents/inc-test-1/notes",
                    json={"body": "PCAP archived for forensics"})
    assert r.status_code == 200
    detail = client.get("/api/incidents/inc-test-1").json()
    assert detail["status"] == "confirmed"
    assert len(detail["notes"]) == 2
    assert any(h["action"] == "status_change"
               for h in detail["history"])


def test_triage_rbac_auditor_denied(client, db, users_seeded):
    _seed_incident(db)
    _login(client, users_seeded, "viewer")
    assert client.get("/api/incidents").status_code == 200
    r = client.patch("/api/incidents/inc-test-1/status",
                     json={"status": "confirmed"})
    assert r.status_code == 403
    r = client.post("/api/incidents/inc-test-1/notes",
                    json={"body": "note"})
    assert r.status_code == 403


def test_report_generation(client, db, users_seeded):
    _seed_incident(db)
    _login(client, users_seeded, "analyst")
    r = client.get("/api/incidents/inc-test-1/report")
    assert r.status_code == 200
    text = r.text
    assert "Incident Report" in text
    assert "Attack Timeline" in text
    assert "Proven (directly observed)" in text
    assert "Suspected (chain-inferred, needs validation)" in text
    assert "Unknown (network-only blindness)" in text
    assert "heuristic and uncalibrated" in text
    assert "ndr-alerts-x:ref-1" in text


def test_404_unknown_incident(client, db, users_seeded):
    _login(client, users_seeded, "analyst")
    assert client.get("/api/incidents/nope").status_code == 404
