"""Cyber Kill Chain API tests (doc 11 - Phase 5b).

Covers: stage_progression + stage_history in the incident detail
(pipeline-persisted path AND legacy fallback computed from evidence),
kill_chain_stage on nodes, deepest_stage in the list view, and the Kill
Chain section of the Markdown report.
"""

from app.models import Incident, IncidentEvidence
from sqlalchemy.orm import sessionmaker

from app.db import engine
from tests.conftest import login
from tests.test_incidents import _seed_incident, _login

TestSession = sessionmaker(bind=engine, autoflush=False,
                           expire_on_commit=False)


import pytest


@pytest.fixture()
def db():
    db = TestSession()
    try:
        yield db
    finally:
        db.close()


def _seed_killchain_incident(db, incident_id="inc-kc-1"):
    inc = _seed_incident(db, incident_id=incident_id)
    # upgrade the outcome blob with pipeline-persisted stage data (doc 11)
    inc.outcome = {
        **(inc.outcome or {}),
        "deepest_stage": "command_and_control",
        "stage_progression": [
            {"stage": "reconnaissance", "label": "Reconnaissance",
             "status": "observed", "evidence_count": 2,
             "signal_count": 2, "context_count": 0, "confidence": 67,
             "attck": [{"tactic": "Reconnaissance",
                        "technique_id": "T1046",
                        "technique": "Network Service Discovery"}],
             "reason": "2 direct signal(s) (alert) mapped to this stage"},
            {"stage": "weaponization", "label": "Weaponization",
             "status": "insufficient_telemetry", "evidence_count": 0,
             "signal_count": 0, "context_count": 0, "confidence": 0,
             "attck": [], "reason": "not visible in network traffic"},
            {"stage": "delivery", "label": "Delivery",
             "status": "not_observed", "evidence_count": 0,
             "signal_count": 0, "context_count": 0, "confidence": 0,
             "attck": [], "reason": "no evidence in this attack story"},
            {"stage": "exploitation", "label": "Exploitation",
             "status": "observed", "evidence_count": 1,
             "signal_count": 1, "context_count": 0, "confidence": 61,
             "attck": [{"tactic": "Initial Access",
                        "technique_id": "T1190",
                        "technique": "Exploit Public-Facing Application"}],
             "reason": "1 direct signal(s) (alert) mapped to this stage"},
            {"stage": "installation", "label": "Installation",
             "status": "insufficient_telemetry", "evidence_count": 0,
             "signal_count": 0, "context_count": 0, "confidence": 0,
             "attck": [], "reason": "needs endpoint telemetry"},
            {"stage": "command_and_control", "label": "Command & Control",
             "status": "observed", "evidence_count": 2,
             "signal_count": 1, "context_count": 1, "confidence": 61,
             "attck": [{"tactic": "Command and Control",
                        "technique_id": "T1071",
                        "technique": "Application Layer Protocol"}],
             "reason": "1 direct signal(s) (alert) mapped to this stage"},
            {"stage": "actions_on_objectives",
             "label": "Actions on Objectives",
             "status": "not_observed", "evidence_count": 0,
             "signal_count": 0, "context_count": 0, "confidence": 0,
             "attck": [], "reason": "no evidence in this attack story"},
        ],
        "stage_history": [
            {"ts_epoch": 1792101601.0, "ts": "2026-10-12T10:00:01Z",
             "stage": "reconnaissance", "from": "not_observed",
             "to": "observed", "evidence_ref": "ref-0"},
        ],
    }
    # tag evidence with dual-framework columns
    for i, ev in enumerate(db.query(IncidentEvidence).filter(
            IncidentEvidence.incident_id == incident_id).all()):
        ev.stage = {0: "reconnaissance", 1: "exploitation",
                    2: "command_and_control", 3: "command_and_control"}[i]
        ev.attck = [{"tactic": "Command and Control",
                     "technique_id": "T1071",
                     "technique": "Application Layer Protocol"}] \
            if i >= 2 else []
    db.commit()
    return inc


def test_detail_stage_progression_persisted(client, db, users_seeded):
    _seed_killchain_incident(db)
    _login(client, users_seeded, "analyst")
    r = client.get("/api/incidents/inc-kc-1")
    assert r.status_code == 200
    detail = r.json()
    stages = {s["stage"]: s for s in detail["stage_progression"]}
    assert len(stages) == 7
    assert stages["reconnaissance"]["status"] == "observed"
    assert stages["weaponization"]["status"] == "insufficient_telemetry"
    assert any(t["technique_id"] == "T1046"
               for t in stages["reconnaissance"]["attck"])
    assert detail["stage_history"], "assessment changes over time"
    assert detail["stage_history"][0]["from"] == "not_observed"
    assert detail["deepest_stage"] == "command_and_control"
    # nodes carry the kill-chain stage projection
    node = next(n for n in detail["nodes"]
                if n["key"] == "ip:203.0.113.25")
    assert node["kill_chain_stage"] == "reconnaissance"
    # evidence carries stage + attck
    assert all(e.get("stage") for e in detail["evidence"])


def test_detail_stage_fallback_for_legacy_incident(client, db,
                                                   users_seeded):
    # legacy incident: no stage data in outcome / evidence columns
    _seed_incident(db, incident_id="inc-legacy")
    _login(client, users_seeded, "analyst")
    r = client.get("/api/incidents/inc-legacy")
    assert r.status_code == 200
    detail = r.json()
    stages = {s["stage"]: s for s in detail["stage_progression"]}
    assert len(stages) == 7  # computed on read from evidence phases
    assert stages["reconnaissance"]["status"] == "observed"
    assert stages["exploitation"]["status"] == "observed"
    assert stages["command_and_control"]["status"] == "observed"
    assert stages["weaponization"]["status"] == "insufficient_telemetry"
    assert detail["deepest_stage"] == "command_and_control"


def test_list_carries_deepest_stage(client, db, users_seeded):
    _seed_killchain_incident(db)
    _login(client, users_seeded, "analyst")
    r = client.get("/api/incidents")
    assert r.status_code == 200
    item = r.json()["items"][0]
    assert item["deepest_stage"] == "command_and_control"


def test_report_contains_kill_chain_section(client, db, users_seeded):
    _seed_killchain_incident(db)
    _login(client, users_seeded, "analyst")
    r = client.get("/api/incidents/inc-kc-1/report")
    assert r.status_code == 200
    md = r.text
    assert "Kill Chain Stage Assessment" in md
    assert "OBSERVED" in md
    assert "INSUFFICIENT TELEMETRY" in md
    assert "T1046" in md
    assert "Assessment changes over time" in md
