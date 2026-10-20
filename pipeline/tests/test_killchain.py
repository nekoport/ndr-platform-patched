"""Cyber Kill Chain dual-framework tests (doc 11 - Phase 5b).

Covers: stage classifier mappings (rule / suricata category / IOC),
alert-doc dual enrichment, the evidence-based 7-stage assessment
(observed / suspected / not_observed / insufficient_telemetry), stage
history (assessment changes over time) and persistence round-trip.
"""

from app.correlation import entities as ce
from app.correlation.story import AttackStory
from app.correlation.store import IncidentStore
from app.detection import killchain as kc
from app.detection.killchain import (STAGES, assess_stages, classify_ioc,
                                     classify_rule, classify_suricata,
                                     stage_for_phase)
from app.detection.rules import build_alert_doc
from app.metrics import Metrics

from test_recon import _alert_doc, _signal


# ------------------------------------------------------------ classifier
def test_stage_mapping_from_internal_phases():
    assert stage_for_phase("recon") == "reconnaissance"
    assert stage_for_phase("initial_access") == "exploitation"
    assert stage_for_phase("delivery") == "delivery"
    assert stage_for_phase("c2") == "command_and_control"
    # lateral + impact both land on Actions on Objectives (doc 11)
    assert stage_for_phase("lateral") == "actions_on_objectives"
    assert stage_for_phase("impact") == "actions_on_objectives"
    assert stage_for_phase(None) == "actions_on_objectives"


def test_seven_stages_and_network_blind_stages():
    assert len(STAGES) == 7
    assert set(kc.NETWORK_BLIND_STAGES) == {"weaponization", "installation"}


def test_classify_rule_dual_framework():
    stage, attck = classify_rule("portscan_suspected")
    assert stage == "reconnaissance"
    ids = {t["technique_id"] for t in attck}
    assert "T1046" in ids          # Network Service Discovery
    assert all(t["tactic"] and t["technique"] for t in attck)

    stage, attck = classify_rule("beaconing_possible")
    assert stage == "command_and_control"
    assert "T1071" in {t["technique_id"] for t in attck}

    stage, attck = classify_rule("internal_lateral_suspected")
    assert stage == "actions_on_objectives"
    assert "T1021" in {t["technique_id"] for t in attck}


def test_classify_suricata_category():
    stage, attck = classify_suricata("web-application-attack")
    assert stage == "exploitation"
    assert "T1190" in {t["technique_id"] for t in attck}

    stage, attck = classify_suricata("attempted-recon")
    assert stage == "reconnaissance"
    assert "T1595" in {t["technique_id"] for t in attck}

    stage, attck = classify_suricata("unknown-category")
    assert stage in STAGES           # never crashes, always mapped
    assert isinstance(attck, list)


def test_classify_ioc():
    stage, attck = classify_ioc("domain")
    assert stage == "command_and_control"
    stage, attck = classify_ioc("sha256")
    assert stage == "delivery"


# --------------------------------------------------- alert doc enrichment
def test_alert_doc_carries_dual_framework():
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    doc = build_alert_doc(
        alert_id="kc-1", alert_type="portscan_suspected", title="t",
        group_key="g", severity="medium", rationale="r", reasons=[],
        first_seen=now, last_seen=now, sensor_id="s", event_count=1,
        source_count=1, destination_count=1, source_ip="203.0.113.9",
        destination_ip=None, transport=None, protocol=None,
        top_sources=[], top_destinations=[], top_rules=[], evidence=[])
    assert doc["kill_chain"]["stage"] == "reconnaissance"
    assert doc["kill_chain"]["stage_label"] == "Reconnaissance"
    assert doc["kill_chain"]["reason"]
    assert any(t["technique_id"] == "T1046" for t in doc["mitre"])


def test_alert_doc_suricata_uses_category():
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    doc = build_alert_doc(
        alert_id="kc-2", alert_type="suricata_alert_group", title="t",
        group_key="g", severity="high", rationale="r", reasons=[],
        first_seen=now, last_seen=now, sensor_id="s", event_count=3,
        source_count=1, destination_count=1, source_ip="203.0.113.9",
        destination_ip="10.0.0.5", transport=None, protocol=None,
        top_sources=[], top_destinations=[], top_rules=[], evidence=[],
        suricata_category="malware-cnc")
    assert doc["kill_chain"]["stage"] == "command_and_control"
    assert "T1071" in {t["technique_id"] for t in doc["mitre"]}


def test_signal_carries_stage_and_attck():
    doc = _alert_doc(alert_type="portscan_suspected", attack_phase="recon")
    doc["kill_chain"] = {"stage": "reconnaissance",
                         "stage_label": "Reconnaissance",
                         "reason": "test reason"}
    doc["mitre"] = [{"tactic": "Reconnaissance", "technique_id": "T1046",
                     "technique": "Network Service Discovery"}]
    sig = ce.extract_from_alert(doc, "ndr-alerts-x")
    assert sig.kill_chain_stage == "reconnaissance"
    assert sig.stage_reason == "test reason"
    assert sig.attck[0]["technique_id"] == "T1046"


# ------------------------------------------------------- stage assessment
def _ev(kind, stage, severity="medium", attck=None):
    return {"kind": kind, "stage": stage, "severity": severity,
            "attck": attck or [], "phase": stage_for_phase(stage)}


def test_assess_statuses_observed_suspected():
    evidence = [_ev("alert", "reconnaissance"),
                _ev("context", "command_and_control")]
    out = {s["stage"]: s for s in assess_stages(evidence)}
    assert out["reconnaissance"]["status"] == "observed"
    assert out["reconnaissance"]["confidence"] >= 55
    assert out["command_and_control"]["status"] == "suspected"
    assert out["command_and_control"]["confidence"] < \
        out["reconnaissance"]["confidence"]


def test_assess_statuses_not_observed_and_blind():
    out = {s["stage"]: s for s in assess_stages([])}
    # telemetry covers delivery, but nothing arrived in this story
    assert out["delivery"]["status"] == "not_observed"
    assert out["delivery"]["reason"]
    # network-only blindness is explicit, never guessed
    assert out["weaponization"]["status"] == "insufficient_telemetry"
    assert out["installation"]["status"] == "insufficient_telemetry"
    assert "network" in out["weaponization"]["reason"].lower()


def test_assess_reasons_and_attck_present():
    evidence = [_ev("alert", "delivery", severity="high")]
    out = {s["stage"]: s for s in assess_stages(evidence)}
    assert out["delivery"]["reason"]
    assert out["delivery"]["attck"], "stage-level ATT&CK fallback"
    assert out["delivery"]["confidence"] > 60  # high severity bonus


# ----------------------------------------------------- story progression
def test_story_stage_progression_and_history():
    story = AttackStory("st-kc-1", gap_seconds=900)
    s1 = _signal(alert_id="kc-r1", alert_type="portscan_suspected",
                 attack_phase="recon",
                 kill_chain_stage="reconnaissance",
                 stage_reason="rule classification")
    story.ingest_signal(s1)
    s2 = _signal(alert_id="kc-c1", alert_type="beaconing_possible",
                 attack_phase="c2",
                 kill_chain_stage="command_and_control")
    story.ingest_signal(s2)

    prog = {s["stage"]: s for s in story.stage_progression()}
    assert prog["reconnaissance"]["status"] == "observed"
    assert prog["command_and_control"]["status"] == "observed"
    assert prog["delivery"]["status"] == "not_observed"
    assert prog["weaponization"]["status"] == "insufficient_telemetry"
    assert prog["exploitation"]["status"] == "not_observed"

    # deepest stage = last observed/suspected in chain order
    assert story.deepest_stage() == "command_and_control"

    # history records transitions over time, newest evidence wins
    assert story.stage_history, "assessment changes are tracked"
    recon_entries = [h for h in story.stage_history
                     if h["stage"] == "reconnaissance"]
    assert recon_entries[0]["from"] == "not_observed"
    assert recon_entries[0]["to"] == "observed"
    assert recon_entries[0]["evidence_ref"] == "kc-r1"


def test_story_dual_framework_summary_detail():
    story = AttackStory("st-kc-2", gap_seconds=900)
    story.ingest_signal(_signal(
        alert_id="kc-d1", alert_type="file_transfer_suspected",
        attack_phase="delivery", kill_chain_stage="delivery"))
    detail = story.to_detail()
    assert detail["stage_progression"]
    assert len(detail["stage_progression"]) == 7
    assert detail["stage_history"]
    stages = {s["stage"]: s for s in detail["stages"]}
    assert stages["delivery"]["status"] == "observed"
    # evidence items carry the dual-framework fields
    assert detail["evidence"][0]["stage"] == "delivery"


def test_story_late_evidence_updates_assessment():
    story = AttackStory("st-kc-3", gap_seconds=3600)
    story.ingest_signal(_signal(
        alert_id="kc-e1", alert_type="suricata_alert_group",
        attack_phase="initial_access",
        kill_chain_stage="exploitation"))
    prog = {s["stage"]: s for s in story.stage_progression()}
    assert prog["exploitation"]["status"] == "observed"
    # late C2 evidence arrives -> assessment deepens, history grows
    story.ingest_signal(_signal(
        alert_id="kc-e2", alert_type="beaconing_possible",
        attack_phase="c2", kill_chain_stage="command_and_control"))
    prog = {s["stage"]: s for s in story.stage_progression()}
    assert prog["command_and_control"]["status"] == "observed"
    assert story.deepest_stage() == "command_and_control"
    c2_entries = [h for h in story.stage_history
                  if h["stage"] == "command_and_control"]
    assert c2_entries[0]["from"] == "not_observed"
    assert c2_entries[0]["to"] == "observed"


# -------------------------------------------------------- persistence
def test_store_roundtrip_stage_data(tmp_path):
    db = f"sqlite:///{tmp_path}/kc.db"
    store = IncidentStore(db)
    story = AttackStory("st-kc-rt", gap_seconds=900)
    story.ingest_signal(_signal(
        alert_id="kc-rt1", alert_type="portscan_suspected",
        attack_phase="recon", kill_chain_stage="reconnaissance"))
    story.ingest_signal(_signal(
        alert_id="kc-rt2", alert_type="beaconing_possible",
        attack_phase="c2", kill_chain_stage="command_and_control"))
    store.save_story(story)

    rows = store.load_active(lookback_hours=24)
    assert rows and rows[0]["incident"]["id"] == "st-kc-rt"
    evs = rows[0]["evidence"]
    stages = {e["stage"] for e in evs}
    assert "reconnaissance" in stages
    assert "command_and_control" in stages
    import json
    outcome = json.loads(rows[0]["incident"]["outcome"])
    assert outcome["stage_progression"]
    assert outcome["stage_history"]
    assert outcome["deepest_stage"] == "command_and_control"

    # reload path (service._story_from_row) restores the history
    from app.correlation.service import ReconstructionService
    from app.config import Config
    svc = ReconstructionService(Config(), Metrics("sensor-test"), store)
    story2 = svc._story_from_row(rows[0])
    assert story2.stage_history == story.stage_history
    assert story2._stage_status["command_and_control"] == "observed"
    ev2 = {e.ref_id: e for e in story2.evidence}
    assert ev2["kc-rt1"].stage == "reconnaissance"
