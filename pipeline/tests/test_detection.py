"""Detection rule tests (aggregation vs dedup guardrails, doc section 8)."""

import queue
from datetime import timedelta

from app.models import CommonEvent, utcnow
from app.detection.rules import (BeaconingDetector, NXDomainBurstDetector,
                                 PortscanDetector, SuricataAlertGrouper)

SENSOR = "sensor-test"


def _ev(**kw):
    now = utcnow()
    defaults = dict(
        event_id="e1", event_time=now, ingest_time=now, sensor_id=SENSOR,
        source_engine="suricata", event_type="alert",
        source_ip="203.0.113.25", destination_ip="192.168.1.50",
        destination_port=80, transport="tcp",
    )
    defaults.update(kw)
    return CommonEvent(**defaults)


def _sweep_all(*rules):
    """Simulate that one window has fully elapsed without new activity."""
    import time as t
    for r in rules:
        r.sweep(t.time() + r.window_seconds + 5)


def test_suricata_alert_grouping_same_signature():
    q = queue.Queue()
    rule = SuricataAlertGrouper(600, 1000, SENSOR, q, lambda ts: "ndr-alerts-x")
    for i in range(5):
        rule.feed(_ev(alert_signature="ET SQLi", signature_id="2016645",
                      severity="high"), "ndr-suricata-2026.10.12")
    _sweep_all(rule)
    alerts = [q.get_nowait() for _ in range(q.qsize())]
    assert len(alerts) == 1
    index, alert_id, doc = alerts[0]
    assert doc["alert_type"] == "suricata_alert_group"
    assert doc["event_count"] == 5
    # Frequency lives in the event_count field - the title must NOT embed
    # the count (doc 8.1: title identifies the signature, not the volume).
    assert doc["title"] == "Suricata: ET SQLi"
    assert "(5x)" not in doc["title"]
    assert doc["severity"] == "high"
    assert len(doc["evidence"]) == 5
    assert "does not by itself prove" in doc["rationale"]


def test_different_sources_not_grouped_together():
    """AT-06 guardrail: two IPs with same signature stay separate."""
    q = queue.Queue()
    rule = SuricataAlertGrouper(600, 1000, SENSOR, q, lambda ts: "ndr-alerts-x")
    rule.feed(_ev(source_ip="1.1.1.1", signature_id="2016645"), "idx")
    rule.feed(_ev(source_ip="2.2.2.2", signature_id="2016645"), "idx")
    _sweep_all(rule)
    alerts = [q.get_nowait() for _ in range(q.qsize())]
    assert len(alerts) == 2
    assert alerts[0][2]["source"]["ip"] != alerts[1][2]["source"]["ip"]


def test_portscan_triggers_on_unique_ports():
    q = queue.Queue()
    rule = PortscanDetector(unique_ports=10, unique_hosts=50, window_min=10,
                            max_keys=1000, sensor_id=SENSOR, sink_queue=q,
                            index_for_alert=lambda ts: "ndr-alerts-x")
    now = utcnow() - timedelta(seconds=15)
    for port in range(1000, 1020):
        ev = _ev(source_engine="zeek", event_type="conn",
                 source_ip="203.0.113.99", destination_ip="192.168.1.10",
                 destination_port=port)
        ev.event_time = now + timedelta(seconds=port % 5)
        rule.feed(ev, "idx")
    _sweep_all(rule)
    _, _, doc = q.get_nowait()
    assert doc["alert_type"] == "portscan_suspected"
    assert doc["destination_count"] >= 1
    assert any("ports" in r for r in doc["reasons"])


def test_portscan_below_threshold_silent():
    q = queue.Queue()
    rule = PortscanDetector(unique_ports=100, unique_hosts=50, window_min=10,
                            max_keys=1000, sensor_id=SENSOR, sink_queue=q,
                            index_for_alert=lambda ts: "ndr-alerts-x")
    now = utcnow()
    for port in range(1000, 1010):  # only 10 ports < threshold 100
        ev = _ev(source_engine="zeek", event_type="conn",
                 source_ip="203.0.113.99", destination_ip="192.168.1.10",
                 destination_port=port)
        ev.event_time = now
        rule.feed(ev, "idx")
    _sweep_all(rule)
    assert q.empty()


def test_nxdomain_burst_triggers():
    q = queue.Queue()
    rule = NXDomainBurstDetector(min_count=10, ratio=0.5, window_min=10,
                                 max_keys=1000, sensor_id=SENSOR, sink_queue=q,
                                 index_for_alert=lambda ts: "ndr-alerts-x")
    now = utcnow() - timedelta(seconds=25)
    for i in range(15):
        ev = _ev(source_engine="suricata", event_type="dns",
                 source_ip="192.168.1.77", dns_rcode="NXDOMAIN",
                 dns_query=f"abc{i}dga.example")
        ev.event_time = now + timedelta(seconds=i)
        rule.feed(ev, "idx")
    _sweep_all(rule)
    _, _, doc = q.get_nowait()
    assert doc["alert_type"] == "dns_nxdomain_burst"
    assert doc["severity"] == "low"
    assert "uncalibrated" in doc["rationale"]


def test_nxdomain_below_ratio_silent():
    q = queue.Queue()
    rule = NXDomainBurstDetector(min_count=10, ratio=0.5, window_min=10,
                                 max_keys=1000, sensor_id=SENSOR, sink_queue=q,
                                 index_for_alert=lambda ts: "ndr-alerts-x")
    now = utcnow() - timedelta(seconds=25)
    for i in range(10):
        rcode = "NXDOMAIN" if i < 3 else "NOERROR"
        ev = _ev(source_engine="suricata", event_type="dns",
                 source_ip="192.168.1.77", dns_rcode=rcode)
        ev.event_time = now + timedelta(seconds=i)
        rule.feed(ev, "idx")
    _sweep_all(rule)
    assert q.empty()


def test_beaconing_detected_on_regular_intervals():
    q = queue.Queue()
    rule = BeaconingDetector(min_connections=10, interval_min_sec=10,
                             interval_max_sec=3600, jitter_max=0.2,
                             window_min=60, max_keys=1000, sensor_id=SENSOR,
                             sink_queue=q, index_for_alert=lambda ts: "ndr-alerts-x")
    base = utcnow() - timedelta(seconds=850)
    for i in range(15):
        ev = _ev(source_engine="zeek", event_type="conn",
                 source_ip="192.168.1.50", destination_ip="198.51.100.6",
                 destination_port=443)
        ev.event_time = base + timedelta(seconds=60 * i)
        rule.feed(ev, "idx")
    _sweep_all(rule)
    _, _, doc = q.get_nowait()
    assert doc["alert_type"] == "beaconing_possible"
    assert doc["source"]["ip"] == "192.168.1.50"
    assert doc["destination"]["ip"] == "198.51.100.6"


def test_beaconing_irregular_not_flagged():
    q = queue.Queue()
    rule = BeaconingDetector(min_connections=10, interval_min_sec=10,
                             interval_max_sec=3600, jitter_max=0.2,
                             window_min=60, max_keys=1000, sensor_id=SENSOR,
                             sink_queue=q, index_for_alert=lambda ts: "ndr-alerts-x")
    base = utcnow() - timedelta(seconds=3600)
    # jittery intervals: 10, 300, 15, 600, ...
    irregular = [10, 300, 15, 600, 30, 240, 18, 700, 25, 450, 12, 320, 40, 800]
    offset = 0
    for i, gap in enumerate(irregular):
        offset += gap
        ev = _ev(source_engine="zeek", event_type="conn",
                 source_ip="192.168.1.50", destination_ip="198.51.100.6",
                 destination_port=443)
        ev.event_time = base + timedelta(seconds=offset)
        rule.feed(ev, "idx")
    _sweep_all(rule)
    assert q.empty()


def test_attack_result_outcome_field():
    """v0.10: alert-level attack-result verdict (`outcome`).

    Taxonomy matches the incident-level OutcomeLabel; `strong_success` is
    reserved for the correlation engine. Only a server-reaction signature
    (ATTACK_RESPONSE family / attack-response classtype) may claim
    suspected_success; scans and behavioral rules stay indeterminate.
    """
    from app.detection.rules import outcome_for_alert

    # exploit-class signature -> attempted (signature proves the attempt,
    # never success)
    q = queue.Queue()
    rule = SuricataAlertGrouper(600, 1000, SENSOR, q, lambda ts: "ndr-alerts-x")
    rule.feed(_ev(alert_signature="ET WEB_SERVER SQL Injection Attempt",
                  signature_id="2016645",
                  alert_category="web-application-attack"), "idx")
    _sweep_all(rule)
    doc = q.get_nowait()[2]
    assert doc["outcome"] == "attempted"

    # server-reaction signature -> suspected_success
    q2 = queue.Queue()
    rule2 = SuricataAlertGrouper(600, 1000, SENSOR, q2, lambda ts: "ndr-alerts-x")
    rule2.feed(_ev(alert_signature="GPL ATTACK_RESPONSE id check returned root",
                   signature_id="2000001",
                   alert_category="attack-response"), "idx")
    _sweep_all(rule2)
    doc2 = q2.get_nowait()[2]
    assert doc2["outcome"] == "suspected_success"

    # scan classtype -> indeterminate (activity may be benign)
    assert outcome_for_alert("suricata_alert_group",
                             "attempted-recon") == "indeterminate"
    assert outcome_for_alert("suricata_alert_group",
                             "policy-violation") == "indeterminate"

    # behavioral rules never claim an attack outcome
    assert outcome_for_alert("portscan_suspected") == "indeterminate"
    assert outcome_for_alert("beaconing_possible") == "indeterminate"
    assert outcome_for_alert("dns_nxdomain_burst") == "indeterminate"
    assert outcome_for_alert("ioc_match") == "indeterminate"

    # strong_success is never set at alert level
    assert outcome_for_alert("suricata_alert_group", "attack-response") \
        != "strong_success"
