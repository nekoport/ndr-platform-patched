"""Attack reconstruction engine tests (doc section 10 - Phase 4).

Covers: entity extraction, temporal/entity linking, story growth and
merge, DNS-answer cross-log correlation, outcome separation
(attempted / suspected_success / strong_success), persistence round-trip
and the Phase 4 behavior rules.
"""

import queue
import time
from datetime import datetime, timedelta, timezone

import pytest

from app.correlation import entities as ce
from app.correlation.service import ReconstructionService
from app.correlation.store import IncidentStore
from app.correlation.story import AttackStory
from app.correlation.trackers import AnswerTracker, SniTracker
from app.detection.behavior import (DGADetector, DnsTunnelingDetector,
                                    FileTransferDetector,
                                    InternalLateralDetector,
                                    LargeOutboundDetector, shannon_entropy)
from app.metrics import Metrics
from app.models import CommonEvent, utcnow

SENSOR = "sensor-test"
ZONES = [("10.0.0.0/8", "internal"), ("192.168.0.0/16", "servers")]


def _alert_doc(**kw):
    doc = {
        "alert_id": kw.pop("alert_id", "a-1"),
        "alert_type": kw.pop("alert_type", "portscan_suspected"),
        "title": kw.pop("title", "Port scan suspected from 203.0.113.25"),
        "group_key": "203.0.113.25",
        "severity": kw.pop("severity", "medium"),
        "attack_phase": kw.pop("attack_phase", "recon"),
        "rationale": "heuristic rationale",
        "reasons": ["r1"],
        "event_count": 10,
        "first_seen": kw.pop("first_seen",
                             "2026-10-12T10:00:01+00:00"),
        "last_seen": "2026-10-12T10:05:00+00:00",
        "source": {"ip": kw.pop("source_ip", "203.0.113.25")},
        "destination": {"ip": kw.pop("destination_ip", "10.0.0.50")},
        "top_sources": [{"ip": "203.0.113.25", "count": 10}],
        "top_destinations": [{"ip": "10.0.0.50", "count": 10}],
        "top_rules": [],
        "evidence": [],
        "related_entities": ["10.0.0.50"],
    }
    doc.update(kw)
    return doc


def _signal(**kw):
    sig = ce.extract_from_alert(_alert_doc(**kw), "ndr-alerts-x")
    assert sig is not None
    return sig


def _ev(**kw):
    now = kw.pop("event_time", utcnow())
    defaults = dict(
        event_id=kw.pop("event_id", "e1"), event_time=now,
        ingest_time=now, sensor_id=SENSOR, source_engine="zeek",
        event_type=kw.pop("event_type", "conn"),
        source_ip=kw.pop("source_ip", "10.0.0.50"),
        destination_ip=kw.pop("destination_ip", "203.0.113.9"),
        destination_port=kw.pop("destination_port", 445),
        transport="tcp", network_bytes=kw.pop("network_bytes", None),
    )
    defaults.update(kw)
    return CommonEvent(**defaults)


# ---------------------------------------------------------------- extraction
def test_entity_normalization():
    assert ce.norm_domain("Example.COM.") == "example.com"
    assert ce.norm_domain("not a domain") is None
    assert ce.norm_ip("10.0.0.1") == "10.0.0.1"
    assert ce.norm_ip("999.1.1.1") is None
    assert ce.norm_hash("AB" * 32) == "ab" * 32      # 64 hex sha256
    assert ce.norm_hash("AB" * 16) == "ab" * 16      # 32 hex md5
    assert ce.norm_hash("zz") is None


def test_extract_from_alert_builds_entities():
    sig = _signal()
    assert "ip:203.0.113.25" in sig.entities
    assert "ip:10.0.0.50" in sig.entities
    assert sig.phase == "recon"
    assert sig.kind == "alert"


def test_alert_base_confidence_bounds():
    doc = _alert_doc(alert_type="ioc_match", severity="low",
                     matched_iocs=[{"ioc_type": "domain",
                                    "ioc_value": "evil.test",
                                    "confidence": "high"}])
    sig = ce.extract_from_alert(doc, "idx")
    assert sig.base_confidence >= ce.IOC_CONF_WEIGHT["high"] - 1


# ---------------------------------------------------------------- trackers
def test_answer_tracker_links_domain_to_ip():
    t = AnswerTracker()
    t.record("c2.evil.test",
             [{"name": "c2.evil.test", "type": "A", "data": "198.51.100.7"}],
             time.time())
    assert "c2.evil.test" in t.domains_for_ip("198.51.100.7")
    assert "198.51.100.7" in t.ips_for_domain("c2.evil.test")


def test_sni_tracker():
    t = SniTracker()
    t.record("198.51.100.9", "cdn.example.test", time.time())
    assert "cdn.example.test" in t.domains_for_ip("198.51.100.9")


# ---------------------------------------------------------------- story
def test_story_growth_and_join():
    story = AttackStory.from_signal(_signal(), gap_seconds=7200)
    assert story.ingest_signal(_signal()) is True    # seed signal
    assert story.ingest_signal(_signal()) is False   # dedup on ref
    second = _signal(alert_id="a-2", alert_type="suricata_alert_group",
                     attack_phase="initial_access", severity="high",
                     title="ET exploit attempt",
                     first_seen="2026-10-12T10:00:08+00:00")
    assert story.ingest_signal(second, _TrackersStub()) is True
    assert story.signal_count == 2
    phases = {p["phase"]: p["status"] for p in story.phase_progression()}
    assert phases["recon"] == "observed"
    assert phases["initial_access"] == "observed"
    assert phases["c2"] == "none"


class _TrackersStub:
    answer = AnswerTracker()
    sni = SniTracker()


def test_index_gap_enforcement():
    """Temporal correlation: signals outside the join gap start a NEW
    story instead of extending an old one (doc 10.3 layer 2)."""
    from app.correlation.service import StoryIndex
    index = StoryIndex(gap_seconds=600, max_stories=10)
    s1 = _signal()   # first_seen 10:00:01, last_seen 10:05:00
    story = AttackStory.from_signal(s1, 600)
    story.ingest_signal(s1)
    index.register(story)

    near = _signal(alert_id="a-8",
                   first_seen="2026-10-12T10:12:00+00:00")  # within gap
    assert len(index.candidates(near)) == 1

    far = _signal(alert_id="a-9",
                  first_seen="2026-10-12T23:00:00+00:00")  # outside gap
    assert index.candidates(far) == []

    # unrelated entity -> no candidate either (no shared entities at all)
    other = _signal(alert_id="a-10", source_ip="203.0.113.99",
                    destination_ip="10.0.0.77",
                    related_entities=[],
                    top_sources=[{"ip": "203.0.113.99", "count": 3}],
                    top_destinations=[{"ip": "10.0.0.77", "count": 3}],
                    first_seen="2026-10-12T10:03:00+00:00")
    assert index.candidates(other) == []


def test_outcome_levels():
    # recon only -> indeterminate
    s1 = AttackStory.from_signal(_signal(), 7200)
    s1.ingest_signal(_signal())
    assert s1.outcome()["label"] == "indeterminate"

    # access attempt only -> attempted
    s2 = AttackStory.from_signal(_signal(), 7200)
    s2.ingest_signal(_signal())
    s2.ingest_signal(_signal(
        alert_id="a-2", alert_type="suricata_alert_group",
        attack_phase="initial_access", severity="high",
        first_seen="2026-10-12T10:00:08+00:00"))
    assert s2.outcome()["label"] == "attempted"

    # access -> c2 with high-confidence TI -> strong_success
    s3 = AttackStory.from_signal(_signal(), 7200)
    s3.ingest_signal(_signal())
    s3.ingest_signal(_signal(
        alert_id="a-2", alert_type="suricata_alert_group",
        attack_phase="initial_access", severity="high",
        first_seen="2026-10-12T10:00:08+00:00"))
    s3.ingest_signal(ce.Signal(
        ts_epoch=1781172075.0, ts_iso="2026-10-12T10:01:15+00:00",
        kind="ioc_event", ref_index="ndr-zeek-conn-x", ref_id="ev-c2",
        title="IOC match: c2.evil.test", severity="high", phase="c2",
        attack_type="ioc_event", base_confidence=32,
        entities={"ip:10.0.0.50", "domain:c2.evil.test"},
        src_ip="10.0.0.50", dst_ip="198.51.100.7",
        detail={}))
    out = s3.outcome()
    assert out["label"] == "strong_success"
    assert out["proven"]
    assert out["disclaimer"]


def test_confidence_saturates():
    story = AttackStory.from_signal(_signal(), 7200)
    for i in range(40):
        story.ingest_signal(_signal(alert_id=f"a-{i}",
                                    first_seen=f"2026-10-12T10:{i:02d}:00+00:00"))
    assert 0 < story.confidence() <= 97


def test_context_dns_and_fileinfo_attach():
    story = AttackStory.from_signal(_signal(), 7200)
    story.ingest_signal(_signal())   # seed: src 203.0.113.25 -> 10.0.0.50
    ts = datetime(2026, 10, 12, 10, 1, 0, tzinfo=timezone.utc)
    ok_dns = story.ingest_context({
        "etype": "dns", "ts": ts.timestamp(),
        "query": "c2.evil.test",
        "answers": [{"name": "c2.evil.test", "type": "A",
                     "data": "198.51.100.7"}],
        "src": "10.0.0.50", "dst": "10.0.0.1"})
    assert ok_dns
    assert "domain:c2.evil.test" in story.entity_keys
    ok_file = story.ingest_context({
        "etype": "fileinfo", "ts": ts.timestamp() + 30,
        "src": "10.0.0.50", "dst": "198.51.100.20",
        "name": "invoice.exe", "mime": "application/x-dosexec",
        "size": 250_000, "md5": None, "sha1": None,
        "sha256": "ab" * 32})
    assert ok_file
    assert any(k.startswith("hash:") for k in story.entity_keys)
    assert story.outcome()["label"] in ("suspected_success",
                                        "strong_success", "attempted")


# ---------------------------------------------------------------- store
def test_store_roundtrip_sqlite(tmp_path):
    store = IncidentStore(f"sqlite:///{tmp_path}/t.db")
    story = AttackStory.from_signal(_signal(), 7200)
    story.ingest_signal(_signal())
    story.ingest_signal(_signal(
        alert_id="a-2", alert_type="internal_lateral_suspected",
        attack_phase="lateral", severity="high",
        source_ip="10.0.0.50", destination_ip="10.0.0.60",
        first_seen="2026-10-12T10:02:30+00:00"))
    store.save_story(story)

    rows = store.load_active(24)
    assert len(rows) == 1
    loaded = rows[0]
    assert loaded["incident"]["id"] == story.id
    kinds = {n["kind"] for n in loaded["nodes"]}
    assert "ip" in kinds
    assert any(e["relation"] == "lateral_to" for e in loaded["edges"])

    counts = store.counts()
    assert counts["total"] == 1
    assert store.update_status(story.id, "confirmed", "analyst1", "ok")
    rows2 = store.load_active(24)
    assert rows2[0]["incident"]["status"] == "confirmed"


# ---------------------------------------------------------------- service
@pytest.fixture
def service(tmp_path):
    cfg = type("Cfg", (), {
        "recon_max_gap_seconds": 7200,
        "recon_lookback_hours": 24,
        "recon_max_active_stories": 50,
        "recon_max_evidence": 100,
        "recon_persist_seconds": 0.05,
        "recon_queue_capacity": 100,
    })()
    store = IncidentStore(f"sqlite:///{tmp_path}/recon.db")
    svc = ReconstructionService(cfg, Metrics(SENSOR), store)
    return svc, store


def _drain(service):
    # run handler loop manually (no thread)
    while True:
        try:
            kind, payload = service._queue.get_nowait()
        except Exception:
            break
        if kind == "signal":
            service._handle_signal(payload)
        else:
            service._handle_context(payload)
    service._flush()


def test_service_links_scan_exploit_c2_lateral_exfil(service):
    svc, store = service
    svc.on_alert(_alert_doc(alert_id="s1"), "ndr-alerts-x")
    svc.on_alert(_alert_doc(
        alert_id="s2", alert_type="suricata_alert_group",
        attack_phase="initial_access", severity="high",
        title="ET exploit attempt", destination_ip="10.0.0.50",
        first_seen="2026-10-12T10:00:08+00:00"), "ndr-alerts-x")
    svc.on_alert(_alert_doc(
        alert_id="s3", alert_type="beaconing_possible",
        attack_phase="c2", source_ip="10.0.0.50",
        destination_ip="198.51.100.7",
        first_seen="2026-10-12T10:01:15+00:00"), "ndr-alerts-x")
    svc.on_alert(_alert_doc(
        alert_id="s4", alert_type="internal_lateral_suspected",
        attack_phase="lateral", severity="high",
        source_ip="10.0.0.50", destination_ip="10.0.0.60",
        first_seen="2026-10-12T10:02:30+00:00"), "ndr-alerts-x")
    svc.on_alert(_alert_doc(
        alert_id="s5", alert_type="large_outbound_transfer",
        attack_phase="impact", source_ip="10.0.0.50",
        destination_ip="198.51.100.99",
        first_seen="2026-10-12T10:05:00+00:00"), "ndr-alerts-x")
    _drain(svc)
    assert len(svc.index.stories) == 1
    story = next(iter(svc.index.stories.values()))
    assert story.signal_count == 5
    chain = {p["phase"] for p in story.phase_progression()
             if p["status"] != "none"}
    assert {"recon", "initial_access", "c2", "lateral",
            "impact"} <= chain
    # persisted
    counts = store.counts()
    assert counts["total"] == 1


def test_service_separate_stories_for_unrelated_entities(service):
    svc, _ = service
    svc.on_alert(_alert_doc(alert_id="u1", source_ip="203.0.113.25",
                            destination_ip="10.0.0.50"), "ndr-alerts-x")
    svc.on_alert(_alert_doc(alert_id="u2", source_ip="203.0.113.99",
                            destination_ip="10.0.0.77",
                            related_entities=[],
                            top_sources=[{"ip": "203.0.113.99",
                                          "count": 3}],
                            top_destinations=[{"ip": "10.0.0.77",
                                               "count": 3}],
                            first_seen="2026-10-12T11:00:00+00:00"),
                 "ndr-alerts-x")
    _drain(svc)
    assert len(svc.index.stories) == 2


def test_service_tracker_correlation_attaches_domain(service):
    svc, _ = service
    # C2 IP appears in beaconing alert; DNS answer was seen earlier
    svc.on_event(_ev(event_type="dns", source_ip="10.0.0.50",
                     destination_ip="10.0.0.1",
                     dns_query="c2.evil.test",
                     dns_answers=[type("A", (), {"name": "c2.evil.test",
                                                 "type": "A",
                                                 "data": "198.51.100.7"})()],
                     event_time=datetime(2026, 10, 12, 10, 0, 55,
                                         tzinfo=timezone.utc)),
                 "ndr-zeek-dns-x")
    svc.on_alert(_alert_doc(
        alert_id="b1", alert_type="beaconing_possible",
        attack_phase="c2", source_ip="10.0.0.50",
        destination_ip="198.51.100.7",
        first_seen="2026-10-12T10:01:15+00:00"), "ndr-alerts-x")
    _drain(svc)
    story = next(iter(svc.index.stories.values()))
    assert "domain:c2.evil.test" in story.entity_keys


# ---------------------------------------------------------------- behavior rules
def _sweep(rule):
    rule.sweep(time.time() + rule.window_seconds + 5)


def test_lateral_rule_fires_cross_zone():
    q = queue.Queue()
    rule = InternalLateralDetector({445, 3389}, 20, 5, 10, 1000, SENSOR, q,
                                   lambda ts: "idx", ZONES)
    ts = utcnow()
    for i in range(6):
        rule.feed(_ev(event_type="conn", source_ip="10.0.0.50",
                      destination_ip="192.168.1.10",
                      destination_port=3389,
                      event_time=ts + timedelta(seconds=i)), "idx")
    _sweep(rule)
    alerts = [q.get_nowait() for _ in range(q.qsize())]
    assert len(alerts) == 1
    doc = alerts[0][2]
    assert doc["alert_type"] == "internal_lateral_suspected"
    assert doc["attack_phase"] == "lateral"
    assert doc["severity"] == "high"


def test_lateral_rule_requires_threshold_same_zone():
    q = queue.Queue()
    rule = InternalLateralDetector({445}, 20, 5, 10, 1000, SENSOR, q,
                                   lambda ts: "idx", ZONES)
    ts = utcnow()
    for i in range(3):   # below same-zone threshold (20)
        rule.feed(_ev(event_type="conn", source_ip="10.0.0.50",
                      destination_ip="10.0.0.99", destination_port=445,
                      event_time=ts + timedelta(seconds=i)), "idx")
    _sweep(rule)
    assert q.qsize() == 0


def test_large_outbound_rule():
    q = queue.Queue()
    rule = LargeOutboundDetector(1000, 10, 1000, SENSOR, q,
                                 lambda ts: "idx", ZONES)
    ts = utcnow()
    for i in range(4):
        rule.feed(_ev(event_type="conn", source_ip="10.0.0.50",
                      destination_ip="198.51.100.99", destination_port=443,
                      source_bytes=500,  # v0.13.0: SENT bytes only; 4x500=2000
                      event_time=ts + timedelta(seconds=i)), "idx")
    # v0.13.0: huge DOWNLOAD (resp bytes only) must NOT count as exfil
    rule.feed(_ev(event_type="conn", source_ip="10.0.0.51",
                  destination_ip="198.51.100.99", destination_port=443,
                  destination_bytes=5_000, network_bytes=5_000,
                  event_time=ts), "idx")
    _sweep(rule)
    alerts = [q.get_nowait() for _ in range(q.qsize())]
    assert len(alerts) == 1
    doc = alerts[0][2]
    assert doc["attack_phase"] == "impact"
    assert "198.51.100.99" in doc["title"]


def test_dga_rule_entropy():
    q = queue.Queue()
    rule = DGADetector(10, 3.0, 10, 1000, SENSOR, q, lambda ts: "idx")
    ts = utcnow()
    domains = [f"qv{x}zkjwm03idor.test" for x in range(12)]
    for i, d in enumerate(domains):
        rule.feed(_ev(event_type="dns", source_ip="10.0.0.50",
                      dns_query=d,
                      event_time=ts + timedelta(milliseconds=100 * i)), "idx")
    _sweep(rule)
    alerts = [q.get_nowait() for _ in range(q.qsize())]
    assert len(alerts) == 1
    assert alerts[0][2]["attack_phase"] == "c2"


def test_dga_rule_ignores_common_domains():
    q = queue.Queue()
    rule = DGADetector(10, 3.0, 10, 1000, SENSOR, q, lambda ts: "idx")
    ts = utcnow()
    for i, d in enumerate(["google.com", "wikipedia.org", "github.com",
                           "amazon.com", "stackoverflow.com"]):
        rule.feed(_ev(event_type="dns", source_ip="10.0.0.50",
                      dns_query=d,
                      event_time=ts + timedelta(seconds=i)), "idx")
    _sweep(rule)
    assert q.qsize() == 0


def test_dns_tunnel_rule():
    q = queue.Queue()
    rule = DnsTunnelingDetector(5, 40, 10, 1000, SENSOR, q, lambda ts: "idx")
    ts = utcnow()
    long_label = "x" * 48
    for i in range(6):
        rule.feed(_ev(event_type="dns", source_ip="10.0.0.50",
                      dns_query=f"{long_label}{i}.tunnel.test",
                      event_time=ts + timedelta(seconds=i)), "idx")
    _sweep(rule)
    alerts = [q.get_nowait() for _ in range(q.qsize())]
    assert len(alerts) == 1
    assert alerts[0][2]["attack_phase"] == "c2"
    assert alerts[0][2]["severity"] == "high"


def test_file_transfer_rule():
    q = queue.Queue()
    rule = FileTransferDetector(5_000_000, 10, 1000, SENSOR, q,
                                lambda ts: "idx")
    ts = utcnow()
    rule.feed(_ev(event_type="fileinfo", source_ip="10.0.0.50",
                  destination_ip="198.51.100.20",
                  file_name="update.exe",
                  file_mime="application/x-dosexec", file_size=120_000,
                  event_time=ts), "idx")
    rule.feed(_ev(event_type="fileinfo", source_ip="10.0.0.50",
                  destination_ip="198.51.100.20",
                  file_name="backup.zip", file_mime="application/zip",
                  file_size=9_000_000, event_time=ts), "idx")
    _sweep(rule)
    alerts = [q.get_nowait() for _ in range(q.qsize())]
    assert len(alerts) == 1
    doc = alerts[0][2]
    assert doc["attack_phase"] == "delivery"
    assert doc["event_count"] == 2


def test_shannon_entropy_basic():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == 2.0
