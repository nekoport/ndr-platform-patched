"""Phase 3 threat intelligence tests (doc section 9)."""

from __future__ import annotations

import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.intel import feeds as ti_feeds  # noqa: E402
from app.intel.collector import IntelService  # noqa: E402
from app.intel.matcher import IntelMatcher, domain_parents  # noqa: E402
from app.intel.store import IntelStore  # noqa: E402
from app.metrics import Metrics  # noqa: E402
from app.models import CommonEvent  # noqa: E402
from app.detection import DetectionEngine  # noqa: E402
from app.detection.rules import build_alert_doc, make_alert_id  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(__file__), "samples", "ti_fixture.jsonl")
NOW = datetime.now(timezone.utc)


def make_store(tmp_path) -> IntelStore:
    return IntelStore(f"sqlite:///{tmp_path}/ti_{uuid.uuid4().hex}.db")


def insert_feed(store: IntelStore, name="fixture-feed", adapter="file",
                url=None, enabled=1, schedule_min=0, ttl_days=14) -> str:
    from sqlalchemy import text
    fid = uuid.uuid4().hex[:12]
    now = NOW.isoformat()
    with store.engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO ti_feeds (id, name, adapter, url, config, enabled, "
            "schedule_min, ttl_days, created_at, updated_at) "
            "VALUES (:id, :name, :adapter, :url, '{}', :en, :sched, :ttl, "
            ":now, :now)"),
            {"id": fid, "name": name, "adapter": adapter,
             "url": url or FIXTURE, "en": enabled, "sched": schedule_min,
             "ttl": ttl_days, "now": now})
    return fid


def insert_job(store: IntelStore, feed_id: str, feed_name: str,
               trigger="manual") -> str:
    from sqlalchemy import text
    jid = uuid.uuid4().hex[:16]
    with store.engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO ti_update_jobs (id, feed_id, feed_name, trigger, "
            "status, counts, created_at) VALUES (:id, :fid, :fn, :tr, "
            "'queued', '{}', :now)"),
            {"id": jid, "fid": feed_id, "fn": feed_name, "tr": trigger,
             "now": NOW.isoformat()})
    return jid


def cfg_for(store: IntelStore) -> SimpleNamespace:
    return SimpleNamespace(
        ti_job_poll_seconds=1, ti_reload_seconds=60, ti_http_timeout=5,
        ti_verify_tls=True, ti_auto_schedule=True,
        ti_database_url=None, ti_enabled=True)


# ------------------------------------------------------------------ feeds

def test_normalize_ip_rejects_private_and_collapses_port():
    assert ti_feeds.normalize_ip("185.222.57.11") == "185.222.57.11"
    assert ti_feeds.normalize_ip("185.222.57.11:443") == "185.222.57.11"
    assert ti_feeds.normalize_ip("10.0.0.1") is None      # private
    assert ti_feeds.normalize_ip("127.0.0.1") is None     # loopback
    assert ti_feeds.normalize_ip("169.254.1.1") is None   # link-local
    assert ti_feeds.normalize_ip("not-an-ip") is None


def test_normalize_domain_url_hash():
    assert ti_feeds.normalize_domain("C2.Evil-Example.test.") == \
        "c2.evil-example.test"
    assert ti_feeds.normalize_domain("-bad..domain") is None
    assert ti_feeds.normalize_url(
        "http://payload.evil-example.test/1.exe") is not None
    assert ti_feeds.normalize_url("ftp://x/y") is None
    assert ti_feeds.normalize_url("http://localhost/x") is None
    assert ti_feeds.normalize_hash("A" * 64) == "a" * 64
    assert ti_feeds.normalize_hash("zz") is None


def test_normalize_ioc_hash_infers_algorithm():
    t, v = ti_feeds.normalize_ioc("hash", "B" * 40)
    assert (t, v) == ("sha1", "b" * 40)


def test_file_adapter_parses_fixture_and_rejects_bad_rows():
    result = ti_feeds.run_feed({"name": "fixture-feed", "adapter": "file",
                                "path": FIXTURE})
    values = {(i.ioc_type, i.value) for i in result.iocs}
    assert ("ip", "185.222.57.11") in values
    assert ("domain", "c2.evil-example.test") in values
    assert ("url", "http://payload.evil-example.test/1.exe") in values
    assert ("sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") \
        in values
    assert ("md5", "d41d8cd98f00b204e9800998ecf8427e") in values
    assert ("ip", "203.0.113.66") in values          # sniffed
    # rejected rows: private ip, loopback, bad domain, unknown type
    assert ("ip", "10.0.0.5") not in values
    assert ("ip", "127.0.0.1") not in values
    assert len(result.iocs) == 6
    assert result.warnings and "4 rows skipped" in result.warnings[0]
    assert len({(i.ioc_type, i.value) for i in result.iocs}) == len(result.iocs)


def test_unknown_adapter_raises():
    with pytest.raises(ValueError):
        ti_feeds.run_feed({"name": "x", "adapter": "nope"})


# ------------------------------------------------------------------ store

def test_upsert_iocs_new_changed_and_expiry(tmp_path):
    store = make_store(tmp_path)
    feed = {"name": "f1"}
    iocs = [ti_feeds.RawIoc("ip", "203.0.113.10", "f1", confidence="high",
                            published=NOW - timedelta(days=1))]
    counts = store.upsert_iocs(feed, iocs, ttl_days=14)
    assert counts["new"] == 1 and counts["changed"] == 0
    # same again -> unchanged, provenance kept single entry
    counts = store.upsert_iocs(feed, iocs, ttl_days=14)
    assert counts["new"] == 0 and counts["unchanged"] == 1
    active = store.active_iocs()
    assert len(active) == 1
    exp = datetime.fromisoformat(active[0]["expires_at"])
    assert exp > NOW
    # confidence change -> changed + provenance updated
    iocs[0].confidence = "low"
    counts = store.upsert_iocs(feed, iocs, ttl_days=14)
    assert counts["changed"] == 1


def test_reactivate_expired_ioc(tmp_path):
    store = make_store(tmp_path)
    feed = {"name": "f1"}
    ioc = ti_feeds.RawIoc("domain", "old.example", "f1", confidence="low")
    store.upsert_iocs(feed, [ioc], ttl_days=1)
    from sqlalchemy import text
    with store.engine.begin() as conn:
        conn.execute(text("UPDATE ioc_records SET expires_at=:p "
                          "WHERE ioc_value=:v"),
                     {"p": (NOW - timedelta(days=2)).isoformat(),
                      "v": "old.example"})
    assert store.expire_stale() == 1
    assert store.active_iocs() == []
    # fresh sighting reactivates
    store.upsert_iocs(feed, [ioc], ttl_days=1)
    assert len(store.active_iocs()) == 1


def test_failed_job_never_expires_iocs(tmp_path):
    """Doc 9.3: a failed feed must not silently remove valid IOCs."""
    store = make_store(tmp_path)
    feed = {"name": "f1"}
    store.upsert_iocs(feed, [ti_feeds.RawIoc("ip", "203.0.113.10", "f1")],
                      ttl_days=14)
    fid = insert_feed(store)
    jid = insert_job(store, fid, "f1")
    job = store.claim_queued_job()
    assert job["status"] == "running"
    # simulate failure path: finish_job(failed) only writes the job row
    store.finish_job(job["id"], "failed", {}, "boom")
    assert len(store.active_iocs()) == 1
    assert store.expire_stale() == 0


def test_claim_is_single_consumer(tmp_path):
    store = make_store(tmp_path)
    fid = insert_feed(store)
    insert_job(store, fid, "f1")
    first = store.claim_queued_job()
    assert first is not None
    assert store.claim_queued_job() is None   # already running


def test_feed_schedule_due(tmp_path):
    store = make_store(tmp_path)
    feed = {"name": "f", "enabled": True, "schedule_min": 60,
            "last_status": "success",
            "last_success_at": (NOW - timedelta(minutes=30)).isoformat()}
    assert not store.feed_schedule_due(feed, 20)
    feed["last_success_at"] = (NOW - timedelta(hours=2)).isoformat()
    assert store.feed_schedule_due(feed, 20)
    feed["last_status"] = "running"
    assert not store.feed_schedule_due(feed, 20)
    feed["enabled"] = False
    feed["last_status"] = "success"
    assert not store.feed_schedule_due(feed, 20)


# ----------------------------------------------------------------- matcher

def test_domain_parents():
    assert domain_parents("a.b.evil.com") == \
        ["a.b.evil.com", "b.evil.com", "evil.com"]


def _matcher_with(store: IntelStore) -> IntelMatcher:
    m = IntelMatcher(store, reload_seconds=60)
    m.reload()
    return m


def test_matcher_ip_and_hash(tmp_path):
    store = make_store(tmp_path)
    store.upsert_iocs({"name": "f"}, [
        ti_feeds.RawIoc("ip", "203.0.113.10", "f", confidence="high"),
        ti_feeds.RawIoc("sha256", "c" * 64, "f", confidence="low")], 14)
    m = _matcher_with(store)
    ev = CommonEvent(event_id="e1", event_time=NOW, ingest_time=NOW,
                     sensor_id="s", source_engine="zeek", event_type="conn",
                     source_ip="192.168.1.50", destination_ip="203.0.113.10")
    out = m.match(ev)
    assert len(out) == 1 and out[0]["ioc_type"] == "ip"
    assert out[0]["match_field"] == "destination"
    assert out[0]["confidence"] == "high"
    ev2 = CommonEvent(event_id="e2", event_time=NOW, ingest_time=NOW,
                      sensor_id="s", source_engine="suricata",
                      event_type="fileinfo", source_ip="192.168.1.50",
                      file_sha256="C" * 64)
    out2 = m.match(ev2)
    assert out2 and out2[0]["ioc_type"] == "sha256"


def test_matcher_domain_suffix(tmp_path):
    store = make_store(tmp_path)
    store.upsert_iocs({"name": "f"}, [
        ti_feeds.RawIoc("domain", "c2.evil-example.test", "f")], 14)
    m = _matcher_with(store)
    ev = CommonEvent(event_id="e3", event_time=NOW, ingest_time=NOW,
                     sensor_id="s", source_engine="zeek", event_type="dns",
                     source_ip="192.168.1.50", dns_query="xxx.c2.evil-example.test")
    out = m.match(ev)
    assert out and out[0]["match_field"] == "dns.query"
    ev_unrelated = CommonEvent(
        event_id="e4", event_time=NOW, ingest_time=NOW, sensor_id="s",
        source_engine="zeek", event_type="dns", source_ip="192.168.1.50",
        dns_query="evil-example.test.evil-lookalike.com")
    assert m.match(ev_unrelated) == []


def test_matcher_allowlist_suppresses(tmp_path):
    store = make_store(tmp_path)
    store.upsert_iocs({"name": "f"}, [
        ti_feeds.RawIoc("domain", "c2.evil-example.test", "f"),
        ti_feeds.RawIoc("ip", "203.0.113.10", "f")], 14)
    from sqlalchemy import text
    with store.engine.begin() as conn:
        conn.execute(text("INSERT INTO ioc_allowlist (ioc_type, ioc_value, "
                          "reason, created_by, created_at) VALUES "
                          "('domain', 'c2.evil-example.test', "
                          "'known internal test', 'analyst', :now)"),
                     {"now": NOW.isoformat()})
    m = _matcher_with(store)
    ev = CommonEvent(event_id="e5", event_time=NOW, ingest_time=NOW,
                     sensor_id="s", source_engine="zeek", event_type="dns",
                     source_ip="192.168.1.50", dns_query="c2.evil-example.test")
    assert m.match(ev) == []
    ev2 = CommonEvent(event_id="e6", event_time=NOW, ingest_time=NOW,
                      sensor_id="s", source_engine="zeek", event_type="conn",
                      source_ip="192.168.1.51",
                      destination_ip="203.0.113.10")
    assert len(m.match(ev2)) == 1   # allowlist only suppressed the domain


def test_event_doc_carries_matched_ioc():
    ev = CommonEvent(event_id="e7", event_time=NOW, ingest_time=NOW,
                     sensor_id="s", source_engine="zeek", event_type="conn",
                     source_ip="192.168.1.50", destination_ip="203.0.113.10")
    ev.matched_ioc = [{"ioc_type": "ip", "ioc_value": "203.0.113.10",
                       "ioc_source": "Emotet", "confidence": "high",
                       "match_field": "destination", "first_seen": None,
                       "last_seen": None, "expires_at": None}]
    doc = ev.to_doc()
    assert doc["matched_ioc"][0]["ioc_value"] == "203.0.113.10"
    assert "first_seen" not in doc["matched_ioc"][0]


# --------------------------------------------------------------- collector

def test_collector_runs_file_job_end_to_end(tmp_path):
    store = make_store(tmp_path)
    fid = insert_feed(store, name="fixture-feed", adapter="file",
                      url=FIXTURE)
    jid = insert_job(store, fid, "fixture-feed")
    svc = IntelService(cfg_for(store), Metrics("sensor-test"), store=store)
    svc._tick()   # claim + run the queued job synchronously
    jobs = [dict(r) for r in store.engine.connect().execute(
        __import__("sqlalchemy").text(
            "SELECT * FROM ti_update_jobs WHERE id=:i"),
        {"i": jid}).mappings()]
    assert jobs[0]["status"] in ("success", "partial_success")
    import json
    counts = json.loads(jobs[0]["counts"])
    assert counts["new"] == 6
    assert svc.snapshot_size() == 6
    # matcher now matches
    ev = CommonEvent(event_id="e8", event_time=NOW, ingest_time=NOW,
                     sensor_id="s", source_engine="zeek", event_type="conn",
                     source_ip="192.168.1.50", destination_ip="203.0.113.66")
    assert svc.match(ev)


def test_collector_failed_job_records_error(tmp_path):
    store = make_store(tmp_path)
    fid = insert_feed(store, name="broken", adapter="file",
                      url="/nonexistent/path.jsonl")
    jid = insert_job(store, fid, "broken")
    svc = IntelService(cfg_for(store), Metrics("sensor-test"), store=store)
    svc._tick()
    from sqlalchemy import text
    row = store.engine.connect().execute(
        text("SELECT status, error FROM ti_update_jobs WHERE id=:i"),
        {"i": jid}).mappings().first()
    assert row["status"] == "failed"
    assert "boom" not in (row["error"] or "")
    assert row["error"]


def test_collector_scheduled_enqueue(tmp_path):
    store = make_store(tmp_path)
    fid = insert_feed(store, name="sched-feed", adapter="file", url=FIXTURE,
                      enabled=1, schedule_min=60)
    from sqlalchemy import text
    with store.engine.begin() as conn:
        conn.execute(text("UPDATE ti_feeds SET last_success_at=:ls, "
                          "last_status='success' WHERE id=:id"),
                     {"ls": (NOW - timedelta(hours=3)).isoformat(), "id": fid})
    svc = IntelService(cfg_for(store), Metrics("sensor-test"), store=store)
    svc._last_sweep = 0.0
    svc._maybe_enqueue_scheduled()
    row = store.engine.connect().execute(
        text("SELECT COUNT(*) FROM ti_update_jobs WHERE trigger='schedule' "
             "AND feed_id=:f"), {"f": fid}).scalar()
    assert row == 1


# --------------------------------------------------------- detection rule

def _detect_engine(sink_queue) -> DetectionEngine:
    cfg = SimpleNamespace(
        detect_alert_window_min=1, detect_max_tracked_keys=1000,
        detect_portscan_unique_ports=100, detect_portscan_unique_hosts=50,
        detect_portscan_window_min=10, detect_nxdomain_min_count=20,
        detect_nxdomain_ratio=0.5, detect_nxdomain_window_min=10,
        detect_beacon_min_connections=20, detect_beacon_interval_min_sec=10,
        detect_beacon_interval_max_sec=3600, detect_beacon_jitter_max=0.2,
        detect_beacon_window_min=10,
        detect_ioc_match=True, detect_ioc_window_min=1, sensor_id="sensor-test",
        detect_window_min=1, detect_file_min_bytes=5_000_000,
        detect_dga_min_unique=10, detect_dga_entropy_min=3.5,
        detect_dga_allowlist=[],
        detect_tunnel_min_count=10, detect_tunnel_min_label_len=40,
        detect_lateral_ports={22, 135, 139, 445, 3389, 5985, 5986},
        detect_lateral_min_conns=20, detect_lateral_cross_zone_min=5,
        detect_exfil_min_bytes=100_000_000, zones=[])
    return DetectionEngine(cfg, None, sink_queue)


def _ioc_event(event_id, src, seconds_ago, ioc_value="203.0.113.66"):
    ev = CommonEvent(
        event_id=event_id,
        event_time=NOW - timedelta(seconds=seconds_ago), ingest_time=NOW,
        sensor_id="sensor-test", source_engine="zeek", event_type="conn",
        source_ip=src, destination_ip=ioc_value, destination_port=443,
        transport="tcp")
    ev.matched_ioc = [{"ioc_type": "ip", "ioc_value": ioc_value,
                       "ioc_source": "Emotet", "confidence": "high",
                       "match_field": "destination", "first_seen": None,
                       "last_seen": None, "expires_at": None}]
    return ev


def test_ioc_match_rule_groups_and_emits():
    q = __import__("queue").Queue()
    engine = _detect_engine(q)
    for i in range(5):
        ev = _ioc_event(f"ev-{i}", "192.168.1.50", seconds_ago=30 + i)
        engine._feed(ev, "ndr-zeek-conn-2026.10.12")
    engine.ioc_match.sweep(time.time() + engine.ioc_match.window_seconds + 5)
    items = []
    while not q.empty():
        items.append(q.get_nowait())
    alerts = [d for idx, _id, d in items if d.get("alert_type") == "ioc_match"]
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["severity"] == "high"       # confidence high
    assert "203.0.113.66" in alert["title"]
    assert "NOT prove host compromise" in alert["rationale"]
    assert alert["matched_iocs"][0]["ioc_value"] == "203.0.113.66"
    assert alert["event_count"] == 5
    # the run loop forwards enriched events; assert doc rendering carries it
    doc0 = _ioc_event("ev-doc", "192.168.1.50", seconds_ago=1).to_doc()
    assert doc0["matched_ioc"][0]["ioc_value"] == "203.0.113.66"


def test_alert_doc_includes_matched_iocs():
    doc = build_alert_doc(
        alert_id=make_alert_id("ioc_match", "k", NOW), alert_type="ioc_match",
        title="t", group_key="k", severity="medium", rationale="r",
        reasons=["x"], first_seen=NOW, last_seen=NOW, sensor_id="s",
        event_count=1, source_count=1, destination_count=0, source_ip="a",
        destination_ip=None, transport=None, protocol=None,
        top_sources=[], top_destinations=[], top_rules=[], evidence=[],
        matched_iocs=[{"ioc_type": "domain", "ioc_value": "x.example"}])
    assert doc["matched_iocs"][0]["ioc_value"] == "x.example"
    plain = build_alert_doc(
        alert_id=make_alert_id("x", "k", NOW), alert_type="x", title="t",
        group_key="k", severity="low", rationale="r", reasons=[],
        first_seen=NOW, last_seen=NOW, sensor_id="s", event_count=1,
        source_count=1, destination_count=0, source_ip=None,
        destination_ip=None, transport=None, protocol=None, top_sources=[],
        top_destinations=[], top_rules=[], evidence=[])
    assert "matched_iocs" not in plain
