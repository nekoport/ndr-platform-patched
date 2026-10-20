"""v0.12.5 regression tests - real-VM deployment findings.

Covers the bug classes from LAPORAN-DEV-GABUNGAN.md that are testable in
the SQLite lab: wall-clock sweep, @timestamp on alert docs, JSONB-vs-TEXT
loading helpers, boolean `inferred` persist, TI job safety net + orphan
recovery + starter feed seeding, and the sensors heartbeat.
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.correlation.service import _jload as recon_jload  # noqa: E402
from app.correlation.store import IncidentStore  # noqa: E402
from app.detection.rules import build_alert_doc  # noqa: E402
from app.intel.store import IntelStore, _jload as intel_jload  # noqa: E402
from app.metrics import HealthPublisher, Metrics  # noqa: E402

NOW = datetime.now(timezone.utc)


def make_intel_store(tmp_path) -> IntelStore:
    return IntelStore(f"sqlite:///{tmp_path}/ti25_{uuid.uuid4().hex}.db")


# ------------------------------------------------------------- clock (§5.11)
def test_detection_sweep_uses_wall_clock_not_monotonic():
    """The sweep scheduler must compare wall-clock to wall-clock.

    `time.monotonic() - last_sweep[time.time()]` is always negative ->
    the sweep never ran and behavioral alert counts stayed zero forever
    (36k Suricata alerts, 0 NDR alerts on the live VM).
    """
    import inspect

    from app.detection import DetectionEngine
    src = inspect.getsource(DetectionEngine.run)
    # strip comment lines - the regression NOTE inside run() mentions the
    # old bug by name; only executable code is under contract here
    code_only = "\n".join(
        line for line in src.splitlines()
        if not line.lstrip().startswith("#"))
    assert "monotonic" not in code_only, \
        "DetectionEngine.run must not mix time.monotonic with wall clock"
    assert "time.time() - last_sweep" in code_only


# ------------------------------------------------- alert doc @timestamp (§6.13)
def _minimal_alert_doc_kwargs():
    return dict(
        alert_id="a1", alert_type="portscan_suspected", title="t",
        group_key="g", severity="medium", rationale="r", reasons=["x"],
        first_seen=NOW, last_seen=NOW + timedelta(seconds=30),
        sensor_id="sensor-01", event_count=5, source_count=1,
        destination_count=1, source_ip="1.2.3.4",
        destination_ip="10.0.0.5", transport="tcp", protocol="tcp",
        top_sources=[("1.2.3.4", 5)], top_destinations=[("10.0.0.5", 5)],
        top_rules=[], evidence=[])


def test_build_alert_doc_carries_timestamp():
    doc = build_alert_doc(**_minimal_alert_doc_kwargs())
    assert "@timestamp" in doc, \
        "alert docs need @timestamp: the API time-filters + sorts on it"
    assert doc["@timestamp"] == doc["last_seen"]


# ---------------------------------------------------- JSONB loader (§6.15)
def test_jload_accepts_already_decoded_json():
    # Postgres JSONB returns decoded dict/list; json.loads() on them
    # raises TypeError and killed the recon thread silently.
    assert recon_jload({"label": "x"}, {}) == {"label": "x"}
    assert recon_jload(["a"], []) == ["a"]
    assert intel_jload({"days": 2}, {}) == {"days": 2}
    # str / bytes / empty / garbage still parse or fall back
    assert recon_jload('{"a": 1}', {}) == {"a": 1}
    assert recon_jload(b"[]", {}) == []
    assert recon_jload(None, {}) == {}
    assert recon_jload("not-json", {"d": 1}) == {"d": 1}


# ------------------------------------------------- inferred BOOLEAN (§5.12)
def test_incident_store_persists_inferred_as_bool(tmp_path):
    """inferred 1/0 ints made every story persist ROLLBACK on Postgres
    (BOOLEAN column); bool() must adapt on both dialects."""
    store = IncidentStore(f"sqlite:///{tmp_path}/inc25_{uuid.uuid4().hex}.db")
    from app.correlation.story import (AttackStory, EvidenceItem, StoryEdge,
                                       StoryNode)

    story = AttackStory("inc-bool-1", 300, 50)
    story.title = "bool test"
    story.nodes["ip:1.2.3.4"] = StoryNode(
        kind="ip", key="ip:1.2.3.4", label="1.2.3.4", role="attacker",
        phase="recon", confidence=70, first_seen=NOW.timestamp(),
        last_seen=NOW.timestamp())
    story.edges[("ip:1.2.3.4", "ip:10.0.0.5", "targeted")] = StoryEdge(
        src="ip:1.2.3.4", dst="ip:10.0.0.5", relation="targeted",
        inferred=True, first_seen=NOW.timestamp(), last_seen=NOW.timestamp(),
        evidence_count=2, confidence=60)
    story.evidence.append(EvidenceItem(
        ts_epoch=NOW.timestamp(), ts_iso=NOW.isoformat(), kind="alert",
        source="pipeline", ref_index="ndr-alerts", ref_id="a1",
        title="t", severity="medium", phase="recon", summary="s",
        detail={"k": "v"}, stage="recon", attck=[]))
    store.save_story(story)

    from sqlalchemy import text
    with store.engine.connect() as conn:
        row = conn.execute(text(
            "SELECT inferred FROM incident_edges WHERE incident_id='inc-bool-1'"
        )).first()
    assert row is not None
    assert bool(row[0]) is True


# ----------------------------------------------------- TI store (§9.20/21)
def test_finish_job_survives_non_json_serializable_counts(tmp_path):
    """A datetime inside counts used to raise TypeError in the
    finally-block -> job stuck 'running' forever (orphaned)."""
    store = make_intel_store(tmp_path)
    from sqlalchemy import text
    jid = uuid.uuid4().hex[:16]
    with store.engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO ti_update_jobs (id, status, counts, created_at) "
            "VALUES (:id, 'running', '{}', :now)"),
            {"id": jid, "now": NOW.isoformat()})
    # queued_at carries a raw datetime exactly like collector._run_job did
    store.finish_job(jid, "success",
                     {"queued_at": datetime.now(timezone.utc), "new": 3})
    with store.engine.connect() as conn:
        row = conn.execute(text(
            "SELECT status, counts FROM ti_update_jobs WHERE id=:i"),
            {"i": jid}).mappings().first()
    assert row["status"] == "success"
    assert "queued_at" in row["counts"]


def test_recover_orphan_jobs_marks_running_as_failed(tmp_path):
    store = make_intel_store(tmp_path)
    from sqlalchemy import text
    with store.engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO ti_update_jobs (id, status, counts, created_at) "
            "VALUES ('j-orphan', 'running', '{}', :now),"
            "('j-done', 'success', '{}', :now)"),
            {"now": NOW.isoformat()})
    assert store.recover_orphan_jobs() == 1
    with store.engine.connect() as conn:
        rows = dict(conn.execute(text(
            "SELECT id, status FROM ti_update_jobs")).all())
    assert rows["j-orphan"] == "failed"
    assert rows["j-done"] == "success"


def test_feed_row_keeps_decoded_config_dict():
    """Non-empty config dicts arrived decoded (JSONB) on run 2 and were
    silently replaced with {} (threatfox days:2 vanished)."""
    row = {"enabled": 1, "config": {"days": 2}}
    assert IntelStore._feed_row(row)["config"] == {"days": 2}
    row2 = {"enabled": 0, "config": '{"days": 2}'}
    assert IntelStore._feed_row(row2)["config"] == {"days": 2}
    row3 = {"enabled": 0, "config": None}
    assert IntelStore._feed_row(row3)["config"] == {}


def test_seed_default_feeds_only_when_empty(tmp_path):
    """default_feed_definitions() was dead code - starter feeds never
    existed. Seeding must fill an EMPTY table once and never resurrect
    operator-modified tables."""
    store = make_intel_store(tmp_path)
    assert store.seed_default_feeds() == 6
    feeds = store.feeds()
    assert len(feeds) == 6
    names = {f["name"] for f in feeds}
    assert {"feodo-c2", "urlhaus-recent", "threatfox-2d"} <= names
    assert all(f["enabled"] is False for f in feeds)  # disabled by design
    # threatfox keeps its days:2 config
    tf = next(f for f in feeds if f["name"] == "threatfox-2d")
    assert tf["config"] == {"days": 2}
    # second run: table no longer empty -> no duplicates
    assert store.seed_default_feeds() == 0
    assert len(store.feeds()) == 6


def test_feeds_enabled_only_filter_portable(tmp_path):
    """`WHERE enabled=1` errors on Postgres BOOLEAN; bare `WHERE enabled`
    works on both dialects (SQLite covered here)."""
    store = make_intel_store(tmp_path)
    from sqlalchemy import text
    with store.engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO ti_feeds (id, name, adapter, url, config, "
            "enabled, schedule_min, ttl_days, created_at, updated_at) "
            "VALUES ('f1','on-feed','file',NULL,'{}',1,0,14,:n,:n),"
            "('f2','off-feed','file',NULL,'{}',0,0,14,:n,:n)"),
            {"n": NOW.isoformat()})
    enabled = store.feeds(enabled_only=True)
    assert [f["name"] for f in enabled] == ["on-feed"]
    assert len(store.feeds()) == 2


# ----------------------------------------------- sensors heartbeat (§12)
def test_health_publisher_heartbeats_sensors_table(tmp_path):
    store_db = f"sqlite:///{tmp_path}/hb_{uuid.uuid4().hex}.db"
    from sqlalchemy import create_engine, text
    engine = create_engine(store_db, future=True)
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE sensors (id TEXT PRIMARY KEY, hostname TEXT "
            "NOT NULL, capture_iface TEXT, software_versions TEXT, "
            "status TEXT NOT NULL DEFAULT 'unknown', last_seen_at TEXT, "
            "notes TEXT, created_at TEXT, updated_at TEXT)"))
    cfg = SimpleNamespace(sensor_id="sensor-01", opensearch_url="http://x:9200",
                          health_interval_seconds=30, metrics_port=0)
    metrics = Metrics("sensor-01")
    hp = HealthPublisher(metrics, cfg, __import__("threading").Event(),
                         db_url=store_db)
    hp._heartbeat()
    row = engine.connect().execute(text(
        "SELECT id, status, hostname FROM sensors")).mappings().first()
    assert row is not None
    assert row["id"] == "sensor-01"
    assert row["status"] == "online"
    # heartbeat again - idempotent upsert, still one row
    hp._heartbeat()
    n = engine.connect().execute(text(
        "SELECT COUNT(*) FROM sensors")).scalar()
    assert n == 1
