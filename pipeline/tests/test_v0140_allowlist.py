"""v0.14.0 pipeline tests: alert whitelist (allowlist) provider + engine gate.

Covers the agreed enforcement contract:
  * L0 -> alert NOT indexed, story (recon fan-out) stays intact, doc tagged
  * L1 -> alert indexed AND tagged suppressed/suppressed_by
  * no match -> doc flows exactly as before (no suppressed fields)
  * IP exact/CIDR, domain suffix (case-insensitive), signature pinning
  * reload picks up status changes; hit counters persist to Postgres
  * provider failures never kill detection
"""

from __future__ import annotations

import queue
import sqlite3

import pytest

from app.detection.allowlist import AlertAllowlistProvider
from app.detection.rules import BeaconingDetector

# ---------------------------------------------------------------- helpers


def _make_db(tmp_path, entries):
    """SQLite file DB with the alert_allowlist DDL + seed rows."""
    path = tmp_path / "allowlist.db"
    conn = sqlite3.connect(str(path))
    conn.execute("DROP TABLE IF EXISTS alert_allowlist")
    conn.execute(
        "CREATE TABLE alert_allowlist ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " alert_type TEXT NOT NULL, signature TEXT,"
        " entity_field TEXT NOT NULL, entity_value TEXT NOT NULL,"
        " layer TEXT NOT NULL DEFAULT 'L1',"
        " status TEXT NOT NULL DEFAULT 'pending',"
        " reason TEXT NOT NULL, retroactive INTEGER NOT NULL DEFAULT 0,"
        " created_by TEXT, created_at TEXT NOT NULL,"
        " approved_by TEXT, approved_at TEXT, expires_at TEXT,"
        " hit_count INTEGER NOT NULL DEFAULT 0, last_hit_at TEXT,"
        " UNIQUE (alert_type, signature, entity_field, entity_value))")
    for e in entries:
        conn.execute(
            "INSERT INTO alert_allowlist (alert_type, signature, "
            "entity_field, entity_value, layer, status, reason, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, '2026-01-01T00:00:00Z')",
            (e["alert_type"], e.get("signature"), e["entity_field"],
             e["entity_value"], e.get("layer", "L1"),
             e.get("status", "active"), e.get("reason", "test")))
    conn.commit()
    conn.close()
    return f"sqlite:///{path}"


def _provider(tmp_path, entries):
    return AlertAllowlistProvider(_make_db(tmp_path, entries))


def _doc(alert_type="beaconing_possible", src="10.0.0.9", dst="10.10.5.7",
         domains=None, signature=None, **extra):
    doc = {
        "alert_id": "a-1", "alert_type": alert_type,
        "last_seen": "2026-10-19T00:00:00Z",
        "source": {"ip": src} if src else None,
        "destination": {"ip": dst} if dst else None,
        "top_rules": [{"signature": signature, "count": 3}] if signature
        else [],
    }
    if domains:
        doc["dns_domains"] = domains
    doc.update(extra)
    return doc


def _detector(sink_q, entries, tmp_path):
    """BeaconingDetector wired to a REAL provider over the SQLite DB."""
    det = BeaconingDetector(min_connections=2, interval_min_sec=1,
                            interval_max_sec=60, jitter_max=5,
                            window_min=60, max_keys=5000,
                            sensor_id="sensor-test", sink_queue=sink_q,
                            index_for_alert=lambda ts: "ndr-alerts-test")
    prov = _provider(tmp_path, entries)
    det.allowlist_check = prov.check
    det.allowlist_hit = prov.bump
    recon_seen = []
    det.recon_sink = lambda doc: recon_seen.append(doc)
    return det, prov, recon_seen


# ---------------------------------------------------------------- L0 / L1


def test_l0_suppress_not_indexed_but_story_intact(tmp_path):
    q = queue.Queue()
    det, prov, recon = _detector(q, [
        {"alert_type": "beaconing_possible", "entity_field": "dst_ip",
         "entity_value": "10.10.5.7", "layer": "L0"}], tmp_path)
    det.emit(_doc(dst="10.10.5.7"))
    assert q.qsize() == 0                    # NOT indexed (whole point of L0)
    assert len(recon) == 1                   # story fan-out still happened
    assert recon[0]["suppressed"] is True    # provenance carried to the story
    assert recon[0]["suppressed_by"] == 1


def test_l1_tagged_and_indexed(tmp_path):
    q = queue.Queue()
    det, prov, recon = _detector(q, [
        {"alert_type": "beaconing_possible", "entity_field": "dst_ip",
         "entity_value": "10.10.5.7", "layer": "L1"}], tmp_path)
    det.emit(_doc(dst="10.10.5.7"))
    assert q.qsize() == 1                    # indexed (kept for the record)
    _, _, doc = q.get_nowait()
    assert doc["suppressed"] is True and doc["suppressed_by"] == 1
    assert len(recon) == 1


def test_no_match_doc_untouched(tmp_path):
    q = queue.Queue()
    det, prov, recon = _detector(q, [
        {"alert_type": "beaconing_possible", "entity_field": "dst_ip",
         "entity_value": "10.10.5.7", "layer": "L0"}], tmp_path)
    det.emit(_doc(dst="10.10.9.9"))
    assert q.qsize() == 1
    _, _, doc = q.get_nowait()
    assert "suppressed" not in doc and "suppressed_by" not in doc


# ------------------------------------------------------- matching rules


def test_ip_cidr_and_miss(tmp_path):
    prov = _provider(tmp_path, [
        {"alert_type": "portscan_suspected", "entity_field": "src_ip",
         "entity_value": "10.10.5.0/24"}])
    assert prov.check(_doc("portscan_suspected", src="10.10.5.99",
                           dst=None))[1] == 1
    assert prov.check(_doc("portscan_suspected", src="10.10.6.1",
                           dst=None)) is None


def test_domain_suffix_case_insensitive(tmp_path):
    prov = _provider(tmp_path, [
        {"alert_type": "dga_suspected", "entity_field": "dst_domain",
         "entity_value": ".Backup.LOCAL"}])
    assert prov.check(_doc("dga_suspected", src="10.0.0.5", dst=None,
                           domains=["nas01.backup.local"]))[1] == 1
    assert prov.check(_doc("dga_suspected", src="10.0.0.5", dst=None,
                           domains=["other.example.com"])) is None


def test_signature_pin(tmp_path):
    prov = _provider(tmp_path, [
        {"alert_type": "suricata_alert_group", "signature": "ET SCAN",
         "entity_field": "src_ip", "entity_value": "10.0.0.9"}])
    assert prov.check(_doc("suricata_alert_group", src="10.0.0.9", dst=None,
                           signature="ET SCAN"))[1] == 1
    assert prov.check(_doc("suricata_alert_group", src="10.0.0.9", dst=None,
                           signature="OTHER SIG")) is None
    assert prov.check(_doc("suricata_alert_group", src="10.0.0.9", dst=None,
                           signature=None)) is None
    # unpinned entry matches any signature
    prov2 = _provider(tmp_path, [
        {"alert_type": "suricata_alert_group", "entity_field": "src_ip",
         "entity_value": "10.0.0.9"}])
    assert prov2.check(_doc("suricata_alert_group", src="10.0.0.9", dst=None,
                            signature="WHATEVER"))[1] == 1


def test_l0_wins_over_l1(tmp_path):
    prov = _provider(tmp_path, [
        {"alert_type": "beaconing_possible", "entity_field": "dst_ip",
         "entity_value": "10.10.5.7", "layer": "L1"},
        {"alert_type": "beaconing_possible", "entity_field": "dst_ip",
         "entity_value": "10.10.5.0/24", "layer": "L0"}])
    assert prov.check(_doc(dst="10.10.5.7"))[0] == "L0"


# ------------------------------------------------------- lifecycle / hits


def test_reload_picks_status_change(tmp_path):
    db_url = _make_db(tmp_path, [
        {"alert_type": "beaconing_possible", "entity_field": "dst_ip",
         "entity_value": "10.10.5.7", "status": "pending"}])
    prov = AlertAllowlistProvider(db_url)
    assert prov.check(_doc(dst="10.10.5.7")) is None      # pending = no-op
    conn = sqlite3.connect(db_url.replace("sqlite:///", ""))
    conn.execute("UPDATE alert_allowlist SET status='active' WHERE id=1")
    conn.commit()
    conn.close()
    prov.load(force=True)
    assert prov.check(_doc(dst="10.10.5.7")) is not None  # now active


def test_bump_and_flush_persist(tmp_path):
    prov = _provider(tmp_path, [
        {"alert_type": "beaconing_possible", "entity_field": "dst_ip",
         "entity_value": "10.10.5.7"}])
    prov.bump(1)
    prov.bump(1)
    prov.flush()
    conn = sqlite3.connect(_make_db.__name__ and
                           str(tmp_path / "allowlist.db"))
    row = conn.execute(
        "SELECT hit_count, last_hit_at FROM alert_allowlist WHERE id=1"
    ).fetchone()
    conn.close()
    assert row[0] == 2 and row[1] is not None


def test_expired_entry_not_matched(tmp_path):
    prov = AlertAllowlistProvider(_make_db(tmp_path, [
        {"alert_type": "beaconing_possible", "entity_field": "dst_ip",
         "entity_value": "10.10.5.7", "status": "expired"}]))
    assert prov.check(_doc(dst="10.10.5.7")) is None


def test_bad_url_never_kills_engine():
    """The engine wiring catches provider construction failures."""
    import queue as _q
    import sys
    from io import StringIO
    from app.config import Config
    from app.detection import DetectionEngine
    cfg = Config(sensor_id="sensor-test")
    cfg.ti_database_url = "this-is-not-a-valid-url"
    err = StringIO()
    old = sys.stderr
    sys.stderr = err
    try:
        eng = DetectionEngine(cfg, _q.Queue(), _q.Queue())
    finally:
        sys.stderr = old
    assert eng.allowlist is None
    # rules keep allowlist hooks unset -> emit() behaves as before
    assert all(r.allowlist_check is None for r in eng.rules)
