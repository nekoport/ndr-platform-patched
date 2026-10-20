"""v0.13.0 re-construction tests for the pipeline (sandbox restored an
older snapshot; these pin the remediation contract permanently)."""

from __future__ import annotations

import gzip
import json
import queue
from datetime import datetime, timezone

import pytest

from app.config import Config
from app.metrics import Metrics
from app.normalize import parse_suricata, parse_zeek
from app.sink.raw_archive import RawArchive


def _ev(**kw):
    from app.models import CommonEvent
    base = dict(
        sensor_id="sensor-test", source_engine="zeek", event_type="conn",
        event_time=datetime.now(timezone.utc),
    )
    base.update(kw)
    return CommonEvent(**base)


# ------------------------------------------------- BLOCKER: raw archive
def test_raw_archive_keeps_engines_separate(tmp_path):
    """A Suricata line must NEVER land in the Zeek archive (and vice versa)
    - the old single-handle design corrupted raw evidence silently."""
    arch = RawArchive(str(tmp_path), retention_hours=72)
    arch.store("zeek", '{"zeek": 1}')
    arch.store("suricata", '{"suricata": 1}')
    arch.store("zeek", '{"zeek": 2}')
    arch.close()

    zeek_path = list(tmp_path.joinpath("raw").glob("*-zeek.jsonl.gz"))[0]
    suri_path = list(tmp_path.joinpath("raw").glob("*-suricata.jsonl.gz"))[0]
    zeek_lines = gzip.open(zeek_path, "rt", encoding="utf-8").read().strip().split("\n")
    suri_lines = gzip.open(suri_path, "rt", encoding="utf-8").read().strip().split("\n")
    assert len(zeek_lines) == 2 and all("zeek" in l for l in zeek_lines)
    assert len(suri_lines) == 1 and "suricata" in suri_lines[0]


def test_raw_archive_hourly_rotation_closes_all_handles(tmp_path, monkeypatch):
    import app.sink.raw_archive as ra_mod

    class _FakeDT:
        hour_label = "2026101908"

        @classmethod
        def now(cls, tz=None):
            fake = datetime.strptime(cls.hour_label, "%Y%m%d%H")
            return fake.replace(tzinfo=timezone.utc)

    monkeypatch.setattr(ra_mod, "datetime", _FakeDT)
    arch = RawArchive(str(tmp_path), retention_hours=72)
    arch.store("zeek", '{"h1": true}')
    _FakeDT.hour_label = "2026101909"          # wall clock crossed the hour
    arch.store("zeek", '{"h2": true}')
    arch.close()
    files = sorted(tmp_path.joinpath("raw").glob("*-zeek.jsonl.gz"))
    assert len(files) == 2
    assert files[0].name.startswith("2026101908")
    assert files[1].name.startswith("2026101909")


# ------------------------------------------------------------- normalize
def test_suricata_severity_non_numeric_does_not_abort():
    raw = json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "alert", "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8",
        "alert": {"severity": "high", "signature_id": 2027865,
                  "signature": "ET TEST", "category": "misc"},
    })
    ev = parse_suricata(raw, "sensor-test", {"alert"}, max_field_len=2048)
    assert ev is not None          # parse continues, no exception
    assert ev.severity in (None, "medium", "high")


def test_dns_qtype_captured_from_both_engines():
    raw = json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "dns", "src_ip": "10.0.0.5",
        "dns": {"rrname": "example.com", "rrtype": "TXT", "rdata": "x"},
    })
    ev = parse_suricata(raw, "sensor-test", {"dns"}, max_field_len=2048)
    assert ev is not None and ev.dns_qtype == "TXT"

    zraw = json.dumps({
        "ts": datetime.now(timezone.utc).timestamp(), "uid": "u1",
        "id.orig_h": "10.0.0.5", "id.resp_h": "8.8.8.8", "proto": "udp",
        "query": "example.com", "qtype_name": "TXT", "rcode_name": "NOERROR",
    })
    zv = parse_zeek(zraw, "sensor-test", "dns", max_field_len=2048)
    assert zv is not None and zv.dns_qtype == "TXT"


def test_zeek_files_log_mapped_and_size_coerced():
    zraw = json.dumps({
        "ts": datetime.now(timezone.utc).timestamp(), "uid": "u2",
        "id.orig_h": "10.0.0.5", "id.resp_h": "93.184.216.34",
        "fuid": "Fabc", "mime_type": "application/x-msdownload",
        "size": "123456",   # Zeek JSON often sends strings
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
    })
    ev = parse_zeek(zraw, "sensor-test", "files", max_field_len=2048)
    assert ev is not None
    assert ev.event_type == "files"
    assert ev.file_size == 123456 and isinstance(ev.file_size, int)
    assert ev.file_mime == "application/x-msdownload"


# ---------------------------------------------------------------- metrics
def test_metrics_snapshot_is_readonly_and_rotate_closes_window():
    m = Metrics("sensor-test")
    m.inc("events_accepted", 100)
    s1 = m.snapshot()
    assert s1["eps_total"] > 0
    # scraping /metrics must NOT reset the window: after two snapshots the
    # window still carries BOTH increments (old bug: reset to 100)
    m.inc("events_accepted", 100)
    m.snapshot()
    assert m._window_counters.get("events_accepted") == 200.0
    # rotate() is the ONLY window reset, owned by the health writer
    m.rotate()
    assert m._window_counters.get("events_accepted", 0) == 0.0
    s3 = m.snapshot()
    assert s3["eps_total"] == 0.0


def test_detection_dropped_counter_and_gauge_present():
    m = Metrics("sensor-test")
    m.inc("detection_dropped", 3)
    snap = m.snapshot()
    assert snap["counters"].get("detection_dropped") == 3.0


# ----------------------------------------------------------------- config
def test_beacon_window_min_dedicated_no_floor(monkeypatch):
    # the field is evaluated at import; reload the module with the env set
    import importlib
    import app.config as cfg_mod
    monkeypatch.setenv("DETECT_BEACON_WINDOW_MIN", "5")
    try:
        importlib.reload(cfg_mod)
        cfg = cfg_mod.Config(sensor_id="sensor-test")
        assert cfg.detect_beacon_window_min == 5   # old code floored at 60
    finally:
        monkeypatch.delenv("DETECT_BEACON_WINDOW_MIN", raising=False)
        importlib.reload(cfg_mod)


def test_lateral_ports_fail_soft(monkeypatch):
    monkeypatch.setenv("DETECT_LATERAL_PORTS", "22, 445,oops,3389")
    cfg = Config(sensor_id="sensor-test")       # must not raise
    assert 22 in cfg.detect_lateral_ports and 3389 in cfg.detect_lateral_ports
    assert 445 in cfg.detect_lateral_ports


# ------------------------------------------------- dedup parser ownership
def test_parser_version_and_dedup_key_parser_owned():
    from app.models import PARSER_VERSION
    assert PARSER_VERSION == "ndr-pipeline/0.7.0"
    raw = json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "dns", "src_ip": "10.0.0.5",
        "dns": {"rrname": "a.example.com", "rrtype": "A"},
    })
    ev = parse_suricata(raw, "sensor-test", {"dns"}, max_field_len=2048)
    assert ev.dedup_key                       # parser-owned, non-empty
    ev2 = parse_suricata(raw, "sensor-test", {"dns"}, max_field_len=2048)
    assert ev2.dedup_key == ev.dedup_key      # replay-stable


# ------------------------------------------------------------- correlation
def test_context_respects_time_gap():
    from app.correlation.story import AttackStory
    from app.correlation.entities import Signal
    story = AttackStory("s-gap", gap_seconds=60, max_evidence=50)
    ts_now = datetime.now(timezone.utc).timestamp()
    sig = Signal(
        ts_epoch=ts_now, ts_iso=datetime.now(timezone.utc).isoformat(),
        kind="alert", ref_index="ndr-alerts", ref_id="a-gap",
        title="scan", severity="medium", phase="recon",
        attack_type="portscan_suspected", base_confidence=14,
        entities={"ip:10.0.0.5"}, src_ip="10.0.0.5",
    )
    story.ingest_signal(sig)
    # context FAR outside the gap must be rejected
    far = dict(etype="dns", ts=ts_now - 10_000, src="10.0.0.5",
               query="x.example.com", answers=[])
    assert story.ingest_context(far) is False
