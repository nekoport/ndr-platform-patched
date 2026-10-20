"""End-to-end mini pipeline test with a fake sink (no OpenSearch needed)."""

import json
import queue
import time

from app.config import Config
from app.main import Pipeline


def _fresh_conn_line() -> str:
    return json.dumps({
        "ts": time.time(), "uid": "U9", "id.orig_h": "192.168.1.50",
        "id.orig_p": 51000, "id.resp_h": "93.184.216.34", "id.resp_p": 443,
        "proto": "tcp", "service": "ssl",
        "orig_bytes": 100, "resp_bytes": 200,
    })


def _today_alert_index(prefix: str) -> str:
    """v0.14.0: sample timestamps are evergreen (conftest shifts them to
    'now'), so the daily index tag follows the wall clock too."""
    from datetime import datetime, timezone
    tag = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    return f"{prefix}-{tag}"


def test_pipeline_processes_eve_and_zeek(tmp_path, eve_lines, zeek_lines):
    """Feed sample lines through the full stage chain via _process_one."""
    cfg = Config(sensor_id="sensor-test")
    cfg.state_dir = str(tmp_path / "state")
    cfg.sources = ["suricata", "zeek"]
    cfg.zeek_logs = ["conn", "dns", "http", "tls"]
    pipe = Pipeline(cfg)

    # valid suricata alert -> detect queue
    pipe._process_one("/input/suricata/eve.json", eve_lines[0])
    # stats line (not in allowed types) -> parse_error path
    pipe._process_one("/input/suricata/eve.json", eve_lines[6])
    # malformed eve -> deadletter
    pipe._process_one("/input/suricata/eve.json", eve_lines[7])
    # stale (2024) zeek conn -> quarantined by validation
    pipe._process_one("/input/zeek/current/conn.log", zeek_lines[0])
    # malformed zeek -> deadletter
    pipe._process_one("/input/zeek/current/conn.log", zeek_lines[5])
    # fresh zeek conn -> detect queue
    pipe._process_one("/input/zeek/current/conn.log", _fresh_conn_line())

    assert pipe.detect_queue.qsize() == 2
    items = [pipe.detect_queue.get_nowait() for _ in range(2)]
    indexes = {idx for _, idx in items}
    assert _today_alert_index("ndr-suricata") in indexes
    assert any(i.startswith("ndr-zeek-conn-") for i in indexes)

    counters = pipe.metrics._counters
    assert counters["events_in"] == 6
    assert counters["events_accepted"] == 2
    assert counters["parse_errors"] == 3      # stats + 2 malformed
    assert counters["quarantined"] == 1       # stale zeek conn
    assert counters.get("duplicates", 0) == 0
    assert pipe.deadletter.count >= 4


def test_pipeline_dedup_on_replay(tmp_path, eve_lines):
    cfg = Config(sensor_id="sensor-test")
    cfg.state_dir = str(tmp_path / "state")
    pipe = Pipeline(cfg)
    for _ in range(3):
        pipe._process_one("/input/suricata/eve.json", eve_lines[0])
    assert pipe.metrics._counters["duplicates"] == 2
    assert pipe.detect_queue.qsize() == 1
