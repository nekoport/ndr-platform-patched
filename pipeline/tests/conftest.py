"""Shared pytest fixtures."""

import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

SAMPLES = os.path.join(os.path.dirname(__file__), "samples")

# v0.14.0: the EVE sample carries FIXED timestamps (2026-10-12) while the
# pipeline validator quarantines events older than 7 days. A static file
# silently rots (all events quarantined -> e2e fails on a later date).
# Keep the sample evergreen: shift every timestamp by a constant delta so
# the sample "happens" a few minutes ago, preserving inter-line order and
# making replay-dedup tests deterministic (identical lines stay identical).
_EVE_TS_BASE = None
_EVE_DELTA = None


def _eve_shift_delta():
    global _EVE_TS_BASE, _EVE_DELTA
    if _EVE_DELTA is None:
        with open(os.path.join(SAMPLES, "eve_sample.jsonl"), "r",
                  encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    ts = obj.get("timestamp")
                    if isinstance(ts, str):
                        _EVE_TS_BASE = datetime.fromisoformat(
                            ts.replace("+0000", "+00:00"))
                        break
                except (ValueError, AttributeError):
                    continue
        if _EVE_TS_BASE is None:
            _EVE_TS_BASE = datetime.now(timezone.utc)
        # first line lands ~5 minutes in the past
        _EVE_DELTA = (datetime.now(timezone.utc) - timedelta(minutes=5)
                      ) - _EVE_TS_BASE
    return _EVE_DELTA


def _shift_eve_line(line: str) -> str:
    """Re-timestamp one EVE JSON line; non-JSON lines pass through untouched
    (malformed lines are deliberate test cases for the deadletter path)."""
    try:
        obj = json.loads(line)
        ts = obj.get("timestamp")
        if not isinstance(ts, str):
            return line
        base = datetime.fromisoformat(ts.replace("+0000", "+00:00"))
        shifted = base + _eve_shift_delta()
        obj["timestamp"] = shifted.strftime("%Y-%m-%dT%H:%M:%S.%f+0000")
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    except (ValueError, AttributeError):
        return line


def read_sample(name: str) -> list[str]:
    with open(os.path.join(SAMPLES, name), "r", encoding="utf-8") as fh:
        return [line.rstrip("\n") for line in fh if line.strip()]


def read_eve_sample_fresh() -> list[str]:
    return [_shift_eve_line(l) for l in read_sample("eve_sample.jsonl")]


@pytest.fixture
def eve_lines() -> list[str]:
    return read_eve_sample_fresh()


@pytest.fixture
def zeek_lines() -> list[str]:
    return read_sample("zeek_sample.jsonl")
