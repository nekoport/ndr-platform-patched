"""v0.12.9 regression tests: DGA false-positive allowlist + per-domain
entropy sampling in alert reasons (reference practice: Tranco/Splunk/
Elastic allowlist filtering before entropy scoring)."""

import queue
import re
import time

from app.detection.behavior import DEFAULT_DGA_ALLOWLIST, DGADetector
from app.models import utcnow

SENSOR = "sensor-test"

# 12-char labels with 12 unique characters -> Shannon entropy log2(12)
# ~= 3.585 (>= default threshold 3.5), matching a random-looking DGA.
_DGA_ALPHABETS = [
    "xkvbqpwmzret", "qazwsxedcrfvt", "plmoknijbuhvy", "zgdxfsyvbnmh",
    "tqwdrjfvkzxn", "mbcnxzlqkjhv", "vhjklmnbpoiuy", "lkjhgfdsapmno",
    "mnbvcxzlkjhgf", "poiuytrewqasd", "qwertzuiopasd", "yxcvbnmasdfgh",
    "asdfghjklqwer", "oiuytrewqzxcv",
]


def _dga_domain(i: int) -> str:
    return f"{_DGA_ALPHABETS[i % len(_DGA_ALPHABETS)]}.com"


def _ev_dns(domain: str, src="10.0.0.50", offset_s=0):
    from datetime import timedelta

    from app.models import CommonEvent
    now = utcnow() + timedelta(seconds=offset_s)
    return CommonEvent(
        event_id=f"e-{domain}", event_time=now, ingest_time=now,
        sensor_id=SENSOR, source_engine="zeek", event_type="dns",
        source_ip=src, dns_query=domain,
    )


def _feed_domains(rule, domains, src="10.0.0.50"):
    # all at the same instant so the sweep cutoff (window elapsed) is hit
    for d in domains:
        rule.feed(_ev_dns(d, src=src), "idx")


def _sweep(rule):
    rule.sweep(time.time() + rule.window_seconds + 5)


def test_built_in_allowlist_covers_popular_and_cdn():
    detector = DGADetector(10, 3.5, 10, 1000, SENSOR, queue.Queue(),
                           lambda ts: "idx")
    assert "google.com" in DEFAULT_DGA_ALLOWLIST
    assert "cloudfront.net" in DEFAULT_DGA_ALLOWLIST
    assert detector._allowlisted("www.google.com")
    assert detector._allowlisted("d1234.cloudfront.net")
    assert not detector._allowlisted("xkvbqpwmzret.com")


def test_allowlist_excluded_from_unique_count():
    """9 DGA domains + 1 popular domain: WITHOUT the allowlist that is
    10 unique domains (alert territory); WITH it only 9 unique
    non-allowlisted domains remain -> below min_unique -> no alert."""
    q = queue.Queue()
    rule = DGADetector(10, 3.5, 10, 1000, SENSOR, q, lambda ts: "idx")
    domains = [_dga_domain(i) for i in range(9)] + ["www.google.com"]
    _feed_domains(rule, domains)
    _sweep(rule)
    assert q.qsize() == 0


def test_alert_reports_skipped_allowlisted_and_per_domain_entropy():
    """10 DGA + 3 popular domains -> alert fires; reasons must disclose
    the skipped allowlisted queries AND carry per-domain entropy scores
    ('domain (3.58)') so the analyst sees the score, not only the mean."""
    q = queue.Queue()
    rule = DGADetector(10, 3.5, 10, 1000, SENSOR, q, lambda ts: "idx")
    domains = ([_dga_domain(i) for i in range(10)]
               + ["www.google.com", "d1234.cloudfront.net", "api.amazon.com"])
    _feed_domains(rule, domains)
    _sweep(rule)
    assert q.qsize() == 1
    _index, _payload, doc = q.get_nowait()
    reasons = doc["reasons"]
    assert any(r.startswith("allowlisted common domains skipped in window: 3")
               for r in reasons)
    sample = next(r for r in reasons
                  if r.startswith("sample high-entropy queries"))
    assert re.search(r"\(\d\.\d\d\)", sample), sample


def test_extra_allowlist_from_env_config():
    q = queue.Queue()
    rule = DGADetector(10, 3.5, 10, 1000, SENSOR, q, lambda ts: "idx",
                       allowlist_extra="mycorp.internal, corp.example")
    assert rule._allowlisted("svc.mycorp.internal")
    assert rule._allowlisted("corp.example")
    assert not rule._allowlisted("other.example")


def test_common_domains_still_ignored(test_guard=None):
    """Guard the original FP contract: 5 popular domains alone must never
    alert (mean entropy far below threshold, and now allowlisted too)."""
    q = queue.Queue()
    rule = DGADetector(10, 3.0, 10, 1000, SENSOR, q, lambda ts: "idx")
    _feed_domains(rule, ["google.com", "wikipedia.org", "github.com",
                         "amazon.com", "stackoverflow.com"])
    _sweep(rule)
    assert q.qsize() == 0
