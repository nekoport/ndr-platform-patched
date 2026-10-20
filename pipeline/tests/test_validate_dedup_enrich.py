"""Validation, dedup and enrichment tests."""

from datetime import timedelta

from app.dedup import DedupStore
from app.enrich import ZoneEnricher
from app.models import utcnow
from app.normalize import parse_suricata, parse_zeek
from app.validate import validate_event

ALLOWED = {"alert", "dns", "http", "tls", "fileinfo", "stats"}


def _valid_event():
    ev = parse_zeek('{"ts":1728702245.0,"uid":"U1","id.orig_h":"192.168.1.50",'
                    '"id.orig_p":51000,"id.resp_h":"93.184.216.34","id.resp_p":443,'
                    '"proto":"tcp"}', "s1", "conn")
    # zeek ts is 2024 -> older than max age; override with fresh time
    ev.event_time = utcnow()
    return ev


# ------------------------------------------------------------------ validate
def test_valid_event_passes():
    ok, reason = validate_event(_valid_event())
    assert ok, reason


def test_future_timestamp_rejected():
    ev = _valid_event()
    ev.event_time = utcnow() + timedelta(minutes=30)
    ok, reason = validate_event(ev)
    assert not ok and "future" in reason


def test_stale_timestamp_rejected():
    ev = _valid_event()
    ev.event_time = utcnow() - timedelta(days=10)
    ok, reason = validate_event(ev)
    assert not ok and "older" in reason


def test_invalid_ip_rejected():
    ev = _valid_event()
    ev.source_ip = "999.1.2.3"
    ok, reason = validate_event(ev)
    assert not ok and "invalid source_ip" in reason


def test_invalid_port_rejected():
    ev = _valid_event()
    ev.destination_port = 70000
    ok, reason = validate_event(ev)
    assert not ok and "port" in reason


def test_partial_parse_flagged_on_long_ua():
    raw = ('{"ts":1728702255.0,"uid":"U2","id.orig_h":"192.168.1.5",'
           '"id.orig_p":1000,"id.resp_h":"1.2.3.4","id.resp_p":80,'
           '"user_agent":"' + "A" * 600 + '"}')
    ev = parse_zeek(raw, "s1", "http")
    ev.event_time = utcnow()
    ok, _ = validate_event(ev)
    assert ok
    assert ev.parse_status == "partial"


# ------------------------------------------------------------------ dedup
def test_dedup_seen_once():
    store = DedupStore()
    assert not store.seen_before("k1")
    assert store.seen_before("k1")
    assert not store.seen_before("k2")


def test_dedup_lru_eviction():
    store = DedupStore(capacity=3)
    for i in range(4):
        store.seen_before(f"k{i}")
    assert len(store) == 3
    assert not store.seen_before("k0")   # evicted
    assert store.seen_before("k3")       # still tracked


# ------------------------------------------------------------------ enrich
def test_zone_classification():
    zones = ZoneEnricher([("192.168.0.0/16", "internal"),
                          ("10.0.0.0/8", "dmz")])
    assert zones.classify("192.168.1.50") == "internal"
    assert zones.classify("10.20.30.40") == "dmz"
    assert zones.classify("93.184.216.34") is None
    assert zones.classify(None) is None
    assert zones.classify("not-an-ip") is None


def test_enrich_sets_event_zone():
    zones = ZoneEnricher([("192.168.0.0/16", "internal")])
    ev = _valid_event()
    zones.enrich(ev)
    assert ev.zone == "internal"
