"""GeoIP optional enrichment tests (Phase 5).

GeoIP must be: off by default, never crash ingestion, never geolocate
private space, and load both sidecar formats.
"""

import json

from app.geoip import GeoEnricher
from app.models import CommonEvent
from datetime import datetime, timezone


def _event(src="203.0.113.25", dst="10.0.20.15"):
    return CommonEvent(
        event_id="e1", event_time=datetime.now(timezone.utc),
        ingest_time=datetime.now(timezone.utc), sensor_id="s1",
        source_engine="zeek", event_type="conn",
        source_ip=src, destination_ip=dst)


def test_disabled_when_no_source(tmp_path):
    geo = GeoEnricher(None, None)
    assert geo.enabled is False
    ev = _event()
    geo.enrich_event(ev)
    assert ev.source_geo is None and ev.destination_geo is None


def test_json_sidecar_longest_prefix_wins(tmp_path):
    sidecar = {"networks": [
        {"cidr": "203.0.0.0/8", "country": "Australia",
         "country_iso_code": "AU", "lat": -27.5, "lon": 153.0},
        {"cidr": "203.0.113.0/24", "country": "Singapore",
         "country_iso_code": "SG", "lat": 1.35, "lon": 103.82,
         "asn_org": "AS64512 demo-vendor"},
    ]}
    path = tmp_path / "geo.json"
    path.write_text(json.dumps(sidecar))
    geo = GeoEnricher(None, str(path))
    assert geo.enabled
    hit = geo.lookup("203.0.113.25")
    assert hit["country"] == "Singapore"          # /24 beats /8
    assert hit["location"] == {"lat": 1.35, "lon": 103.82}
    assert hit["asn_org"] == "AS64512 demo-vendor"
    assert geo.lookup("8.8.8.8") is None          # outside entries


def test_never_geolocates_private_space(tmp_path):
    path = tmp_path / "geo.json"
    path.write_text(json.dumps({"networks": [
        {"cidr": "10.0.0.0/8", "country": "Nowhere",
         "country_iso_code": "XX", "lat": 0.0, "lon": 0.0}]}))
    geo = GeoEnricher(None, str(path))
    assert geo.lookup("10.0.20.15") is None
    assert geo.lookup("not-an-ip") is None
    assert geo.lookup(None) is None


def test_enrich_event_attaches_geo_both_sides(tmp_path):
    sidecar = {"networks": [
        {"cidr": "203.0.113.0/24", "country": "Singapore",
         "country_iso_code": "SG", "lat": 1.35, "lon": 103.82},
        {"cidr": "198.51.100.0/24", "country": "Australia",
         "country_iso_code": "AU", "lat": -33.87, "lon": 151.21},
    ]}
    path = tmp_path / "geo.json"
    path.write_text(json.dumps(sidecar))
    geo = GeoEnricher(None, str(path))
    ev = _event(src="203.0.113.25", dst="198.51.100.7")
    geo.enrich_event(ev)
    assert ev.source_geo["country"] == "Singapore"
    assert ev.destination_geo["country"] == "Australia"
    doc = ev.to_doc()
    assert doc["source"]["geo"]["location"]["lat"] == 1.35
    assert doc["destination"]["geo"]["country"] == "Australia"


def test_broken_sidecar_degrades_to_disabled(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    geo = GeoEnricher(None, str(path))
    assert geo.enabled is False
    ev = _event()
    geo.enrich_event(ev)          # must not raise
    assert ev.source_geo is None
