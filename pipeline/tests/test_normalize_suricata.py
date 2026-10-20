"""Suricata EVE normalizer tests."""

from app.normalize import parse_suricata

ALLOWED = {"alert", "dns", "http", "tls", "fileinfo", "stats"}
SENSOR = "sensor-test"


def test_alert_event_normalized(eve_lines):
    ev = parse_suricata(eve_lines[0], SENSOR, ALLOWED)
    assert ev is not None
    assert ev.source_engine == "suricata"
    assert ev.event_type == "alert"
    assert ev.source_ip == "203.0.113.25"
    assert ev.destination_port == 80
    assert ev.signature_id == "2016645"
    assert ev.severity == "high"          # severity 2
    assert ev.severity_score == 75
    assert ev.alert_signature == "ET WEB_SERVER Attempted SQL Injection"
    assert ev.http_host == "intranet.example.local"
    assert ev.community_id == "1:abc123="
    assert ev.event_id and len(ev.event_id) == 36


def test_dns_query_event(eve_lines):
    ev = parse_suricata(eve_lines[1], SENSOR, ALLOWED)
    assert ev.event_type == "dns"
    assert ev.dns_query == "xj2kdmf4oqw.example-dga[.]com"
    assert ev.dns_type == "query"


def test_dns_nxdomain_response(eve_lines):
    ev = parse_suricata(eve_lines[2], SENSOR, ALLOWED)
    assert ev.dns_rcode == "NXDOMAIN"


def test_tls_event_extracts_ja3(eve_lines):
    ev = parse_suricata(eve_lines[4], SENSOR, ALLOWED)
    assert ev.tls_sni == "updates.vendor.example"
    assert ev.tls_ja3 == "a0e9f5b6cb495f75b3b1b8f1c7f0c8f4"
    assert ev.tls_subject.startswith("CN=updates.vendor.example")


def test_fileinfo_event(eve_lines):
    ev = parse_suricata(eve_lines[5], SENSOR, ALLOWED)
    assert ev.file_sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert ev.file_size == 1048576


def test_stats_event_skipped(eve_lines):
    assert parse_suricata(eve_lines[6], SENSOR, ALLOWED) is None


def test_malformed_line_returns_none(eve_lines):
    assert parse_suricata(eve_lines[7], SENSOR, ALLOWED) is None


def test_disallowed_type_filtered(eve_lines):
    assert parse_suricata(eve_lines[0], SENSOR, {"dns"}) is None


def test_deterministic_event_id(eve_lines):
    a = parse_suricata(eve_lines[0], SENSOR, ALLOWED)
    b = parse_suricata(eve_lines[0], SENSOR, ALLOWED)
    assert a.event_id == b.event_id


def test_to_doc_shape(eve_lines):
    ev = parse_suricata(eve_lines[0], SENSOR, ALLOWED)
    doc = ev.to_doc()
    assert doc["@timestamp"].endswith("Z")
    assert doc["source"]["ip"] == "203.0.113.25"
    assert doc["destination"]["port"] == 80
    assert doc["network"]["transport"] == "tcp"
    assert doc["severity"] == "high"
    assert "raw_line" not in doc
