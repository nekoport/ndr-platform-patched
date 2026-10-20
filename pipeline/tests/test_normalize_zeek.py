"""Zeek JSON normalizer tests."""

from app.normalize import parse_zeek

SENSOR = "sensor-test"


def test_conn_event(zeek_lines):
    ev = parse_zeek(zeek_lines[0], SENSOR, "conn")
    assert ev.event_type == "conn"
    assert ev.source_ip == "192.168.1.50"
    assert ev.destination_port == 443
    assert ev.transport == "tcp"
    assert ev.protocol == "ssl"
    assert ev.session_id == "CAbcdefGhijKlmnoP"
    assert ev.source_bytes == 2400
    assert ev.destination_bytes == 18000
    assert ev.network_bytes == 20400
    assert ev.network_packets == 54


def test_dns_event(zeek_lines):
    ev = parse_zeek(zeek_lines[3], SENSOR, "dns")
    assert ev.dns_query == "xj2kdmf4oqw.example-dga[.]com"
    assert ev.dns_rcode == "NXDOMAIN"
    assert ev.dns_type == "response"


def test_http_event(zeek_lines):
    ev = parse_zeek(zeek_lines[2], SENSOR, "http")
    assert ev.http_host == "updates.vendor.example"
    assert ev.http_url == "/downloads/setup.exe"
    assert ev.http_status == 200
    assert ev.http_method == "GET"


def test_tls_event(zeek_lines):
    ev = parse_zeek(zeek_lines[4], SENSOR, "tls")
    assert ev.tls_version == "TLSv13"
    assert ev.tls_sni == "updates.vendor.example"
    assert ev.tls_ja3 == "a0e9f5b6cb495f75b3b1b8f1c7f0c8f4"


def test_malformed_line(zeek_lines):
    assert parse_zeek(zeek_lines[5], SENSOR, "conn") is None


def test_event_time_from_epoch(zeek_lines):
    ev = parse_zeek(zeek_lines[0], SENSOR, "conn")
    assert ev.event_time.year == 2024  # 1728702245 = 2024-10-12
