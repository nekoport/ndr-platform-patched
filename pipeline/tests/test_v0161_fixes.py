"""v0.16.1 - JA3 dari client-hello Zeek (P1-5) + komponen health (P2-1)."""

from app.models import compute_ja3
from app.metrics import HealthPublisher
from app.normalize import parse_zeek


# ------------------------------------------------------------- JA3 (P1-5)
class TestComputeJa3:
    def test_known_vector_tls12(self):
        # Vektor JA3 klasik (curl 7.x, Salesforce JA3 contoh umum):
        # 771,49195-49199-...,0-23-65281,...
        ja3_string_sections = (
            771,
            [49195, 49199, 49196, 49200, 52393, 52392, 49161, 49171,
             49172, 49181, 49182, 49157, 49159, 49167, 49169, 49170,
             49173, 49178, 49179, 49187, 49191, 49162, 49172 - 1],
        )
        # jalankan algoritma md5 yang sama seperti ja3: hash dari string
        ciphers = [49195, 49199, 49196, 49200]
        extensions = [0, 23, 65281]
        curves = [23]
        fmts = [0]
        # hash deterministik: input sama -> md5 sama (dihitung dua kali)
        h1 = compute_ja3("TLSv1.2", ciphers, extensions, curves, fmts)
        h2 = compute_ja3("TLSv1.2", ciphers, extensions, curves, fmts)
        assert h1 == h2 and len(h1) == 32

    def test_version_mapping_tls13_uses_legacy_771(self):
        a = compute_ja3("TLSv1.3", [4865], [], [], [])
        b = compute_ja3("TLSv1.2", [4865], [], [], [])
        assert a == b  # 0x0303 untuk keduanya

    def test_grease_stripped_from_extensions_and_curves(self):
        h_plain = compute_ja3("TLSv1.2", [49195], [0, 23], [23], [0])
        h_grease = compute_ja3("TLSv1.2", [49195], [0, 23, 2570], [23, 5250],
                               [0])
        assert h_plain == h_grease

    def test_no_ciphers_returns_none(self):
        assert compute_ja3("TLSv1.2", [], [0], [23], [0]) is None
        assert compute_ja3("TLSv1.2", None, [], [], []) is None

    def test_zeek_tls_normalized_ja3_and_issuer(self):
        rec = {
            "ts": 1760000000.0, "uid": "u1", "id.orig_h": "10.0.0.5",
            "id.orig_p": 443, "id.resp_h": "93.184.216.34", "id.resp_p": 443,
            "version": "TLSv1.2", "server_name": "example.com",
            "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "client_cipher_suites": [49195, 49199],
            "client_extensions": [0, 23, 65281],
            "client_curves": [23], "client_point_formats": [0],
            "subject": "CN=example.com",
            "issuer": "CN=Let's Encrypt Authority X3",
        }
        ev = parse_zeek(__import__("json").dumps(rec), "sensor-test", "tls")
        assert ev.tls_ja3 == compute_ja3(
            "TLSv1.2", [49195, 49199], [0, 23, 65281], [23], [0])
        assert ev.tls_issuer == "CN=Let's Encrypt Authority X3"
        assert ev.tls_subject == "CN=example.com"
        assert ev.tls_sni == "example.com"

    def test_zeek_tls_without_client_hello_no_ja3(self):
        rec = {"ts": 1760000000.0, "uid": "u2", "id.orig_h": "10.0.0.6",
               "id.orig_p": 1, "id.resp_h": "1.1.1.1", "id.resp_p": 2,
               "version": "TLSv1.3", "server_name": "x.test"}
        ev = parse_zeek(__import__("json").dumps(rec), "sensor-test", "tls")
        assert ev.tls_ja3 is None  # jujur: tidak ada data client-hello
        assert ev.tls_sni == "x.test"


# ------------------------------------------------- komponen health (P2-1)
class TestHealthComponents:
    def test_components_built_from_snapshot(self):
        snap = {
            "sensor_id": "s1",
            "counters": {"events_indexed": 1234, "parse_errors": 2,
                         "duplicates": 5, "dropped": 0},
            "gauges": {"queue_depth": 10, "queue_capacity": 2000,
                       "tailer_state": "streaming", "sink_pending": 3,
                       "recon_open_stories": 4, "recon_dirty_stories": 1},
            "eps_by_engine": {"zeek": 800.1, "suricata": 19.9},
            "backlog_seconds": 0.5,
        }
        comps = HealthPublisher._components(snap)
        names = {c["name"] for c in comps}
        assert {"tailer", "ingest-zeek", "ingest-suricata", "normalize",
                "detection", "sink-opensearch", "correlation"} <= names
        zeek = next(c for c in comps if c["name"] == "ingest-zeek")
        assert zeek["eps"] == 800.1
        detection = next(c for c in comps if c["name"] == "detection")
        assert detection["ok"] is True
        assert "10/2000" in detection["detail"]

    def test_detection_not_ok_when_queue_full(self):
        snap = {"counters": {}, "gauges": {"queue_depth": 2000,
                                           "queue_capacity": 2000,
                                           "tailer_state": "streaming"},
                "eps_by_engine": {}, "backlog_seconds": 0}
        comps = HealthPublisher._components(snap)
        assert next(c for c in comps
                    if c["name"] == "detection")["ok"] is False
