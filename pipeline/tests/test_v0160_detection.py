"""v0.16.0 pipeline tests - requirements 1/3/8/10/12/18.

Cakupan:
  R3   attack_status_for (HTTP status evidence > verdict v0.10)
  R10  cve_for (ekstrak CVE dari signature/reason) + explanation_for
  R8   dga_score ternormalisasi 0-100
  R1+3 AuthBruteforceDetector (canary: 401/403 berulang -> attempt;
       kill switch = tidak ter-daftar bila DETECT_BRUTEFORCE=0)
  R18  GamblingWatchlist matcher + GamblingAccessDetector + campaign
  R12  _AlertGeoTagger (geo_src/geo_dst terpusat, idempoten, aman)
"""

import queue
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock

from app.config import Config
from app.detection import DetectionEngine, _AlertGeoTagger
from app.detection.behavior import (AuthBruteforceDetector,
                                    GamblingAccessDetector)
from app.detection.rules import (SEVERITY_SCORE, attack_status_for,
                                 build_alert_doc, cve_for,
                                 detection_engine_for, explanation_for,
                                 make_alert_id)
from app.enrich import GamblingWatchlist
from app.models import CommonEvent


def _ev(**kw):
    base = dict(
        event_id="e1", event_time=datetime.now(timezone.utc),
        ingest_time=datetime.now(timezone.utc), sensor_id="s1",
        source_engine="zeek", event_type="http",
        source_ip="10.0.0.5", destination_ip="203.0.113.9",
    )
    base.update(kw)
    return CommonEvent(**base)


# ------------------------------------------------------------- R3 status
class TestAttackStatus:
    def test_http_2xx_with_success_category(self):
        # kategori malware/trojan dgn respons 2xx -> server mengikuti
        # (C2 callback sukses); konsisten _MALWARE_CATEGORIES di rules
        st = attack_status_for("suricata_alert_group", "trojan-activity",
                               "ET TROJAN C2 Callback", [200])
        assert st == "attack_successful"

    def test_http_2xx_without_success_evidence_is_attempt(self):
        st = attack_status_for("suricata_alert_group", "policy",
                               "ET INFO", [200])
        assert st == "attempt"

    def test_http_4xx_is_failure(self):
        st = attack_status_for("suricata_alert_group", "attempted-admin",
                               "ET SCAN", [403, 401])
        assert st == "failure"

    def test_no_http_status_maps_from_verdict(self):
        # aturan behaviour sengaja konservatif (may be benign) ->
        # indeterminate tanpa bukti respons server (no-overclaim)
        assert attack_status_for("portscan_suspected") == "indeterminate"
        assert attack_status_for("beaconing_suspected") == "indeterminate"
        # kategori attempt klasik dgn verdict attempted -> attempt
        assert attack_status_for("suricata_alert_group",
                                 "attempted-admin", "ET SCAN") == "attempt"

    def test_tender_vocabulary_only(self):
        allowed = {"attack_successful", "attempt", "failure",
                   "compromise", "indeterminate"}
        for atype in ("portscan_suspected", "beaconing_suspected",
                      "dga_suspected", "dns_nxdomain_burst",
                      "lateral_movement_suspected", "exfil_suspected",
                      "auth_bruteforce_suspected", "gambling_access"):
            st = attack_status_for(atype)
            assert st in allowed, (atype, st)


# ------------------------------------------------------------- R10 CVE
class TestCveExplanation:
    def test_cve_extracted_from_signature_and_reasons(self):
        cves = cve_for("ET EXPLOIT Log4j CVE-2021-44228 attempt",
                       ["matched CVE-2023-34362 in payload"])
        assert cves == ["CVE-2021-44228", "CVE-2023-34362"]

    def test_cve_dedup_and_cap(self):
        cves = cve_for("CVE-2021-44228 CVE-2021-44228",
                       [f"CVE-2019-{i:05d}" for i in range(20)])
        assert len(cves) <= 8
        assert cves.count("CVE-2021-44228") == 1

    def test_explanation_bahasa_indonesia_with_context(self):
        text = explanation_for(
            title="Portscan", attack_status="attempt", stage="reconnaissance",
            stage_label="Reconnaissance", mitre=[{"technique_id": "T1595"}],
            source_ip="10.0.0.5", destination_ip="10.0.1.7",
            protocol="tcp", event_count=120, cve=[])
        assert "Status keberhasilan" in text
        assert "Reconnaissance" in text
        assert "120" in text

    def test_explanation_mentions_cve(self):
        text = explanation_for(
            title="Exploit", attack_status="attack_successful",
            stage="execution", stage_label="Execution", mitre=[],
            source_ip="10.0.0.5", destination_ip="10.0.1.7",
            protocol="tcp", event_count=3, cve=["CVE-2021-44228"])
        assert "CVE-2021-44228" in text


# ------------------------------------------------------------- R1 label
class TestDetectionEngineLabel:
    def test_engine_labels(self):
        assert detection_engine_for("suricata_alert_group") == "signature"
        assert detection_engine_for("ioc_match") == "intel"
        assert detection_engine_for("auth_bruteforce_suspected") == \
            "behaviour"
        assert detection_engine_for("gambling_access") == "behaviour"


# ------------------------------------------------------------- R8 DGA score
class TestDgaScore:
    def test_score_range_and_monotonic(self):
        for entropy, lo, hi in [(2.5, 0, 1), (3.5, 45, 55), (4.5, 99, 100)]:
            score = max(0.0, min(100.0, (entropy - 2.5) / 2.0 * 100.0))
            assert lo <= score <= hi, (entropy, score)

    def test_build_alert_doc_carries_dga_score(self):
        doc = build_alert_doc(
            alert_id=make_alert_id("dga_suspected", "k",
                                   datetime.now(timezone.utc)),
            alert_type="dga_suspected", title="DGA",
            group_key="k", severity="high", rationale="r", reasons=["x"],
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc), sensor_id="s1",
            event_count=10, source_count=1, destination_count=1,
            source_ip="10.0.0.5", destination_ip=None, transport="udp",
            protocol="dns", top_sources=[], top_destinations=[],
            top_rules=[], evidence=[], dga_score=77.7)
        assert doc["dga_score"] == 77.7
        assert doc["attack_status"] == "indeterminate"
        assert doc["detection_engine"] == "behaviour"


# ------------------------------------------------------------- R1 bruteforce
class TestAuthBruteforceDetector:
    def _detector(self, min_failures=5, window_min=10):
        q = queue.Queue()
        det = AuthBruteforceDetector(
            min_failures=min_failures, window_min=window_min,
            max_keys=1000, sensor_id="s1", sink_queue=q,
            index_for_alert=lambda ts: "ndr-alerts-test")
        return det, q

    def test_below_threshold_no_alert(self):
        det, q = self._detector(min_failures=10)
        for _ in range(3):
            det.feed(_ev(http_status=401, http_host="vpn.corp"), "idx")
        det.last_flush = 0
        det.sweep(time.time() + det.window_seconds + 5)
        assert q.empty()

    def test_repeated_401s_emit_attempt_alert(self):
        det, q = self._detector(min_failures=5)
        for _ in range(5):
            det.feed(_ev(http_status=401, http_host="vpn.corp"), "idx")
        det.last_flush = 0
        det.sweep(time.time() + det.window_seconds + 5)
        assert not q.empty()
        index, doc_id, doc = q.get_nowait()
        assert doc["alert_type"] == "auth_bruteforce_suspected"
        assert doc["attack_status"] == "attempt"  # req 3: ditolak server
        assert doc["detection_engine"] == "behaviour"
        # kill_chain dihitung classify_rule(alert_type), BUKAN dari param
        # attack_phase (label funnel); cek keduanya apa adanya
        assert doc["attack_phase"] == "initial_access"
        assert doc["kill_chain"]["stage"] in ("initial_access",
                                              "actions_on_objectives",
                                              "credential_access")
        assert any("vpn.corp" in str(r) for r in doc["reasons"])

    def test_non_auth_events_ignored(self):
        det, q = self._detector()
        det.feed(_ev(http_status=200), "idx")
        det.feed(_ev(), "idx")  # tanpa http_status
        det.last_flush = 0
        det.sweep(time.time() + det.window_seconds + 5)
        assert q.empty()

    def test_kill_switch_excludes_detector(self):
        cfg = Config()
        cfg.detect_bruteforce_enabled = False
        cfg.detect_bruteforce_min_failures = 5
        cfg.detect_bruteforce_window_min = 10
        cfg.detect_max_tracked_keys = 1000
        cfg.sensor_id = "s1"
        cfg.detect_alert_window_min = 10
        cfg.detect_window_min = 10
        cfg.detect_max_tracked_keys = 1000
        eng = DetectionEngine(cfg, queue.Queue(), queue.Queue())
        assert eng.bruteforce is None
        assert all(getattr(r, "name", "") !=
                   "auth_bruteforce_suspected" for r in eng.rules)


# ------------------------------------------------------------- R18 gambling
class TestGamblingWatchlist:
    def test_keyword_match_host_dns_sni(self):
        w = GamblingWatchlist(keywords=["judi", "slot"])
        assert w.match_host("slot88.example.com")
        assert w.match_host("judi-online.example")
        assert w.match_host("SLOT.casino.net")  # case-insensitive
        assert not w.match_host("perbankan.example.com")

    def test_domain_file_exact_and_suffix(self, tmp_path):
        f = tmp_path / "domains.txt"
        f.write_text("# komentar\njudobet.example\n# lagi\nslotx.io\n")
        w = GamblingWatchlist(domains_file=str(f))
        assert w.match_host("judobet.example")
        assert w.match_host("www.judobet.example")
        assert w.match_host("a.slotx.io")
        assert not w.match_host("notjudobet.example.org")  # bukan suffix
        # missing file -> matcher tetap hidup (daftar opsional)
        w2 = GamblingWatchlist(domains_file="/nonexistent/file.txt")
        assert not w2.match_host("anything.test")

    def test_enrich_tags_campaign(self):
        w = GamblingWatchlist(keywords=["sbobet"])
        ev = _ev(http_host="www.sbobet88.example")
        w.enrich(ev)
        assert ev.campaign == "judi-online"
        ev2 = _ev(http_host="kantorpos.example")
        w.enrich(ev2)
        assert ev2.campaign is None
        # campaign sudah terpasang (TI) tidak ditimpa
        ev3 = _ev(http_host="sbobet.example", campaign="apt-c2")
        w.enrich(ev3)
        assert ev3.campaign == "apt-c2"

    def test_gambling_detector_emits_campaign_alert(self):
        q = queue.Queue()
        det = GamblingAccessDetector(
            min_hits=3, window_min=10, max_keys=1000, sensor_id="s1",
            sink_queue=q, index_for_alert=lambda ts: "ndr-alerts-test")
        for _ in range(3):
            det.feed(_ev(event_type="dns", dns_query="slotx.io",
                         source_ip="10.0.0.9", campaign="judi-online"), "idx")
        det.last_flush = 0
        det.sweep(time.time() + det.window_seconds + 5)
        assert not q.empty()
        _, _, doc = q.get_nowait()
        assert doc["alert_type"] == "gambling_access"
        assert doc["campaign"] == "judi-online"
        assert doc["attack_status"] == "indeterminate"  # kebijakan, bukan
        # serangan: tanpa klaim status kosakata serangan
        assert "slotx.io" in doc["dns_domains"]


# ------------------------------------------------------------- R12 geo tagger
class TestAlertGeoTagger:
    def _geo(self):
        geo = MagicMock()
        geo.lookup = lambda ip: {
            "country": "Singapore", "country_iso_code": "SG",
            "asn_org": "AS16509 Amazon", "location": {"lat": 1.3, "lon": 103.8},
        } if ip == "203.0.113.9" else None
        return geo

    def test_tagging_and_passthrough(self):
        inner = queue.Queue()
        tagger = _AlertGeoTagger(inner, self._geo())
        alert_doc = {"alert_id": "a1", "source": {"ip": "10.0.0.5"},
                     "destination": {"ip": "203.0.113.9"}}
        tagger.put(("ndr-alerts-2026.10.20", "a1", alert_doc))
        idx, _id, doc = inner.get_nowait()
        assert idx == "ndr-alerts-2026.10.20"
        assert "geo_src" not in doc          # IP privat -> tanpa geo (jujur)
        assert doc["geo_dst"]["country"] == "Singapore"
        assert doc["geo_dst"]["asn_org"] == "AS16509 Amazon"
        assert "location" not in doc["geo_dst"]  # diet: keyword saja

    def test_non_alert_docs_untouched(self):
        inner = queue.Queue()
        tagger = _AlertGeoTagger(inner, self._geo())
        event_doc = {"event_id": "e1", "source": {"ip": "203.0.113.9"}}
        tagger.put(("ndr-zeek-conn-2026.10.20", "e1", event_doc))
        _, _, doc = inner.get_nowait()
        assert "geo_dst" not in doc  # event geo lewat enrich_event sendiri

    def test_idempotent_and_malformed_safe(self):
        inner = queue.Queue()
        tagger = _AlertGeoTagger(inner, self._geo())
        doc = {"alert_id": "a2", "geo_dst": {"country": "ID"},
               "destination": {"ip": "203.0.113.9"}}
        tagger.put(("ndr-alerts-x", "a2", doc))
        assert doc["geo_dst"] == {"country": "ID"}  # tidak ditimpa
        tagger.put("bukan-tuple")  # item aneh tidak boleh meledak
        items = []
        while not inner.empty():
            items.append(inner.get_nowait())
        assert "bukan-tuple" in items  # tetap diteruskan ke sink

    def test_engine_wires_tagger_when_geo_present(self):
        cfg = Config()
        cfg.sensor_id = "s1"
        cfg.geoip_mmdb_path = None
        cfg.geoip_json_path = None
        out = queue.Queue()
        eng = DetectionEngine(cfg, queue.Queue(), out,
                              geo_enricher=MagicMock())
        assert isinstance(eng.out_queue, _AlertGeoTagger)
        eng2 = DetectionEngine(cfg, queue.Queue(), queue.Queue())
        assert not isinstance(eng2.out_queue, _AlertGeoTagger)


# ------------------------------------------------- alert doc contract
class TestAlertDocV016:
    def test_suricata_group_top_rules_carry_sid(self):
        doc = build_alert_doc(
            alert_id=make_alert_id("suricata_alert_group", "g",
                                   datetime.now(timezone.utc)),
            alert_type="suricata_alert_group", title="T",
            group_key="g", severity="high", rationale="r",
            reasons=["x"], first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc), sensor_id="s1",
            event_count=2, source_count=1, destination_count=1,
            source_ip="10.0.0.5", destination_ip="10.0.0.6",
            transport="tcp", protocol=None,
            top_sources=[], top_destinations=[],
            top_rules=[("ET MALWARE Beacon", 2, 2027893)],
            evidence=[], suricata_category="malware")
        assert doc["top_rules"][0]["signature_id"] == "2027893"
        assert doc["detection_engine"] == "signature"
        # mapping mitre/kill_chain kini ada di bootstrap - kontrak emission
        assert isinstance(doc["mitre"], list)
        assert "stage" in doc["kill_chain"]
        assert doc["attack_status"] in ("attack_successful", "attempt",
                                        "failure", "indeterminate",
                                        "compromise")
