"""v0.16.1 - regresi LAPORAN-BUG-VENDOR-0.16.0.md (deploy 2026-10-22).

Setiap test memetakan satu bug lapangan:
  P0-4  detail alert 502 pada alias multi-index (guard salah atribut)
  P0-5  Event Search selalu 0 hasil (term teks ke field ip)
  P1-3  Rule Manager "not found"/"offline" -> /api/rules/status
  P2-6  GET /api/alerts/search jatuh ke /{alert_id}
  P2-7  /api/version 404
  P2-1  komponen pipeline lewat /api/health
  P1-2  /api/stats/overview memuat field rich (hosts/zone_traffic/mttr)
"""

import pytest

from app import __version__
from app.os_client import OSClient
from opensearchpy import RequestError

from tests.conftest import login

ADMIN = {"username": "admin", "password": "bootstrap-admin-pass-01"}


def _real_os_with_search(search_fn) -> OSClient:
    """OSClient ASLI (bukan FakeOS) dengan client.search distub -
    diperlukan karena FakeOS meng-override get_by_id."""
    os = OSClient("http://localhost:9200")
    os.client = type("_Stub", (), {"search": staticmethod(search_fn)})()
    return os


# ------------------------------------------------------------- P0-4
class TestGetByIdAliasSafe:
    def test_requesterror_alias_degrades_to_none(self):
        """Guard lama memeriksa exc.error ('illegal_argument_exception')
        sehingga pesan alias tidak pernah kena -> 502. Kini args penuh
        diperiksa dan alias-multi-index DOWNGRADE ke None (fallback)."""
        def raise_alias_error(**kw):
            raise RequestError(400, "illegal_argument_exception",
                               "alias [ndr-alerts-read] has more than one "
                               "index associated with it [a, b], can't "
                               "execute a single index op")
        os = _real_os_with_search(raise_alias_error)
        assert os.get_by_id("ndr-alerts-read", "abc") is None

    def test_get_by_id_uses_ids_query(self):
        captured = {}

        def fake_search(**kw):
            captured.update(kw)
            return {"hits": {"hits": [{"_id": "x1", "_index": "i1",
                                       "_source": {"alert_id": "x1"}}]}}

        os = _real_os_with_search(fake_search)
        doc = os.get_by_id("ndr-alerts-read", "x1")
        assert doc is not None
        # v0.16.1: jalur utama = search ids-query (fan-out aman)
        assert captured["body"]["query"] == {"ids": {"values": ["x1"]}}

    def test_other_requesterror_still_raises(self):
        def raise_other(**kw):
            raise RequestError(400, "parse_exception", "boom")

        os = _real_os_with_search(raise_other)
        with pytest.raises(RequestError):
            os.get_by_id("ndr-alerts-read", "abc")

    def test_get_alert_doc_falls_back(self, client, _fake_os, monkeypatch):
        """Detail alert 200 walau GET by _id kena alias multi-index."""
        monkeypatch.setattr(_fake_os, "get_by_id",
                            lambda alias, doc_id: None)
        monkeypatch.setattr(_fake_os, "search_alert_doc",
                            lambda alert_id: {"_id": alert_id, "_source": {
                                "title": "t", "severity": "high"}})
        login(client, **ADMIN)
        res = client.get("/api/alerts/66dde163-3c6e-54cd-9219-28fe750ae6e0")
        assert res.status_code == 200, res.text
        assert res.json()["source"]["title"] == "t"


# ------------------------------------------------------------- P0-5
class TestFreeTextQuery:
    def test_event_type_fast_path(self):
        q = OSClient.build_free_text_query("dns")
        should = q["bool"]["should"]
        assert {"term": {"event_type": "dns"}} in should
        assert q["bool"]["minimum_should_match"] == 1

    def test_ip_fast_path_no_text_fields(self):
        q = OSClient.build_free_text_query("10.0.5.20")
        should = q["bool"]["should"]
        assert {"term": {"source.ip": "10.0.5.20"}} in should
        assert {"term": {"destination.ip": "10.0.5.20"}} in should
        # tidak ada wildcard untuk IP murni (biar tidak dobel kueri)
        assert not any("wildcard" in c for c in should)

    def test_text_never_terms_ip_fields(self):
        q = OSClient.build_free_text_query("evil-dga")
        blob = str(q)
        assert "source.ip" not in blob and "destination.ip" not in blob
        # wildcard case-insensitive pada whitelist field
        assert {"wildcard": {"dns.query": {"value": "*evil-dga*"}}} \
            in q["bool"]["should"]

    def test_empty_returns_none(self):
        assert OSClient.build_free_text_query("") is None
        assert OSClient.build_free_text_query(None) is None

    def test_search_endpoint_uses_query_text(self, client, _fake_os,
                                             monkeypatch):
        captured = {}

        def fake_guarded_search(**kw):
            captured.update(kw)
            return {"hits": {"total": {"value": 1, "relation": "eq"},
                             "hits": [{"_id": "e1", "_index": "i1",
                                       "_source": {"event_type": "dns"}}]}}

        monkeypatch.setattr(_fake_os, "guarded_search", fake_guarded_search)
        login(client, **ADMIN)
        res = client.post("/api/events/search", json={
            "index": "ndr-events-read",
            "query_text": "dns",
            "time_from": "2026-10-01T00:00:00Z"})
        assert res.status_code == 200, res.text
        assert res.json()["total"] == 1
        sent = captured["query"]
        assert {"term": {"event_type": "dns"}} in sent["bool"]["should"]

    def test_exact_total_flag(self, client, _fake_os, monkeypatch):
        captured = {}

        def fake_guarded_search(**kw):
            captured.update(kw)
            return {"hits": {"total": {"value": 5, "relation": "eq"},
                             "hits": []}}

        monkeypatch.setattr(_fake_os, "guarded_search", fake_guarded_search)
        login(client, **ADMIN)
        res = client.post("/api/events/search", json={
            "index": "ndr-events-read", "query_text": "dns",
            "exact_total": True,
            "time_from": "2026-10-01T00:00:00Z"})
        assert res.status_code == 200
        assert captured["exact_total"] is True


# ------------------------------------------------------------- P1-3
class TestRulesStatus:
    def test_status_endpoint(self, client):
        login(client, **ADMIN)
        res = client.get("/api/rules/status")
        assert res.status_code == 200, res.text
        body = res.json()
        for key in ("rules_file", "rules_file_exists", "rules_file_updated",
                    "unix_socket", "socket_present", "sensor_online"):
            assert key in body
        # path persis dari perspektif container API - kunci diagnosa mount
        assert body["rules_file"].endswith("suricata.rules")


# ------------------------------------------------------------- P2-6
class TestAlertsSearchRoute:
    def test_get_search_is_405_not_502(self, client):
        login(client, **ADMIN)
        res = client.get("/api/alerts/search")
        assert res.status_code == 405, res.text


# ------------------------------------------------------------- P2-7
class TestVersionEndpoint:
    def test_version(self, client):
        res = client.get("/api/version")
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["version"] == __version__
        assert body["service"] == "ndr-api"


# ------------------------------------------------------------- P2-1 / P1-2
class TestOverviewRich:
    def test_health_passes_pipeline_components(self, client, _fake_os,
                                               monkeypatch):
        monkeypatch.setattr(_fake_os, "latest_health_doc", lambda: {
            "sensor_id": "s1", "eps": 12.5, "backlog_seconds": 1.0,
            "components": [{"name": "tailer", "ok": True,
                            "detail": "state=streaming"}]})
        login(client, **ADMIN)
        body = client.get("/api/health").json()
        assert body["pipeline"]["components"][0]["name"] == "tailer"

    def test_stats_overview_rich_fields(self, client, _fake_os,
                                        monkeypatch):
        # agregasi host: terms source/destination + sub sum bytes
        def fake_aggregate(alias, body):
            aggs = body.get("aggs", {})
            if "by_src" in aggs:
                return {"hits": {"total": {"value": 10}},
                        "aggregations": {
                            "by_src": {"buckets": [
                                {"key": "10.0.0.5", "doc_count": 42,
                                 "bytes": {"value": 8_640_000_000}},
                                {"key": "8.8.8.8", "doc_count": 7,
                                 "bytes": {"value": 1_000_000}}]},
                            "by_dst": {"buckets": [
                                {"key": "10.0.0.5", "doc_count": 10,
                                 "bytes": {"value": 1_000_000}}]},
                        }}
            return {"hits": {"total": {"value": 0}},
                    "aggregations": {k: {"buckets": []}
                                     for k in aggs}}

        monkeypatch.setattr(_fake_os, "aggregate", fake_aggregate)
        monkeypatch.setattr(_fake_os, "count", lambda alias, q=None: 777)
        login(client, **ADMIN)
        res = client.get("/api/stats/overview")
        assert res.status_code == 200, res.text
        body = res.json()
        # v0.16.1: field rich diisi dari agregasi NYATA
        assert body["events_24h"] == 777
        hosts = body["hosts"]
        assert len(hosts) == 1  # 8.8.8.8 eksternal -> tidak masuk
        assert hosts[0]["ip"] == "10.0.0.5"
        assert hosts[0]["bytes_in"] == 1_000_000
        assert hosts[0]["bytes_out"] == 8_640_000_000
        assert body["zone_traffic"][0]["zone"] == "internal"
        assert body["traffic_24h"]["bytes_out"] == 8_640_000_000
        # MTTR kosong tapi field ada (Reports tidak blank)
        assert "mttr" in body and "alert_daily_7d" in body


# ------------------------------------------------------------- JWT (P2-3)
class TestJwtSecretGuard:
    def test_weak_secret_replaced(self):
        from app.config import Config, _harden_jwt_secret
        old = Config.jwt_secret
        Config.jwt_secret = "9byte"
        try:
            _harden_jwt_secret()
            assert len(Config.jwt_secret) >= 32
        finally:
            Config.jwt_secret = old
