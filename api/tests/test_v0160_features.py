"""v0.16.0 feature tests - requirement 5/6/7/9/14/15/18/19 + SSO bake.

Kontrak yang dijaga (lihat TIKET-DEVELOPER-0.16.0 blueprint):
  R5   filter DSL AST (and/or/not, is/is_one/include/exclude, cidr) -
       injeksi mustahil, whitelist field per konteks, nesting max 6.
  R6   export alert xlsx/csv: guard sama dgn /search, cap baris, audit.
  R7   DNS explorer: summary rasio resolved + search transaksi.
  R9   TLS insights (metadata-only agregasi).
  R14+15 rule stats: tabel rule_stats + endpoint + join list rules.
  R18  gambling preset view.
  R19  live SSE metrics (cap koneksi, tick terformat, degrade jujur).
  R13  SSO proxy: 503 jujur tanpa secret, 403 utk role tanpa
       evidence_export, deep-link public base.
"""

import json

from tests.conftest import login

ADMIN = {"username": "admin", "password": "bootstrap-admin-pass-01"}
VIEWER = {"username": "viewer", "password": "Password-123456"}


# ============================================================ R5 filter DSL
class TestFilterDSL:
    def _search(self, client, filter_ast):
        login(client, **ADMIN)
        return client.post("/api/alerts/search", json={
            "index": "ndr-alerts-read", "filter": filter_ast})

    def test_is_leaf_accepted(self, client):
        res = self._search(client, {"field": "severity", "op": "is",
                                    "value": "high"})
        assert res.status_code == 200, res.text

    def test_nested_and_or_not(self, client):
        ast = {"and": [
            {"or": [
                {"field": "severity", "op": "is_one",
                 "value": ["high", "critical"]},
                {"field": "attack_status", "op": "is",
                 "value": "attempt"},
            ]},
            {"not": {"field": "status", "op": "is", "value": "closed"}},
            {"field": "source.ip", "op": "cidr", "value": "10.0.0.0/8"},
            {"field": "campaign", "op": "exclude", "value": "judi-online"},
        ]}
        res = self._search(client, ast)
        assert res.status_code == 200, res.text

    def test_unknown_field_rejected(self, client):
        res = self._search(client, {"field": "raw_event", "op": "is",
                                    "value": "x"})
        assert res.status_code == 400
        assert "not filterable" in res.json()["detail"]

    def test_op_not_allowed_on_field_rejected(self, client):
        # severity tidak mengizinkan include (wildcard utk keyword jelas)
        res = self._search(client, {"field": "severity", "op": "include",
                                    "value": "hi"})
        assert res.status_code == 400

    def test_query_string_injection_rejected(self, client):
        # filter bukan jalur injeksi: value scalar saja, tanpa script DSL
        res = self._search(client, {"field": "severity", "op": "is",
                                    "value": {"script": "true"}})
        assert res.status_code == 400

    def test_group_mixing_rejected(self, client):
        res = self._search(client, {"and": [], "field": "severity",
                                    "op": "is", "value": "high"})
        assert res.status_code == 400

    def test_depth_overflow_rejected(self, client):
        ast: dict = {"field": "severity", "op": "is", "value": "high"}
        for _ in range(7):
            ast = {"not": ast}
        res = self._search(client, ast)
        assert res.status_code == 400

    def test_filter_applies_to_stats_and_export(self, client, _fake_os,
                                                monkeypatch):
        login(client, **ADMIN)
        res = client.post("/api/alerts/stats", json={
            "index": "ndr-alerts-read",
            "filter": {"field": "attack_status", "op": "is_one",
                       "value": ["attempt", "failure"]}})
        assert res.status_code == 200
        # export: pagination stub kosong - guard filter sudah divalidasi
        # sebelum query; yang diuji = filter diterima jalur export.
        def empty_search(index=None, body=None, **kw):
            return {"hits": {"hits": []}}
        monkeypatch.setattr(_fake_os.client, "search", empty_search)
        res = client.post("/api/alerts/export", json={
            "format": "csv",
            "time_from": "2026-10-01T00:00:00Z",
            "time_to": "2026-10-02T00:00:00Z",
            "filter": {"field": "dns_domains", "op": "include",
                       "value": "evil"}})
        assert res.status_code == 200, res.text


# ============================================================ R6 export
def _stub_client_search(_fake_os, monkeypatch, doc: dict):
    """Export berjalan lewat os.client.search (search_after pagination)."""
    calls = []

    def fake_search(index=None, body=None, **kw):
        calls.append(body)
        if body is not None and body.get("search_after") is not None:
            return {"hits": {"hits": []}}  # pagination habis
        return {"hits": {"total": {"value": 1, "relation": "eq"},
                         "hits": [{"_id": doc["alert_id"], "_source": doc,
                                   "sort": ["2026-10-12T10:00:00Z",
                                            doc["alert_id"]]}]}}

    monkeypatch.setattr(_fake_os.client, "search", fake_search)
    return calls


class TestExport:
    def _body(self, **kw):
        base = {"format": "csv",
                "time_from": "2026-10-01T00:00:00Z",
                "time_to": "2026-10-02T00:00:00Z"}
        base.update(kw)
        return base

    def test_csv_headers_and_content_type(self, client, _fake_os,
                                          monkeypatch):
        doc = {
            "alert_id": "a1", "severity": "high",
            "title": "ET MALWARE Beacon",
            "attack_status": "attempt",
            "kill_chain": {"stage": "command_control"},
            "cve": ["CVE-2021-44228"],
            "campaign": "judi-online",
            "mitre": [{"technique_id": "T1071",
                       "technique": "Application Layer Protocol"}],
            "@timestamp": "2026-10-12T10:00:00Z",
        }
        _stub_client_search(_fake_os, monkeypatch, doc)
        login(client, **ADMIN)
        res = client.post("/api/alerts/export", json=self._body())
        assert res.status_code == 200, res.text
        assert "text/csv" in res.headers["content-type"]
        body = res.text
        assert "alert_id" in body and "attack_status" in body
        assert "ET MALWARE Beacon" in body
        assert "CVE-2021-44228" in body
        assert "T1071" in body
        assert res.headers["X-Export-Rows"] == "1"

    def test_xlsx_is_zip_container(self, client, _fake_os, monkeypatch):
        _stub_client_search(_fake_os, monkeypatch, {
            "alert_id": "a2", "@timestamp": "2026-10-12T10:00:00Z",
            "severity": "medium", "title": "x"})
        login(client, **ADMIN)
        res = client.post("/api/alerts/export", json=self._body(
            format="xlsx"))
        assert res.status_code == 200, res.text
        assert ("spreadsheetml" in res.headers["content-type"]
                or "octet-stream" in res.headers["content-type"])
        # xlsx = zip: magic bytes PK
        assert res.content[:2] == b"PK"

    def test_bad_format_400(self, client):
        login(client, **ADMIN)
        res = client.post("/api/alerts/export", json=self._body(format="pdf"))
        assert res.status_code == 400

    def test_unknown_column_400(self, client):
        login(client, **ADMIN)
        res = client.post("/api/alerts/export", json=self._body(
            columns=["raw_event"]))
        assert res.status_code == 400

    def test_default_time_window_applied(self, client):
        # build_time_filter: tanpa window -> default 24 jam (bukan 422);
        # guard tetap jalan dan tanpa backend hasilnya 502 jujur.
        login(client, **ADMIN)
        res = client.post("/api/alerts/export", json={"format": "csv"})
        assert res.status_code == 502

    def test_auditor_can_export_readonly(self, client, _fake_os,
                                         monkeypatch, users_seeded):
        # permission "search" = semua role termasuk auditor (read-only);
        # export mengikuti permission yang sama -> auditor boleh export.
        _stub_client_search(_fake_os, monkeypatch, {
            "alert_id": "a3", "@timestamp": "2026-10-12T10:00:00Z"})
        login(client, **VIEWER)
        res = client.post("/api/alerts/export", json=self._body())
        assert res.status_code == 200, res.text


# ============================================================ R7 DNS
class TestDnsExplorer:
    def _agg_result(self):
        return {
            "hits": {"total": {"value": 100, "relation": "eq"}},
            "aggregations": {
                "by_rcode": {"buckets": [
                    {"key": "NOERROR", "doc_count": 80},
                    {"key": "NXDOMAIN", "doc_count": 18},
                    {"key": "SERVFAIL", "doc_count": 2},
                ]},
                # v0.16.1 (P1-4): penyebut rasio = dokumen dengan rcode
                "has_rcode": {"doc_count": 100},
                "top_queried": {"buckets": [
                    {"key": "evil-dga.test", "doc_count": 22}]},
                "top_clients": {"buckets": [
                    {"key": "10.0.0.5", "doc_count": 40}]},
            },
        }

    def test_summary_ratio_and_tops(self, client, _fake_os, monkeypatch):
        monkeypatch.setattr(_fake_os, "guarded_aggregate",
                            lambda **kw: self._agg_result())
        monkeypatch.setattr(_fake_os, "exact_total",
                            lambda *a, **k: 100)
        login(client, **ADMIN)
        res = client.get("/api/dns/summary?hours=24")
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["total"] == 100
        assert body["transactions"] == 100
        assert body["resolved"] == 80
        assert body["unresolved"] == 20
        assert body["resolved_pct"] == 80.0
        assert body["top_queried"][0]["domain"] == "evil-dga.test"
        assert body["top_clients"][0]["ip"] == "10.0.0.5"

    def test_ratio_denominator_ignores_capped_total(self, client, _fake_os,
                                                    monkeypatch):
        """v0.16.1 (P1-4) REGRESI rasio 9133%: pembilang NOERROR eksak
        (agg) tidak boleh dibagi hits.total yang ter-cap track_total_hits.
        NOERROR 80 dari 100 transaksi harus selalu 80%, bukan 800%."""
        monkeypatch.setattr(_fake_os, "guarded_aggregate",
                            lambda **kw: self._agg_result())
        monkeypatch.setattr(_fake_os, "exact_total",
                            lambda *a, **k: 100)
        login(client, **ADMIN)
        body = client.get("/api/dns/summary?hours=24").json()
        assert body["resolved_pct"] <= 100.0
        assert body["resolved_pct"] == 80.0

    def test_search_maps_transaction_fields(self, client, _fake_os,
                                            monkeypatch):
        def fake_search(**kw):
            return {"hits": {"total": {"value": 1, "relation": "eq"},
                             "hits": [{"_id": "e1", "_source": {
                                 "@timestamp": "2026-10-12T10:00:00Z",
                                 "source": {"ip": "10.0.0.5"},
                                 "destination": {"ip": "8.8.8.8"},
                                 "dns": {"query": "x.evil.test",
                                         "rcode": "NXDOMAIN",
                                         "type": "A",
                                         "answers": []},
                                 "campaign": "judi-online",
                             }}]}}

        monkeypatch.setattr(_fake_os, "guarded_search", fake_search)
        login(client, **ADMIN)
        res = client.post("/api/dns/search", json={
            "index": "ndr-zeek-dns-read",
            "time_from": "2026-10-01T00:00:00Z",
            "time_to": "2026-10-02T00:00:00Z"})
        assert res.status_code == 200, res.text
        hit = res.json()["hits"][0]
        assert hit["query"] == "x.evil.test"
        assert hit["rcode"] == "NXDOMAIN"
        assert hit["resolved"] is False  # NOERROR + answers gagal
        assert hit["client"] == "10.0.0.5"

    def test_alias_forced_to_dns(self, client, _fake_os, monkeypatch):
        captured = {}

        def fake_search(**kw):
            captured["alias"] = kw["alias"]
            return {"hits": {"total": {"value": 0, "relation": "eq"},
                             "hits": []}}

        monkeypatch.setattr(_fake_os, "guarded_search", fake_search)
        login(client, **ADMIN)
        client.post("/api/dns/search", json={"index": "ndr-alerts-read"})
        assert captured["alias"] == "ndr-zeek-dns-read"


# ============================================================ R9 TLS
class TestTlsInsights:
    def test_summary_buckets(self, client, _fake_os, monkeypatch):
        def fake_agg(**kw):
            return {"hits": {"total": {"value": 55, "relation": "eq"}},
                    "aggregations": {
                        "by_version": {"buckets": [
                            {"key": "TLSv1.3", "doc_count": 50}]},
                        "top_ja3": {"buckets": [
                            {"key": "a1b2c3", "doc_count": 10}]},
                        "top_sni": {"buckets": [
                            {"key": "cdn.example", "doc_count": 30}]},
                        "by_issuer": {"buckets": [
                            {"key": "Let's Encrypt", "doc_count": 40}]},
                    }}

        monkeypatch.setattr(_fake_os, "guarded_aggregate", fake_agg)
        monkeypatch.setattr(_fake_os, "exact_total", lambda *a, **k: 55)
        login(client, **ADMIN)
        res = client.get("/api/tls/summary")
        assert res.status_code == 200, res.text
        body = res.json()
        # v0.16.1 (P1-5): total = EKSAK fan-out 2 alias (bukan cap)
        assert body["total"] == 55
        assert body["versions"][0]["key"] == "TLSv1.3"


# ============================================================ R18 gambling
class TestGamblingView:
    def test_summary_uses_campaign_term(self, client, _fake_os,
                                        monkeypatch):
        captured = {}

        def fake_agg(**kw):
            captured["query"] = kw.get("query")
            return {"hits": {"total": {"value": 7, "relation": "eq"}},
                    "aggregations": {k: {"buckets": []}
                                     for k in (kw.get("aggs") or {})}}

        monkeypatch.setattr(_fake_os, "guarded_aggregate", fake_agg)
        login(client, **ADMIN)
        res = client.get("/api/gambling/summary")
        assert res.status_code == 200, res.text
        # kunci compliance: query TERKUNCI campaign judi-online
        assert captured["query"] == {"term": {"campaign": "judi-online"}}
        assert res.json()["total_events"] == 7

    def test_keywords_exposed_for_display(self, client):
        login(client, **ADMIN)
        res = client.get("/api/gambling/keywords")
        if res.status_code == 200:  # endpoint opsional utk UI
            assert "keywords" in res.json()


# ============================================================ R19 SSE
class TestMetricsLive:
    def test_stream_yields_formatted_sse_and_stops(self, _fake_os):
        from app.routers import metrics_live as m
        ticks = list(m._event_stream("admin", max_ticks=2))
        assert len(ticks) == 2
        for raw in ticks:
            assert raw.startswith("data: ")
            point = json.loads(raw[6:])
            for key in ("ts", "eps", "eps_by_engine", "queue_depth",
                        "queue_capacity", "backlog_seconds"):
                assert key in point
        # koneksi bersih: counter kembali 0 setelah generator selesai
        assert m._active_connections == 0

    def test_connection_cap_429(self, client, monkeypatch):
        from app.routers import metrics_live as m
        monkeypatch.setattr(m, "_active_connections", m.MAX_CONNECTIONS)
        login(client, **ADMIN)
        res = client.get("/api/metrics/live")
        assert res.status_code == 429

    def test_latest_health_degrades_empty(self, _fake_os):
        from app.routers.metrics_live import _latest_health
        assert _latest_health() == {}

    def test_count_5m_degrades_none(self, _fake_os):
        from app.routers.metrics_live import _count_5m
        assert _count_5m("ndr-alerts-read") is None


# ============================================================ R14/15 stats
class TestRuleStats:
    def _agg(self, suricata_hits=42, behaviour_hits=8):
        def fake_aggregate(alias, body):
            aggs = {}
            for name in body.get("aggs", {}):
                if name == "by_rule":
                    aggs[name] = {"buckets": [{
                        "key": "1000001", "doc_count": suricata_hits,
                        "sev": {"buckets": [
                            {"key": "high", "doc_count": 30}]},
                        "last_hit": {"value_as_string":
                                     "2026-10-19T02:00:00Z"},
                        "sample": {"hits": {"hits": [
                            {"_id": "al-1", "_source": {
                                "alert_id": "al-1"}}]}},
                        "sig_name": {"buckets": [
                            {"key": "ET MALWARE Beacon"}]},
                    }]}
                elif name == "by_type":
                    aggs[name] = {"buckets": [{
                        "key": "dga_suspected", "doc_count": behaviour_hits,
                        "sev": {"buckets": [
                            {"key": "medium", "doc_count": 8}]},
                        "last_hit": {"value_as_string":
                                     "2026-10-19T01:00:00Z"},
                        "sample": {"hits": {"hits": [
                            {"_id": "al-2"}]}},
                    }]}
            return {"hits": {"total": {"value": 50, "relation": "eq"}},
                    "aggregations": aggs}

        return fake_aggregate

    def test_refresh_upserts_and_is_idempotent(self, client, _fake_os,
                                               monkeypatch):
        from app.db import SessionLocal
        from app.models import RuleStat
        from app.rule_stats import refresh_rule_stats

        monkeypatch.setattr(_fake_os, "aggregate", self._agg())
        db = SessionLocal()
        try:
            n1 = refresh_rule_stats(db)
            n2 = refresh_rule_stats(db)
            assert n1 == n2 == 2
            rows = db.query(RuleStat).all()
            assert len(rows) == 2
            by_key = {r.rule_key: r for r in rows}
            assert by_key["1000001"].source == "suricata"
            assert by_key["1000001"].hits_24h == 42
            assert by_key["1000001"].hits_7d == 42
            assert by_key["1000001"].sev_max == "high"
            assert by_key["1000001"].sample_alert_id == "al-1"
            assert by_key["dga_suspected"].source == "pipeline"
            assert by_key["dga_suspected"].hits_24h == 8
            assert by_key["dga_suspected"].last_hit_at is not None
        finally:
            db.close()

    def test_stats_endpoint_shape(self, client, _fake_os, monkeypatch):
        from app.db import SessionLocal
        from app.models import RuleStat

        monkeypatch.setattr(_fake_os, "aggregate", self._agg())
        db = SessionLocal()
        try:
            db.add(RuleStat(rule_key="1000001", source="suricata",
                            signature="ET MALWARE Beacon", hits_24h=42,
                            hits_7d=1500, sev_max="high"))
            db.add(RuleStat(rule_key="dga_suspected", source="pipeline",
                            hits_24h=8, hits_7d=9))
            db.commit()
        finally:
            db.close()
        login(client, **ADMIN)
        res = client.get("/api/rules/stats")
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["total"] == 2
        assert body["noisy"] == 1  # 1500 > 1000
        top = body["items"][0]
        assert top["rule_key"] == "1000001"
        assert top["hits_24h"] == 42 and top["hits_7d"] == 1500
        assert top["noisy"] is True

    def test_list_rules_joins_stats_columns(self, client, _fake_os,
                                            monkeypatch):
        from app.db import SessionLocal
        from app.models import RuleStat
        from app.routers import rules as rules_router

        db = SessionLocal()
        try:
            db.add(RuleStat(rule_key="1000001", source="suricata",
                            hits_24h=10, hits_7d=60, sev_max="high"))
            db.commit()
        finally:
            db.close()
        fake_item = {"sid": 1000001, "msg": "ET MALWARE Beacon",
                     "enabled": True, "classtype": "malware",
                     "source": "suricata", "action": "alert",
                     "protocol": "ip", "priority": 1}
        monkeypatch.setattr(rules_router, "_load_rules", lambda db_: {
            "items": [dict(fake_item)], "skipped": 0, "file_exists": True})
        login(client, **ADMIN)
        res = client.get("/api/rules?limit=50")
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["stats_available"] is True
        hit = next(it for it in body["items"] if it["sid"] == 1000001)
        assert hit["hits_24h"] == 10
        assert hit["hits_7d"] == 60
        assert hit["sev_max"] == "high"
        assert hit["last_hit_at"] is None


# ============================================================ R13 SSO proxy
class TestArkimeSSOProxy:
    def test_admin_gets_503_when_secret_missing(self, client):
        login(client, **ADMIN)
        res = client.get("/api/arkime/sessions")
        assert res.status_code == 503
        assert "ARKIME_PROXY_SECRET" in res.json()["detail"]

    def test_auditor_denied_before_proxy(self, client, users_seeded):
        login(client, **VIEWER)
        res = client.get("/api/arkime/sessions")
        assert res.status_code in (401, 403)

    def test_router_registered(self, client):
        paths = {r.path for r in client.app.routes}
        assert any(p.startswith("/api/arkime/") for p in paths), paths


# ============================================================ wiring
class TestV0160Wiring:
    def test_new_routers_mounted(self, client):
        paths = {r.path for r in client.app.routes}
        for expected in ("/api/dns/summary", "/api/dns/search",
                         "/api/tls/summary", "/api/gambling/summary",
                         "/api/metrics/live"):
            assert expected in paths, f"missing {expected}"

    def test_version_is_0160(self, client):
        res = client.get("/api/meta")
        assert res.status_code == 200
        # v0.16.1: kontrak versi mengikuti rilis (bugfix lapangan)
        assert res.json()["version"] == "0.16.1"
