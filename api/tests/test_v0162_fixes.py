"""v0.16.2 regression pins - hasil verifikasi 0.16.1 (LAPORAN-VERIFIKASI).

BUG-0161-01: agregasi `engines` nested di by_ts (kontrak timeline baru).
BUG-0161-02: stats overview menyediakan alert_daily_7d + split severity.
BUG-0161-05: guard hasil parsial shard + agregasi `.keyword` untuk index
             lama ber-mapping text.
BUG-0161-06: fallback JWT secret PERSISTEN (file), bukan ephemeral.
BUG-0161-07: normalisasi branding legacy ("Ever SEEN" -> "NDR Console").
"""

from __future__ import annotations

import pytest

from app.os_client import DSLValidationError, OSClient


class _StubInnerClient:
    """Stand-in untuk client OpenSearch di dalam OSClient (level method)."""

    def __init__(self, search_result=None, field_caps=None, alias_members=None):
        self.search_result = search_result if search_result is not None else {}
        self.field_caps_result = field_caps or {}
        self.alias_members = alias_members or {}
        self.search_calls: list[dict] = []

    def search(self, index=None, body=None, request_timeout=None):
        self.search_calls.append({"index": index, "body": body})
        if isinstance(self.search_result, Exception):
            raise self.search_result
        return self.search_result

    def field_caps(self, index=None, fields=None):
        return self.field_caps_result

    class _Indices:
        """mirror client.indices.get_alias yang dipakai resolve_alias_indices"""

        def __init__(self, alias_members):
            self.alias_members = alias_members

        def get_alias(self, name=None):
            return self.alias_members

    @property
    def indices(self):
        return _StubInnerClient._Indices(self.alias_members)


def _client(stub: _StubInnerClient) -> OSClient:
    c = OSClient("http://localhost:9200")
    c.client = stub
    return c


# ------------------------------------------------- BUG-0161-05: shard guard
def test_guarded_aggregate_rejects_partial_shards():
    stub = _StubInnerClient(search_result={
        "_shards": {"total": 10, "successful": 9, "failed": 1,
                    "failures": [{"index": "ndr-zeek-dns-2026.10.14",
                                  "shard": 0,
                                  "reason": {"type": "illegal_argument_exception",
                                             "reason": "Fielddata is disabled on text fields"}}]},
        "hits": {"total": {"value": 5, "relation": "eq"}},
        "aggregations": {"by_ts": {"buckets": []}},
    })
    c = _client(stub)
    aggs = {"by_ts": {"date_histogram": {"field": "@timestamp"}}}
    with pytest.raises(DSLValidationError) as exc:
        c.guarded_aggregate(alias="ndr-events-read", query=None, aggs=aggs,
                            time_from="2026-10-19T00:00:00Z", time_to=None)
    assert "1 shard gagal" in str(exc.value)

    # allow_partial=True: diterima TAPI diberi penanda eksplisit
    res = c.guarded_aggregate(alias="ndr-events-read", query=None, aggs=aggs,
                              time_from="2026-10-19T00:00:00Z", time_to=None,
                              allow_partial=True)
    assert res["_ndr_partial_shards"]["failed"] == 1


def test_guarded_aggregate_clean_shards_pass():
    stub = _StubInnerClient(search_result={
        "_shards": {"total": 10, "successful": 10, "failed": 0},
        "hits": {"total": {"value": 5, "relation": "eq"}},
        "aggregations": {"by_ts": {"buckets": []}},
    })
    c = _client(stub)
    res = c.guarded_aggregate(alias="ndr-events-read", query=None,
                              aggs={"by_ts": {"date_histogram":
                                              {"field": "@timestamp"}}},
                              time_from="2026-10-19T00:00:00Z", time_to=None)
    assert "_ndr_partial_shards" not in res


def test_guarded_aggregate_concrete_must_be_alias_member():
    stub = _StubInnerClient(search_result={
        "_shards": {"failed": 0},
        "hits": {"total": {"value": 0, "relation": "eq"}},
        "aggregations": {}})
    stub.alias_members = {"ndr-zeek-dns-2026.10.22": {"aliases": {}}}
    c = _client(stub)
    aggs = {"by_ts": {"date_histogram": {"field": "@timestamp"}}}

    # anggota alias -> diterima, search menjalankan daftar konkret
    c.guarded_aggregate(alias="ndr-events-read", query=None, aggs=aggs,
                        time_from=None, time_to=None,
                        concrete=["ndr-zeek-dns-2026.10.22"])
    assert stub.search_calls[-1]["index"] == ["ndr-zeek-dns-2026.10.22"]

    # index di luar alias -> DITOLAK (tidak ada penyelundupan index)
    with pytest.raises(DSLValidationError):
        c.guarded_aggregate(alias="ndr-events-read", query=None, aggs=aggs,
                            time_from=None, time_to=None,
                            concrete=["ndr-secret-index-2026.01.01"])


# --------------------------------- BUG-0161-05: grup agregasi keyword legacy
def test_keyword_groups_split_legacy_and_new():
    stub = _StubInnerClient(
        field_caps={
            "indices": ["ndr-suricata-2026.10.14",
                        "ndr-zeek-dns-2026.10.22"],
            "fields": {
                "source_engine": {
                    "text": {"type": "text",
                             "indices": ["ndr-suricata-2026.10.14"]},
                    "keyword": {"type": "keyword",
                                "indices": ["ndr-zeek-dns-2026.10.22"]},
                },
                "source_engine.keyword": {
                    "keyword": {"type": "keyword",
                                "indices": ["ndr-suricata-2026.10.14"]},
                },
            }},
        alias_members={"ndr-suricata-2026.10.14": {"aliases": {}},
                       "ndr-zeek-dns-2026.10.22": {"aliases": {}}})
    c = _client(stub)
    groups, excluded = c.keyword_aggregation_groups("ndr-events-read",
                                                    "source_engine")
    assert groups == [("source_engine", ["ndr-zeek-dns-2026.10.22"]),
                      ("source_engine.keyword", ["ndr-suricata-2026.10.14"])]
    assert excluded == []


def test_keyword_groups_excludes_text_without_keyword_subfield():
    stub = _StubInnerClient(
        field_caps={
            "indices": ["ndr-suricata-2026.10.14"],
            "fields": {
                "source_engine": {
                    "text": {"type": "text",
                             "indices": ["ndr-suricata-2026.10.14"]},
                },
                # TANPA source_engine.keyword -> tidak bisa diagregasi
            }},
        alias_members={"ndr-suricata-2026.10.14": {"aliases": {}}})
    c = _client(stub)
    groups, excluded = c.keyword_aggregation_groups("ndr-events-read",
                                                    "source_engine")
    # tidak ada kelompok konkret aman -> fallback alias-level (perilaku
    # lama); index bermasalah TETAP dilaporkan sebagai excluded
    assert groups == [("source_engine", [])]
    assert excluded == ["ndr-suricata-2026.10.14"]


def test_keyword_groups_rejects_index_outside_alias():
    stub = _StubInnerClient(
        field_caps={"indices": ["ndr-evil-2026.01.01"], "fields": {
            "source_engine": {"keyword": {"type": "keyword",
                                          "indices": ["ndr-evil-2026.01.01"]}}}},
        alias_members={})  # alias kosong
    c = _client(stub)
    groups, excluded = c.keyword_aggregation_groups("ndr-events-read",
                                                    "source_engine")
    # index di luar whitelist tidak pernah dikembalikan
    assert all(not g[1] for g in groups)
    assert excluded == []


# --------------------------------------------- BUG-0161-02: severity split
def test_stats_overview_alert_daily_has_severity_split(client, _fake_os, monkeypatch):
    """/api/stats/overview mengirim alert_daily_7d dengan split severity
    per hari (dipakai chart stacked severity Reports)."""
    def fake_aggregate(alias, body):
        assert alias == "ndr-alerts-read"
        daily = body["aggs"]["daily"]
        assert "aggs" in daily and "sev" in daily["aggs"]
        return {"aggregations": {"daily": {"buckets": [
            {"key_as_string": "2026-10-21T00:00:00Z", "doc_count": 10,
             "sev": {"buckets": [
                 {"key": "critical", "doc_count": 2},
                 {"key": "high", "doc_count": 3},
                 {"key": "medium", "doc_count": 4},
                 {"key": "low", "doc_count": 1}]}},
            {"key_as_string": "2026-10-22T00:00:00Z", "doc_count": 0,
             "sev": {"buckets": []}},
        ]}}}

    monkeypatch.setattr(_fake_os, "aggregate", fake_aggregate)
    from tests.conftest import login
    r0 = login(client, username="admin", password="bootstrap-admin-pass-01")
    assert r0.status_code == 200
    r = client.get("/api/stats/overview")
    assert r.status_code == 200
    body = r.json()
    daily = body["alert_daily_7d"]
    assert daily[0]["alerts"] == 10
    assert daily[0]["critical"] == 2 and daily[0]["high"] == 3
    assert daily[0]["medium"] == 4 and daily[0]["low"] == 1
    assert daily[1]["alerts"] == 0
    assert body["alerts_7d"] == 10


# ------------------------------------------------- BUG-0161-06: JWT persisten
def test_jwt_secret_generated_and_persisted(tmp_path, monkeypatch):
    from app import config as cfg_mod

    secret_file = tmp_path / "jwt-secret.key"
    monkeypatch.setenv("JWT_SECRET_FILE", str(secret_file))
    monkeypatch.setattr(cfg_mod.Config, "jwt_secret", "")
    cfg_mod._harden_jwt_secret()
    first = cfg_mod.Config.jwt_secret
    assert len(first) >= 32
    assert secret_file.exists()
    assert secret_file.read_text(encoding="utf-8").strip() == first

    # pemanggilan berikutnya (simulasi worker/restart lain) memakai
    # secret yang SAMA dari file - tidak ada lagi 401 acak antar-worker
    monkeypatch.setattr(cfg_mod.Config, "jwt_secret", "")
    cfg_mod._harden_jwt_secret()
    assert cfg_mod.Config.jwt_secret == first


def test_jwt_strong_env_secret_wins_without_file(tmp_path, monkeypatch):
    from app import config as cfg_mod

    secret_file = tmp_path / "unused.key"
    monkeypatch.setenv("JWT_SECRET_FILE", str(secret_file))
    monkeypatch.setattr(cfg_mod.Config, "jwt_secret", "x" * 40)
    cfg_mod._harden_jwt_secret()
    assert cfg_mod.Config.jwt_secret == "x" * 40
    assert not secret_file.exists()


# ------------------------------------------- BUG-0161-07: branding legacy
def test_normalize_legacy_branding(tmp_path, monkeypatch):
    from app.db import Base, SessionLocal, engine
    from app.main import _normalize_legacy_branding
    from app.models import SystemSetting

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        db.query(SystemSetting).filter(SystemSetting.key == "system").delete()
        db.add(SystemSetting(key="system",
                             value={"name": "Ever SEEN",
                                    "tagline": "x"}))
        db.commit()
    finally:
        db.close()

    _normalize_legacy_branding()

    db = SessionLocal()
    try:
        row = db.get(SystemSetting, "system")
        assert row.value["name"] == "NDR Console"
        assert row.value["tagline"] == "x"  # field lain dipertahankan
    finally:
        db.close()


def test_normalize_branding_respects_custom_name():
    from app.db import Base, SessionLocal, engine
    from app.main import _normalize_legacy_branding
    from app.models import SystemSetting

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # bersihkan state dari test branding lain (primary key sama)
        db.query(SystemSetting).filter(SystemSetting.key == "system").delete()
        db.add(SystemSetting(key="system",
                             value={"name": "SOC Pusat Kustom"}))
        db.commit()
    finally:
        db.close()

    _normalize_legacy_branding()

    db = SessionLocal()
    try:
        row = db.get(SystemSetting, "system")
        # nama kustom operator dihormati - TIDAK ditimpa
        assert row.value["name"] == "SOC Pusat Kustom"
    finally:
        db.close()
