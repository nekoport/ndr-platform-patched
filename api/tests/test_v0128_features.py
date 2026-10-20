"""v0.12.8 regression tests: rules hot-path cache, DGA focus summary,
honest alert -> incident linkage."""

import pytest

from tests.conftest import login

ADMIN = {"username": "admin", "password": "bootstrap-admin-pass-01"}

RULES_FILE = """\
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Cobalt Strike Beacon Observed"; flow:established,to_server; classtype:trojan-activity; sid:2033715; rev:3;)
alert dns $HOME_NET any -> any any (msg:"ET MALWARE DGA Domain in DNS Lookup"; classtype:misc-activity; sid:2050244; rev:4;)
"""


def _setup_rules(monkeypatch, tmp_path, content=RULES_FILE):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)
    (rules_dir / "suricata.rules").write_text(content)
    from app.config import config
    monkeypatch.setattr(config, "rules_dir", str(rules_dir))
    monkeypatch.setattr(config, "rules_data_dir", str(tmp_path))
    monkeypatch.setattr(config, "suricata_conf",
                        str(tmp_path / "suricata.yaml"))
    return rules_dir


def _reset_rules_cache():
    """Module-level caches persist across tests - force a cold rebuild."""
    from app.routers import rules as rules_router
    rules_router._PARSED_CACHE = None
    rules_router._FILES_SIG = None
    rules_router._ITEMS_CACHE = None
    rules_router._ITEMS_SIG = None


@pytest.fixture(autouse=True)
def _cold_rules_cache():
    _reset_rules_cache()
    yield
    _reset_rules_cache()


# ------------------------------------------------- rules hot path (fix 2)

def test_rules_cache_hit_skips_meta_sync(client, monkeypatch, tmp_path):
    """Second list call must serve the merged-items cache: no re-parse,
    no second 53k-row meta sync, identical payload."""
    _setup_rules(monkeypatch, tmp_path)
    login(client, **ADMIN)

    calls = {"sync": 0}
    from app.routers import rules as rules_router
    orig_sync = rules_router._sync_meta

    def counting_sync(db, items, enabled_sids):
        calls["sync"] += 1
        return orig_sync(db, items, enabled_sids)

    monkeypatch.setattr(rules_router, "_sync_meta", counting_sync)

    r1 = client.get("/api/rules")
    assert r1.status_code == 200
    first = r1.json()
    assert calls["sync"] == 1

    r2 = client.get("/api/rules")
    assert r2.status_code == 200
    second = r2.json()
    # cache hit: no second meta sync, identical page
    assert calls["sync"] == 1
    assert second["items"] == first["items"]
    assert second["total"] == first["total"] == 2

    # summary also runs on the shared cache
    r3 = client.get("/api/rules/summary")
    assert r3.status_code == 200
    assert calls["sync"] == 1
    assert r3.json()["total"] == 2


def test_rules_custom_create_invalidates_items_cache(client, monkeypatch,
                                                     tmp_path):
    """Creating a custom rule must appear in the next list call even on a
    warm file cache (custom-rule signature invalidation)."""
    _setup_rules(monkeypatch, tmp_path)
    login(client, **ADMIN)

    before = client.get("/api/rules").json()
    assert all(it["source"] != "local" for it in before["items"])

    text = ('alert http $HOME_NET any -> $EXTERNAL_NET 80 '
            '(msg:"NDRLAB test custom"; flow:established,to_server; '
            'http.user_agent; content:"x"; classtype:attempted-recon; '
            'sid:1000001; rev:1;)')
    r = client.post("/api/rules/custom",
                    json={"rule_text": text})
    assert r.status_code == 201, r.text

    after = client.get("/api/rules").json()
    sids = {it["sid"]: it for it in after["items"]}
    assert 1000001 in sids
    assert sids[1000001]["source"] == "local"
    assert after["total"] == before["total"] + 1


# --------------------------------------------- DGA focus summary (fix 1)

def test_dga_summary_shape_and_filter(client, monkeypatch, _fake_os):
    login(client, **ADMIN)
    captured = {}

    def fake_aggregate(**kw):
        captured.update(kw)
        return {
            "hits": {"total": {"value": 3, "relation": "eq"}},
            "aggregations": {
                "by_source": {"buckets": [
                    {"key": "192.168.4.55", "doc_count": 3}]},
                "timeline": {"buckets": [
                    {"key_as_string": "2026-10-14T00:00:00Z",
                     "doc_count": 2},
                    {"key_as_string": "2026-10-14T01:00:00Z",
                     "doc_count": 1}]},
                "newest": {"value": 1.0,
                           "value_as_string": "2026-10-14T01:00:00Z"},
            },
        }

    monkeypatch.setattr(_fake_os, "guarded_aggregate", fake_aggregate)

    r = client.get("/api/alerts/dga/summary?hours=24")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["total"] == 3
    assert data["hours"] == 24
    assert data["alert_types"] == ["dga_suspected", "dns_nxdomain_burst"]
    assert data["sources"][0]["key"] == "192.168.4.55"
    assert len(data["timeline"]) == 2
    assert data["last_seen"] == "2026-10-14T01:00:00Z"
    # the aggregation must carry the DGA-type terms filter + bounded window
    terms = captured["query"]["bool"]["filter"][0]["terms"]
    assert terms["alert_type"] == ["dga_suspected", "dns_nxdomain_burst"]
    assert captured["time_from"] is not None
    # aggregation-only: no documents requested
    assert "size" not in captured or captured.get("aggs")


def test_dga_summary_hourly_vs_daily_interval(client, monkeypatch, _fake_os):
    login(client, **ADMIN)
    intervals = []

    def fake_aggregate(**kw):
        intervals.append(kw["aggs"]["timeline"]["date_histogram"]
                         ["fixed_interval"])
        return {"hits": {"total": {"value": 0, "relation": "eq"}},
                "aggregations": {k: {"buckets": []}
                                 for k in kw.get("aggs", {})}}

    monkeypatch.setattr(_fake_os, "guarded_aggregate", fake_aggregate)

    assert client.get("/api/alerts/dga/summary?hours=24").status_code == 200
    assert client.get("/api/alerts/dga/summary?hours=336").status_code == 200
    assert intervals == ["1h", "1d"]


def test_dga_summary_validation_and_502(client, monkeypatch, _fake_os):
    login(client, **ADMIN)
    # hours outside [1, 336] -> 422
    assert client.get("/api/alerts/dga/summary?hours=0").status_code == 422
    assert client.get("/api/alerts/dga/summary?hours=400").status_code == 422
    # backend down -> honest 502 (never a fabricated empty 200)
    def boom(**kw):
        raise RuntimeError("opensearch down")
    monkeypatch.setattr(_fake_os, "guarded_aggregate", boom)
    r = client.get("/api/alerts/dga/summary?hours=24")
    assert r.status_code == 502
    assert "Search backend unavailable" in r.json()["detail"]


# ------------------------------------- alert -> incident linkage (fix 5)

def _seed_incident_with_alert_evidence(alert_id: str, incident_id: str):
    from app.db import SessionLocal
    from app.models import Incident, IncidentEvidence
    db = SessionLocal()
    db.add(Incident(
        id=incident_id, title=f"Reconstruction for {alert_id}",
        status="open", severity="medium", confidence=55,
        first_seen="2026-10-14T00:00:00Z",
        last_seen="2026-10-14T01:00:00Z",
        outcome={"label": "attempted"},
        evidence_count=1, signal_count=1,
    ))
    db.add(IncidentEvidence(
        incident_id=incident_id, ts="2026-10-14T01:00:00Z",
        kind="alert_ref", source="dga_suspected",
        ref_index="ndr-alerts-read", ref_id=alert_id,
        title="Possible DGA queries", severity="medium", phase="c2",
    ))
    db.commit()
    db.close()


def test_related_incident_returns_recorded_links(client):
    login(client, **ADMIN)
    _seed_incident_with_alert_evidence("alert-abc-1", "inc-rel-test-1")

    r = client.get("/api/alerts/alert-abc-1/related-incident")
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) == 1
    assert items[0]["incident_id"] == "inc-rel-test-1"
    assert items[0]["status"] == "open"
    assert items[0]["outcome_label"] == "attempted"

    # an alert that no incident recorded -> honest empty list
    r2 = client.get("/api/alerts/alert-unknown/related-incident",
                   )
    assert r2.status_code == 200
    assert r2.json()["items"] == []


def test_related_incident_requires_view_permission(client, users_seeded):
    login(client, username="viewer", password="Password-123456")
    r = client.get("/api/alerts/whatever/related-incident")
    assert r.status_code == 200  # auditor holds view permission
