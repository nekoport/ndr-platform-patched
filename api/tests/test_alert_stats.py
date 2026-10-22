"""v0.12.6 Alert Center: /api/alerts/stats aggregations + server-side
pagination contract for /api/alerts/search (from/sort passthrough)."""

from tests.conftest import login

ADMIN = {"username": "admin", "password": "bootstrap-admin-pass-01"}


def _stub_stats(monkeypatch, fake):
    """Realistic aggregation payloads on the FakeOS instance
    (the autouse _fake_os fixture monkeypatches app.os_client._client)."""
    fake_calls = {"aggregate": [], "search": []}

    def fake_aggregate(alias, body):
        fake_calls["aggregate"].append((alias, body))
        aggs = {}
        for name in body.get("aggs", {}):
            if name == "by_severity":
                aggs[name] = {"buckets": [
                    {"key": "critical", "doc_count": 2},
                    {"key": "high", "doc_count": 10},
                    {"key": "medium", "doc_count": 33},
                ]}
            elif name == "by_status":
                aggs[name] = {"buckets": [{"key": "new", "doc_count": 40}]}
            elif name == "by_outcome":
                aggs[name] = {"buckets": [
                    {"key": "attempted", "doc_count": 45}]}
            elif name == "by_mitre":
                aggs[name] = {"buckets": [
                    {"key": "T1110", "doc_count": 12},
                    {"key": "T1595", "doc_count": 7},
                ]}
        return {"hits": {"total": {"value": 45, "relation": "eq"}},
                "aggregations": aggs}

    def fake_guarded_search(**kw):
        fake_calls["search"].append(kw)
        return {"hits": {"hits": [
            {"_id": "a1", "_source": {
                "last_seen": "2026-10-12T10:00:00Z", "severity": "high",
                "risk_score": 80, "title": "ET MALWARE Beacon",
                "mitre": [{"technique_id": "T1110",
                           "technique": "Brute Force"}]}},
            {"_id": "a2", "_source": {
                "last_seen": "2026-10-12T09:00:00Z", "severity": "medium",
                "risk_score": 40, "title": "ET SCAN Nmap",
                "mitre": [{"technique_id": "T1595",
                           "technique": "Active Scanning"}]}},
        ]}}

    monkeypatch.setattr(fake, "aggregate", fake_aggregate)
    monkeypatch.setattr(fake, "guarded_search", fake_guarded_search)
    return fake_calls


def test_alert_stats_aggregations(client, monkeypatch, _fake_os):
    calls = _stub_stats(monkeypatch, _fake_os)
    login(client, **ADMIN)
    res = client.post("/api/alerts/stats", json={"index": "ndr-alerts-read"})
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 45
    # v0.16.0 (bug A6 fix): kontrak UI = LIST {key,count} urut count desc;
    # bentuk dict 0.13.0 dipindah ke body["aggregations"] agar dua
    # generasi kontrak aman berdampingan.
    assert body["severity"][0] == {"key": "medium", "count": 33}
    assert {b["key"]: b["count"] for b in body["severity"]}["critical"] == 2
    assert {b["key"]: b["count"] for b in body["severity"]}["high"] == 10
    assert body["status"][0] == {"key": "new", "count": 40}
    assert body["outcome"][0] == {"key": "attempted", "count": 45}
    # bentuk dict lama masih tersedia di bawah aggregations.*
    assert body["aggregations"]["severity"]["critical"] == 2
    assert body["new_count"] == 40
    assert body["critical_count"] == 2
    assert body["mitre"][0] == ["T1110", "Brute Force", 12]
    assert len(body["scatter"]) == 2
    assert body["scatter"][0]["title"] == "ET MALWARE Beacon"
    assert body["sample_size"] == 2
    # scatter sample is a bounded newest-first search, never the full set
    assert calls["search"] and calls["search"][0]["size"] == 300


def test_alert_stats_degrades_on_os_error(client, monkeypatch, _fake_os):
    def boom(alias, body):
        raise RuntimeError("opensearch down")

    monkeypatch.setattr(_fake_os, "aggregate", boom)
    login(client, **ADMIN)
    res = client.post("/api/alerts/stats", json={"index": "ndr-alerts-read"})
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 0 and body["mitre"] == []
    assert "unavailable" in body.get("note", "")


def test_alerts_search_passes_pagination(client, monkeypatch, _fake_os):
    """The UI paginates server-side now - the router must forward
    from/sort instead of silently truncating at 500."""
    captured = {}

    def fake_guarded_search(**kw):
        captured.update(kw)
        return {"hits": {"total": {"value": 1234, "relation": "gte"},
                         "hits": []}}

    monkeypatch.setattr(_fake_os, "guarded_search", fake_guarded_search)
    login(client, **ADMIN)
    res = client.post("/api/alerts/search", json={
        "index": "ndr-alerts-read", "size": 25, "from": 50,
        "sort": [{"last_seen": {"order": "desc"}}],
    })
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 1234
    assert body["relation"] == "gte"
    assert captured["from_"] == 50
    assert captured["size"] == 25
    assert captured["sort"] == [{"last_seen": {"order": "desc"}}]
