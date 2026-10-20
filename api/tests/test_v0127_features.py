"""v0.12.7 feature tests: /api/alerts/stats, rule-source taxonomy,
Zeek policy inventory, relationship render caps, geo pair cap.

Covers the VM feedback batch:
  * Alert Center header charts must be EXACT for any result size
    (POST /api/alerts/stats, aggregation-only, guarded like /search)
  * Rule Manager must separate LOCAL vs SURICATA rules (source field +
    server-side source filter) and inventory ZEEK scripts read-only
  * the merged relationship graph must be pruned to the most significant
    entities with the trim visible in meta (never silent data loss)
  * geo flows respond trimmed to top-volume pairs (default 120)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from conftest import login  # noqa: E402

ADMIN = {"username": "admin", "password": "bootstrap-admin-pass-01"}

VALID_LOCAL_RULE = ("alert http $EXTERNAL_NET any -> $HOME_NET 80 "
                    "(msg:\"NDRLAB v0127 local source probe\"; "
                    "flow:established,to_server; http.user_agent; "
                    "content:\"ndr-0127-agent\"; "
                    "classtype:attempted-recon; sid:1000127; rev:1;)")


def _login(client):
    res = login(client, **ADMIN)
    assert res.status_code == 200, res.text


# ------------------------------------------------------------------ stats
def test_alert_stats_shape_and_guard(client, _fake_os, monkeypatch):
    """Stats returns EXACT buckets (v0.13.0 dict form) and never leaks
    documents: aggregation runs with size 0, the scatter is a bounded
    newest-first SAMPLE, never the full set."""
    captured: dict = {}

    def _agg(alias, body):
        captured["alias"] = alias
        captured["body"] = body
        return {
            "hits": {"total": {"value": 1234, "relation": "eq"}},
            "aggregations": {
                "by_severity": {"buckets": [
                    {"key": "high", "doc_count": 900},
                    {"key": "critical", "doc_count": 334},
                ]},
                "by_status": {"buckets": [{"key": "new", "doc_count": 1200}]},
                "by_outcome": {"buckets": [
                    {"key": "attempted", "doc_count": 1000},
                ]},
                "by_mitre": {"buckets": [{"key": "T1110", "doc_count": 12}]},
            },
        }

    monkeypatch.setattr(_fake_os, "aggregate", _agg)
    _login(client)
    res = client.post("/api/alerts/stats", json={
        "index": "ndr-alerts-read",
        "query": {"term": {"severity": "high"}},
        "time_from": "2026-10-01T00:00:00Z",
        "time_to": "2026-10-02T00:00:00Z",
    })
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["total"] == 1234
    assert body["severity"]["high"] == 900
    assert body["severity"]["critical"] == 334
    assert body["status"]["new"] == 1200
    assert body["outcome"]["attempted"] == 1000
    assert body["new_count"] == 1200
    assert body["critical_count"] == 334
    assert body["mitre"][0][0] == "T1110"
    # aggregation-only: size 0 -> documents NEVER leak through /stats
    assert captured["body"]["size"] == 0
    # scatter is a bounded sample, sample_size matches
    assert isinstance(body["scatter"], list)
    assert body["sample_size"] == len(body["scatter"])


def test_alert_stats_degrades_when_backend_down(client, _fake_os,
                                                monkeypatch):
    """v0.13.0: a dead backend DEGRADES the header (200 + honest note)
    instead of 502-ing the whole Alert Center view."""
    def _boom(alias, body):
        raise RuntimeError("opensearch down")

    monkeypatch.setattr(_fake_os, "aggregate", _boom)
    _login(client)
    res = client.post("/api/alerts/stats", json={})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["total"] == 0 and body["mitre"] == []
    assert "unavailable" in body.get("note", "")


def test_alert_stats_rejects_dangerous_dsl(client, _fake_os):
    """Same query guard as /search - script DSL never reaches the backend."""
    _login(client)
    res = client.post("/api/alerts/stats", json={
        "query": {"script": {"script": "true"}},
    })
    assert res.status_code == 400, res.text


# ------------------------------------------------- rule source taxonomy
def test_rules_list_has_source_field(client, _fake_os):
    """Every rule row carries the source taxonomy (local vs suricata)."""
    _login(client)
    res = client.post("/api/rules/custom", json={"rule_text": VALID_LOCAL_RULE})
    assert res.status_code == 201, res.text
    res = client.get("/api/rules", params={"limit": 50})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["total"] >= 1
    for it in body["items"]:
        assert it["source"] in ("local", "suricata")
    created = [it for it in body["items"] if it["sid"] == 1000127]
    assert created and created[0]["source"] == "local"


def test_rules_source_filter_local_vs_suricata(client, _fake_os):
    _login(client)
    # idempotent create (the DB may already hold SID 1000127 from the
    # previous test - both tests share the app-scoped sqlite)
    exists = client.get("/api/rules/custom").json()
    if not any(r["sid"] == 1000127 for r in exists["items"]):
        res = client.post("/api/rules/custom",
                          json={"rule_text": VALID_LOCAL_RULE})
        assert res.status_code == 201, res.text

    local = client.get("/api/rules", params={"source": "local"}).json()
    assert local["total"] >= 1
    assert all(it["source"] == "local" for it in local["items"])
    assert any(it["sid"] == 1000127 for it in local["items"])

    et = client.get("/api/rules", params={"source": "suricata"}).json()
    assert all(it["source"] == "suricata" for it in et["items"])
    assert all(it["sid"] != 1000127 for it in et["items"])

    summary = client.get("/api/rules/summary").json()
    assert summary["by_source"]["local"] >= 1
    assert summary["by_source"]["suricata"] == et["total"]


def test_rules_source_filter_rejects_unknown(client, _fake_os):
    _login(client)
    res = client.get("/api/rules", params={"source": "zeek"})
    assert res.status_code == 422  # zeek is a SEPARATE endpoint, not a filter


# ---------------------------------------------------- zeek policy inventory
def test_zeek_inventory_parses_local_conf(client, _fake_os, monkeypatch,
                                          tmp_path):
    conf = tmp_path / "local.zeek"
    conf.write_text(
        "# sensor policy\n"
        "@load base/frameworks/notice\n"
        "@load policy/tuning/defaults\n"
        "\n"
        "@load-sigs ./my-signatures.sig\n"
        "redef ignore_checksums = T;\n"
        "@unknown-directive\n",
        encoding="utf-8")
    from app.config import config
    monkeypatch.setattr(config, "zeek_local_conf", str(conf))
    _login(client)
    res = client.get("/api/rules/zeek")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["exists"] is True
    assert body["total_lines"] == 7
    assert body["comment_lines"] == 1
    assert body["load_count"] == 2
    kinds = {it["kind"] for it in body["items"]}
    assert kinds == {"load", "load-sigs", "redef", "directive"}


def test_zeek_inventory_missing_file_is_graceful(client, _fake_os,
                                                 monkeypatch, tmp_path):
    from app.config import config
    monkeypatch.setattr(config, "zeek_local_conf",
                        str(tmp_path / "nope.zeek"))
    _login(client)
    res = client.get("/api/rules/zeek")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["exists"] is False
    assert body["items"] == []
    assert "not readable" in body["note"]


# --------------------------------------------------- relationship render cap
def test_relationship_payload_pruned_to_140(client, _fake_os):
    """The merged graph is trimmed to the most significant 140 entities;
    the trim is honest (meta.full_counts + edges filtered to survivors)."""
    from app import graph as graphsvc

    payload = {
        "nodes": [{"key": f"ip:10.0.0.{i}", "label": f"10.0.0.{i}",
                   "kind": "ip", "evidence_count": i, "degree": 2,
                   "ti_match": i % 10 == 0, "incident_ids": ["inc-1"]}
                  for i in range(200)],
        "edges": [{"src": f"ip:10.0.0.{i}", "dst": f"ip:10.0.0.{i + 1}",
                   "relation": "connected_to", "evidence_count": 1,
                   "inferred": False}
                  for i in range(199)],
        "campaigns": [],
        "meta": {},
    }
    out = graphsvc.prune_relationship_payload(payload)
    assert len(out["nodes"]) == graphsvc.RELATIONSHIP_MAX_NODES == 140
    assert len(out["edges"]) <= 500
    # every edge endpoint survived the trim
    keys = {n["key"] for n in out["nodes"]}
    assert all(e["src"] in keys and e["dst"] in keys for e in out["edges"])
    # TI-matched nodes are prioritised when trimming
    assert sum(1 for n in out["nodes"] if n["ti_match"]) == 20
    assert out["meta"]["full_counts"]["nodes"] == 200
    assert out["meta"]["pruned"] is True


# --------------------------------------------------------------- geo cap
def test_geo_endpoint_trims_to_top_pairs(client, _fake_os, monkeypatch):
    captured: dict = {}

    def _geo(aggregate, db, hours=24, max_pairs=400):
        captured["hours"] = hours
        captured["max_pairs"] = max_pairs
        return {"hours": hours, "geo_enabled": True,
                "flows": [], "unmapped": [], "generated_at": "t"}

    from app.routers import graph as graph_router
    monkeypatch.setattr(graph_router.graphsvc, "geo_flows_from_events", _geo)
    _login(client)
    res = client.get("/api/graph/geo")
    assert res.status_code == 200, res.text
    assert captured["max_pairs"] == 120  # v0.12.7 default top-volume cap

    res = client.get("/api/graph/geo", params={"max_pairs": 15})
    assert res.status_code == 200, res.text
    assert captured["max_pairs"] == 15
