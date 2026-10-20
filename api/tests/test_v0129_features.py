"""v0.12.9 regression tests: focused alert relationship endpoint
(Alert Center -> Threat Map jump fix) and per-IOC activity feed
(Threat Intel detail completeness)."""

import pytest

from tests.conftest import login

ADMIN = {"username": "admin", "password": "bootstrap-admin-pass-01"}


# ------------------------------------- focused alert relationship (item 3)

def _seed_incident_graph(incident_id: str, alert_id: str):
    from app.db import SessionLocal
    from app.models import (Incident, IncidentEdge, IncidentEvidence,
                            IncidentNode)
    db = SessionLocal()
    db.add(Incident(
        id=incident_id, title=f"Recon chain {alert_id}",
        status="open", severity="high", confidence=72,
        first_seen="2026-10-14T00:00:00Z",
        last_seen="2026-10-14T02:00:00Z",
        outcome={"label": "suspected_success"},
        entity_count=2, edge_count=1, evidence_count=1, signal_count=1,
    ))
    db.add(IncidentNode(
        incident_id=incident_id, kind="ip", key="ip:10.0.105.250",
        label="10.0.105.250", role="compromised_host", phase="recon",
        confidence=72, first_seen="2026-10-14T00:00:00Z",
        last_seen="2026-10-14T02:00:00Z", attrs={},
    ))
    db.add(IncidentNode(
        incident_id=incident_id, kind="ip", key="ip:203.0.113.9",
        label="203.0.113.9", role="attacker", phase="recon",
        confidence=72, first_seen="2026-10-14T00:00:00Z",
        last_seen="2026-10-14T02:00:00Z", attrs={},
    ))
    db.add(IncidentEdge(
        incident_id=incident_id, src_key="ip:203.0.113.9",
        dst_key="ip:10.0.105.250", relation="port_scan", phase="recon",
        inferred=False, first_seen="2026-10-14T00:00:00Z",
        last_seen="2026-10-14T02:00:00Z", evidence_count=7, confidence=72,
    ))
    db.add(IncidentEvidence(
        incident_id=incident_id, ts="2026-10-14T01:00:00Z",
        kind="alert_ref", source="portscan_suspected",
        ref_index="ndr-alerts-read", ref_id=alert_id,
        title="Port scan", severity="high", phase="recon",
    ))
    db.commit()
    db.close()


def test_relationship_incident_basis(client, _fake_os, monkeypatch):
    """An alert recorded as incident evidence returns THAT incident's
    subgraph (basis: incident) - the focused jump must render the attack
    chain of this alert, not the global campaign graph."""
    _seed_incident_graph("inc-rel-v129", "alert-abc-9")
    monkeypatch.setattr(
        _fake_os, "search_alert_doc",
        lambda alert_id: {"_id": "os-id-9", "_source": {
            "alert_id": alert_id, "title": "Port scan",
            "alert_type": "portscan_suspected", "severity": "high",
            "status": "new"}})
    login(client, **ADMIN)
    r = client.get("/api/alerts/alert-abc-9/relationship")
    assert r.status_code == 200
    body = r.json()
    assert body["basis"] == "incident"
    assert body["incidents"][0]["incident_id"] == "inc-rel-v129"
    keys = {n["key"] for n in body["graph"]["nodes"]}
    assert {"ip:10.0.105.250", "ip:203.0.113.9"} <= keys
    assert body["graph"]["campaigns"], "chain must carry campaign metadata"
    assert body["graph"]["meta"]["basis"]
    assert body["graph"]["meta"]["node_count"] == len(body["graph"]["nodes"])


def test_relationship_alert_basis_is_honest(client, _fake_os, monkeypatch):
    """Not yet correlated: honest minimal graph from the alert's OWN
    entities - every edge observed (inferred False) and citing the alert
    id; no invented relations."""
    def fake_doc(alert_id):
        return {"_id": "os-id-1", "_source": {
            "alert_id": alert_id,
            "title": "IOC match: 198.51.100.66 (ip)",
            "alert_type": "ioc_match", "severity": "high", "status": "new",
            "kill_chain": {"stage": "Command and Control"},
            "source": {"ip": "10.0.0.50"},
            "destination": {"ip": "198.51.100.66"},
            "first_seen": "2026-10-15T00:00:00Z",
            "last_seen": "2026-10-15T00:10:00Z", "event_count": 12,
            "matched_iocs": [{"ioc_type": "ip",
                              "ioc_value": "198.51.100.66",
                              "match_field": "destination",
                              "confidence": "high"}],
        }}

    monkeypatch.setattr(_fake_os, "get_alert_doc", fake_doc)
    login(client, **ADMIN)
    r = client.get("/api/alerts/alert-only-1/relationship")
    assert r.status_code == 200
    body = r.json()
    assert body["basis"] == "alert"
    assert body["incidents"] == []
    keys = {n["key"] for n in body["graph"]["nodes"]}
    assert keys == {"ip:10.0.0.50", "ip:198.51.100.66"}
    edges = body["graph"]["edges"]
    rels = {e["relation"] for e in edges}
    assert "alerted_activity" in rels
    assert "connected_to" in rels  # ioc edge (match_field=destination)
    for e in edges:
        assert e["inferred"] is False
        assert any("alert-only-1" in reason for reason in e["reasons"])


def test_relationship_none_basis_when_no_entities(client, _fake_os,
                                                  monkeypatch):
    def fake_doc(alert_id):
        return {"_id": "os-id-2", "_source": {
            "alert_id": alert_id, "title": "Odd", "alert_type": "x",
            "severity": "low"}}

    monkeypatch.setattr(_fake_os, "get_alert_doc", fake_doc)
    login(client, **ADMIN)
    r = client.get("/api/alerts/noentity/relationship")
    assert r.status_code == 200
    body = r.json()
    assert body["basis"] == "none"
    assert body["graph"]["nodes"] == []
    assert body["graph"]["edges"] == []


def test_relationship_404_and_502(client, _fake_os, monkeypatch):
    login(client, **ADMIN)
    # genuinely missing alert -> 404 (FakeOS default: no doc)
    assert client.get(
        "/api/alerts/does-not-exist/relationship").status_code == 404

    def boom(alert_id):
        raise RuntimeError("opensearch down")

    monkeypatch.setattr(_fake_os, "get_alert_doc", boom)
    r = client.get("/api/alerts/x/relationship")
    assert r.status_code == 502
    assert "Search backend unavailable" in r.json()["detail"]


# ------------------------------------------- per-IOC activity feed (item 5)

def _seed_ioc(value="198.51.100.66", ioc_type="ip"):
    from app.db import SessionLocal
    from app.models import IocRecord
    db = SessionLocal()
    db.add(IocRecord(
        ioc_type=ioc_type, ioc_value=value, status="active",
        confidence="high", malware="CobaltStrike", tags=["c2", "rat"],
        provenance=[{"feed": "feodo-c2",
                     "first_seen": "2026-10-10T00:00:00Z",
                     "last_seen": "2026-10-14T00:00:00Z",
                     "confidence": "high",
                     "reference": "https://feodotracker.abuse.ch/",
                     "malware": "CobaltStrike"}],
    ))
    db.commit()
    db.close()


def test_ioc_activity_shape_and_honest_alert_linkage(client, _fake_os,
                                                     monkeypatch):
    _seed_ioc()
    captured = {}

    def fake_aggregate(alias, body):
        captured[alias] = body
        if alias == "ndr-ioc-matches-read":
            if body.get("size") == 0:
                return {"hits": {"total": {"value": 7, "relation": "eq"}},
                        "aggregations": {
                            "hosts": {"buckets": [
                                {"key": "10.0.0.50", "doc_count": 5}]},
                            "fields": {"buckets": [
                                {"key": "destination", "doc_count": 7}]},
                            "host_card": {"value": 1},
                            "first_match": {
                                "value_as_string":
                                    "2026-10-14T01:00:00Z"},
                            "last_match": {
                                "value_as_string":
                                    "2026-10-14T05:00:00Z"},
                        }}
            return {"hits": {"total": {"value": 7}, "hits": [
                {"_id": "m1", "_source": {
                    "@timestamp": "2026-10-14T05:00:00Z",
                    "event_id": "ev-1", "source_ip": "10.0.0.50",
                    "match_field": "destination"}},
            ]}}
        # ndr-alerts-read
        return {"hits": {"total": {"value": 2}, "hits": [
            {"_id": "a1", "_source": {
                "alert_id": "alert-ioc-1",
                "title": "IOC match: 198.51.100.66 (ip)",
                "severity": "high", "alert_type": "ioc_match",
                "status": "new",
                "first_seen": "2026-10-14T01:00:00Z",
                "last_seen": "2026-10-14T01:10:00Z",
                "source": {"ip": "10.0.0.50"},
                "destination": {"ip": "198.51.100.66"}}},
        ]}}

    monkeypatch.setattr(_fake_os, "aggregate", fake_aggregate)
    login(client, **ADMIN)
    r = client.get("/api/ti/iocs/activity?value=198.51.100.66")
    assert r.status_code == 200
    body = r.json()
    assert body["ioc"]["malware"] == "CobaltStrike"
    assert body["ioc"]["provenance"][0]["feed"] == "feodo-c2"
    assert body["activity"]["matches_total"] == 7
    assert body["activity"]["unique_source_hosts"] == 1
    assert body["activity"]["top_source_hosts"][0]["key"] == "10.0.0.50"
    assert body["recent_matches"][0]["event_id"] == "ev-1"
    assert body["related_alerts"]["total"] == 2
    assert body["related_alerts"]["items"][0]["alert_id"] == "alert-ioc-1"
    # alert-side linkage must use the RECORDED detector signature
    # (top_rules.signature == "ioc:<value>"), never a similarity guess
    alert_filters = captured["ndr-alerts-read"]["query"]["bool"]["filter"]
    assert {"term": {"top_rules.signature":
                     "ioc:198.51.100.66"}} in alert_filters


def test_ioc_activity_404_and_502(client, _fake_os, monkeypatch):
    login(client, **ADMIN)
    assert client.get(
        "/api/ti/iocs/activity?value=unknown-io").status_code == 404
    _seed_ioc(value="1.2.3.4")

    def boom(alias, body):
        raise RuntimeError("opensearch down")

    monkeypatch.setattr(_fake_os, "aggregate", boom)
    r = client.get("/api/ti/iocs/activity?value=1.2.3.4")
    assert r.status_code == 502
    assert "Search backend unavailable" in r.json()["detail"]
