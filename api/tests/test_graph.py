"""Threat-map graph API tests (Phase 5).

Covers:
  * merged relationship graph across campaigns (entity aggregation)
  * cross-campaign correlation edges exist ONLY on shared checkable
    infrastructure (never on time proximity alone)
  * correlation reasons always name the shared entity
  * entity pivot: aggregated view + related edges + blast radius
  * blast radius: direct (observed) vs indirect (inferred) impact
  * geo flows: external<->internal classification, unmapped handling,
    graceful degradation when OpenSearch is unavailable
"""

import pytest

from sqlalchemy.orm import sessionmaker

from app.db import engine
from app.models import (Incident, IncidentEdge, IncidentNode, NetworkZone)
from tests.conftest import login

TestSession = sessionmaker(bind=engine, autoflush=False,
                           expire_on_commit=False)


@pytest.fixture()
def db():
    s = TestSession()
    try:
        yield s
    finally:
        s.close()


def _node(iid, kind, key, label, role="entity", phase="unknown",
          confidence=50, attrs=None):
    return IncidentNode(incident_id=iid, kind=kind, key=key, label=label,
                        role=role, phase=phase, confidence=confidence,
                        first_seen="2026-10-12T10:00:00Z",
                        last_seen="2026-10-12T10:05:00Z",
                        attrs=attrs or {})


def _edge(iid, src, dst, relation, phase="c2", inferred=False,
          evidence_count=1, confidence=60):
    return IncidentEdge(incident_id=iid, src_key=src, dst_key=dst,
                        relation=relation, phase=phase,
                        inferred=inferred,
                        first_seen="2026-10-12T10:00:00Z",
                        last_seen="2026-10-12T10:05:00Z",
                        evidence_count=evidence_count,
                        confidence=confidence)


@pytest.fixture()
def two_campaigns_shared_c2(db):
    """Campaign 1: attacker A exploits host B, B contacts C2 domain X.
    Campaign 2: attacker C (different IP) contacts the SAME C2 domain X.

    Expectation: A and C become correlated_with each other with a
    reason naming domain:c2.evil.test - this is the multi-IP campaign
    feature. A control pair sharing NOTHING gets no edge.
    """
    inc1 = Incident(
        id="inc-1", title="203.0.113.25 -> 10.0.0.50 (Recon > C2)",
        status="open", severity="high", confidence=72,
        first_seen="2026-10-12T10:00:00Z",
        last_seen="2026-10-12T10:05:00Z", outcome={"label":
                                                   "suspected_success"},
        phases=[], entity_count=3, edge_count=2, evidence_count=4,
        signal_count=4)
    inc2 = Incident(
        id="inc-2", title="198.51.100.9 -> c2.evil.test (C2)",
        status="open", severity="medium", confidence=58,
        first_seen="2026-10-12T11:00:00Z",
        last_seen="2026-10-12T11:04:00Z", outcome={"label":
                                                   "attempted"},
        phases=[], entity_count=2, edge_count=1, evidence_count=2,
        signal_count=2)
    db.add_all([inc1, inc2])
    # campaign 1 nodes/edges
    db.add(_node("inc-1", "ip", "ip:203.0.113.25", "203.0.113.25",
                 role="attacker", phase="recon", confidence=70))
    db.add(_node("inc-1", "ip", "ip:10.0.0.50", "10.0.0.50",
                 role="compromised_host", phase="c2", confidence=65,
                 attrs={"hostname": "web-prod-02"}))
    db.add(_node("inc-1", "domain", "domain:c2.evil.test", "c2.evil.test",
                 role="c2_infra", phase="c2", confidence=88,
                 attrs={"ti_match": True, "ti_source": "urlhaus-demo",
                        "ti_updated": "2026-10-12T09:00:00Z"}))
    db.add(_node("inc-1", "ip", "ip:198.51.100.77", "198.51.100.77",
                 role="c2_infra", phase="c2", confidence=80))
    db.add(_edge("inc-1", "ip:203.0.113.25", "ip:10.0.0.50", "probed",
                 phase="recon", confidence=70))
    db.add(_edge("inc-1", "ip:10.0.0.50", "domain:c2.evil.test",
                 "contacted", phase="c2", evidence_count=3, confidence=82))
    db.add(_edge("inc-1", "domain:c2.evil.test", "ip:198.51.100.77",
                 "resolved_to", phase="c2", inferred=True, confidence=75))
    # campaign 2 nodes/edges (shared C2 domain, different attacker)
    db.add(_node("inc-2", "ip", "ip:198.51.100.9", "198.51.100.9",
                 role="compromised_host", phase="c2", confidence=60))
    db.add(_edge("inc-2", "ip:198.51.100.9", "domain:c2.evil.test",
                 "contacted", phase="c2", evidence_count=2, confidence=66))
    # control: unrelated closed campaign with a private host pair
    inc3 = Incident(
        id="inc-3", title="10.0.0.77 -> 10.0.1.5 (Lateral)",
        status="closed", severity="low", confidence=30,
        first_seen="2026-10-11T08:00:00Z",
        last_seen="2026-10-11T08:10:00Z", outcome={"label":
                                                   "indeterminate"},
        phases=[], entity_count=2, edge_count=1, evidence_count=1,
        signal_count=1)
    db.add(inc3)
    db.add(_node("inc-3", "ip", "ip:10.0.0.77", "10.0.0.77",
                 role="compromised_host", phase="lateral", confidence=35))
    db.add(_node("inc-3", "ip", "ip:10.0.1.5", "10.0.1.5",
                 role="entity", phase="lateral", confidence=30))
    db.add(_edge("inc-3", "ip:10.0.0.77", "ip:10.0.1.5", "lateral_to",
                 phase="lateral", confidence=40))
    db.commit()
    return {"shared": "domain:c2.evil.test"}


def test_relationships_merges_shared_entity(client, users_seeded,
                                            two_campaigns_shared_c2):
    login(client, "analyst", "Password-123456")
    res = client.get("/api/graph/relationships?status=open,confirmed,closed")
    assert res.status_code == 200
    body = res.json()
    keys = {n["key"] for n in body["nodes"]}
    # shared entity merged into ONE node referenced by both campaigns
    shared = next(n for n in body["nodes"]
                  if n["key"] == "domain:c2.evil.test")
    assert set(shared["incident_ids"]) == {"inc-1", "inc-2"}
    assert shared["ti_match"] is True
    assert shared["evidence_count"] >= 2
    # cross-campaign correlation edge exists between the two members
    corr = [e for e in body["edges"] if e["relation"] == "correlated_with"]
    assert corr, "expected cross-campaign correlation edges"
    pairs = {(e["src"], e["dst"]) for e in corr}
    assert any(set(p) == {"ip:203.0.113.25", "ip:198.51.100.9"}
               for p in pairs), f"missing attacker pair in {pairs}"
    # every correlation edge names the shared entity as the reason
    for e in corr:
        assert e["reasons"], "correlation edge must carry a reason"
        assert any("c2.evil.test" in r for r in e["reasons"])
        assert e["inferred"] is True
        assert set(e["incident_ids"]) == {"inc-1", "inc-2"}
    # campaigns bundle node keys for the UI highlight
    camp = {c["id"]: c for c in body["campaigns"]}
    assert "domain:c2.evil.test" in camp["inc-1"]["node_keys"]
    assert camp["inc-2"]["confidence"] == 58
    # control campaign nodes exist but no invented edges beyond evidence
    assert "ip:10.0.0.77" in keys
    unrelated = [e for e in body["edges"]
                 if {e["src"], e["dst"]} == {"ip:10.0.0.77",
                                             "ip:198.51.100.9"}]
    assert not unrelated


def test_relationships_respects_status_filter(client, users_seeded,
                                              two_campaigns_shared_c2):
    login(client, "analyst", "Password-123456")
    res = client.get("/api/graph/relationships?status=open")
    body = res.json()
    camp_ids = {c["id"] for c in body["campaigns"]}
    assert "inc-3" not in camp_ids          # closed campaign filtered
    assert {"inc-1", "inc-2"} <= camp_ids


def test_relationships_requires_view_permission(client, users_seeded,
                                                two_campaigns_shared_c2):
    # not authenticated
    assert client.get("/api/graph/relationships").status_code == 401


def test_entity_pivot_and_blast_radius(client, users_seeded,
                                       two_campaigns_shared_c2):
    login(client, "analyst", "Password-123456")
    res = client.get("/api/graph/entity/ip:10.0.0.50")
    assert res.status_code == 200
    body = res.json()
    assert body["entity"]["key"] == "ip:10.0.0.50"
    assert body["entity"]["attrs"].get("hostname") == "web-prod-02"
    rel = {(r["peer_key"], r["relation"]) for r in body["related"]}
    assert ("domain:c2.evil.test", "contacted") in rel
    assert any(c["id"] == "inc-1" for c in body["campaigns"])
    # blast radius: C2 domain reachable via observed edge (direct),
    # the C2 IP behind it via inferred resolved_to (indirect)
    br = body["blast_radius"]
    direct_keys = {e["key"] for e in br["direct"]}
    indirect_keys = {e["key"] for e in br["indirect"]}
    assert "domain:c2.evil.test" in direct_keys
    assert "ip:198.51.100.77" in indirect_keys
    assert all(e["hop"] <= 2 for e in (*br["direct"], *br["indirect"]))


def test_entity_pivot_404_unknown(client, users_seeded,
                                  two_campaigns_shared_c2):
    login(client, "analyst", "Password-123456")
    res = client.get("/api/graph/entity/ip:203.0.113.99")
    assert res.status_code == 404


def test_geo_flows_classifies_and_lists_unmapped(client, users_seeded,
                                                 db, monkeypatch):
    # ensure a zone exists so 10.0.0.0/8 hosts count as internal even
    # without the RFC1918 fallback
    db.add(NetworkZone(cidr="10.0.0.0/8", name="servers", description=""))
    db.commit()

    def fake_aggregate(**kw):
        body = kw["body"]
        pairs = {"buckets": [
            {"key": {"src": "203.0.113.25", "dst": "10.0.0.50"},
             "doc_count": 42, "bytes": {"value": 90000},
             "engines": {"buckets": [{"key": "suricata"}]},
             "last": {"value_as_string": "2026-10-12T10:05:00Z"},
             "ioc_hits": {"doc_count": 3},
             "alert_hits": {"doc_count": 2}},
            {"key": {"src": "10.0.0.50", "dst": "198.51.100.77"},
             "doc_count": 23, "bytes": {"value": 5000},
             "engines": {"buckets": [{"key": "zeek"}]},
             "last": {"value_as_string": "2026-10-12T10:06:00Z"},
             "ioc_hits": {"doc_count": 0},
             "alert_hits": {"doc_count": 0}},
            # internal<->internal: must be skipped entirely
            {"key": {"src": "10.0.0.50", "dst": "10.0.0.31"},
             "doc_count": 5, "bytes": {"value": 100},
             "engines": {"buckets": []},
             "last": {"value_as_string": "2026-10-12T10:07:00Z"},
             "ioc_hits": {"doc_count": 0},
             "alert_hits": {"doc_count": 0}},
        ]}
        geo = {"buckets": [
            {"key": "203.0.113.25", "country": {"buckets":
                                                [{"key": "Australia"}]},
             "lat": {"value": -27.5}, "lon": {"value": 153.0},
             "asn": {"buckets": [{"key": "AS64512 demo-vendor"}]}},
            # 198.51.100.77 has NO geo entry -> must land in unmapped
        ]}
        return {"aggregations": {"pairs": pairs, "geo_by_ip": geo}}

    fake = type("FakeOS2", (), {})()
    fake.validate_alias = staticmethod(lambda a: a)
    fake.client = type("FakeClient", (), {})()
    fake.client.search = staticmethod(fake_aggregate)
    monkeypatch.setattr("app.routers.graph.get_os", lambda: fake)
    login(client, "analyst", "Password-123456")
    res = client.get("/api/graph/geo?hours=24")
    assert res.status_code == 200
    body = res.json()
    assert body["geo_enabled"] is True
    flows = {(f["external_ip"], f["internal_ip"], f["direction"])
             for f in body["flows"]}
    assert ("203.0.113.25", "10.0.0.50", "inbound") in flows
    assert ("198.51.100.77", "10.0.0.50", "outbound") in flows
    assert not any(f["external_ip"] == "10.0.0.31" for f in body["flows"])
    inbound = next(f for f in body["flows"]
                   if f["external_ip"] == "203.0.113.25")
    assert inbound["geo"]["country"] == "Australia"
    assert inbound["ioc_hits"] == 3 and inbound["alert_hits"] == 2
    unmapped = {u["ip"] for u in body["unmapped"]}
    assert "198.51.100.77" in unmapped
    assert all("not placed" in u["reason"] or "GeoIP" in u["reason"]
               for u in body["unmapped"])


def test_geo_flows_degrades_when_opensearch_down(client, users_seeded,
                                                 monkeypatch):
    def boom(_body):
        raise RuntimeError("opensearch unreachable")

    monkeypatch.setattr("app.routers.graph.get_os", lambda: type(
        "FakeOS3", (), {"aggregate": staticmethod(boom),
                        "validate_alias": staticmethod(lambda a: a)})())
    login(client, "analyst", "Password-123456")
    res = client.get("/api/graph/geo")
    assert res.status_code == 200
    body = res.json()
    assert body["flows"] == [] and body["geo_enabled"] is False
    assert "unavailable" in body["note"]
