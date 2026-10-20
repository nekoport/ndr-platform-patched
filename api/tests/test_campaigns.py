"""Campaign API tests (v0.12).

Campaigns are analyst bookkeeping over reconstructed incidents:
merge (group), split (detach), rename, close, dissolve. They must
never rewrite incident evidence or relations, only membership.
"""

import pytest

from sqlalchemy.orm import sessionmaker

from app.db import engine
from app.models import AuditRecord, Incident, IncidentHistory
from tests.conftest import login

TestSession = sessionmaker(bind=engine, autoflush=False,
                           expire_on_commit=False)


@pytest.fixture()
def db():
    db = TestSession()
    try:
        yield db
    finally:
        db.close()


def _seed(db, incident_id, severity="high", first="2026-10-12T10:00:00Z",
          last="2026-10-12T10:05:00Z", status="open"):
    db.add(Incident(id=incident_id, title=f"Story {incident_id}",
                    status=status, severity=severity, confidence=60,
                    first_seen=first, last_seen=last, outcome={}, phases=[],
                    entity_count=1, edge_count=0, evidence_count=1,
                    signal_count=1))
    db.commit()


@pytest.fixture()
def seeded(db, users_seeded):
    _seed(db, "inc-a", severity="high",
          first="2026-10-12T08:00:00Z", last="2026-10-12T08:30:00Z")
    _seed(db, "inc-b", severity="critical",
          first="2026-10-12T09:00:00Z", last="2026-10-12T09:45:00Z")
    _seed(db, "inc-c", severity="low",
          first="2026-10-12T07:00:00Z", last="2026-10-12T07:10:00Z")
    return db


def _as_analyst(client):
    r = login(client, "analyst", "Password-123456")
    assert r.status_code == 200, r.text


# --------------------------------------------------------------- create/merge
def test_campaign_create_with_rollups(client, seeded):
    _as_analyst(client)
    r = client.post("/api/campaigns", json={
        "title": "Intrusion wave 203.0.113.0/24",
        "description": "Same actor, two stories",
        "incident_ids": ["inc-a", "inc-b"],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"].startswith("cmp-")
    assert body["incident_count"] == 2
    # rollup: max severity wins, window spans members
    assert body["severity"] == "critical"
    assert body["first_seen"] == "2026-10-12T08:00:00Z"
    assert body["last_seen"] == "2026-10-12T09:45:00Z"
    assert body["created_by"] == "analyst"
    cid = body["id"]

    # incident list carries campaign membership
    r2 = client.get("/api/incidents")
    items = {i["id"]: i for i in r2.json()["items"]}
    assert items["inc-a"]["campaign_id"] == cid
    assert items["inc-a"]["campaign_title"] == \
        "Intrusion wave 203.0.113.0/24"
    assert items["inc-c"]["campaign_id"] is None

    # incident detail carries it too
    r3 = client.get("/api/incidents/inc-a")
    assert r3.json()["campaign_id"] == cid

    # merge history appended on each member
    r4 = client.get("/api/incidents/inc-a")
    actions = [h["action"] for h in r4.json()["history"]]
    assert "campaign_merge" in actions


def test_campaign_create_requires_members(client, seeded):
    _as_analyst(client)
    r = client.post("/api/campaigns", json={
        "title": "Empty campaign", "incident_ids": []})
    assert r.status_code == 422


def test_campaign_create_unknown_incident(client, seeded):
    _as_analyst(client)
    r = client.post("/api/campaigns", json={
        "title": "Ghost campaign", "incident_ids": ["inc-nope"]})
    assert r.status_code == 400
    assert "inc-nope" in r.json()["detail"]


def test_campaign_title_validation(client, seeded):
    _as_analyst(client)
    r = client.post("/api/campaigns", json={
        "title": "ab", "incident_ids": ["inc-a"]})
    assert r.status_code == 422


# --------------------------------------------------------------- attach/move
def test_campaign_attach_moves_membership(client, seeded):
    _as_analyst(client)
    r = client.post("/api/campaigns", json={
        "title": "Campaign one", "incident_ids": ["inc-a"]})
    assert r.status_code == 200
    cid1 = r.json()["id"]
    r = client.post("/api/campaigns", json={
        "title": "Campaign two", "incident_ids": ["inc-b"]})
    cid2 = r.json()["id"]

    # move inc-b into campaign one
    r = client.post(f"/api/campaigns/{cid1}/incidents",
                    json={"incident_ids": ["inc-b"]})
    assert r.status_code == 200
    assert r.json()["incident_count"] == 2
    assert r.json()["severity"] == "critical"  # max(inc-a high, inc-b critical)

    r2 = client.get(f"/api/campaigns/{cid1}")
    assert r2.json()["severity"] == "critical"
    r3 = client.get(f"/api/campaigns/{cid2}")
    assert r3.json()["incident_count"] == 0
    assert r3.json()["first_seen"] is None

    # history trail on the moved incident
    r4 = client.get("/api/incidents/inc-b")
    merges = [h for h in r4.json()["history"]
              if h["action"] == "campaign_merge"]
    assert len(merges) == 2


def test_campaign_attach_unknown_campaign(client, seeded):
    _as_analyst(client)
    r = client.post("/api/campaigns/cmp-missing/incidents",
                    json={"incident_ids": ["inc-a"]})
    assert r.status_code == 404


# --------------------------------------------------------------- split
def test_campaign_detach_splits_one(client, seeded):
    _as_analyst(client)
    r = client.post("/api/campaigns", json={
        "title": "To split", "incident_ids": ["inc-a", "inc-b"]})
    cid = r.json()["id"]
    r = client.delete(f"/api/campaigns/{cid}/incidents/inc-a")
    assert r.status_code == 200
    assert r.json()["incident_count"] == 1
    assert r.json()["severity"] == "critical"

    r2 = client.get("/api/incidents/inc-a")
    assert r2.json()["campaign_id"] is None
    actions = [h["action"] for h in r2.json()["history"]]
    assert "campaign_split" in actions

    # detaching a non-member -> 404
    r3 = client.delete(f"/api/campaigns/{cid}/incidents/inc-a")
    assert r3.status_code == 404


# --------------------------------------------------------------- update/close
def test_campaign_update_and_close(client, seeded):
    _as_analyst(client)
    r = client.post("/api/campaigns", json={
        "title": "Initial title", "incident_ids": ["inc-a"]})
    cid = r.json()["id"]
    r = client.patch(f"/api/campaigns/{cid}",
                     json={"title": "Renamed campaign",
                           "status": "closed"})
    assert r.status_code == 200
    assert r.json()["title"] == "Renamed campaign"
    assert r.json()["status"] == "closed"

    r2 = client.get("/api/incidents/inc-a")
    actions = [h["action"] for h in r2.json()["history"]]
    assert "campaign_update" in actions

    # invalid status -> 422
    r3 = client.patch(f"/api/campaigns/{cid}", json={"status": "archived"})
    assert r3.status_code == 422


# --------------------------------------------------------------- dissolve
def test_campaign_dissolve_detaches_all(client, seeded):
    _as_analyst(client)
    r = client.post("/api/campaigns", json={
        "title": "Doomed", "incident_ids": ["inc-a", "inc-b", "inc-c"]})
    cid = r.json()["id"]
    r = client.delete(f"/api/campaigns/{cid}")
    assert r.status_code == 200
    assert sorted(r.json()["detached"]) == ["inc-a", "inc-b", "inc-c"]

    assert client.get(f"/api/campaigns/{cid}").status_code == 404
    r2 = client.get("/api/incidents")
    assert all(i["campaign_id"] is None for i in r2.json()["items"])


# --------------------------------------------------------------- RBAC
def test_campaign_rbac_auditor_readonly(client, seeded, users_seeded):
    assert client.post("/api/campaigns", json={
        "title": "x", "incident_ids": ["inc-a"]}).status_code == 401
    assert login(client, "viewer", "Password-123456").status_code == 200
    # read works
    assert client.get("/api/campaigns").status_code == 200
    # mutations denied
    r = client.post("/api/campaigns", json={
        "title": "Viewer campaign", "incident_ids": ["inc-a"]})
    assert r.status_code == 403


# --------------------------------------------------------------- audit
def test_campaign_actions_audited(client, seeded):
    _as_analyst(client)
    r = client.post("/api/campaigns", json={
        "title": "Audited campaign", "incident_ids": ["inc-a", "inc-b"]})
    cid = r.json()["id"]
    client.delete(f"/api/campaigns/{cid}/incidents/inc-a")
    db = seeded
    actions = [a.action for a in db.query(AuditRecord)
               .filter(AuditRecord.target_type == "campaign").all()]
    assert "campaign.create" in actions
    assert "campaign.split" in actions


# --------------------------------------------------------------- misc
def test_campaign_not_found(client, seeded):
    login(client, "admin", "bootstrap-admin-pass-01")
    assert client.get("/api/campaigns/cmp-missing").status_code == 404


def test_campaign_list_filter_and_search(client, seeded):
    _as_analyst(client)
    client.post("/api/campaigns", json={
        "title": "Northwave intrusion", "incident_ids": ["inc-a"]})
    client.post("/api/campaigns", json={
        "title": "Insider case", "incident_ids": ["inc-c"]})
    r = client.get("/api/campaigns")
    assert r.json()["total"] == 2
    r = client.get("/api/campaigns", params={"q": "northwave"})
    assert r.json()["total"] == 1
    assert r.json()["items"][0]["title"] == "Northwave intrusion"
    r = client.get("/api/campaigns", params={"status": "open"})
    assert r.json()["total"] == 2
