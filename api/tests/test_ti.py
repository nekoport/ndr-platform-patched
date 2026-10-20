"""Threat Intelligence API tests (doc section 9 - Phase 3)."""

from __future__ import annotations

import sys

import pytest

sys.path.insert(0, ".")

from app.models import IocAllowlist, IocRecord, TIFeed, TIUpdateJob  # noqa: E402
from app.schemas import MASK  # noqa: E402


@pytest.fixture()
def ti_users(users_seeded):
    return {"admin": ("admin", "bootstrap-admin-pass-01"),
            "analyst": ("analyst", "Password-123456"),
            "engineer": ("engineer", "Password-123456"),
            "auditor": ("viewer", "Password-123456")}


def _login(client, users, who):
    u, p = users[who]
    r = login(client, u, p)
    assert r.status_code == 200, r.text
    return r


def login(client, username, password):
    return client.post("/api/auth/login",
                       json={"username": username, "password": password})


def _feed_payload(**over):
    body = {"name": "feodo-c2", "adapter": "feodo",
            "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            "enabled": False, "schedule_min": 60, "ttl_days": 14}
    body.update(over)
    return body


# ---------------------------------------------------------------- feeds
def test_feed_crud_and_permission(client, ti_users):
    _login(client, ti_users, "admin")
    r = client.post("/api/ti/feeds", json=_feed_payload())
    assert r.status_code == 201, r.text
    feed = r.json()
    assert feed["name"] == "feodo-c2" and feed["enabled"] is False

    # soc_analyst may NOT create feeds (ti_admin)
    _login(client, ti_users, "analyst")
    r = client.post("/api/ti/feeds", json=_feed_payload(name="other"))
    assert r.status_code == 403

    # analyst can still read feeds (view)
    r = client.get("/api/ti/feeds")
    assert r.status_code == 200 and len(r.json()) == 1

    # auditor cannot even view... auditor has view role -> CAN read
    _login(client, ti_users, "auditor")
    assert client.get("/api/ti/feeds").status_code == 200
    # but cannot create
    r = client.post("/api/ti/feeds", json=_feed_payload(name="x2"))
    assert r.status_code == 403


def test_feed_config_masked_and_merge_safe(client, ti_users):
    _login(client, ti_users, "admin")
    r = client.post("/api/ti/feeds", json=_feed_payload(
        adapter="threatfox",
        config={"api_key": "super-secret", "days": 2}))
    assert r.status_code == 201
    fid = r.json()["id"]
    assert r.json()["config"]["api_key"] == MASK
    assert r.json()["config"]["days"] == 2

    # UI sends masked value back -> stored secret must not be overwritten
    r = client.patch(f"/api/ti/feeds/{fid}",
                     json={"config": {"api_key": MASK, "days": 3}})
    assert r.status_code == 200
    assert r.json()["config"]["days"] == 3
    # stored value unchanged (verify via ORM directly)
    from app.db import SessionLocal
    db = SessionLocal()
    feed = db.query(TIFeed).filter(TIFeed.id == fid).first()
    assert feed.config["api_key"] == "super-secret"
    assert feed.config["days"] == 3
    db.close()


def test_update_now_enqueues_and_dedupes(client, ti_users):
    _login(client, ti_users, "admin")
    fid = client.post("/api/ti/feeds", json=_feed_payload()).json()["id"]
    r = client.post(f"/api/ti/feeds/{fid}/update")
    assert r.status_code == 202
    job_id = r.json()["job_id"]
    # second immediate update conflicts (already queued)
    r2 = client.post(f"/api/ti/feeds/{fid}/update")
    assert r2.status_code == 409
    # job visible in history
    jobs = client.get("/api/ti/jobs").json()
    assert any(j["id"] == job_id for j in jobs)
    assert jobs[0]["status"] == "queued"
    # analyst cannot trigger update
    _login(client, ti_users, "analyst")
    assert client.get("/api/ti/jobs").status_code == 200


def test_feed_validation(client, ti_users):
    _login(client, ti_users, "admin")
    r = client.post("/api/ti/feeds", json=_feed_payload(adapter="nope"))
    assert r.status_code == 422
    r = client.post("/api/ti/feeds", json=_feed_payload(adapter="feodo",
                                                        url=None))
    assert r.status_code == 400
    r = client.post("/api/ti/feeds", json=_feed_payload(name="a"))
    assert r.status_code == 422


# ----------------------------------------------------------------- iocs
def test_ioc_listing_and_filters(client, ti_users):
    from app.db import SessionLocal
    db = SessionLocal()
    db.add(IocRecord(ioc_type="ip", ioc_value="203.0.113.10",
                     confidence="high", malware="Emotet"))
    db.add(IocRecord(ioc_type="domain", ioc_value="c2.evil.test",
                     status="expired"))
    db.commit()
    db.close()
    _login(client, ti_users, "analyst")
    r = client.get("/api/ti/iocs")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1 and body["items"][0]["ioc_value"] == \
        "203.0.113.10"
    r = client.get("/api/ti/iocs", params={"status": "expired"})
    assert r.json()["total"] == 1
    r = client.get("/api/ti/iocs", params={"q": "emotet"})
    assert r.json()["total"] == 1
    r = client.get("/api/ti/iocs", params={"type": "domain",
                                           "status": "expired"})
    assert r.json()["items"][0]["ioc_value"] == "c2.evil.test"


# -------------------------------------------------------------- matches
def test_matches_guarded_alias(client, ti_users, _fake_os):
    def fake_aggregate(alias, body):
        assert alias == "ndr-ioc-matches-read"
        return {"hits": {"total": {"value": 1}, "hits": [
            {"_id": "m1", "_source": {"ioc_type": "ip",
                                      "ioc_value": "203.0.113.10",
                                      "ioc_confidence": "high"}}]}}

    _fake_os.aggregate = fake_aggregate
    _login(client, ti_users, "analyst")
    r = client.get("/api/ti/matches")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert body["hits"][0]["source"]["ioc_value"] == "203.0.113.10"


def test_overview_counts(client, ti_users, _fake_os):
    from app.db import SessionLocal
    db = SessionLocal()
    db.add(IocRecord(ioc_type="ip", ioc_value="203.0.113.10"))
    db.add(IocRecord(ioc_type="domain", ioc_value="c2.evil.test"))
    db.add(TIFeed(**{"id": "f1", "name": "feodo", "adapter": "feodo",
                     "enabled": True, "last_status": "success"}))
    db.add(TIFeed(**{"id": "f2", "name": "urlhaus", "adapter": "urlhaus",
                     "enabled": True, "last_status": "failed"}))
    db.commit()
    db.close()
    _fake_os.count = lambda alias, query=None: 7
    _fake_os.aggregate = lambda alias, body: {
        "aggregations": {
            "by_type": {"buckets": [{"key": "ip", "doc_count": 5}]},
            "by_source": {"buckets": [{"key": "Emotet", "doc_count": 3}]}}}
    _login(client, ti_users, "analyst")
    r = client.get("/api/ti/overview")
    assert r.status_code == 200
    body = r.json()
    assert body["iocs_active"] == 2
    assert body["feeds_enabled"] == 2
    assert body["feeds_degraded"] == 1     # urlhaus failed
    assert body["matches_24h"] == 7
    assert body["matches_by_type"]["ip"] == 5


# ------------------------------------------------------------ allowlist
def test_allowlist_add_remove_audit(client, ti_users):
    _login(client, ti_users, "admin")
    r = client.post("/api/ti/allowlist", json={
        "ioc_type": "domain", "ioc_value": "c2.evil.test",
        "reason": "internal lab domain (verified)"})
    assert r.status_code == 201
    entry_id = r.json()["id"]
    # duplicate rejected
    r = client.post("/api/ti/allowlist", json={
        "ioc_type": "domain", "ioc_value": "c2.evil.test",
        "reason": "again"})
    assert r.status_code == 409
    # visible
    rows = client.get("/api/ti/allowlist").json()
    assert len(rows) == 1 and rows[0]["created_by"] == "admin"
    # delete
    r = client.delete(f"/api/ti/allowlist/{entry_id}")
    assert r.status_code == 204
    assert client.get("/api/ti/allowlist").json() == []
    # analyst cannot modify allowlist
    _login(client, ti_users, "analyst")
    r = client.post("/api/ti/allowlist", json={
        "ioc_type": "ip", "ioc_value": "203.0.113.10", "reason": "nope"})
    assert r.status_code == 403


def test_allowlist_reason_required(client, ti_users):
    _login(client, ti_users, "admin")
    r = client.post("/api/ti/allowlist", json={
        "ioc_type": "ip", "ioc_value": "203.0.113.10", "reason": "x"})
    assert r.status_code == 422
    r = client.post("/api/ti/allowlist", json={
        "ioc_type": "banana", "ioc_value": "x", "reason": "testing"})
    assert r.status_code == 422
