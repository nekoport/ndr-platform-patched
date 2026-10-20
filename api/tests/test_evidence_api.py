"""PCAP & evidence workflow API tests (doc section 15 - AT-11/18/19/28).

Covers: capture storage stats, session resolution per alert/incident with
evidence statuses (available / partially_available / expired /
not_captured), selective export with manifest + SHA-256 + limits, TTL
expiry, download lifecycle, RBAC and audit records.
"""

from __future__ import annotations

import json
import os
import zipfile
from datetime import datetime, timedelta, timezone

import pytest

from app.config import config
from app.db import SessionLocal
from app.models import AuditRecord, Incident, IncidentNode, PcapExport
from app.security import hash_password
from conftest import login


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


@pytest.fixture()
def pcap_env(tmp_path, monkeypatch):
    """Redirect PCAP + export dirs into tmp and create capture files."""
    pcap_dir = tmp_path / "pcap"
    exp_dir = tmp_path / "pcap-exports"
    pcap_dir.mkdir()
    exp_dir.mkdir()
    monkeypatch.setattr(config, "pcap_dir", str(pcap_dir))
    monkeypatch.setattr(config, "pcap_export_dir", str(exp_dir))
    return {"pcap": pcap_dir, "exports": exp_dir}


def _make_pcap(pcap_dir, name: str, mtime: datetime, size: int = 2048) -> str:
    path = pcap_dir / name
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + os.urandom(size))
    ts = mtime.timestamp()
    os.utime(path, (ts, ts))
    return name


def _alert_doc(alert_id: str, src: dict) -> dict:
    return {"_id": alert_id, "_index": "ndr-alerts-x", "_source": src}


def _event_doc(doc_id: str, ts: datetime, **extra) -> dict:
    src = {"@timestamp": _iso(ts), "session_id": f"flow-{doc_id}",
           "source_engine": "suricata", "event_type": "alert",
           "source": {"ip": "203.0.113.25"},
           "destination": {"ip": "10.0.0.50", "port": 443},
           "network": {"transport": "tcp"}, **extra}
    return {"_id": doc_id, "_index": "ndr-events-x", "_source": src}


def _fake_os_docs(monkeypatch, fake, alerts: dict, events: dict):
    def get_by_id(alias, doc_id):
        if alias == "ndr-alerts-read":
            return alerts.get(doc_id)
        if alias == "ndr-events-read":
            return events.get(doc_id)
        return None

    def aggregate(alias, body):
        assert alias in ("ndr-events-read", "ndr-alerts-read")
        hits = [{"_id": k, "_index": v["_index"],
                 "_source": v["_source"]}
                for k, v in (events if alias == "ndr-events-read"
                             else alerts).items()]
        return {"hits": {"total": {"value": len(hits), "relation": "eq"},
                         "hits": hits}}

    monkeypatch.setattr(fake, "get_by_id", get_by_id)
    monkeypatch.setattr(fake, "aggregate", aggregate)

    # v0.13.0 (B5): export resolution now uses the BATCH ids-query
    def get_docs_by_ids(alias, ids):
        src_map = (events if alias == "ndr-events-read" else alerts)
        return [{"_id": i, "_source": src_map[i]["_source"]}
                for i in ids if i in src_map]

    monkeypatch.setattr(fake, "get_docs_by_ids", get_docs_by_ids)


NOW = datetime.now(timezone.utc)


# ------------------------------------------------------------------ storage
def test_pcap_storage_stats(client, pcap_env):
    _make_pcap(pcap_env["pcap"], "eth0-1.pcap", NOW - timedelta(hours=2))
    _make_pcap(pcap_env["pcap"], "eth0-2.pcap", NOW - timedelta(minutes=5))
    login(client, "admin", "bootstrap-admin-pass-01")
    res = client.get("/api/evidence/pcap/storage")
    assert res.status_code == 200
    body = res.json()
    assert body["file_count"] == 2
    assert body["total_bytes"] > 0
    assert body["dir_exists"] is True
    assert body["coverage_from"] < body["coverage_to"]
    assert body["granularity"] == "file-level"
    assert body["arkime_viewer_url"]


def test_pcap_storage_empty_dir(client, pcap_env):
    login(client, "admin", "bootstrap-admin-pass-01")
    body = client.get("/api/evidence/pcap/storage").json()
    assert body["file_count"] == 0
    assert body["coverage_from"] is None


# ----------------------------------------------------------------- sessions
def test_alert_sessions_statuses(client, pcap_env, monkeypatch, _fake_os):
    """AT-11 spirit: every session carries an honest evidence status."""
    oldest = NOW - timedelta(hours=2)
    _make_pcap(pcap_env["pcap"], "a.pcap", oldest)
    _make_pcap(pcap_env["pcap"], "b.pcap", NOW - timedelta(minutes=5))
    alert = _alert_doc("A1", {
        "alert_id": "A1", "title": "C2 beacon", "severity": "high",
        "first_seen": _iso(NOW - timedelta(hours=3)),
        "last_seen": _iso(NOW - timedelta(minutes=6)),
        "source": {"ip": "203.0.113.25"},
        "destination": {"ip": "10.0.0.50"},
    })
    events = {
        "e-old": _event_doc("e-old", NOW - timedelta(hours=3)),
        "e-now": _event_doc("e-now", NOW - timedelta(minutes=9)),
    }
    _fake_os_docs(monkeypatch, _fake_os, {"A1": alert}, events)
    login(client, "admin", "bootstrap-admin-pass-01")
    res = client.get("/api/evidence/alerts/A1/sessions")
    assert res.status_code == 200
    body = res.json()
    statuses = {s["doc_id"]: s["pcap_status"] for s in body["sessions"]}
    assert statuses["e-now"] == "available"
    assert statuses["e-old"] == "expired"
    assert body["scope"] == "alert"
    assert body["entities"]["ips"] == ["203.0.113.25", "10.0.0.50"]
    assert body["pcap"]["file_count"] == 2


def test_alert_sessions_not_captured(client, pcap_env, monkeypatch, _fake_os):
    alert = _alert_doc("A2", {
        "alert_id": "A2", "first_seen": _iso(NOW - timedelta(minutes=10)),
        "last_seen": _iso(NOW - timedelta(minutes=9)),
        "source": {"ip": "198.51.100.9"},
    })
    _fake_os_docs(monkeypatch, _fake_os, {"A2": alert},
                  {"e1": _event_doc("e1", NOW - timedelta(minutes=9))})
    login(client, "admin", "bootstrap-admin-pass-01")
    body = client.get("/api/evidence/alerts/A2/sessions").json()
    assert body["sessions"][0]["pcap_status"] == "not_captured"


def test_alert_sessions_404(client, _fake_os):
    login(client, "admin", "bootstrap-admin-pass-01")
    assert client.get("/api/evidence/alerts/missing/sessions").status_code == 404


def test_incident_sessions(client, pcap_env, monkeypatch, _fake_os):
    db = SessionLocal()
    db.add(Incident(id="inc-1", title="Multi-stage", severity="high",
                    first_seen=_iso(NOW - timedelta(minutes=30)),
                    last_seen=_iso(NOW - timedelta(minutes=5))))
    db.add(IncidentNode(incident_id="inc-1", kind="ip", key="ip:10.0.0.50",
                        label="web-01", role="target"))
    db.commit()
    db.close()
    _make_pcap(pcap_env["pcap"], "c.pcap", NOW - timedelta(minutes=10))
    _fake_os_docs(monkeypatch, _fake_os, {},
                  {"e9": _event_doc("e9", NOW - timedelta(minutes=12))})
    login(client, "admin", "bootstrap-admin-pass-01")
    res = client.get("/api/evidence/incidents/inc-1/sessions")
    assert res.status_code == 200
    body = res.json()
    assert body["scope"] == "incident"
    assert body["entities"]["ips"] == ["10.0.0.50"]
    assert body["sessions"][0]["pcap_status"] == "available"


# ------------------------------------------------------------------- export
def _export_payload(**kw):
    base = {"reason": "Incident INC-42 forensic follow-up",
            "sessions": ["e-now"], "alert_id": "A1"}
    base.update(kw)
    return base


def test_export_roundtrip_and_manifest(client, pcap_env, monkeypatch,
                                       _fake_os):
    _make_pcap(pcap_env["pcap"], "hit.pcap", NOW - timedelta(minutes=9),
               size=4096)
    events = {"e-now": _event_doc("e-now", NOW - timedelta(minutes=9))}
    _fake_os_docs(monkeypatch, _fake_os, {}, events)
    login(client, "admin", "bootstrap-admin-pass-01")
    res = client.post("/api/evidence/pcap/export", json=_export_payload())
    assert res.status_code == 200, res.text
    rec = res.json()
    assert rec["status"] == "ready"
    assert rec["session_count"] == 1
    assert rec["files"][0]["name"] == "hit.pcap"
    assert len(rec["files"][0]["sha256"]) == 64
    assert rec["bundle_sha256"]

    # bundle on disk: zip with manifest + pcap; manifest carries custody
    bundle = pcap_env["exports"] / rec["bundle_name"]
    assert bundle.is_file()
    with zipfile.ZipFile(bundle) as zf:
        names = set(zf.namelist())
        assert names == {"hit.pcap", "manifest.json"}
        manifest = json.loads(zf.read("manifest.json"))
    assert manifest["actor"] == "admin"
    assert manifest["reason"] == _export_payload()["reason"]
    assert manifest["granularity"] == "file-level"
    assert manifest["integrity"]["algorithm"] == "sha256"
    assert manifest["files"][0]["sha256"] == rec["files"][0]["sha256"]
    assert manifest["sessions"][0]["doc_id"] == "e-now"

    # register lists it; hash matches the file on disk
    listed = client.get("/api/evidence/pcap/exports").json()
    assert listed["items"][0]["id"] == rec["id"]
    import hashlib
    assert hashlib.sha256(bundle.read_bytes()).hexdigest() \
        == rec["bundle_sha256"]

    # download works and is audited
    dl = client.get(f"/api/evidence/pcap/exports/{rec['id']}/download")
    assert dl.status_code == 200
    assert dl.headers["content-type"] == "application/zip"
    audited = (SessionLocal().query(AuditRecord)
               .filter(AuditRecord.action == "evidence.pcap.download")
               .all())
    assert len(audited) == 1


def test_export_requires_reason(client, pcap_env, _fake_os):
    login(client, "admin", "bootstrap-admin-pass-01")
    res = client.post("/api/evidence/pcap/export",
                 json={"sessions": ["e-now"], "reason": "x"})
    assert res.status_code == 422


def test_export_invalid_session_id_rejected(client, pcap_env, _fake_os):
    login(client, "admin", "bootstrap-admin-pass-01")
    res = client.post("/api/evidence/pcap/export",
                 json=_export_payload(sessions=["bad id with spaces/../"]))
    assert res.status_code == 422


def test_export_no_coverage_recorded_failed(client, pcap_env,
                                            monkeypatch, _fake_os):
    """AT-11: unavailable evidence explains itself, never fabricates."""
    events = {"e1": _event_doc("e1", NOW - timedelta(minutes=9))}
    _fake_os_docs(monkeypatch, _fake_os, {}, events)
    login(client, "admin", "bootstrap-admin-pass-01")
    res = client.post("/api/evidence/pcap/export",
                 json=_export_payload(sessions=["e1"]))
    assert res.status_code == 200
    rec = res.json()
    assert rec["status"] == "failed"
    assert "pruned" in rec["error"] or "not capturing" in rec["error"]
    audited = (SessionLocal().query(AuditRecord)
               .filter(AuditRecord.action == "evidence.pcap.export")
               .all())
    assert audited[0].result == "failure"


def test_export_unknown_sessions_404(client, pcap_env, _fake_os):
    login(client, "admin", "bootstrap-admin-pass-01")
    res = client.post("/api/evidence/pcap/export",
                 json=_export_payload(sessions=["ghost"]))
    assert res.status_code == 404


def test_export_size_limit_rejected(client, pcap_env, monkeypatch, _fake_os):
    _make_pcap(pcap_env["pcap"], "big.pcap",
               NOW - timedelta(minutes=9), size=8192)
    events = {"e1": _event_doc("e1", NOW - timedelta(minutes=9))}
    _fake_os_docs(monkeypatch, _fake_os, {}, events)
    monkeypatch.setattr(config, "pcap_export_max_bytes", 1024)
    login(client, "admin", "bootstrap-admin-pass-01")
    res = client.post("/api/evidence/pcap/export",
                 json=_export_payload(sessions=["e1"]))
    assert res.status_code == 400
    assert "policy limits" in res.json()["detail"]


# ------------------------------------------------------------------ TTL/RBAC
def test_export_ttl_expiry_and_410(client, pcap_env, monkeypatch, _fake_os):
    _make_pcap(pcap_env["pcap"], "t.pcap", NOW - timedelta(minutes=9))
    events = {"e1": _event_doc("e1", NOW - timedelta(minutes=9))}
    _fake_os_docs(monkeypatch, _fake_os, {}, events)
    login(client, "admin", "bootstrap-admin-pass-01")
    rec = client.post("/api/evidence/pcap/export",
                 json=_export_payload(sessions=["e1"])).json()
    bundle = pcap_env["exports"] / rec["bundle_name"]
    assert bundle.is_file()

    db = SessionLocal()
    row = db.get(PcapExport, rec["id"])
    row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()
    db.close()

    listed = client.get("/api/evidence/pcap/exports").json()
    assert listed["items"][0]["status"] == "expired"
    assert not bundle.exists()  # TTL sweep removed the file
    assert client.get(f"/api/evidence/pcap/exports/{rec['id']}/download"
                 ).status_code == 410
    expired_audit = (SessionLocal().query(AuditRecord)
                     .filter(AuditRecord.action == "evidence.pcap.expire")
                     .all())
    assert len(expired_audit) == 1


def test_export_rbac_auditor_denied(client, pcap_env, users_seeded):
    """AT-18/AT-28: export needs the permission; auditor is read-only."""
    users_seeded
    login(client, "viewer", "Password-123456")
    assert client.get("/api/evidence/pcap/storage").status_code == 200  # view ok
    res = client.post("/api/evidence/pcap/export",
                 json=_export_payload(sessions=["e1"]))
    assert res.status_code == 403
    assert client.get("/api/evidence/pcap/exports/x/download").status_code == 403


def test_export_unauthenticated_401(client, pcap_env):
    assert client.get("/api/evidence/pcap/storage").status_code == 401
    assert client.post("/api/evidence/pcap/export",
                       json=_export_payload()).status_code == 401


def test_sessions_rbac_auditor_allowed(client, users_seeded, _fake_os,
                                       monkeypatch):
    users_seeded
    alert = _alert_doc("A1", {
        "alert_id": "A1", "first_seen": _iso(NOW - timedelta(minutes=10)),
        "last_seen": _iso(NOW - timedelta(minutes=9)),
        "source": {"ip": "198.51.100.9"}})
    _fake_os_docs(monkeypatch, _fake_os, {"A1": alert}, {})
    login(client, "viewer", "Password-123456")
    # auditor may VIEW sessions (view permission) - export is the denied op
    res = client.get("/api/evidence/alerts/A1/sessions")
    assert res.status_code == 200
    assert res.json()["scope"] == "alert"
