"""Arkime PCAP telemetry tests (v0.12).

Covers: sanitized expression building (injection-safe), deep-link
URL construction, honest reachability degradation, and the arkime
block present in the sessions response.
"""

import httpx
import pytest

from app import arkime
from app.config import config
from tests.conftest import login


# ------------------------------------------------------- expression
def test_build_expression_basic():
    expr = arkime.build_expression(["203.0.113.25"], ["c2.evil.test"],
                                   [443])
    # v0.16.0: nilai IP TANPA kutip - quirk Arkime 5.6.2 terverifikasi
    # live (fix §27c-4): 'ip == "x"' -> "not a valid ip". String (host)
    # tetap di-quote, port numeric polos.
    assert "ip == 203.0.113.25" in expr
    assert 'host == "c2.evil.test"' in expr
    assert "port == 443" in expr
    assert " || " in expr


def test_build_expression_drops_unsafe_values():
    # expression injection attempts must NEVER reach the expression
    expr = arkime.build_expression(
        ['203.0.113.25" || uid == "x'],
        ['evil.test" && alert == "1'],
        ["443; DROP TABLE x"])
    assert 'uid == "x"' not in expr
    assert "alert == " not in expr
    assert "DROP TABLE" not in expr
    assert expr == ""  # everything unsafe -> graceful empty


def test_build_expression_empty_inputs():
    assert arkime.build_expression([], [], []) == ""
    assert arkime.build_expression(None, None, None) == ""


# ------------------------------------------------------- deep links
def test_session_viewer_url_shape():
    url = arkime.session_viewer_url('ip == 203.0.113.25', 1760000000,
                                    1760003600)
    # v0.16.0: deep link ke PUBLIC BASE (browser lewat proxy SSO API),
    # bukan URL internal viewer - sesuai desain bake SSO (req 13).
    assert url.startswith(config.arkime_public_base.rstrip("/"))
    assert "/sessions?" in url
    assert "startTime=1760000000" in url
    assert "stopTime=1760003600" in url
    # expression is URL-encoded (spaces safe-quoted away)
    assert "expression=ip%20%3D%3D%20203.0.113.25" in url


def test_probe_unreachable_is_honest(monkeypatch):
    def _raise(*a, **kw):
        raise httpx.ConnectError("connection refused")
    monkeypatch.setattr(httpx, "get", _raise)
    status = arkime.probe()
    assert status["reachable"] is False
    assert status["error"] == "ConnectError"


def test_probe_reachable(monkeypatch):
    class _R:
        status_code = 200

    monkeypatch.setattr(httpx, "get", lambda *a, **kw: _R())
    status = arkime.probe()
    assert status["reachable"] is True
    assert status["http_status"] == 200
    assert status["latency_ms"] >= 0


# -------------------------------------------------- sessions response
def test_sessions_response_carries_arkime_block(client, monkeypatch):
    from app.routers import evidence as ev

    rows = [{
        "doc_id": "doc-1", "@timestamp": "2026-10-12T10:00:01Z",
        "source_ip": "203.0.113.25", "destination_ip": "10.0.20.15",
        "destination_port": 443, "source_engine": "suricata",
    }]
    monkeypatch.setattr(ev, "_query_sessions", lambda *a, **kw: rows)
    from datetime import datetime, timezone
    t_from = datetime(2026, 10, 12, 9, 0, tzinfo=timezone.utc)
    t_to = datetime(2026, 10, 12, 11, 0, tzinfo=timezone.utc)
    out = ev._sessions_response("alert", "alr-1", ["203.0.113.25"],
                                ["c2.evil.test"], t_from, t_to,
                                {"dir_exists": False, "file_count": 0})
    assert "arkime" in out
    assert out["arkime"]["reachable"] in (True, False)  # honest either way
    assert 'host == "c2.evil.test"' in out["arkime"]["expression"]
    assert out["arkime"]["url"]  # whole-scope deep link present
    # per-session link built from the 5-tuple
    assert out["sessions"][0]["arkime_url"]
    assert "ip%20%3D%3D" in out["sessions"][0]["arkime_url"]


def test_arkime_status_endpoint(client):
    assert login(client, "admin", "bootstrap-admin-pass-01").status_code == 200
    r = client.get("/api/evidence/arkime/status")
    assert r.status_code == 200
    body = r.json()
    # honest: in tests nothing listens on the viewer URL
    assert body["reachable"] is False
    assert body["viewer_url"]
    assert body["error"]


def test_arkime_status_requires_auth(client):
    assert client.get("/api/evidence/arkime/status").status_code == 401
