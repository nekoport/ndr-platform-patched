"""TLS hardening tests (v0.12): security headers + Secure cookie flag.

The headers are unconditional; HSTS and the cookie Secure flag follow
config.tls_enabled (TLS_ENABLED=1) so plain-HTTP demo deployments keep
working while TLS deployments are locked down.
"""

import pytest

from fastapi import Response

from app.config import config
from app.security import set_session_cookie
from tests.conftest import login


@pytest.fixture()
def client(client):
    return client


def test_security_headers_present(client):
    r = client.get("/api/meta")
    assert r.status_code == 200
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert r.headers["Cache-Control"] == "no-store"


def test_hsts_absent_over_plain_http(client):
    r = client.get("/api/meta")
    assert "Strict-Transport-Security" not in r.headers


def test_cookie_secure_off_over_http(client):
    r = login(client, "admin", "bootstrap-admin-pass-01")
    assert r.status_code == 200
    cookies = [h for h in r.headers.get_list("set-cookie")
               if h.startswith(f"{config.session_cookie}=")]
    assert cookies, "session cookie missing from login response"
    cookie = cookies[0]
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie
    assert "Secure" not in cookie  # plain HTTP demo deployment


def test_cookie_secure_on_when_tls_enabled():
    resp = Response()
    original = config.tls_enabled
    try:
        config.tls_enabled = True
        set_session_cookie(resp, "token-value")
        cookie = resp.headers["set-cookie"]
        assert "Secure" in cookie
        assert "HttpOnly" in cookie
        assert "SameSite=lax" in cookie
    finally:
        config.tls_enabled = original


def test_login_response_carries_request_id(client):
    r = client.post("/api/auth/login",
                    json={"username": "admin",
                          "password": "bootstrap-admin-pass-01"})
    assert r.headers.get("X-Request-ID")
    assert r.headers.get("X-Response-Time", "").endswith("ms")
