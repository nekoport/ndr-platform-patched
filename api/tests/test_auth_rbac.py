"""Auth flow + RBAC enforcement tests (backend-enforced, doc section 12)."""

from tests.conftest import login

ADMIN = {"username": "admin", "password": "bootstrap-admin-pass-01"}


def test_meta_public(client):
    res = client.get("/api/meta")
    assert res.status_code == 200
    assert res.json()["service"] == "ndr-api"


def test_bootstrap_admin_can_login(client):
    res = login(client, **ADMIN)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["role"] == "administrator"
    assert body["must_change_password"] is True


def test_wrong_password_401(client):
    res = login(client, username="admin", password="wrong-password")
    assert res.status_code == 401


def test_me_requires_auth(client):
    assert client.get("/api/auth/me").status_code == 401


def test_me_with_session(client):
    login(client, **ADMIN)
    res = client.get("/api/auth/me")
    assert res.status_code == 200
    assert res.json()["username"] == "admin"


def test_change_password_revokes_sessions(client):
    login(client, **ADMIN)
    res = client.post("/api/auth/change-password", json={
        "current_password": ADMIN["password"],
        "new_password": "BrandNew-Passw0rd-99"})
    assert res.status_code == 200
    # old session token_version invalidated
    assert client.get("/api/auth/me").status_code == 401
    # relogin works with the new password
    assert login(client, username="admin",
                 password="BrandNew-Passw0rd-99").status_code == 200


def test_rbac_user_admin_only_for_admin(client, users_seeded):
    login(client, **ADMIN)
    assert client.get("/api/users").status_code == 200

    login(client, username="analyst", password="Password-123456")
    res = client.get("/api/users")
    assert res.status_code == 403
    assert "user_admin" in res.json()["detail"]


def test_rbac_alert_update_roles(client, users_seeded):
    # auditor (read-only) may search...
    login(client, username="viewer", password="Password-123456")
    assert client.post("/api/events/search", json={
        "index": "ndr-events-read", "size": 5}).status_code == 200
    # ...but not update alerts
    res = client.patch("/api/alerts/some-id", json={"status": "closed"})
    assert res.status_code == 403


def test_lockout_after_failed_attempts(client):
    for _ in range(5):
        login(client, username="admin", password="definitely-wrong")
    res = login(client, **ADMIN)
    assert res.status_code == 423  # locked even with correct password
