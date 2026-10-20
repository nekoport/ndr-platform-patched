"""v0.11 feature tests: custom rule editor, STIX/TAXII/MISP feeds,
system settings (NTP/network/branding/diagnosis)."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from conftest import login  # noqa: E402

VALID_RULE = ("alert http $EXTERNAL_NET any -> $HOME_NET 80 "
              "(msg:\"NDRLAB Suspicious UA\"; flow:established,to_server; "
              "http.user_agent; content:\"ndr-lab-agent\"; "
              "classtype:attempted-recon; sid:1000001; rev:1;)")


def _login(client, username="admin", password="bootstrap-admin-pass-01"):
    res = login(client, username, password)
    assert res.status_code == 200, res.text
    return res


def _engineer(client):
    res = login(client, "engineer", "Password-123456")
    assert res.status_code == 200
    return res


# ------------------------------------------------------------ custom rules
def test_validate_rule_ok_and_bad(client):
    _login(client)
    res = client.post("/api/rules/validate", json={"rule_text": VALID_RULE})
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is True
    assert body["parsed"]["sid"] == 1000001
    assert body["parsed"]["action"] == "alert"

    bad = client.post("/api/rules/validate", json={"rule_text":
                      "alert http src any (no sid here)"})
    assert bad.status_code == 200
    assert bad.json()["ok"] is False


def test_validate_rejects_foreign_sid_range(client):
    _login(client)
    res = client.post("/api/rules/validate", json={"rule_text":
                      "alert http any any -> any 80 "
                      "(msg:\"ET foreign\"; sid:2027865; rev:1;)"})
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is False
    assert "1000000" in body["error"].replace(",", "")


def test_custom_rule_crud_flow(client):
    _login(client)
    # auto-sid when the text carries none? text must carry one: use 1000001
    res = client.post("/api/rules/custom",
                      json={"rule_text": VALID_RULE, "enabled": True})
    assert res.status_code == 201, res.text
    rule = res.json()
    assert rule["sid"] == 1000001
    assert rule["msg"] == "NDRLAB Suspicious UA"

    # duplicate rejected
    dup = client.post("/api/rules/custom", json={"rule_text": VALID_RULE})
    assert dup.status_code == 409

    # appears in the unified list flagged custom
    lst = client.get("/api/rules").json()
    mine = [r for r in lst["items"] if r.get("custom")]
    assert any(r["sid"] == 1000001 for r in mine)

    # update text (rev bump)
    upd = client.put("/api/rules/custom/1000001", json={
        "rule_text": VALID_RULE.replace("rev:1", "rev:2")
                               .replace("Suspicious UA", "Suspicious UA v2")})
    assert upd.status_code == 200, upd.text
    assert upd.json()["msg"] == "NDRLAB Suspicious UA v2"
    assert upd.json()["rev"] == 2

    # disable via enabled flag
    dis = client.put("/api/rules/custom/1000001", json={"enabled": False})
    assert dis.status_code == 200
    assert dis.json()["enabled"] is False

    # sid declared in text must match the path sid
    wrong = client.put("/api/rules/custom/1000001", json={
        "rule_text": VALID_RULE.replace("sid:1000001", "sid:1000002")})
    assert wrong.status_code == 422

    # delete
    dele = client.delete("/api/rules/custom/1000001")
    assert dele.status_code == 204
    gone = client.get("/api/rules/custom").json()
    assert all(r["sid"] != 1000001 for r in gone["items"])


def test_custom_rule_editor_reserves_sid_on_create(client):
    _login(client)
    text = VALID_RULE.replace("sid:1000001", "sid:1000042")
    res = client.post("/api/rules/custom",
                      json={"rule_text": text, "sid": 1000099})
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["sid"] == 1000099
    assert "sid:1000099" in body["rule_text"]
    client.delete("/api/rules/custom/1000099")


def test_custom_rule_rbac(client, users_seeded):
    _engineer(client)
    # engineer HAS rule_admin: allowed
    ok = client.post("/api/rules/validate", json={"rule_text": VALID_RULE})
    assert ok.status_code == 200
    # analyst does not
    login(client, "analyst", "Password-123456")
    denied = client.post("/api/rules/custom", json={"rule_text": VALID_RULE})
    assert denied.status_code == 403


def test_summary_counts_custom_rules(client):
    _login(client)
    client.post("/api/rules/custom", json={"rule_text": VALID_RULE})
    s = client.get("/api/rules/summary").json()
    assert s["total"] >= 1
    client.delete("/api/rules/custom/1000001")


# ------------------------------------------------------- TI standard feeds
def test_create_feed_standard_adapters(client):
    _login(client)
    for adapter, cfg in (("stix", {}),
                         ("taxii", {"username": "svc",
                                    "password": "s3cret",
                                    "collection_id": "abc"}),
                         ("misp", {"max_events": 25})):
        res = client.post("/api/ti/feeds", json={
            "name": f"v011-{adapter}", "adapter": adapter,
            "url": f"https://ti.example.org/{adapter}",
            "config": cfg, "enabled": False, "schedule_min": 60,
            "ttl_days": 14})
        assert res.status_code == 201, res.text
        body = res.json()
        assert body["adapter"] == adapter
        if adapter == "taxii":
            # credentials must be masked on every read path
            assert body["config"]["password"] == "*****"


def test_create_feed_unknown_adapter_rejected(client):
    _login(client)
    res = client.post("/api/ti/feeds", json={
        "name": "v011-bad", "adapter": "suricata-et-magic",
        "url": "https://x.example.org"})
    assert res.status_code == 422


# --------------------------------------------------------- system settings
def test_settings_defaults_and_rename(client):
    _login(client)
    cur = client.get("/api/settings").json()
    assert cur["system"]["name"] == "NDR Console"
    assert cur["ntp"]["timezone"] == "Asia/Jakarta"
    assert isinstance(cur["network"]["interfaces"], list)

    res = client.patch("/api/settings/system",
                       json={"name": "SOC Nusantara",
                             "tagline": "NDR BSSN lab"})
    assert res.status_code == 200
    assert res.json()["name"] == "SOC Nusantara"
    assert client.get("/api/settings").json()["system"]["name"] == \
        "SOC Nusantara"


def test_settings_rbac(client, users_seeded):
    _engineer(client)
    res = client.patch("/api/settings/system", json={"name": "nope"})
    assert res.status_code == 403


def test_ntp_patch_and_validation(client):
    _login(client)
    ok = client.patch("/api/settings/ntp", json={
        "servers": ["time.google.com", "id.pool.ntp.org"],
        "timezone": "Asia/Makassar", "enabled": True})
    assert ok.status_code == 200
    bad = client.patch("/api/settings/ntp", json={"timezone": "Mars/Olympus"})
    assert bad.status_code == 422
    bad_srv = client.patch("/api/settings/ntp", json={
        "servers": ["time.google.com; reboot"]})
    assert bad_srv.status_code == 422


def test_ntp_status_degrades_gracefully(client):
    _login(client)
    res = client.post("/api/settings/ntp/status")
    assert res.status_code == 200
    body = res.json()
    assert "available" in body
    assert body["config"]["timezone"]


def test_branding_data_url_roundtrip(client):
    _login(client)
    png = ("data:image/png;base64,"
           "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
           "YPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
    res = client.patch("/api/settings/branding", json={"logo_data_url": png})
    assert res.status_code == 200
    assert client.get("/api/settings").json()["branding"]["logo"] == png
    bad = client.patch("/api/settings/branding",
                       json={"logo_data_url": "data:text/html;base64,PGI+"})
    assert bad.status_code == 422
    reset = client.patch("/api/settings/branding", json={"reset_logo": True})
    assert reset.status_code == 200
    assert client.get("/api/settings").json()["branding"]["logo"] is None


def test_network_patch_honest_about_container(client):
    _login(client)
    res = client.patch("/api/settings/network", json={
        "hostname": "ndr-node-01", "dns_servers": ["9.9.9.9"]})
    assert res.status_code == 200
    body = res.json()
    assert body["hostname"] == "ndr-node-01"
    # container: hostnamectl is unavailable -> applied false + guidance
    assert body["applied"] is False
    assert body["notes"]


def test_diagnosis_dns_and_guard(client, monkeypatch):
    _login(client)
    # Deterministic resolver answer: a loaded CI sandbox can transiently
    # fail the real getaddrinfo("localhost") (temporary name-resolution
    # failure), which made this test flaky. What we test here is the
    # endpoint logic (resolve -> output), not the OS resolver itself.
    import socket as _socket
    fake_infos = [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "",
                   ("127.0.0.1", 0))]
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **k: fake_infos)
    res = client.post("/api/settings/diagnosis",
                      json={"tool": "dns", "target": "localhost"})
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is True
    assert "127.0.0.1" in body["output"] or "::1" in body["output"]

    # shell injection target is rejected by the schema validator
    bad = client.post("/api/settings/diagnosis",
                      json={"tool": "ping", "target": "8.8.8.8; rm -rf /"})
    assert bad.status_code == 422

    # unknown tool rejected
    wrong = client.post("/api/settings/diagnosis",
                        json={"tool": "nmap", "target": "localhost"})
    assert wrong.status_code == 422

    # port tool against a closed port degrades honestly
    port = client.post("/api/settings/diagnosis",
                       json={"tool": "port", "target": "127.0.0.1",
                             "port": 59999})
    assert port.status_code == 200
    assert port.json()["ok"] is False


def test_diagnosis_rbac(client, users_seeded):
    _engineer(client)  # sensor_admin covers admin+engineer
    ok = client.post("/api/settings/diagnosis",
                     json={"tool": "dns", "target": "localhost"})
    assert ok.status_code == 200
    login(client, "analyst", "Password-123456")
    denied = client.post("/api/settings/diagnosis",
                         json={"tool": "dns", "target": "localhost"})
    assert denied.status_code == 403
