"""Rule manager tests: parsing, disable.conf persistence, RBAC, update flow."""

from tests.conftest import login

ADMIN = {"username": "admin", "password": "bootstrap-admin-pass-01"}

RULES_FILE = """\
# Emerging Threats generated ruleset (fixture)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Cobalt Strike Beacon Observed"; flow:established,to_server; classtype:trojan-activity; sid:2033715; rev:3;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET MALWARE Win32/Emotet Payload Delivery"; flow:established,to_server; priority:1; sid:2027865; rev:5;)
drop http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET EXPLOIT-KIT MegaCortex redirection attempt"; classtype:exploit-kit; sid:2042150; rev:2;)
alert dns $HOME_NET any -> any any (msg:"ET MALWARE DGA Domain in DNS Lookup"; classtype:misc-activity; sid:2050244; rev:4;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE TA450 Mafalda TLS SNI"; classtype:command-and-control; priority:1; sid:2046218; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET SCAN Nmap User-Agent Detected"; classtype:attempted-recon; sid:2024317; rev:4;)
alert tcp any any -> any any
this line is completely malformed
"""


def _setup_rules(monkeypatch, tmp_path, content=RULES_FILE):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)
    if content is not None:
        (rules_dir / "suricata.rules").write_text(content)
    from app.config import config
    monkeypatch.setattr(config, "rules_dir", str(rules_dir))
    monkeypatch.setattr(config, "rules_data_dir", str(tmp_path))
    monkeypatch.setattr(config, "suricata_conf", str(tmp_path / "suricata.yaml"))
    return rules_dir


def _fake_update_ok(monkeypatch, rules_dir, drop_sids=()):
    """Replace run_update with a regeneration that honours disable.conf."""
    from app import rules_engine

    def fake_run_update(timeout=None):
        lines = [ln for ln in (rules_dir / "suricata.rules")
                 .read_text().splitlines()]
        kept = []
        for ln in lines:
            sid_tokens = [s for s in ln.split(";") if "sid:" in s]
            if sid_tokens:
                try:
                    sid = int(sid_tokens[0].split(":")[1].strip())
                except (ValueError, IndexError):
                    sid = None
                if sid in drop_sids:
                    continue
            kept.append(ln)
        (rules_dir / "suricata.rules").write_text("\n".join(kept) + "\n")
        return {"ok": True, "output": "regenerated", "error": None}

    monkeypatch.setattr(rules_engine, "run_update", fake_run_update)
    monkeypatch.setattr(rules_engine, "reload_via_socket",
                        lambda timeout=15: {"ok": False,
                                            "detail": "sensor offline (test)"})


def test_parse_rules_file_counts_skipped(monkeypatch, tmp_path):
    _setup_rules(monkeypatch, tmp_path)
    from app import rules_engine
    parsed = rules_engine.parse_rules_file()
    assert len(parsed["items"]) == 6
    assert parsed["skipped"] == 2  # no-options rule + malformed line
    by_sid = {r["sid"]: r for r in parsed["items"]}
    assert by_sid[2033715]["msg"] == "ET MALWARE Cobalt Strike Beacon Observed"
    assert by_sid[2033715]["action"] == "alert"
    assert by_sid[2042150]["action"] == "drop"
    assert by_sid[2027865]["priority"] == 1


def test_disable_conf_preserves_operator_lines(monkeypatch, tmp_path):
    rules_dir = _setup_rules(monkeypatch, tmp_path)
    from app import rules_engine
    (rules_dir / "disable.conf").write_text(
        "# operator comment\nre:ETUSER.*\n2001219\n")
    rules_engine.add_disable_sid(2033715, comment="pcap review")
    assert "re:ETUSER.*" in (rules_dir / "disable.conf").read_text()
    assert "2001219" in (rules_dir / "disable.conf").read_text()
    assert "2033715" in (rules_dir / "disable.conf").read_text()
    rules_engine.remove_disable_sid(2033715)
    text = (rules_dir / "disable.conf").read_text()
    assert "2033715" not in text
    assert "re:ETUSER.*" in text and "2001219" in text


def test_rules_list_and_summary(client, monkeypatch, tmp_path):
    _setup_rules(monkeypatch, tmp_path)
    login(client, **ADMIN)
    res = client.get("/api/rules")
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 6
    assert all(it["enabled"] for it in body["items"])
    res = client.get("/api/rules/summary")
    assert res.status_code == 200
    summary = res.json()
    assert summary["total"] == 6 and summary["enabled"] == 6
    assert summary["disabled"] == 0
    assert summary["actions"]["drop"] == 1
    assert "trojan-activity" in summary["top_categories"]
    assert summary["rules_file_updated"] is not None


def test_rules_list_filters(client, monkeypatch, tmp_path):
    _setup_rules(monkeypatch, tmp_path)
    login(client, **ADMIN)
    res = client.get("/api/rules", params={"q": "cobalt"})
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) == 1 and items[0]["sid"] == 2033715
    res = client.get("/api/rules", params={"category": "exploit-kit"})
    items = res.json()["items"]
    assert len(items) == 1 and items[0]["sid"] == 2042150
    res = client.get("/api/rules", params={"status": "disabled"})
    assert res.json()["total"] == 0


def test_toggle_disable_enable_roundtrip(client, monkeypatch, tmp_path):
    rules_dir = _setup_rules(monkeypatch, tmp_path)
    _fake_update_ok(monkeypatch, rules_dir, drop_sids=(2027865,))
    login(client, **ADMIN)

    # disable: disable.conf gains the SID, regeneration drops the rule
    res = client.post("/api/rules/2027865/toggle", json={"enabled": False})
    assert res.status_code == 200
    body = res.json()
    assert body["enabled"] is False and body["update_ok"] is True
    assert "2027865" in (rules_dir / "disable.conf").read_text()

    res = client.get("/api/rules")
    items = {it["sid"]: it for it in res.json()["items"]}
    assert 2027865 in items and items[2027865]["enabled"] is False
    # metadata cache keeps the message visible for disabled rules
    assert items[2027865]["msg"] == "ET MALWARE Win32/Emotet Payload Delivery"
    assert items[2027865]["changed_by"] == "admin"
    assert res.json()["total"] == 6

    res = client.get("/api/rules/summary")
    assert res.json()["disabled"] == 1

    # re-enable: line removed from disable.conf, rule back in file
    res = client.post("/api/rules/2027865/toggle", json={"enabled": True})
    assert res.status_code == 200
    assert "2027865" not in (rules_dir / "disable.conf").read_text()
    res = client.get("/api/rules")
    items = {it["sid"]: it for it in res.json()["items"]}
    assert items[2027865]["enabled"] is True


def test_toggle_unknown_sid_404(client, monkeypatch, tmp_path):
    _setup_rules(monkeypatch, tmp_path)
    _fake_update_ok(monkeypatch, tmp_path / "rules")
    login(client, **ADMIN)
    res = client.post("/api/rules/9999999/toggle", json={"enabled": False})
    assert res.status_code == 404


def test_toggle_requires_rule_admin(client, users_seeded,
                                    monkeypatch, tmp_path):
    rules_dir = _setup_rules(monkeypatch, tmp_path)
    _fake_update_ok(monkeypatch, rules_dir)
    assert client.post("/api/rules/2033715/toggle",
                       json={"enabled": False}).status_code == 401
    login(client, username="analyst", password="Password-123456")
    assert client.post("/api/rules/2033715/toggle",
                       json={"enabled": False}).status_code == 403
    login(client, username="viewer", password="Password-123456")
    assert client.get("/api/rules").status_code == 200  # auditor may view
    assert client.post("/api/rules/2033715/toggle",
                       json={"enabled": False}).status_code == 403


def test_update_endpoint_and_audit(client, monkeypatch, tmp_path):
    rules_dir = _setup_rules(monkeypatch, tmp_path)
    _fake_update_ok(monkeypatch, rules_dir)
    login(client, **ADMIN)
    res = client.post("/api/rules/update")
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is True and body["rules_loaded"] == 6
    assert body["reloaded"] is False  # sensor offline in tests

    res = client.get("/api/audit?action=rules.update")
    assert res.status_code == 200
    assert res.json()["records"][0]["action"] == "rules.update"


def test_update_requires_rule_admin(client, users_seeded,
                                    monkeypatch, tmp_path):
    _setup_rules(monkeypatch, tmp_path)
    _fake_update_ok(monkeypatch, tmp_path / "rules")
    login(client, username="analyst", password="Password-123456")
    assert client.post("/api/rules/update").status_code == 403


def test_disabled_rule_survives_meta_cache_when_file_missing(
        client, monkeypatch, tmp_path):
    """Sensor volume without suricata.rules: UI degrades honestly."""
    rules_dir = _setup_rules(monkeypatch, tmp_path, content=None)
    login(client, **ADMIN)
    res = client.get("/api/rules")
    assert res.status_code == 200
    assert res.json()["total"] == 0
    res = client.get("/api/rules/summary")
    assert res.json()["rules_file_exists"] is False
    assert res.json()["sensor_online"] is False
