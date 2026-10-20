"""v0.11 TI feed adapter tests: STIX 2/1, TAXII 2.1, MISP.

All network access is monkeypatched at feeds._fetch_url so the tests are
offline-deterministic; fixtures use RFC 5737 documentation ranges (allowed
by the normalizer) and private IPs (must be REJECTED).
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.intel import feeds  # noqa: E402


def test_stix2_bundle_indicator_patterns():
    bundle = json.dumps({"type": "bundle", "id": "bundle-1", "objects": [
        {"type": "indicator", "spec_version": "2.1",
         "pattern": "[domain-name:value = 'c2.example.com']",
         "confidence": 80, "labels": ["c2"],
         "created": "2026-10-01T00:00:00Z"},
        {"type": "indicator", "spec_version": "2.1",
         "pattern": "[ipv4-addr:value = '203.0.113.66']"},
        # combined OR pattern with two extractable values
        {"type": "indicator", "spec_version": "2.1",
         "pattern": "[url:value = 'http://phish.example.net/login' "
                    "OR ipv4-addr:value = '198.51.100.20']"},
        # private IP must be dropped by the shared normalizer
        {"type": "indicator", "spec_version": "2.1",
         "pattern": "[ipv4-addr:value = '10.0.0.9']"},
    ]}).encode()
    iocs = feeds.parse_stix2_bundle(bundle, "stix-partner")
    values = {(i.ioc_type, i.value) for i in iocs}
    assert ("domain", "c2.example.com") in values
    assert ("ip", "203.0.113.66") in values
    assert ("url", "http://phish.example.net/login") in values
    assert ("ip", "198.51.100.20") in values
    assert not any(i.value == "10.0.0.9" for i in iocs)
    c2 = next(i for i in iocs if i.value == "c2.example.com")
    assert c2.confidence == "high"      # 80 -> high
    assert c2.tags == ["c2"]


def test_stix2_file_hashes_and_scos():
    bundle = json.dumps({"type": "bundle", "id": "bundle-2", "objects": [
        {"type": "indicator", "pattern":
            f"[file:hashes.'SHA-256' = '{'a' * 64}']"},
        {"type": "indicator", "pattern": f"[file:hashes.md5 = '{'b' * 32}']"},
        {"type": "ipv4-addr", "value": "203.0.113.99"},
        {"type": "domain-name", "value": "sco.example.org"},
    ]}).encode()
    iocs = feeds.parse_stix2_bundle(bundle, "stix-partner")
    values = {(i.ioc_type, i.value) for i in iocs}
    assert ("sha256", "a" * 64) in values
    assert ("md5", "b" * 32) in values
    assert ("ip", "203.0.113.99") in values
    assert ("domain", "sco.example.org") in values


def test_stix1_xml_document():
    xml = b"""<stix:STIX_Package xmlns:stix="http://stix.mitre.org/stix-1"
      xmlns:cybox="http://cybox.mitre.org/cybox-2">
      <stix:Indicators>
        <stix:Indicator id="ind-1">
          <cybox:Object>
            <cybox:Properties>
              <cybox:Value>203.0.113.77</cybox:Value>
            </cybox:Properties>
          </cybox:Object>
        </stix:Indicator>
        <stix:Indicator id="ind-2">
          <cybox:Object>
            <cybox:Properties>
              <cybox:Value>10.0.0.1</cybox:Value>
            </cybox:Properties>
          </cybox:Object>
        </stix:Indicator>
      </stix:Indicators>
    </stix:STIX_Package>"""
    iocs = feeds.parse_stix1_xml(xml, "stix-legacy")
    assert [(i.ioc_type, i.value) for i in iocs] == [("ip", "203.0.113.77")]


def test_fetch_stix_dispatches_by_payload(tmp_path):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps({"type": "bundle", "objects": [
        {"type": "domain-name", "value": "file-feed.example.org"}]}))
    result = feeds.fetch_stix({"name": "s", "url": f"file://{path}"},
                              timeout=5, verify=True)
    assert [i.value for i in result.iocs] == ["file-feed.example.org"]


def test_misp_event_attributes_and_confidence():
    event = {"Event": {"info": "Botnet C2 campaign", "timestamp":
                       "1727000000", "Attribute": [
        {"type": "ip-dst", "value": "203.0.113.10", "to_ids": True,
         "category": "Network activity"},
        {"type": "domain", "value": "evil.example.net", "to_ids": False},
        {"type": "filename|sha256", "value": "evil.dll|" + "c" * 64,
         "to_ids": True},
        {"type": "domain|ip", "value": "mixed.example.org|203.0.113.44",
         "to_ids": True},
        {"type": "ip-src", "value": "192.168.50.5", "to_ids": True},
        {"type": "ip-dst", "value": "198.51.100.999", "to_ids": True},
        {"type": "btc", "value": "1abc", "to_ids": True},
    ]}}
    iocs = feeds.parse_misp_event(event, "misp-community")
    got = {(i.ioc_type, i.value) for i in iocs}
    assert ("ip", "203.0.113.10") in got
    assert ("domain", "evil.example.net") in got
    assert ("sha256", "c" * 64) in got
    assert ("ip", "203.0.113.44") in got          # domain|ip -> ip half
    # private + malformed + unmapped types rejected
    assert not any("192.168" in i.value for i in iocs)
    assert not any("999" in i.value for i in iocs)
    assert not any(i.ioc_type == "btc" for i in iocs)
    ids_ip = next(i for i in iocs if i.value == "203.0.113.10")
    assert ids_ip.confidence == "high"
    assert ids_ip.malware == "Botnet C2 campaign"
    misp_ip = next(i for i in iocs if i.value == "evil.example.net")
    assert misp_ip.confidence == "medium"


def test_misp_manifest_feed_poll(monkeypatch):
    manifest = {"e" * 32: {"timestamp": 1727000000, "info": "old"},
                "f" * 32: {"timestamp": 1727100000, "info": "new"}}
    events = {
        "e" * 32: {"Event": {"timestamp": "1727000000", "Attribute": [
            {"type": "domain", "value": "old.example.org",
             "to_ids": True}]}},
        "f" * 32: {"Event": {"timestamp": "1727100000", "Attribute": [
            {"type": "ip-dst", "value": "203.0.113.55",
             "to_ids": True}]}},
    }

    def fake_fetch(url, **kw):
        if url.endswith("manifest.json"):
            return json.dumps(manifest).encode(), {}
        h = url.rsplit("/", 1)[-1].removesuffix(".json")
        return json.dumps(events[h]).encode(), {}

    monkeypatch.setattr(feeds, "_fetch_url", fake_fetch)
    result = feeds.fetch_misp(
        {"name": "misp-community", "url": "https://misp.example.org/feed/1"},
        timeout=5, verify=True)
    values = {(i.ioc_type, i.value) for i in result.iocs}
    assert ("ip", "203.0.113.55") in values
    assert ("domain", "old.example.org") in values
    assert result.version["events"] == 2


def test_misp_single_cached_event_json(monkeypatch):
    event = {"Event": {"timestamp": "1727100000", "Attribute": [
        {"type": "url", "value": "http://cache.example.net/x",
         "to_ids": True}]}}

    def fake_fetch(url, **kw):
        return json.dumps(event).encode(), {}

    monkeypatch.setattr(feeds, "_fetch_url", fake_fetch)
    result = feeds.fetch_misp(
        {"name": "m", "url": "https://misp.example.org/cache/event.json"},
        timeout=5, verify=True)
    assert [i.ioc_type for i in result.iocs] == ["url"]


def test_taxii_discovery_and_collection_poll(monkeypatch):
    stix_bundle = {"type": "bundle", "objects": [
        {"type": "indicator",
         "pattern": "[domain-name:value = 'taxii.example.com']"}]}
    calls = []

    def fake_fetch(url, headers=None, **kw):
        calls.append((url, (headers or {}).get("Accept"),
                      (headers or {}).get("Authorization")))
        if "discovery" in url:
            return json.dumps({"api_roots":
                               ["https://taxii.example.csirt/api/"]}) \
                .encode(), {}
        if url.endswith("/collections/"):
            return json.dumps({"collections": [{"id": "col-1"}]}) \
                .encode(), {}
        if url.endswith("/objects/"):
            return json.dumps(stix_bundle).encode(), {}
        raise AssertionError(f"unexpected taxii url {url}")

    monkeypatch.setattr(feeds, "_fetch_url", fake_fetch)
    result = feeds.fetch_taxii(
        {"name": "taxii-csirt",
         "url": "https://taxii.example.csirt/discovery",
         "username": "svc", "password": "pw"},
        timeout=5, verify=True)
    values = {i.value for i in result.iocs}
    assert "taxii.example.com" in values
    assert result.version["collections"] == 1
    # proper TAXII/STIX content negotiation happened
    assert calls[0][1] == feeds.TAXII_ACCEPT
    assert calls[-1][1] == feeds.TAXII_STIX_ACCEPT
    # Basic auth header present
    import base64
    assert calls[0][2] == "Basic " + base64.b64encode(b"svc:pw").decode()


def test_run_feed_dedupes_within_fetch(tmp_path):
    path = tmp_path / "dup.json"
    path.write_text(json.dumps({"type": "bundle", "objects": [
        {"type": "domain-name", "value": "dup.example.org"},
        {"type": "domain-name", "value": "dup.example.org"},
    ]}))
    result = feeds.run_feed({"name": "s", "adapter": "stix",
                             "url": f"file://{path}"}, timeout=5)
    assert len(result.iocs) == 1


def test_unknown_adapter_rejected_by_run_feed():
    with pytest.raises(ValueError, match="unknown feed adapter"):
        feeds.run_feed({"name": "x", "adapter": "magic"}, timeout=1)
