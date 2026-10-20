"""Threat feed adapters (doc section 9.1, 9.2).

Each adapter knows how to fetch one feed over a secure connection (or a
local file for PoC / offline evaluation), validate the payload schema, and
normalize entries into `RawIoc` records.

Normalization rules:
  * domain: lowercased, trailing dot stripped
  * ip: "ip:port" collapsed to the IP; private / loopback / link-local
    addresses are REJECTED (internal indicators would cause self-matches)
  * url: must parse with http/https scheme and a hostname
  * hash: hex string of length 32/40/64 -> md5/sha1/sha256

Feeds implemented (small, no-auth, verifiable starters per doc 9.1):
  * urlhaus    - URLhaus csv_recent (abuse.ch, CC BY 4.0)
  * threatfox  - ThreatFox JSON API (abuse.ch, CC BY 4.0)
  * feodo      - Feodo Tracker C2 ipblocklist.json (abuse.ch, CC BY 4.0)
  * file       - local JSONL fixture (offline PoC / tests)
  * stix       - STIX 2.x bundle JSON or STIX 1.x XML document (v0.11)
  * taxii      - TAXII 2.1 collection objects poll (Basic auth) (v0.11)
  * misp       - MISP feed manifest + event JSON (v0.11)

Production hardening notes live in docs/OPERATIONS.md (TI runbook).
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

USER_AGENT = "ndr-platform-ti/0.4 (+self-hosted NDR; local use)"
MAX_FEED_BYTES = 26_214_400  # 25 MB hard cap
DEFAULT_TIMEOUT = 30

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]([a-z0-9-]{0,61}[a-z0-9])?$")
HASH_RE = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$")
_DOC_RANGES = tuple(ipaddress.ip_network(c) for c in
                    ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))

VALID_TYPES = ("ip", "domain", "url", "md5", "sha1", "sha256")
CONFIDENCE_LEVELS = ("high", "medium", "low")


@dataclass
class RawIoc:
    ioc_type: str
    value: str
    source: str
    confidence: str = "medium"
    malware: str | None = None
    tags: list[str] = field(default_factory=list)
    published: datetime | None = None
    reference: str | None = None


@dataclass
class FeedResult:
    iocs: list[RawIoc]
    version: dict | None = None       # last-modified / etag / row count info
    warnings: list[str] = field(default_factory=list)


def confidence_from_score(score) -> str:
    try:
        score = int(score)
    except (TypeError, ValueError):
        return "medium"
    if score >= 75:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


# ---------------------------------------------------------------- helpers

def normalize_domain(value: str) -> str | None:
    v = value.strip().lower().rstrip(".")
    if not v or len(v) > 253 or " " in v:
        return None
    if DOMAIN_RE.match(v):
        return v
    return None


def normalize_ip(value: str) -> str | None:
    """Collapse 'ip:port', reject private/reserved ranges.

    RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24) are explicitly ALLOWED: fixtures, demos and docs use
    them, and real internal hosts never do - so no self-match noise.
    """
    v = value.strip().lower()
    if v.startswith("[") and "]" in v:            # [ipv6]:port
        v = v.split("]")[0].lstrip("[")
    elif v.count(":") == 1:                        # ipv4:port
        v = v.split(":")[0]
    try:
        addr = ipaddress.ip_address(v)
    except ValueError:
        return None
    doc_range = any(addr in net for net in _DOC_RANGES)
    if not doc_range and (addr.is_private or addr.is_loopback
                          or addr.is_link_local or addr.is_multicast
                          or addr.is_reserved or addr.is_unspecified):
        return None
    return str(addr)


def normalize_url(value: str) -> str | None:
    v = value.strip()
    if not v.lower().startswith(("http://", "https://")) or len(v) > 2048:
        return None
    host = v.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].split("@")[-1]
    if normalize_ip(host) is None and normalize_domain(host) is None:
        return None
    return v


def normalize_hash(value: str) -> str | None:
    v = value.strip().lower()
    if HASH_RE.match(v):
        return v
    return None


def normalize_ioc(ioc_type: str, value: str) -> tuple[str, str] | None:
    """Validate + normalize (type, value). Returns None when rejectable."""
    value = (value or "").strip()
    if not value or len(value) > 2048:
        return None
    if ioc_type == "ip":
        ip = normalize_ip(value)
        return ("ip", ip) if ip else None
    if ioc_type == "domain":
        d = normalize_domain(value)
        return ("domain", d) if d else None
    if ioc_type == "url":
        u = normalize_url(value)
        return ("url", u) if u else None
    if ioc_type in ("md5", "sha1", "sha256", "hash"):
        h = normalize_hash(value)
        if not h:
            return None
        inferred = {"32": "md5", "40": "sha1", "64": "sha256"}[str(len(h))]
        return (inferred, h)
    if ioc_type in VALID_TYPES:
        return (ioc_type, value.lower())
    return None


def sniff_ioc(value: str) -> tuple[str, str] | None:
    """Infer IOC type when the feed does not label it."""
    v = (value or "").strip()
    if not v:
        return None
    if normalize_url(v):
        return ("url", normalize_url(v))
    if normalize_hash(v):
        return normalize_hash(v) and sniff_hash(v)
    if normalize_ip(v):
        return ("ip", normalize_ip(v))
    if normalize_domain(v):
        return ("domain", normalize_domain(v))
    return None


def sniff_hash(value: str):
    h = normalize_hash(value)
    if not h:
        return None
    return ({"32": "md5", "40": "sha1", "64": "sha256"}[len(h)], h)


def _parse_dt(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = str(value).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s.replace("+00:00", "Z") if fmt.endswith("Z") else s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _fetch_url(url: str, *, timeout: int, verify: bool,
               method: str = "GET", body: dict | None = None,
               headers: dict | None = None) -> tuple[bytes, dict]:
    """HTTP(S) fetch with size cap; returns (payload, meta)."""
    req = urllib.request.Request(url, method=method,
                                 headers={"User-Agent": USER_AGENT,
                                          **(headers or {})})
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    ctx = None
    if url.lower().startswith("https") and not verify:
        import ssl
        ctx = ssl._create_unverified_context()  # noqa: SLF001 - opt-in only
    with urllib.request.urlopen(req, data=data, timeout=timeout, context=ctx) as resp:
        meta = {"url": url, "last_modified": resp.headers.get("Last-Modified"),
                "etag": resp.headers.get("ETag"),
                "final_url": resp.geturl()}
        payload = resp.read(MAX_FEED_BYTES + 1)
    if len(payload) > MAX_FEED_BYTES:
        raise ValueError(f"feed payload exceeds {MAX_FEED_BYTES} bytes cap")
    return payload, meta


# ---------------------------------------------------------------- adapters

def fetch_urlhaus(feed_cfg: dict, *, timeout: int, verify: bool) -> FeedResult:
    """URLhaus recent payload URLs (CSV, '#'-prefixed comments)."""
    url = feed_cfg.get("url", "https://urlhaus.abuse.ch/downloads/csv_recent/")
    payload, meta = _fetch_url(url, timeout=timeout, verify=verify)
    text = payload.decode("utf-8", errors="replace")
    iocs, skipped = [], 0
    reader = csv.DictReader(io.StringIO(
        "\n".join(l for l in text.splitlines() if not l.startswith("#"))))
    for row in reader:
        parsed = normalize_ioc("url", row.get("url", ""))
        if parsed is None:
            skipped += 1
            continue
        iocs.append(RawIoc(
            ioc_type="url", value=parsed[1], source=feed_cfg["name"],
            confidence="medium",
            malware=(row.get("threat") or None),
            tags=[t for t in (row.get("tags") or "").split(",") if t][:4],
            published=_parse_dt(row.get("date_added")),
            reference=row.get("urlhaus_link") or None))
    meta["rows"] = len(iocs)
    warnings = [f"{skipped} rows skipped (invalid/private)"] if skipped else []
    return FeedResult(iocs=iocs, version=meta, warnings=warnings)


def fetch_threatfox(feed_cfg: dict, *, timeout: int, verify: bool) -> FeedResult:
    """ThreatFox API get_iocs (JSON POST)."""
    url = feed_cfg.get("url", "https://threatfox.abuse.ch/api/v1/")
    days = int(feed_cfg.get("days", 2))
    payload, meta = _fetch_url(url, timeout=timeout, verify=verify,
                               method="POST",
                               body={"query": "get_iocs", "days": days})
    data = json.loads(payload.decode("utf-8", errors="replace"))
    if data.get("query_status") not in ("ok", "no_result"):
        raise ValueError(f"threatfox query_status={data.get('query_status')!r}")
    iocs, skipped = [], 0
    for item in data.get("data") or []:
        raw = item.get("ioc") or ""
        # threatfox 'ioc' may be 'ip:port', 'domain', 'url', or a hash
        parsed = (normalize_ioc("url", raw) if "://" in raw
                  else sniff_ioc(raw) or (None, None))
        if parsed is None or parsed[1] is None:
            skipped += 1
            continue
        ioc_type, value = parsed
        iocs.append(RawIoc(
            ioc_type=ioc_type, value=value, source=feed_cfg["name"],
            confidence=confidence_from_score(item.get("confidence", 50)),
            malware=item.get("malware") or None,
            tags=[t for t in (item.get("tags") or []) if t][:4],
            published=_parse_dt(item.get("first_seen")) or _parse_dt(item.get("last_seen")),
            reference=item.get("reference") or None))
    meta["rows"] = len(iocs)
    warnings = [f"{skipped} rows skipped (invalid/private)"] if skipped else []
    return FeedResult(iocs=iocs, version=meta, warnings=warnings)


def fetch_feodo(feed_cfg: dict, *, timeout: int, verify: bool) -> FeedResult:
    """Feodo Tracker C2 IP blocklist (JSON array)."""
    url = feed_cfg.get("url",
                       "https://feodotracker.abuse.ch/downloads/ipblocklist.json")
    payload, meta = _fetch_url(url, timeout=timeout, verify=verify)
    data = json.loads(payload.decode("utf-8", errors="replace"))
    iocs, skipped = [], 0
    if not isinstance(data, list):
        raise ValueError("feodo feed: expected JSON array")
    for item in data:
        parsed = normalize_ioc("ip", item.get("ip_address", ""))
        if parsed is None:
            skipped += 1
            continue
        iocs.append(RawIoc(
            ioc_type="ip", value=parsed[1], source=feed_cfg["name"],
            confidence=confidence_from_score(item.get("confidence_level", 75)),
            malware=item.get("malware") or None,
            published=_parse_dt(item.get("first_seen")),
            reference="https://feodotracker.abuse.ch"))
    meta["rows"] = len(iocs)
    warnings = [f"{skipped} rows skipped (invalid/private)"] if skipped else []
    return FeedResult(iocs=iocs, version=meta, warnings=warnings)


def fetch_file(feed_cfg: dict, *, timeout: int, verify: bool) -> FeedResult:
    """Local JSONL fixture: one JSON object per line.

    Fields: type|value required; confidence, malware, tags, published,
    reference optional. Used for offline PoC, replay demos and tests.
    """
    path = feed_cfg.get("path") or feed_cfg.get("url") or ""
    with open(path, "rb") as fh:
        payload = fh.read(MAX_FEED_BYTES + 1)
    if len(payload) > MAX_FEED_BYTES:
        raise ValueError("fixture exceeds size cap")
    iocs, skipped = [], 0
    for line in payload.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        raw_type = (item.get("type") or "").strip().lower()
        raw_value = item.get("value") or ""
        parsed = (normalize_ioc(raw_type, raw_value) if raw_type
                  else sniff_ioc(raw_value))
        if parsed is None:
            skipped += 1
            continue
        conf = (item.get("confidence") or "medium").strip().lower()
        if conf not in CONFIDENCE_LEVELS:
            conf = "medium"
        tags = item.get("tags") or []
        if isinstance(tags, str):
            tags = [t for t in tags.split(",") if t]
        iocs.append(RawIoc(
            ioc_type=parsed[0], value=parsed[1], source=feed_cfg["name"],
            confidence=conf, malware=item.get("malware") or None,
            tags=tags[:4], published=_parse_dt(item.get("published")),
            reference=item.get("reference") or None))
    import os
    meta = {"url": path, "rows": len(iocs),
            "mtime": int(os.path.getmtime(path)) if os.path.exists(path) else None}
    warnings = [f"{skipped} rows skipped (invalid)"] if skipped else []
    return FeedResult(iocs=iocs, version=meta, warnings=warnings)


# ------------------------------------------------ standard formats (v0.11)
# STIX 2.x pattern LHS -> ioc_type (values are matched with the same
# normalizers as every other feed, so private IPs etc. stay rejected).
_STIX_OBJ_MAP = {
    "domain-name:value": "domain",
    "url:value": "url",
    "ipv4-addr:value": "ip",
    "ipv6-addr:value": "ip",
    "email-addr:value": "domain",
}
_STIX_HASH_MAP = {
    "md5": "md5", "sha-1": "sha1", "sha1": "sha1",
    "sha-256": "sha256", "sha256": "sha256",
}
# full LHS capture incl. property path + quoted hash algos:
#   domain-name:value / ipv4-addr:value / file:hashes.'SHA-256' / url:value
_STIX_PATTERN = re.compile(r"([A-Za-z0-9_.:'-]+)\s*=\s*'([^']+)'")
_STIX_HASH_KEY = re.compile(r"^file:hashes\.?'?([A-Za-z0-9-]+)'?$", re.I)

TAXII_ACCEPT = "application/taxii+json;version=2.1"
TAXII_STIX_ACCEPT = "application/stix+json;version=2.1"
MISP_TYPE_MAP = {
    "ip-dst": "ip", "ip-src": "ip", "ip": "ip", "ip-dst|port": "ip",
    "ip-src|port": "ip", "domain": "domain", "hostname": "domain",
    "domain|ip": "domain", "url": "url", "uri": "url", "link": "url",
    "md5": "md5", "sha1": "sha1", "sha256": "sha256",
    "filename|md5": "md5", "filename|sha1": "sha1",
    "filename|sha256": "sha256",
}


def _stix_pattern_iocs(pattern: str) -> list[tuple[str, str]]:
    """Extract (ioc_type, value) pairs from one STIX 2 pattern."""
    out: list[tuple[str, str]] = []
    for key, value in _STIX_PATTERN.findall(pattern or ""):
        key_l = key.lower()
        if key_l in _STIX_OBJ_MAP:
            parsed = normalize_ioc(_STIX_OBJ_MAP[key_l], value)
            if parsed:
                out.append(parsed)
        else:
            hash_m = _STIX_HASH_KEY.match(key_l)
            if hash_m:
                algo = _STIX_HASH_MAP.get(
                    hash_m.group(1).lower().replace("_", "-"),
                    hash_m.group(1).lower())
                parsed = normalize_ioc(algo, value)
                if parsed:
                    out.append(parsed)
    return out


def parse_stix2_bundle(payload: bytes, source: str) -> list[RawIoc]:
    """Parse a STIX 2.x bundle (or raw object list) into RawIoc records.

    Handles: indicator.pattern expressions, and plain SCOs that carry a
    `value` (domain-name / url / ipv4-addr / ipv6-addr / email-addr) or
    `hashes` (file). Everything goes through the shared normalizers, so
    private IPs and malformed values stay rejected like every other feed.
    """
    data = json.loads(payload.decode("utf-8", errors="replace"))
    objects = data.get("objects", []) if isinstance(data, dict) else data
    if not isinstance(objects, list):
        raise ValueError("stix feed: expected a bundle object list")
    iocs: list[RawIoc] = []
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        conf = confidence_from_score(obj["confidence"]) \
            if obj.get("confidence") is not None else "medium"
        labels = obj.get("labels") or []
        if isinstance(labels, str):
            labels = [labels]
        tags = [str(x)[:32] for x in labels[:4]]
        malware = str(obj.get("name"))[:128] if obj.get("name") else None
        published = _parse_dt(obj.get("created"))
        otype = str(obj.get("type") or "")
        if otype == "indicator" and obj.get("pattern"):
            for ioc_type, value in _stix_pattern_iocs(obj["pattern"]):
                iocs.append(RawIoc(
                    ioc_type=ioc_type, value=value, source=source,
                    confidence=conf, malware=malware, tags=tags,
                    published=published))
        elif otype in ("domain-name", "url", "ipv4-addr", "ipv6-addr",
                       "email-addr") and obj.get("value"):
            mapped = _STIX_OBJ_MAP.get(f"{otype}:value")
            if mapped:
                parsed = normalize_ioc(mapped, str(obj["value"]))
                if parsed:
                    iocs.append(RawIoc(
                        ioc_type=parsed[0], value=parsed[1], source=source,
                        confidence=conf, malware=malware, tags=tags,
                        published=published))
        elif otype == "file" and isinstance(obj.get("hashes"), dict):
            for algo, value in obj["hashes"].items():
                norm = _STIX_HASH_MAP.get(
                    algo.lower().replace("_", "-"), algo.lower())
                parsed = normalize_ioc(norm, str(value))
                if parsed:
                    iocs.append(RawIoc(
                        ioc_type=parsed[0], value=parsed[1], source=source,
                        confidence=conf, malware=malware, tags=tags,
                        published=published))
    return iocs


def parse_stix1_xml(payload: bytes, source: str) -> list[RawIoc]:
    """Parse STIX 1.x / CybOX XML (namespace-agnostic, stdlib only)."""
    import xml.etree.ElementTree as ET
    root = ET.fromstring(payload)
    iocs: list[RawIoc] = []
    for val in root.iter():
        tag = val.tag.rsplit("}", 1)[-1].lower()
        if tag == "value" and val.text:
            parsed = sniff_ioc(val.text)
            if parsed:
                iocs.append(RawIoc(ioc_type=parsed[0], value=parsed[1],
                                   source=source, confidence="medium"))
    return iocs


def fetch_stix(feed_cfg: dict, *, timeout: int, verify: bool) -> FeedResult:
    """STIX document: STIX 2.x bundle JSON (default) or STIX 1.x XML."""
    import os
    source = feed_cfg["name"]
    url = feed_cfg.get("url") or ""
    if url.startswith("file://"):
        path = url[7:]
        with open(path, "rb") as fh:
            payload = fh.read(MAX_FEED_BYTES + 1)
        meta = {"url": url, "mtime": int(os.path.getmtime(path))
                if os.path.exists(path) else None}
    else:
        payload, meta = _fetch_url(url, timeout=timeout, verify=verify)
    if len(payload) > MAX_FEED_BYTES:
        raise ValueError("stix payload exceeds size cap")
    head = payload.lstrip()[:64].lstrip()
    if head.startswith(b"{") or head.startswith(b"["):
        iocs = parse_stix2_bundle(payload, source)
    elif head.startswith(b"<"):
        iocs = parse_stix1_xml(payload, source)
    else:
        raise ValueError("stix feed: payload is neither JSON nor XML")
    meta["rows"] = len(iocs)
    return FeedResult(iocs=iocs, version=meta)


def fetch_taxii(feed_cfg: dict, *, timeout: int, verify: bool) -> FeedResult:
    """TAXII 2.1 collection poll (Basic auth optional).

    Config: url (api-root OR discovery root), collection_id (optional -
    all collections on the api-root are polled when absent, capped),
    username/password, limit (max objects per collection).
    """
    import base64
    source = feed_cfg["name"]
    url = (feed_cfg.get("url") or "").rstrip("/")
    if not url:
        raise ValueError("taxii feed: url is required")
    username = feed_cfg.get("username")
    password = feed_cfg.get("password")
    headers = {"Accept": TAXII_ACCEPT}
    if username:
        token = base64.b64encode(
            f"{username}:{password or ''}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    limit = int(feed_cfg.get("limit", 5000))

    def _get(u: str, accept: str) -> bytes:
        h = {**headers, "Accept": accept}
        payload, _meta = _fetch_url(u, timeout=timeout, verify=verify,
                                    headers=h)
        return payload

    api_root = url
    if re.search(r"/discovery[/A-Za-z0-9_-]*$", url) \
            or "api-root" not in url and url.count("/") <= 2:
        # discovery endpoint: pick the first api-root advertised
        disc = json.loads(_get(url, TAXII_ACCEPT).decode("utf-8",
                                                         errors="replace"))
        roots = disc.get("api_roots") or []
        if not roots:
            raise ValueError("taxii discovery advertised no api_roots")
        api_root = str(roots[0]).rstrip("/")
    collections_url = f"{api_root}/collections/"
    cols = json.loads(_get(collections_url, TAXII_ACCEPT)
                      .decode("utf-8", errors="replace"))
    col_list = cols.get("collections", []) if isinstance(cols, dict) else cols
    wanted = feed_cfg.get("collection_id")
    ids = [c.get("id") for c in col_list
           if isinstance(c, dict) and c.get("id")
           and (not wanted or c.get("id") == wanted)][:10]
    if not ids:
        raise ValueError("taxii feed: no matching collection found")
    iocs: list[RawIoc] = []
    for cid in ids:
        obj_url = f"{api_root}/collections/{cid}/objects/"
        bundle = _get(obj_url, TAXII_STIX_ACCEPT)
        iocs.extend(parse_stix2_bundle(bundle, source)[:limit])
    version_meta = {"url": api_root, "collections": len(ids),
                    "rows": len(iocs)}
    return FeedResult(iocs=iocs, version=version_meta)


def _misp_attribute_ioc(attr: dict) -> tuple[str, str, str | None] | None:
    """Map one MISP attribute to a normalized (type, value, note)."""
    raw_type = str(attr.get("type") or "").strip().lower()
    raw_value = str(attr.get("value") or "").strip()
    if not raw_value or attr.get("deleted"):
        return None
    ioc_type = MISP_TYPE_MAP.get(raw_type)
    if ioc_type is None:
        return None
    if "|" in raw_value:
        left, right = raw_value.split("|", 1)
        if raw_type.startswith("filename|"):
            raw_value = right          # the hash is the indicator
        elif raw_type == "domain|ip":
            ioc_type = "ip"            # the IP half becomes the indicator
            raw_value = right
        elif raw_type in ("ip-dst|port", "ip-src|port"):
            raw_value = left           # the IP half
    parsed = normalize_ioc(ioc_type, raw_value)
    if not parsed:
        return None
    note = attr.get("category") or None
    return (parsed[0], parsed[1], note)


def parse_misp_event(data: dict, source: str) -> list[RawIoc]:
    """Parse one MISP event JSON (feed file or API response)."""
    event = data.get("Event") if isinstance(data, dict) else None
    attrs = (event or data).get("Attribute") or []
    if not isinstance(attrs, list):
        raise ValueError("misp event: Attribute must be a list")
    info = str((event or {}).get("info") or "")[:128] or None
    published = _parse_dt((event or {}).get("timestamp"))
    ts = (event or {}).get("timestamp")
    if published is None and ts:
        try:
            published = datetime.fromtimestamp(int(ts), tz=timezone.utc)
        except (TypeError, ValueError, OverflowError):
            published = None
    iocs: list[RawIoc] = []
    for attr in attrs:
        if not isinstance(attr, dict):
            continue
        mapped = _misp_attribute_ioc(attr)
        if mapped is None:
            continue
        ioc_type, value, note = mapped
        to_ids = bool(attr.get("to_ids"))
        tags = [t.get("name", "") for t in (attr.get("Tag") or [])
                if isinstance(t, dict) and t.get("name")][:4]
        iocs.append(RawIoc(
            ioc_type=ioc_type, value=value, source=source,
            confidence="high" if to_ids else "medium",
            malware=info or note, tags=tags, published=published))
    return iocs


def fetch_misp(feed_cfg: dict, *, timeout: int, verify: bool) -> FeedResult:
    """MISP feed: manifest.json + per-event JSON files (capped), or a
    single cached event JSON when the URL points straight at one."""
    source = feed_cfg["name"]
    base = (feed_cfg.get("url") or "").rstrip("/")
    if not base:
        raise ValueError("misp feed: url is required")
    max_events = int(feed_cfg.get("max_events", 50))

    def _fetch_rel(rel: str) -> bytes:
        target = base if base.endswith(".json") else f"{base}/{rel}"
        payload, _meta = _fetch_url(target, timeout=timeout, verify=verify)
        return payload

    iocs: list[RawIoc] = []
    if base.endswith(".json"):
        payload = _fetch_rel("")
        data = json.loads(payload.decode("utf-8", errors="replace"))
        iocs.extend(parse_misp_event(data, source))
        meta = {"url": base, "events": 1, "rows": len(iocs)}
        return FeedResult(iocs=iocs, version=meta)

    manifest = json.loads(_fetch_rel("manifest.json")
                          .decode("utf-8", errors="replace"))
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError("misp feed: manifest.json is empty or invalid")
    # newest events first (manifest timestamp is unix epoch)
    ranked = sorted(manifest.items(),
                    key=lambda kv: int(kv[1].get("timestamp", 0))
                    if isinstance(kv[1], dict) else 0,
                    reverse=True)[:max_events]
    skipped = 0
    for event_hash, _info in ranked:
        try:
            event_json = json.loads(
                _fetch_rel(f"{event_hash}.json").decode("utf-8",
                                                        errors="replace"))
        except (ValueError, urllib.error.URLError):
            skipped += 1
            continue
        iocs.extend(parse_misp_event(event_json, source))
    meta = {"url": base, "events": len(ranked) - skipped, "rows": len(iocs)}
    warnings = ([f"{skipped} event file(s) skipped (fetch/parse error)"]
                if skipped else [])
    return FeedResult(iocs=iocs, version=meta, warnings=warnings)


ADAPTERS = {
    "urlhaus": fetch_urlhaus,
    "threatfox": fetch_threatfox,
    "feodo": fetch_feodo,
    "file": fetch_file,
    "stix": fetch_stix,
    "taxii": fetch_taxii,
    "misp": fetch_misp,
}


def run_feed(feed_cfg: dict, *, timeout: int = DEFAULT_TIMEOUT,
             verify: bool = True) -> FeedResult:
    """Execute one feed fetch. Raises on transport/schema failure."""
    adapter = ADAPTERS.get(feed_cfg.get("adapter", ""))
    if adapter is None:
        raise ValueError(f"unknown feed adapter {feed_cfg.get('adapter')!r}; "
                         f"known: {', '.join(sorted(ADAPTERS))}")
    result = adapter(feed_cfg, timeout=timeout, verify=verify)
    # dedupe within one fetch (same value may appear twice upstream)
    seen: set[tuple[str, str]] = set()
    unique: list[RawIoc] = []
    for ioc in result.iocs:
        key = (ioc.ioc_type, ioc.value)
        if key in seen:
            continue
        seen.add(key)
        unique.append(ioc)
    result.iocs = unique
    return result


def resolve_dns_safety(url: str) -> bool:
    """Cheap SSRF guard helper: reject obviously local feed URLs."""
    try:
        host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        addr = ipaddress.ip_address(socket.gethostbyname(host))
        return not (addr.is_private or addr.is_loopback or addr.is_link_local)
    except Exception:  # noqa: BLE001 - DNS failure surfaces at fetch time
        return True


def default_feed_definitions() -> list[dict]:
    """Starter feed set (doc 9.1); disabled by default until configured."""
    return [
        {"name": "feodo-c2", "adapter": "feodo", "url":
         "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
         "schedule_min": 60, "ttl_days": 14, "enabled": False},
        {"name": "urlhaus-recent", "adapter": "urlhaus", "url":
         "https://urlhaus.abuse.ch/downloads/csv_recent/",
         "schedule_min": 120, "ttl_days": 14, "enabled": False},
        {"name": "threatfox-2d", "adapter": "threatfox", "url":
         "https://threatfox.abuse.ch/api/v1/", "days": 2,
         "schedule_min": 120, "ttl_days": 14, "enabled": False},
        # v0.11 standard-format starters (disabled until configured)
        {"name": "stix-partner", "adapter": "stix",
         "url": "https://cis.example.org/stix/bundle.json",
         "schedule_min": 360, "ttl_days": 30, "enabled": False},
        {"name": "taxii-national-csirt", "adapter": "taxii",
         "url": "https://taxii.example.csirt/discovery",
         "schedule_min": 360, "ttl_days": 30, "enabled": False},
        {"name": "misp-community", "adapter": "misp",
         "url": "https://misp.example.org/feeds/1",
         "schedule_min": 360, "ttl_days": 30, "enabled": False},
    ]


def ttl_deadline(published: datetime | None, last_seen: datetime,
                 ttl_days: int) -> datetime:
    base = published if (published and published > last_seen) else last_seen
    return base + timedelta(days=max(1, ttl_days))
