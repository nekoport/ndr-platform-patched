"""Entity extraction + normalization for the correlation engine (doc 10.3).

Layer 1 - ENTITY correlation: every alert/context item is reduced to a
set of normalized entities:

    ip:<addr>          internal host or external endpoint
    domain:<name>      DNS query, TLS SNI, HTTP host, DNS answer
    hash:<sha256|...>  file hashes from fileinfo events

Normalization is deliberately conservative: lowercase domains, strip
trailing dots, skip obviously invalid values.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from app.detection.killchain import classify_ioc

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
                       r"[a-z]{2,63}$", re.IGNORECASE)

_HASH_TYPES = {"md5", "sha1", "sha256"}


def norm_domain(value: str | None) -> str | None:
    if not value:
        return None
    d = value.strip().lower().rstrip(".")
    if not d or len(d) > 253 or " " in d:
        return None
    if not DOMAIN_RE.match(d):
        return None
    return d


def norm_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def norm_hash(value: str | None) -> str | None:
    if not value:
        return None
    h = value.strip().lower()
    if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", h):
        return h
    return None


def entity_key(kind: str, value: str) -> str:
    return f"{kind}:{value}"


def split_entity_key(key: str) -> tuple[str, str]:
    kind, _, rest = key.partition(":")
    return kind, rest


@dataclass
class Signal:
    """A reconstruction input (an alert, or an IOC-matched event)."""

    ts_epoch: float
    ts_iso: str
    kind: str                       # alert | ioc_event
    ref_index: str                  # OpenSearch index / source ref
    ref_id: str                     # alert_id / event_id (dedup within story)
    title: str
    severity: str
    phase: str                      # taxonomy phase (unknown allowed)
    attack_type: str                # rule name / category
    base_confidence: int            # heuristic weight (doc 10.4)
    entities: set[str] = field(default_factory=set)
    src_ip: str | None = None
    dst_ip: str | None = None
    end_ts_epoch: float = 0.0       # window end (alerts aggregate a window)
    summary: str = ""
    rationale: str = ""
    reasons: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)
    # Dual-framework classification (doc 11): LM kill-chain stage +
    # MITRE ATT&CK techniques carried from the alert doc.
    kill_chain_stage: str = ""
    stage_reason: str = ""
    attck: list = field(default_factory=list)


SEVERITY_WEIGHT = {"critical": 45, "high": 35, "medium": 22, "low": 12,
                   "informational": 6}
RULE_WEIGHT = {
    "portscan_suspected": 14,
    "dns_nxdomain_burst": 10,
    "beaconing_possible": 24,
    "dga_suspected": 20,
    "dns_tunneling_suspected": 30,
    "internal_lateral_suspected": 32,
    "large_outbound_transfer": 30,
    "file_transfer_suspected": 18,
    "suricata_alert_group": 0,       # severity-driven
    "ioc_match": 0,                  # feed-confidence-driven
}
IOC_CONF_WEIGHT = {"high": 32, "medium": 20, "low": 10}


def alert_base_confidence(doc: dict) -> int:
    """Heuristic, explicitly UNCALIBRATED signal weight (doc 10.4)."""
    atype = doc.get("alert_type", "")
    sev = str(doc.get("severity", "low")).lower()
    base = SEVERITY_WEIGHT.get(sev, 10)
    rule_w = RULE_WEIGHT.get(atype)
    if rule_w:
        base = max(base // 2, rule_w)
    if atype == "ioc_match":
        iocs = doc.get("matched_iocs") or []
        conf = str((iocs[0] or {}).get("confidence", "medium")).lower()
        base = max(base, IOC_CONF_WEIGHT.get(conf, 15))
    return min(base, 50)


def extract_from_alert(doc: dict, index_name: str) -> Signal | None:
    """Reduce an alert doc (as emitted by detection rules) to a Signal."""
    alert_id = doc.get("alert_id")
    if not alert_id:
        return None
    entities: set[str] = set()
    src = norm_ip((doc.get("source") or {}).get("ip"))
    dst = norm_ip((doc.get("destination") or {}).get("ip"))
    if src:
        entities.add(entity_key("ip", src))
    if dst:
        entities.add(entity_key("ip", dst))
    for e in doc.get("related_entities") or []:
        ip = norm_ip(e)
        if ip:
            entities.add(entity_key("ip", ip))
    for group in ("top_destinations", "top_sources"):
        for item in (doc.get(group) or [])[:10]:
            ip = norm_ip(item.get("ip"))
            if ip:
                entities.add(entity_key("ip", ip))
    for rule in doc.get("top_rules") or []:
        sig = str(rule.get("signature") or "")
        if sig.lower().startswith("ioc:"):
            value = sig[4:].strip().lower()
            d = norm_domain(value)
            entities.add(entity_key("domain", d or value))
    for ioc in doc.get("matched_iocs") or []:
        ioc_type = str(ioc.get("ioc_type", "")).lower()
        value = str(ioc.get("ioc_value", "")).strip().lower()
        if not value:
            continue
        if ioc_type in ("domain", "url"):
            d = norm_domain(value)
            entities.add(entity_key("domain", d or value))
        elif ioc_type in _HASH_TYPES:
            entities.add(entity_key("hash", value))
        elif ioc_type == "ip":
            ip = norm_ip(value)
            entities.add(entity_key("ip", ip or value))
        else:
            entities.add(entity_key("ioc", value))

    first_seen = doc.get("first_seen") or doc.get("@timestamp")
    ts_epoch = _iso_to_epoch(first_seen)
    end_epoch = _iso_to_epoch(doc.get("last_seen")) or ts_epoch
    reasons = list(doc.get("reasons") or [])
    kc = doc.get("kill_chain") or {}
    return Signal(
        ts_epoch=ts_epoch,
        ts_iso=first_seen or "",
        kind="alert",
        ref_index=index_name,
        ref_id=alert_id,
        title=str(doc.get("title") or "Alert"),
        severity=str(doc.get("severity") or "low").lower(),
        phase=str(doc.get("attack_phase") or "unknown"),
        attack_type=str(doc.get("alert_type") or "unknown"),
        base_confidence=alert_base_confidence(doc),
        entities=entities,
        src_ip=src,
        dst_ip=dst,
        end_ts_epoch=end_epoch,
        summary=str(doc.get("rationale") or ""),
        rationale=str(doc.get("rationale") or ""),
        reasons=reasons,
        kill_chain_stage=str(kc.get("stage") or ""),
        stage_reason=str(kc.get("reason") or ""),
        attck=[t for t in (doc.get("mitre") or [])
               if isinstance(t, dict) and t.get("technique_id")],
        detail={
            "alert_type": doc.get("alert_type"),
            "group_key": doc.get("group_key"),
            "event_count": doc.get("event_count"),
            "attack_phase": doc.get("attack_phase"),
            "matched_iocs": doc.get("matched_iocs") or [],
            "evidence": doc.get("evidence") or [],
        },
    )


def extract_from_event(ev, index_name: str) -> Signal | None:
    """Reduce an IOC-matched event to a Signal (kind=ioc_event)."""
    entities: set[str] = set()
    src = norm_ip(ev.source_ip)
    dst = norm_ip(ev.destination_ip)
    if src:
        entities.add(entity_key("ip", src))
    if dst:
        entities.add(entity_key("ip", dst))
    d = norm_domain(ev.dns_query) or norm_domain(ev.tls_sni) \
        or norm_domain(ev.http_host)
    if d:
        entities.add(entity_key("domain", d))
    for h in (ev.file_sha256, ev.file_sha1, ev.file_md5):
        nh = norm_hash(h)
        if nh:
            entities.add(entity_key("hash", nh))
    if not entities:
        return None
    ts_iso = ev.event_time.isoformat().replace("+00:00", "Z")
    iocs = ev.matched_ioc or []
    first = iocs[0] if iocs else {}
    ioc_type = str(first.get("ioc_type") or "") or None
    stage, attck = classify_ioc(ioc_type)
    return Signal(
        ts_epoch=ev.event_time.timestamp(),
        ts_iso=ts_iso,
        kind="ioc_event",
        ref_index=index_name,
        ref_id=ev.event_id,
        title=(f"IOC match: {first.get('ioc_value')} "
               f"({first.get('ioc_type')})") if first
        else "IOC-matched activity",
        severity=str(ev.severity or "medium").lower(),
        phase="delivery" if any(k.startswith("hash:") for k in entities)
        else "c2",
        attack_type="ioc_event",
        base_confidence=IOC_CONF_WEIGHT.get(
            str(first.get("confidence", "medium")).lower(), 15),
        kill_chain_stage=stage,
        stage_reason=f"ioc type '{ioc_type or 'unknown'}' classified as "
                     f"{stage} by IOC mapping (doc 11)",
        attck=attck,
        entities=entities,
        src_ip=src,
        dst_ip=dst,
        summary=f"Event matched {len(iocs)} threat-intelligence IOC(s). "
                f"IOC matches are contextual evidence, not proof of "
                f"compromise (doc 9.2).",
        rationale="IOC-matched event observed by the pipeline.",
        reasons=[f"ioc: {m.get('ioc_type')} {m.get('ioc_value')}"
                 for m in iocs[:3]],
        detail={
            "event_type": ev.event_type,
            "source_engine": ev.source_engine,
            "dns_query": ev.dns_query,
            "tls_sni": ev.tls_sni,
            "http_host": ev.http_host,
            "file_name": ev.file_name,
            "matched_ioc": iocs[:3],
            "community_id": ev.community_id,
        },
    )


def extract_context(ev) -> dict | None:
    """Context facts from plain events (never create stories).

    Returns a dict describing DNS answers / SNI / file info so the
    service can enrich trackers and existing stories.
    """
    etype = ev.event_type
    if etype == "dns":
        answers = [{"name": a.name, "type": a.type, "data": a.data}
                   for a in (ev.dns_answers or [])
                   if a.data and _is_addressish(a.data)]
        query = norm_domain(ev.dns_query)
        if not answers and not query:
            return None
        return {"etype": "dns", "ts": ev.event_time.timestamp(),
                "query": query, "answers": answers,
                "src": norm_ip(ev.source_ip),
                "dst": norm_ip(ev.destination_ip)}
    if etype == "tls":
        sni = norm_domain(ev.tls_sni)
        if not sni:
            return None
        return {"etype": "tls", "ts": ev.event_time.timestamp(),
                "domain": sni, "src": norm_ip(ev.source_ip),
                "dst": norm_ip(ev.destination_ip)}
    if etype == "http":
        host = norm_domain(ev.http_host)
        if not host:
            return None
        return {"etype": "http", "ts": ev.event_time.timestamp(),
                "domain": host, "url": ev.http_url,
                "method": ev.http_method, "status": ev.http_status,
                "src": norm_ip(ev.source_ip),
                "dst": norm_ip(ev.destination_ip)}
    if etype == "fileinfo":
        if not (ev.file_sha256 or ev.file_md5 or ev.file_sha1):
            return None
        return {"etype": "fileinfo", "ts": ev.event_time.timestamp(),
                "src": norm_ip(ev.source_ip),
                "dst": norm_ip(ev.destination_ip),
                "name": ev.file_name, "mime": ev.file_mime,
                "size": ev.file_size,
                "md5": norm_hash(ev.file_md5),
                "sha1": norm_hash(ev.file_sha1),
                "sha256": norm_hash(ev.file_sha256)}
    return None


def _is_addressish(value: str) -> bool:
    v = (value or "").strip()
    if not v:
        return False
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _iso_to_epoch(iso: str | None) -> float:
    if not iso:
        return 0.0
    try:
        from datetime import datetime
        s = iso.replace("Z", "+00:00")
        return datetime.fromisoformat(s).timestamp()
    except (ValueError, TypeError, OverflowError):
        return 0.0
