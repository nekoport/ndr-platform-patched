"""Common event schema (doc section 6.2) shared by all sources."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

PARSER_VERSION = "ndr-pipeline/0.7.0"  # v0.13.0: parser-owned dedup keys

NS_NDR = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # RFC 4122 URL ns base
EVENT_NS = uuid.uuid5(NS_NDR, "ndr/event/v1")


def make_event_id(dedup_key: str) -> str:
    """Deterministic id: identical re-parsed events collapse to the same doc."""
    return str(uuid.uuid5(EVENT_NS, dedup_key))


def make_dedup_key(*parts) -> str:
    raw = "|".join("" if p is None else str(p) for p in parts)
    return hashlib.sha1(raw.encode()).hexdigest()


@dataclass
class Answer:
    name: str | None = None
    type: str | None = None
    data: str | None = None


@dataclass
class CommonEvent:
    """Normalized event. Field names align with the OpenSearch mappings."""

    event_id: str
    event_time: datetime          # activity time (event time, doc 7.2)
    ingest_time: datetime         # pipeline receive time
    sensor_id: str
    source_engine: str            # zeek | suricata
    event_type: str               # conn | dns | http | tls | alert | fileinfo | weird
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    transport: str | None = None  # tcp | udp | icmp
    protocol: str | None = None   # app protocol (service)
    severity: str | None = None   # critical|high|medium|low|informational
    severity_score: int | None = None
    signature_id: str | None = None
    rule_id: str | None = None
    category: str | None = None
    session_id: str | None = None
    community_id: str | None = None
    network_bytes: int | None = None
    network_packets: int | None = None
    source_bytes: int | None = None
    destination_bytes: int | None = None
    dns_query: str | None = None
    dns_type: str | None = None
    dns_rcode: str | None = None
    dns_qtype: str | None = None  # v0.13.0: rrtype/qtype_name (tunneling)
    dns_answers: list[Answer] = field(default_factory=list)
    http_host: str | None = None
    http_url: str | None = None
    http_method: str | None = None
    http_status: int | None = None
    http_user_agent: str | None = None
    http_referrer: str | None = None
    tls_sni: str | None = None
    tls_version: str | None = None
    tls_ja3: str | None = None
    tls_subject: str | None = None
    tls_issuer: str | None = None
    file_name: str | None = None
    file_mime: str | None = None
    file_size: int | None = None
    file_md5: str | None = None
    file_sha1: str | None = None
    file_sha256: str | None = None
    alert_signature: str | None = None
    alert_category: str | None = None
    alert_severity_id: int | None = None
    zone: str | None = None
    matched_ioc: list[dict] = field(default_factory=list)  # TI enrich (Phase 3)
    source_geo: dict | None = None      # GeoIP enrich (Phase 5, optional)
    destination_geo: dict | None = None # GeoIP enrich (Phase 5, optional)
    parse_status: str = "ok"          # ok | partial
    dedup_key: str | None = None      # v0.13.0: parser-owned dedup key
    raw_event_ref: str | None = None  # sha256 of raw source line
    raw_line: str | None = None       # transient; not indexed

    def to_doc(self) -> dict:
        """Render for OpenSearch bulk indexing (drops transient fields)."""
        doc = {
            "@timestamp": self.event_time.isoformat().replace("+00:00", "Z"),
            "ingest_time": self.ingest_time.isoformat().replace("+00:00", "Z"),
            "event_id": self.event_id,
            "sensor_id": self.sensor_id,
            "source_engine": self.source_engine,
            "event_type": self.event_type,
            "parse_status": self.parse_status,
            "parser_version": PARSER_VERSION,
        }
        if self.source_ip:
            doc["source"] = {"ip": self.source_ip}
            if self.source_port is not None:
                doc["source"]["port"] = self.source_port
        if self.destination_ip:
            doc["destination"] = {"ip": self.destination_ip}
            if self.destination_port is not None:
                doc["destination"]["port"] = self.destination_port
        net: dict = {}
        if self.transport:
            net["transport"] = self.transport
        if self.protocol:
            net["protocol"] = self.protocol
        if self.network_bytes is not None:
            net["bytes"] = self.network_bytes
        if self.network_packets is not None:
            net["packets"] = self.network_packets
        if self.community_id:
            net["community_id"] = self.community_id
        if net:
            doc["network"] = net
        if self.source_bytes is not None:
            doc.setdefault("source", {})["bytes"] = self.source_bytes
        if self.destination_bytes is not None:
            doc.setdefault("destination", {})["bytes"] = self.destination_bytes
        if self.source_geo:
            doc.setdefault("source", {})["geo"] = self.source_geo
        if self.destination_geo:
            doc.setdefault("destination", {})["geo"] = self.destination_geo
        if self.severity:
            doc["severity"] = self.severity
        if self.severity_score is not None:
            doc["severity_score"] = self.severity_score
        for k in ("signature_id", "rule_id", "category", "session_id", "zone"):
            v = getattr(self, k)
            if v:
                doc[k] = v
        if self.raw_event_ref:
            doc["raw_event_ref"] = self.raw_event_ref
        if (self.dns_query or self.dns_type or self.dns_rcode
                or self.dns_qtype or self.dns_answers):
            dns: dict = {}
            if self.dns_query:
                dns["query"] = self.dns_query
            if self.dns_type:
                dns["type"] = self.dns_type
            if self.dns_rcode:
                dns["rcode"] = self.dns_rcode
            if self.dns_qtype:
                dns["qtype"] = self.dns_qtype
            if self.dns_answers:
                dns["answers"] = [
                    {"name": a.name, "type": a.type, "data": a.data}
                    for a in self.dns_answers if (a.name or a.data)
                ]
            doc["dns"] = dns
        http = {k: v for k, v in {
            "host": self.http_host, "url": self.http_url,
            "method": self.http_method, "status_code": self.http_status,
            "user_agent": self.http_user_agent, "referrer": self.http_referrer,
        }.items() if v is not None}
        if http:
            doc["http"] = http
        tls = {k: v for k, v in {
            "sni": self.tls_sni, "version": self.tls_version, "ja3": self.tls_ja3,
            "subject": self.tls_subject, "issuer": self.tls_issuer,
        }.items() if v}
        if tls:
            doc["tls"] = tls
        file = {k: v for k, v in {
            "name": self.file_name, "mime_type": self.file_mime,
            "size": self.file_size,
        }.items() if v is not None}
        hashes = {k: v for k, v in {
            "md5": self.file_md5, "sha1": self.file_sha1, "sha256": self.file_sha256,
        }.items() if v}
        if hashes:
            file["hash"] = hashes
        if file:
            doc["file"] = file
        alert = {k: v for k, v in {
            "signature": self.alert_signature, "category": self.alert_category,
            "severity_id": self.alert_severity_id,
        }.items() if v is not None}
        if alert:
            doc["alert"] = alert
        if self.matched_ioc:
            # Threat intelligence context (doc 9): evidence, not verdict.
            doc["matched_ioc"] = [
                {k: m[k] for k in ("ioc_type", "ioc_value", "ioc_source",
                                   "confidence", "match_field")}
                for m in self.matched_ioc[:3]]
        return doc


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
