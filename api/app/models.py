"""ORM models - Phase 0-2 subset of doc section 6.5."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (JSON, BigInteger, Boolean, DateTime, Integer, String,
                        Text)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def gen_uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(32))
    full_name: Mapped[str | None] = mapped_column(String(128), default=None)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True),
                                                          default=None)
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True),
                                                           default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow,
                                                 onupdate=utcnow)


class AuditRecord(Base):
    __tablename__ = "audit_records"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"),
                                    primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                  default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64), index=True)
    actor_role: Mapped[str | None] = mapped_column(String(32), default=None)
    action: Mapped[str] = mapped_column(String(128), index=True)
    target_type: Mapped[str | None] = mapped_column(String(64), default=None)
    target_id: Mapped[str | None] = mapped_column(String(128), default=None)
    result: Mapped[str] = mapped_column(String(16), default="success")
    source_ip: Mapped[str | None] = mapped_column(String(64), default=None)
    request_id: Mapped[str | None] = mapped_column(String(64), default=None)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class Sensor(Base):
    __tablename__ = "sensors"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # sensor_id
    hostname: Mapped[str] = mapped_column(String(128))
    capture_iface: Mapped[str | None] = mapped_column(String(32), default=None)
    software_versions: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="unknown")
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True),
                                                          default=None)
    notes: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow,
                                                 onupdate=utcnow)


class NetworkZone(Base):
    __tablename__ = "network_zones"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    cidr: Mapped[str] = mapped_column(String(64))
    zone_type: Mapped[str] = mapped_column(String(16), default="internal")
    description: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow)


class SystemSetting(Base):
    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow,
                                                 onupdate=utcnow)


# ---------- Threat Intelligence (doc section 9 - Phase 3) -------

class TIFeed(Base):
    __tablename__ = "ti_feeds"

    id: Mapped[str] = mapped_column(String(36), primary_key=True,
                                    default=gen_uuid)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    adapter: Mapped[str] = mapped_column(String(32))
    url: Mapped[str | None] = mapped_column(String(512), default=None)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    schedule_min: Mapped[int] = mapped_column(Integer, default=0)
    ttl_days: Mapped[int] = mapped_column(Integer, default=14)
    last_success_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None)
    last_status: Mapped[str | None] = mapped_column(String(32), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow,
                                                 onupdate=utcnow)


class TIUpdateJob(Base):
    __tablename__ = "ti_update_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True,
                                    default=gen_uuid)
    feed_id: Mapped[str | None] = mapped_column(String(36), default=None,
                                                index=True)
    feed_name: Mapped[str | None] = mapped_column(String(64), default=None)
    trigger: Mapped[str] = mapped_column(String(16), default="manual")
    status: Mapped[str] = mapped_column(String(16), default="queued",
                                        index=True)
    counts: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    created_by: Mapped[str | None] = mapped_column(String(64), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True),
                                                        default=None)
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None)


class IocRecord(Base):
    __tablename__ = "ioc_records"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"),
                                    primary_key=True, autoincrement=True)
    ioc_type: Mapped[str] = mapped_column(String(16), index=True)
    ioc_value: Mapped[str] = mapped_column(String(512), index=True)
    status: Mapped[str] = mapped_column(String(16), default="active")
    confidence: Mapped[str] = mapped_column(String(16), default="medium")
    malware: Mapped[str | None] = mapped_column(String(128), default=None)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    provenance: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                default=utcnow)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True),
                                                       default=None)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True),
                                                        default=None)


class IocAllowlist(Base):
    __tablename__ = "ioc_allowlist"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"),
                                    primary_key=True, autoincrement=True)
    ioc_type: Mapped[str] = mapped_column(String(16))
    ioc_value: Mapped[str] = mapped_column(String(512))
    reason: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str | None] = mapped_column(String(64), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow)


class AlertAllowlist(Base):
    """v0.14.0 alert whitelist (allowlist) - suppress recurring FALSE
    POSITIVES from legitimate internal tooling (vuln scanners, backup
    servers, NTP, monitoring).

    Two enforcement layers, chosen PER ENTRY:
      * L0 (pipeline): the matching alert is never indexed; only the
        hit counter increments (cheapest noise control).
      * L1 (post-alert): the alert IS indexed but carries
        suppressed=True + suppressed_by - kept for the record, hidden
        from the default triage queue (UI filter).

    Governance: two-man rule (analyst submits -> pending; admin/
    security_engineer approves; admin self-approve is allowed and
    audited), mandatory reason, optional TTL, raw events are NEVER
    touched - only alert noisiness is affected. Correlation/kill-chain
    keep running (the story is not cut by a whitelist entry).
    """
    __tablename__ = "alert_allowlist"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"),
                                    primary_key=True, autoincrement=True)
    alert_type: Mapped[str] = mapped_column(String(48))
    signature: Mapped[str | None] = mapped_column(String(255), default=None)
    entity_field: Mapped[str] = mapped_column(String(24))
    entity_value: Mapped[str] = mapped_column(String(255))
    layer: Mapped[str] = mapped_column(String(2), default="L1")
    status: Mapped[str] = mapped_column(String(12), default="pending")
    reason: Mapped[str] = mapped_column(Text)
    retroactive: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str | None] = mapped_column(String(64), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow)
    approved_by: Mapped[str | None] = mapped_column(String(64), default=None)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True),
                                                          default=None)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True),
                                                         default=None)
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    last_hit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True),
                                                          default=None)


# ---------- Attack Reconstruction (doc section 10 - Phase 4) ------
# Story data is written by the pipeline's reconstruction engine
# (raw SQL, ISO timestamps); the API owns analyst triage writes.

class Campaign(Base):
    """Analyst-managed grouping of related incidents (v0.12).

    Campaigns are pure analyst bookkeeping: merging incidents into a
    campaign NEVER rewrites the incidents' reconstructed evidence,
    entities or relations. Rollup fields (severity/first_seen/last_seen/
    incident_count) are derived from members on every membership change.
    """
    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(16), default="open",
                                        index=True)  # open|closed
    created_by: Mapped[str | None] = mapped_column(String(64), default=None)
    incident_count: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str] = mapped_column(String(16), default="low")
    first_seen: Mapped[str | None] = mapped_column(String(40), default=None)
    last_seen: Mapped[str | None] = mapped_column(String(40), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow,
                                                 onupdate=utcnow)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(Text)
    campaign_id: Mapped[str | None] = mapped_column(
        String(64), default=None, index=True)  # v0.12 analyst grouping
    status: Mapped[str] = mapped_column(String(16), default="open",
                                        index=True)  # open|confirmed|benign|closed
    severity: Mapped[str] = mapped_column(String(16), default="low")
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[str | None] = mapped_column(String(40), default=None)
    last_seen: Mapped[str | None] = mapped_column(String(40), default=None)
    outcome: Mapped[dict] = mapped_column(JSON, default=dict)
    phases: Mapped[list] = mapped_column(JSON, default=list)
    entity_count: Mapped[int] = mapped_column(Integer, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, default=0)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    signal_count: Mapped[int] = mapped_column(Integer, default=0)
    analyst: Mapped[str | None] = mapped_column(String(64), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow,
                                                 onupdate=utcnow)


class IncidentNode(Base):
    __tablename__ = "incident_nodes"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"),
                                    primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(16))   # ip|domain|hash|ioc
    key: Mapped[str] = mapped_column(String(320))
    label: Mapped[str] = mapped_column(String(320))
    role: Mapped[str | None] = mapped_column(String(32), default=None)
    phase: Mapped[str | None] = mapped_column(String(32), default=None)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    first_seen: Mapped[str | None] = mapped_column(String(40), default=None)
    last_seen: Mapped[str | None] = mapped_column(String(40), default=None)
    attrs: Mapped[dict] = mapped_column(JSON, default=dict)


class IncidentEdge(Base):
    __tablename__ = "incident_edges"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"),
                                    primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    src_key: Mapped[str] = mapped_column(String(320))
    dst_key: Mapped[str] = mapped_column(String(320))
    relation: Mapped[str] = mapped_column(String(32))
    phase: Mapped[str | None] = mapped_column(String(32), default=None)
    inferred: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[str | None] = mapped_column(String(40), default=None)
    last_seen: Mapped[str | None] = mapped_column(String(40), default=None)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[int] = mapped_column(Integer, default=50)


class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"),
                                    primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    ts: Mapped[str | None] = mapped_column(String(40), default=None)
    kind: Mapped[str | None] = mapped_column(String(16), default=None)
    source: Mapped[str | None] = mapped_column(String(32), default=None)
    ref_index: Mapped[str | None] = mapped_column(String(128), default=None)
    ref_id: Mapped[str | None] = mapped_column(String(128), default=None)
    title: Mapped[str | None] = mapped_column(Text, default=None)
    severity: Mapped[str | None] = mapped_column(String(16), default=None)
    phase: Mapped[str | None] = mapped_column(String(32), default=None)
    summary: Mapped[str | None] = mapped_column(Text, default=None)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    # doc 11 dual-framework: LM kill-chain stage + MITRE ATT&CK list
    stage: Mapped[str | None] = mapped_column(String(32), default=None)
    attck: Mapped[list] = mapped_column(JSON, default=list)


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"),
                                    primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    author: Mapped[str | None] = mapped_column(String(64), default=None)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow)


class IncidentHistory(Base):
    __tablename__ = "incident_history"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"),
                                    primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                  default=utcnow)
    actor: Mapped[str | None] = mapped_column(String(64), default=None)
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class IncidentReportVersion(Base):
    """Versioned incident report snapshots (v0.12).

    Each version freezes the Markdown report as generated at a point in
    time, so the analyst can prove what the platform claimed THEN vs
    NOW (report = evidence artifact, not a live view). Version numbers
    are per-incident, 1-based, gapless by construction (max+1).
    """
    __tablename__ = "incident_report_versions"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"),
                                    primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    markdown: Mapped[str] = mapped_column(Text)
    generated_by: Mapped[str | None] = mapped_column(String(64), default=None)
    incident_status: Mapped[str | None] = mapped_column(String(16),
                                                        default=None)
    severity: Mapped[str | None] = mapped_column(String(16), default=None)
    outcome_label: Mapped[str | None] = mapped_column(String(32), default=None)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    signal_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow)


class SuricataRuleMeta(Base):
    """Last-known metadata for Suricata rules seen on the rules volume.

    suricata-update REMOVES disabled SIDs from suricata.rules, so the
    generated file alone cannot describe disabled rules. This cache keeps
    their last-known msg/classtype so the rule manager still shows them.
    """
    __tablename__ = "suricata_rule_meta"

    sid: Mapped[int] = mapped_column(Integer, primary_key=True)
    gid: Mapped[int] = mapped_column(Integer, default=1)
    rev: Mapped[int | None] = mapped_column(Integer, default=None)
    action: Mapped[str | None] = mapped_column(String(16), default=None)
    protocol: Mapped[str | None] = mapped_column(String(16), default=None)
    msg: Mapped[str | None] = mapped_column(Text, default=None)
    classtype: Mapped[str | None] = mapped_column(String(64), default=None)
    priority: Mapped[int | None] = mapped_column(Integer, default=None)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    changed_by: Mapped[str | None] = mapped_column(String(64), default=None)
    changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None)
    last_seen_in_rules: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow,
                                                 onupdate=utcnow)


class PcapExport(Base):
    """PCAP export record - chain of custody for doc section 15.3.

    Records who exported what (alert/incident, selected sessions, time
    window), the produced bundle (files, sizes, SHA-256), and applies the
    TTL lifecycle for temporary export files (doc 15.1 step 8).
    """
    __tablename__ = "pcap_exports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True,
                                    default=gen_uuid)
    actor: Mapped[str] = mapped_column(String(64))
    actor_role: Mapped[str | None] = mapped_column(String(32), default=None)
    alert_id: Mapped[str | None] = mapped_column(String(128), default=None)
    incident_id: Mapped[str | None] = mapped_column(String(64), default=None)
    reason: Mapped[str] = mapped_column(Text)
    session_count: Mapped[int] = mapped_column(Integer, default=0)
    sessions: Mapped[list | None] = mapped_column(JSON, default=None)
    window_from: Mapped[str | None] = mapped_column(String(64), default=None)
    window_to: Mapped[str | None] = mapped_column(String(64), default=None)
    files: Mapped[list | None] = mapped_column(JSON, default=None)
    total_bytes: Mapped[int] = mapped_column(Integer, default=0)
    bundle_name: Mapped[str | None] = mapped_column(String(255), default=None)
    bundle_sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    # ready -> available for download until TTL; expired -> TTL swept;
    # failed -> export could not be produced (error has the reason)
    status: Mapped[str] = mapped_column(String(16), default="ready")
    error: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None)


class Asset(Base):
    """Manually registered asset inventory (v0.10).

    Complements the traffic-derived host profile: machines the SOC
    explicitly registers. Alert enrichment (Alert Center source/destination
    labels) joins on `ip`; the registry is authoritative for the hostname.
    """
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True,
                                    default=gen_uuid)
    ip: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(128))
    zone: Mapped[str] = mapped_column(String(32), default="servers")
    role: Mapped[str] = mapped_column(String(128), default="")
    criticality: Mapped[str] = mapped_column(String(16), default="medium")
    notes: Mapped[str | None] = mapped_column(Text, default=None)
    created_by: Mapped[str | None] = mapped_column(String(64), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow)


class CustomRule(Base):
    """Operator-authored Suricata rule (v0.11 custom rule editor).

    SIDs are constrained to the reserved local range 1,000,000-1,999,999
    by parse_rule_text() so a UI rule can never shadow a subscribed ET
    rule. Enabled rules are written to custom.rules on the shared rules
    volume and synced into the marker-delimited section of suricata.rules
    (see rules_engine.sync_custom_section).
    """
    __tablename__ = "custom_rules"

    sid: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_text: Mapped[str] = mapped_column(Text)
    msg: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(String(16), default="alert")
    protocol: Mapped[str] = mapped_column(String(16), default="ip")
    classtype: Mapped[str | None] = mapped_column(String(64), default=None)
    priority: Mapped[int | None] = mapped_column(Integer, default=None)
    rev: Mapped[int | None] = mapped_column(Integer, default=None)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str | None] = mapped_column(String(64), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(64), default=None)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow,
                                                 onupdate=utcnow)


class RuleStat(Base):
    """Hit statistics per rule (v0.16.0 - requirements 14 + 15).

    rule_key semantics:
      * source='suricata' -> rule_key is the numeric SID (string form)
      * source='zeek'     -> rule_key is a zeek_* alert type (script)
      * source='pipeline' -> rule_key is a behaviour alert_type
    Refreshed by app.rule_stats.RuleStatsRefresher (15 min default);
    the Rules Manager joins this table for the Hits 24h/7d columns.
    """
    __tablename__ = "rule_stats"

    rule_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    source: Mapped[str] = mapped_column(String(16), default="suricata")
    signature: Mapped[str | None] = mapped_column(String(512), default=None)
    hits_24h: Mapped[int] = mapped_column(BigInteger, default=0)
    hits_7d: Mapped[int] = mapped_column(BigInteger, default=0)
    sev_max: Mapped[str | None] = mapped_column(String(16), default=None)
    last_hit_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None)
    sample_alert_id: Mapped[str | None] = mapped_column(String(64),
                                                        default=None)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow,
                                                 onupdate=utcnow)
