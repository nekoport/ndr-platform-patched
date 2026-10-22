"""Pydantic DTOs."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=10, max_length=256)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64,
                          pattern=r"^[a-zA-Z0-9._-]+$")
    password: str = Field(min_length=10, max_length=256)
    role: str
    full_name: str | None = None

    @field_validator("role")
    @classmethod
    def role_valid(cls, v: str) -> str:
        from app.security import ROLES
        if v not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        return v


ALLOWED_ROLES = ("administrator", "security_engineer", "soc_analyst",
                 "soc_lead", "auditor")
ALLOWED_SENSOR_STATUS = ("unknown", "online", "degraded", "offline")


class UserUpdate(BaseModel):
    # v0.13.0: role VALIDATED - a PATCH used to be able to set ANY role
    # string (including non-existent ones), bypassing the RBAC matrix
    role: str | None = Field(default=None, pattern="|".join(ALLOWED_ROLES))
    is_active: bool | None = None
    full_name: str | None = None
    new_password: str | None = Field(default=None, min_length=10, max_length=256)


class UserOut(BaseModel):
    id: str
    username: str
    role: str
    full_name: str | None
    is_active: bool
    must_change_password: bool
    last_login_at: datetime | None
    created_at: datetime

    class Config:
        from_attributes = True


class SensorCreate(BaseModel):
    id: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")
    hostname: str = Field(min_length=1, max_length=128)
    capture_iface: str | None = None
    notes: str | None = None


class SensorUpdate(BaseModel):
    hostname: str | None = None
    capture_iface: str | None = None
    # v0.13.0: status VALIDATED against the postgres CHECK (422, not 500)
    status: str | None = Field(
        default=None, pattern="|".join(ALLOWED_SENSOR_STATUS))
    notes: str | None = None


class SearchRequest(BaseModel):
    """Guarded search over whitelisted aliases (doc section 4.5)."""

    index: str = "ndr-events-read"
    query: dict[str, Any] = Field(default_factory=dict)
    # v0.16.0 (req 5): custom filter DSL (and/or/not + is/is_one/include/
    # exclude) - AST JSON divalidasi app.filters.build_query, bukan DSL mentah.
    filter: dict[str, Any] | None = None
    # v0.16.1 (P0-5): mode simple TIDAK lagi dibangun di client (dulu
    # 'term' teks pada field ip membuat hasil selalu 0). Kirim kata
    # kunci mentah; API membangun query-nya sendiri via
    # OSClient.build_free_text_query (whitelist field, IP fast-path,
    # event_type fast-path).
    query_text: str | None = Field(default=None, max_length=256)
    # v0.16.1 (P2-4): minta total EKSAK (tanpa cap 10.000) untuk
    # analisis/ekspor skala besar.
    exact_total: bool = False
    size: int = Field(default=50, ge=1, le=500)
    from_: int = Field(default=0, ge=0, alias="from", le=10000)
    sort: list[dict[str, Any]] | None = None
    time_from: str | None = None
    time_to: str | None = None

    model_config = {"populate_by_name": True}


class AlertUpdate(BaseModel):
    status: str | None = None
    assignee: str | None = None
    notes: str | None = None

    @field_validator("status")
    @classmethod
    def status_valid(cls, v: str | None) -> str | None:
        if v is None:
            return v
        allowed = {"new", "acknowledged", "in_progress", "closed", "false_positive"}
        if v not in allowed:
            raise ValueError(f"status must be one of {allowed}")
        return v


# ---------- Threat Intelligence (doc section 9 - Phase 3) -------

# v0.11: +stix / +taxii / +misp (STIX 2/1 documents, TAXII 2.1 collections,
# MISP feed manifest/event JSON) alongside the abuse.ch + file starters.
TI_ADAPTERS = ("urlhaus", "threatfox", "feodo", "file",
               "stix", "taxii", "misp")
MASK = "*****"


class TIFeedCreate(BaseModel):
    name: str = Field(min_length=2, max_length=64,
                      pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]+$")
    adapter: str
    url: str | None = Field(default=None, max_length=512)
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = False
    schedule_min: int = Field(default=0, ge=0, le=10080)
    ttl_days: int = Field(default=14, ge=1, le=365)

    @field_validator("adapter")
    @classmethod
    def adapter_valid(cls, v: str) -> str:
        if v not in TI_ADAPTERS:
            raise ValueError(f"adapter must be one of {TI_ADAPTERS}")
        return v

    @field_validator("url")
    @classmethod
    def url_scheme(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not v.lower().startswith(("http://", "https://", "file://")) \
                and "://" in v:
            raise ValueError("feed url scheme not allowed")
        return v


class TIFeedUpdate(BaseModel):
    enabled: bool | None = None
    schedule_min: int | None = Field(default=None, ge=0, le=10080)
    ttl_days: int | None = Field(default=None, ge=1, le=365)
    url: str | None = Field(default=None, max_length=512)
    config: dict[str, Any] | None = None


class TIFeedOut(BaseModel):
    id: str
    name: str
    adapter: str
    url: str | None
    enabled: bool
    schedule_min: int
    ttl_days: int
    last_success_at: datetime | None
    last_status: str | None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class TIJobOut(BaseModel):
    id: str
    feed_id: str | None
    feed_name: str | None
    trigger: str
    status: str
    counts: dict
    error: str | None
    created_by: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None

    class Config:
        from_attributes = True


class IocOut(BaseModel):
    id: int
    ioc_type: str
    ioc_value: str
    status: str
    confidence: str
    malware: str | None
    tags: list
    provenance: list
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None

    class Config:
        from_attributes = True


class AllowlistCreate(BaseModel):
    ioc_type: str = Field(pattern=r"^(ip|domain|url|md5|sha1|sha256)$")
    ioc_value: str = Field(min_length=1, max_length=512)
    reason: str = Field(min_length=3, max_length=512)


# ---------- Attack Reconstruction (doc section 10 - Phase 4) ------

class IncidentPhaseOut(BaseModel):
    phase: str
    status: str
    evidence_count: int
    signal_count: int
    context_count: int


class IncidentOut(BaseModel):
    id: str
    title: str
    campaign_id: str | None = None
    status: str
    severity: str
    confidence: int
    confidence_basis: str = "heuristic-uncalibrated"
    first_seen: str | None = None
    last_seen: str | None = None
    entity_count: int
    edge_count: int
    evidence_count: int
    signal_count: int
    outcome_label: str | None = None
    phases: list = []
    deepest_stage: str | None = None
    analyst: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    class Config:
        from_attributes = True


class IncidentStatusUpdate(BaseModel):
    status: str = Field(pattern=r"^(open|confirmed|benign|closed)$")
    note: str | None = Field(default=None, max_length=2000)


class IncidentNoteCreate(BaseModel):
    body: str = Field(min_length=2, max_length=2000)


# ---------- Campaigns (v0.12 - analyst grouping of incidents) ------

class CampaignCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=2000)
    incident_ids: list[str] = Field(min_length=1, max_length=50)

    @field_validator("incident_ids")
    @classmethod
    def _ids_shape(cls, v: list[str]) -> list[str]:
        import re
        pat = re.compile(r"^[\w.:-]{1,64}$")
        for i in v:
            if not pat.match(i):
                raise ValueError(f"invalid incident id: {i!r}")
        # dedupe, keep order
        return list(dict.fromkeys(v))


class CampaignUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    status: str | None = Field(default=None,
                               pattern=r"^(open|closed)$")


class CampaignMembership(BaseModel):
    incident_ids: list[str] = Field(min_length=1, max_length=50)

    @field_validator("incident_ids")
    @classmethod
    def _ids_shape(cls, v: list[str]) -> list[str]:
        import re
        pat = re.compile(r"^[\w.:-]{1,64}$")
        for i in v:
            if not pat.match(i):
                raise ValueError(f"invalid incident id: {i!r}")
        return list(dict.fromkeys(v))


class RuleToggle(BaseModel):
    enabled: bool


class PcapExportRequest(BaseModel):
    """Selective PCAP export request (doc 15.1): an analyst picks the
    sessions shown for an alert/incident and must state a reason; the
    backend re-resolves every session server-side and enforces the
    size/duration limits before touching the capture storage."""
    alert_id: str | None = Field(default=None, max_length=128)
    incident_id: str | None = Field(default=None, max_length=64)
    reason: str = Field(min_length=3, max_length=2000)
    sessions: list[str] = Field(default_factory=list)
    entity_ip: str | None = Field(default=None, max_length=64)

    @field_validator("sessions")
    @classmethod
    def _sessions_shape(cls, v: list[str]) -> list[str]:
        import re
        pat = re.compile(r"^[\w.:-]{1,160}$")
        for s in v:
            if not pat.match(s):
                raise ValueError(
                    f"invalid session id: {s[:20]!r}")
        if len(v) > 500:
            raise ValueError("too many sessions selected (max 500)")
        return v


# ------------------------------------------------------------- assets (v0.10)
class AssetCreate(BaseModel):
    ip: str = Field(pattern=r"^\d{1,3}(\.\d{1,3}){3}$", max_length=64)
    hostname: str = Field(min_length=1, max_length=128)
    zone: str = Field(default="servers", max_length=32)
    role: str = Field(default="", max_length=128)
    criticality: str = Field(default="medium", max_length=16)
    notes: str | None = None

    @field_validator("criticality")
    @classmethod
    def crit_valid(cls, v: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        if v not in allowed:
            raise ValueError(f"criticality must be one of {allowed}")
        return v


class AssetUpdate(BaseModel):
    hostname: str | None = Field(default=None, min_length=1, max_length=128)
    zone: str | None = Field(default=None, max_length=32)
    role: str | None = Field(default=None, max_length=128)
    criticality: str | None = Field(default=None, max_length=16)
    notes: str | None = None


class AssetOut(BaseModel):
    id: str
    ip: str
    hostname: str
    zone: str
    role: str
    criticality: str
    notes: str | None
    created_by: str | None
    created_at: datetime

    class Config:
        from_attributes = True


# ------------------------------------------------- manual escalation (v0.10)
class EscalateRequest(BaseModel):
    """Body for POST /api/alerts/{id}/escalate (manual incident creation)."""
    reason: str | None = Field(default=None, max_length=2000)


# ------------------------------------------------- custom rules (v0.11)
class CustomRuleCreate(BaseModel):
    rule_text: str = Field(min_length=1, max_length=4096)
    enabled: bool = True
    sid: int | None = Field(default=None, ge=1_000_000, le=1_999_999)


class CustomRuleUpdate(BaseModel):
    rule_text: str | None = Field(default=None, min_length=1, max_length=4096)
    enabled: bool | None = None


class CustomRuleOut(BaseModel):
    sid: int
    rule_text: str
    msg: str
    action: str
    protocol: str
    classtype: str | None
    priority: int | None
    rev: int | None
    enabled: bool
    created_by: str | None
    created_at: datetime
    updated_by: str | None
    updated_at: datetime

    class Config:
        from_attributes = True


# ------------------------------------------------- system settings (v0.11)
class SystemPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=64)
    tagline: str | None = Field(default=None, max_length=128)


class BrandingPatch(BaseModel):
    logo_data_url: str | None = Field(default=None, max_length=400_000)
    favicon_data_url: str | None = Field(default=None, max_length=100_000)
    reset_logo: bool = False
    reset_favicon: bool = False

    @field_validator("logo_data_url", "favicon_data_url")
    @classmethod
    def _data_url_image(cls, v: str | None) -> str | None:
        import re
        if v is None:
            return v
        if not re.match(
                r"^data:image/(png|jpeg|webp|svg\+xml|x-icon|vnd\.microsoft\.icon);base64,[A-Za-z0-9+/=\s]+$",
                v):
            raise ValueError(
                "must be a base64 data URL of type png/jpeg/webp/svg/x-icon")
        return v


class NtpPatch(BaseModel):
    servers: list[str] = Field(default_factory=list, max_length=4)
    timezone: str | None = Field(default=None, max_length=64)
    enabled: bool | None = None

    @field_validator("servers")
    @classmethod
    def _server_hostnames(cls, v: list[str]) -> list[str]:
        import re
        pat = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,250}[a-zA-Z0-9])?$")
        for s in v:
            if not s or not pat.match(s):
                raise ValueError(f"invalid NTP server hostname: {s!r}")
        return v


class NetworkPatch(BaseModel):
    hostname: str | None = Field(default=None, min_length=1, max_length=63)
    dns_servers: list[str] | None = Field(default=None, max_length=4)

    @field_validator("hostname")
    @classmethod
    def _hostname_shape(cls, v: str | None) -> str | None:
        import re
        if v is None:
            return v
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$", v):
            raise ValueError("invalid hostname")
        return v


class DiagnoseRequest(BaseModel):
    tool: str
    target: str = Field(min_length=1, max_length=253)
    count: int = Field(default=4, ge=1, le=10)
    port: int | None = Field(default=None, ge=1, le=65535)

    @field_validator("tool")
    @classmethod
    def _tool_known(cls, v: str) -> str:
        allowed = {"ping", "traceroute", "dns", "port"}
        if v not in allowed:
            raise ValueError(f"tool must be one of {allowed}")
        return v

    @field_validator("target")
    @classmethod
    def _target_shape(cls, v: str) -> str:
        import re
        # hostname or IP only - no spaces/shell metacharacters; argv is
        # used downstream, this is a second belt for the braces
        if not re.match(r"^[a-zA-Z0-9._:-]{1,253}$", v):
            raise ValueError("target must be a hostname or IP address")
        return v
