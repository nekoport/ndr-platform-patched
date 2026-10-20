"""NDR API main application."""

from __future__ import annotations

import time
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.audit import audit
from app.config import config
from app.db import Base, SessionLocal, engine
from app.routers import (admin, alerts, assets, auth, campaigns, evidence,
                         events, graph, health, incidents, rules, settings,
                         ti)
from app.routers.auth import bootstrap_admin
from app.security import get_current_user

app = FastAPI(
    title="NDR Platform API",
    version=__version__,
    description="Phase 0-6 API: guarded search, alerts, health, "
                "administration, audit, threat intelligence (doc section 9), "
                "attack reconstruction (doc section 10), threat-map "
                "relationship graph & geo flows, suricata rule manager, "
                "PCAP & evidence workflow (doc section 15), custom rule "
                "editor + STIX/TAXII/MISP feeds + system settings (v0.11), "
                "campaigns + report versioning + hardening (v0.12).",
)

# Same-origin only (UI proxies /backend/* to this API). No wildcard CORS.
app.add_middleware(CORSMiddleware, allow_origins=[],
                   allow_credentials=False, allow_methods=[],
                   allow_headers=[])

app.include_router(auth.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(health.router)
app.include_router(admin.router)
app.include_router(assets.router)
app.include_router(ti.router)
app.include_router(incidents.router)
app.include_router(campaigns.router)
app.include_router(graph.router)
app.include_router(rules.router)
app.include_router(evidence.router)
app.include_router(settings.router)
from app.routers import allowlist  # noqa: E402 - v0.14.0 alert whitelist
app.include_router(allowlist.router)
from app.routers import arkime_proxy  # noqa: E402 - NDR SSO Arkime proxy
app.include_router(arkime_proxy.router)


@app.middleware("http")
async def request_context(request: Request, call_next):
    request.state.request_id = request.headers.get("X-Request-ID",
                                                   str(uuid.uuid4()))
    start = time.monotonic()
    response = await call_next(request)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["X-Response-Time"] = f"{elapsed_ms}ms"
    return response


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Baseline hardening headers on every API response (v0.12).

    HSTS is only advertised when the deployment actually serves TLS
    (TLS_ENABLED=1) - advertising it over plain HTTP would break the
    demo/http deployment for browsers that honour it prematurely.
    """
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    if config.tls_enabled:
        response.headers.setdefault("Strict-Transport-Security",
                                    "max-age=31536000; includeSubDomains")
    return response


@app.on_event("startup")
def on_startup() -> None:
    # Create tables if missing (production uses postgres/init/001_schema.sql;
    # this covers first boot against an empty database).
    Base.metadata.create_all(bind=engine)
    _migrate_doc11_columns()
    _migrate_v012_columns()
    _migrate_ti_adapter_check()
    db = SessionLocal()
    try:
        bootstrap_admin(db)
    finally:
        db.close()


def _migrate_doc11_columns() -> None:
    """doc 11 dual-framework columns (idempotent, inspector-guarded).

    The pipeline owns the incident schema; this only guarantees the
    stage/attck columns exist so the API never fails when it boots
    before the pipeline's own migration. Column existence is checked
    via the SQLAlchemy inspector FIRST, so the ALTER only runs on
    databases that genuinely miss the columns. This avoids the old
    exception-driven flow that spammed the Postgres log with
    `column "..." already exists` on every API boot (v0.12.4 fix).
    The inspector keeps the check dialect-agnostic (SQLite in tests,
    PostgreSQL in production - neither shares an ADD COLUMN IF NOT
    EXISTS syntax across both).
    """
    from sqlalchemy import inspect, text

    existing = {c["name"]
                for c in inspect(engine).get_columns("incident_evidence")}
    missing = [(col, ddl) for col, ddl in (("stage", "VARCHAR(32)"),
                                           ("attck", "JSON DEFAULT '[]'"))
               if col not in existing]
    if not missing:
        return
    with engine.begin() as conn:
        for col, ddl in missing:
            conn.execute(text(
                f"ALTER TABLE incident_evidence ADD COLUMN "
                f"{col} {ddl}"))


def _migrate_v012_columns() -> None:
    """v0.12 campaign columns (idempotent, inspector-guarded).

    incidents.campaign_id is analyst-owned bookkeeping: the pipeline's
    raw-SQL upsert never touches it. Existing databases get the column
    added on boot; fresh databases already have it from create_all.
    Inspector-guarded so already-migrated databases boot silently
    (no duplicate-column noise in the Postgres log - v0.12.4 fix).
    """
    from sqlalchemy import inspect, text

    existing = {c["name"] for c in inspect(engine).get_columns("incidents")}
    if "campaign_id" in existing:
        return
    with engine.begin() as conn:
        conn.execute(text(
            "ALTER TABLE incidents ADD COLUMN "
            "campaign_id VARCHAR(64)"))


def _migrate_ti_adapter_check() -> None:
    """v0.12.5: widen the ti_feeds.adapter CHECK to the full TI_ADAPTERS.

    Pre-0.12.5 databases carried CHECK (adapter IN ('urlhaus','threatfox',
    'feodo','file')) while the API accepts +stix/taxii/misp - creating a
    standard-format feed failed with a 500 (CHECK violation, live-verified
    on the deployment VM). Fresh installs get the widened constraint from
    postgres/init/001_schema.sql; existing ones are migrated here, once,
    guarded via pg_constraint so nothing runs on SQLite or twice.
    """
    if engine.dialect.name != "postgresql":
        return
    from sqlalchemy import text
    with engine.begin() as conn:
        row = conn.execute(text(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid = 'ti_feeds'::regclass AND contype = 'c' "
            "AND pg_get_constraintdef(oid) LIKE '%adapter%'"
        )).first()
        if row is None or "stix" in (row[0] or ""):
            return  # nothing to migrate / already widened
        conn.execute(text(
            "ALTER TABLE ti_feeds DROP CONSTRAINT ti_feeds_adapter_check"))
        conn.execute(text(
            "ALTER TABLE ti_feeds ADD CONSTRAINT ti_feeds_adapter_check "
            "CHECK (adapter IN ('urlhaus','threatfox','feodo','file',"
            "'stix','taxii','misp'))"))


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    return JSONResponse(status_code=500,
                        content={"detail": "Internal server error",
                                 "request_id": getattr(request.state,
                                                       "request_id", None)})


@app.get("/api/meta")
def meta():
    return {"service": "ndr-api", "version": __version__,
            "phase": "0-5-threat-map-correlation"}
