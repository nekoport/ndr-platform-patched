-- ============================================================
-- NDR Platform - PostgreSQL logical schema (Phase 0-2 subset)
-- Ref: NDR System Design & Implementation Plan v1.0, section 6.5
-- ============================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------- Users & access (doc section 12) ------------------
CREATE TABLE IF NOT EXISTS users (
    -- TEXT (not UUID): must match ORM models.py which uses String(36)
    id                   TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    username             TEXT NOT NULL UNIQUE,
    password_hash        TEXT NOT NULL,
    role                 TEXT NOT NULL CHECK (role IN (
                            'administrator','security_engineer','soc_analyst',
                            'soc_lead','auditor')),
    full_name            TEXT,
    is_active            BOOLEAN NOT NULL DEFAULT TRUE,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    failed_attempts      INT   NOT NULL DEFAULT 0,
    locked_until         TIMESTAMPTZ,
    token_version        INT   NOT NULL DEFAULT 0,
    last_login_at        TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- Sensors & network inventory (doc sections 6.1, 14.1)
CREATE TABLE IF NOT EXISTS sensors (
    id                 TEXT PRIMARY KEY,           -- sensor_id (e.g. sensor-01)
    hostname           TEXT NOT NULL,
    capture_iface      TEXT,
    software_versions  JSONB NOT NULL DEFAULT '{}'::jsonb,
    status             TEXT NOT NULL DEFAULT 'unknown'
                       CHECK (status IN ('unknown','online','degraded','offline')),
    last_seen_at       TIMESTAMPTZ,
    notes              TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS network_zones (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    cidr        TEXT NOT NULL,
    zone_type   TEXT NOT NULL DEFAULT 'internal'
                CHECK (zone_type IN ('internal','dmz','external','guest','management')),
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS subnets (
    id        SERIAL PRIMARY KEY,
    zone_id   INT NOT NULL REFERENCES network_zones(id) ON DELETE CASCADE,
    cidr      TEXT NOT NULL,
    label     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- Audit (doc section 13) ---------------------------
CREATE TABLE IF NOT EXISTS audit_records (
    id          BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor       TEXT NOT NULL,
    actor_role  TEXT,
    action      TEXT NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    result      TEXT NOT NULL DEFAULT 'success' CHECK (result IN ('success','failure','denied')),
    source_ip   TEXT,
    request_id  TEXT,
    detail      JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_audit_occurred_at ON audit_records (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor       ON audit_records (actor);
CREATE INDEX IF NOT EXISTS idx_audit_action      ON audit_records (action);

-- ---------- System settings ----------------------------------
CREATE TABLE IF NOT EXISTS system_settings (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO system_settings (key, value) VALUES
  ('retention.metadata_days', '60'::jsonb),
  ('platform.phase',          '"0-2-foundation"'::jsonb),
  ('platform.doc_version',    '"NDR Design v1.0"'::jsonb)
ON CONFLICT (key) DO NOTHING;

-- ---------- Custom Suricata rules (v0.11 custom rule editor) ----------
CREATE TABLE IF NOT EXISTS custom_rules (
    sid        INTEGER PRIMARY KEY,          -- reserved range 1,000,000+
    rule_text  TEXT NOT NULL,
    msg        TEXT NOT NULL,
    action     VARCHAR(16)  NOT NULL DEFAULT 'alert',
    protocol   VARCHAR(16)  NOT NULL DEFAULT 'ip',
    classtype  VARCHAR(64),
    priority   INTEGER,
    rev        INTEGER,
    enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    created_by VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by VARCHAR(64),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------- Reserved for later phases (created now, used then)
CREATE TABLE IF NOT EXISTS update_jobs (
    id          BIGSERIAL PRIMARY KEY,
    job_type    TEXT NOT NULL,                -- ti_update | rule_update
    status      TEXT NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued','running','success','partial_success','failed')),
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    result      JSONB NOT NULL DEFAULT '{}'::jsonb,
    error       TEXT
);

CREATE TABLE IF NOT EXISTS maintenance_jobs (
    id          BIGSERIAL PRIMARY KEY,
    job_type    TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'queued',
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    result      JSONB NOT NULL DEFAULT '{}'::jsonb,
    error       TEXT
);

-- ---------- Threat Intelligence (doc section 9 - Phase 3) -----
CREATE TABLE IF NOT EXISTS ti_feeds (
    id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name            TEXT NOT NULL UNIQUE,
    adapter         TEXT NOT NULL CHECK (adapter IN
                       ('urlhaus','threatfox','feodo','file',
                        'stix','taxii','misp')),
    url             TEXT,
    config          JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    schedule_min    INT   NOT NULL DEFAULT 0,
    ttl_days        INT   NOT NULL DEFAULT 14,
    last_success_at TIMESTAMPTZ,
    last_status     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ti_update_jobs (
    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    feed_id     TEXT REFERENCES ti_feeds(id) ON DELETE SET NULL,
    feed_name   TEXT,
    trigger     TEXT NOT NULL DEFAULT 'manual' CHECK (trigger IN ('manual','schedule')),
    status      TEXT NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued','running','success','partial_success','failed')),
    counts      JSONB NOT NULL DEFAULT '{}'::jsonb,
    error       TEXT,
    created_by  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_ti_job_status ON ti_update_jobs (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ti_job_feed   ON ti_update_jobs (feed_id);

CREATE TABLE IF NOT EXISTS ioc_records (
    id          BIGSERIAL PRIMARY KEY,
    ioc_type    TEXT NOT NULL CHECK (ioc_type IN ('ip','domain','url','md5','sha1','sha256')),
    ioc_value   TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','expired')),
    confidence  TEXT NOT NULL DEFAULT 'medium' CHECK (confidence IN ('high','medium','low')),
    malware     TEXT,
    tags        JSONB NOT NULL DEFAULT '[]'::jsonb,
    provenance  JSONB NOT NULL DEFAULT '[]'::jsonb,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    published   TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    UNIQUE (ioc_type, ioc_value)
);

CREATE INDEX IF NOT EXISTS idx_ioc_status ON ioc_records (status);
CREATE INDEX IF NOT EXISTS idx_ioc_type_value ON ioc_records (ioc_type, ioc_value);

CREATE TABLE IF NOT EXISTS ioc_allowlist (
    id          BIGSERIAL PRIMARY KEY,
    ioc_type    TEXT NOT NULL,
    ioc_value   TEXT NOT NULL,
    reason      TEXT NOT NULL,
    created_by  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (ioc_type, ioc_value)
);

-- v0.14.0: alert whitelist (allowlist) - recurring false-positive
-- control for legitimate internal tooling (scanner/backup/NTP/monitoring).
-- L0 = pipeline suppress (alert never indexed), L1 = alert indexed with
-- suppressed=true (kept, hidden from default triage). Raw events are
-- NEVER touched. Two-man rule: analyst submits -> pending; admin/
-- security_engineer approves. Raw events untouched, story not cut.
CREATE TABLE IF NOT EXISTS alert_allowlist (
    id           BIGSERIAL PRIMARY KEY,
    alert_type   TEXT NOT NULL,
    signature    TEXT,
    entity_field TEXT NOT NULL,
    entity_value TEXT NOT NULL,
    layer        TEXT NOT NULL DEFAULT 'L1'
                 CHECK (layer IN ('L0','L1')),
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending','active','rejected','expired')),
    reason       TEXT NOT NULL,
    retroactive  BOOLEAN NOT NULL DEFAULT FALSE,
    created_by   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_by  TEXT,
    approved_at  TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    hit_count    INTEGER NOT NULL DEFAULT 0,
    last_hit_at  TIMESTAMPTZ,
    UNIQUE (alert_type, signature, entity_field, entity_value)
);
CREATE INDEX IF NOT EXISTS idx_alert_allowlist_status
    ON alert_allowlist (status);

UPDATE system_settings SET value = '"0-3-threat-intel"'::jsonb
WHERE key = 'platform.phase';

-- ---------- Attack Reconstruction (doc section 10 - Phase 4) ----------
-- Story data (nodes/edges/evidence) is written by the pipeline's
-- reconstruction engine; the API owns analyst triage writes.

-- Campaigns (v0.12): analyst bookkeeping that groups related incidents.
-- Rollup columns are derived from members on every membership change.
CREATE TABLE IF NOT EXISTS campaigns (
    id             TEXT PRIMARY KEY,
    title          TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'open'
                   CHECK (status IN ('open','closed')),
    created_by     TEXT,
    incident_count INT  NOT NULL DEFAULT 0,
    severity       TEXT NOT NULL DEFAULT 'low'
                   CHECK (severity IN ('critical','high','medium','low','informational')),
    -- TEXT (not TIMESTAMPTZ): rollups hold raw ISO strings copied from incidents
    -- (see models.py Campaign.first_seen) - must match ORM String(40)
    first_seen     TEXT,
    last_seen      TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_campaign_status ON campaigns (status);

CREATE TABLE IF NOT EXISTS incidents (
    id               TEXT PRIMARY KEY,
    title            TEXT NOT NULL,
    campaign_id      TEXT REFERENCES campaigns(id) ON DELETE SET NULL,
    status           TEXT NOT NULL DEFAULT 'open'
                     CHECK (status IN ('open','confirmed','benign','closed')),
    severity         TEXT NOT NULL DEFAULT 'low'
                     CHECK (severity IN ('critical','high','medium','low','informational')),
    confidence       INT    NOT NULL DEFAULT 0,
    -- TEXT (not TIMESTAMPTZ): raw SQL writes ISO strings here
    -- (see models.py Incident.first_seen) - must match ORM String(40)
    first_seen       TEXT,
    last_seen        TEXT,
    outcome          JSONB  NOT NULL DEFAULT '{}'::jsonb,
    phases           JSONB  NOT NULL DEFAULT '[]'::jsonb,
    entity_count     INT    NOT NULL DEFAULT 0,
    edge_count       INT    NOT NULL DEFAULT 0,
    evidence_count   INT    NOT NULL DEFAULT 0,
    signal_count     INT    NOT NULL DEFAULT 0,
    analyst          TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_incident_status    ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incident_last_seen ON incidents (last_seen);
CREATE INDEX IF NOT EXISTS idx_incident_campaign  ON incidents (campaign_id);

CREATE TABLE IF NOT EXISTS incident_nodes (
    id            BIGSERIAL PRIMARY KEY,
    incident_id   TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,
    key           TEXT NOT NULL,
    label         TEXT NOT NULL,
    role          TEXT,
    phase         TEXT,
    confidence    INT  NOT NULL DEFAULT 50,
    -- TEXT (not TIMESTAMPTZ): raw SQL writes ISO strings - must match ORM String(40)
    first_seen    TEXT,
    last_seen     TEXT,
    attrs         JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_incident_nodes_iid ON incident_nodes (incident_id);

CREATE TABLE IF NOT EXISTS incident_edges (
    id             BIGSERIAL PRIMARY KEY,
    incident_id    TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    src_key        TEXT NOT NULL,
    dst_key        TEXT NOT NULL,
    relation       TEXT NOT NULL,
    phase          TEXT,
    inferred       BOOLEAN NOT NULL DEFAULT FALSE,
    -- TEXT (not TIMESTAMPTZ): raw SQL writes ISO strings - must match ORM String(40)
    first_seen     TEXT,
    last_seen      TEXT,
    evidence_count INT NOT NULL DEFAULT 0,
    confidence     INT NOT NULL DEFAULT 50
);
CREATE INDEX IF NOT EXISTS idx_incident_edges_iid ON incident_edges (incident_id);

CREATE TABLE IF NOT EXISTS incident_evidence (
    id           BIGSERIAL PRIMARY KEY,
    incident_id  TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    -- TEXT (not TIMESTAMPTZ): raw SQL writes ISO strings - must match ORM String(40)
    ts           TEXT,
    kind         TEXT,
    source       TEXT,
    ref_index    TEXT,
    ref_id       TEXT,
    title        TEXT,
    severity     TEXT,
    phase        TEXT,
    summary      TEXT,
    detail       JSONB NOT NULL DEFAULT '{}'::jsonb,
    stage        TEXT,
    attck        JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_incident_evidence_iid ON incident_evidence (incident_id);

CREATE TABLE IF NOT EXISTS incident_notes (
    id           BIGSERIAL PRIMARY KEY,
    incident_id  TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author       TEXT,
    body         TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_incident_notes_iid ON incident_notes (incident_id);

CREATE TABLE IF NOT EXISTS incident_history (
    id           BIGSERIAL PRIMARY KEY,
    incident_id  TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor        TEXT,
    action       TEXT NOT NULL,
    detail       JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_incident_history_iid ON incident_history (incident_id);

-- ---------- Suricata Rule Manager (Phase 6) ----------------------
-- Last-known metadata for rules seen on the shared rules volume.
-- suricata-update REMOVES disabled SIDs from suricata.rules, so this
-- cache keeps disabled rules visible (msg/classtype) in the UI.
CREATE TABLE IF NOT EXISTS suricata_rule_meta (
    sid                INT PRIMARY KEY,
    gid                INT NOT NULL DEFAULT 1,
    rev                INT,
    action             TEXT,
    protocol           TEXT,
    msg                TEXT,
    classtype          TEXT,
    priority           INT,
    enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    changed_by         TEXT,
    changed_at         TIMESTAMPTZ,
    last_seen_in_rules TIMESTAMPTZ,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rule_meta_enabled ON suricata_rule_meta (enabled);
CREATE INDEX IF NOT EXISTS idx_rule_meta_class   ON suricata_rule_meta (classtype);

-- ---------- PCAP & Evidence Workflow (doc section 15) ------------
-- Chain of custody for selective PCAP exports: actor, reason, scope,
-- bundle hash and TTL lifecycle (doc 15.3 + AT-19).
CREATE TABLE IF NOT EXISTS pcap_exports (
    -- TEXT (not UUID): must match ORM models.py which uses String(36)
    id            TEXT PRIMARY KEY,
    actor         TEXT NOT NULL,
    actor_role    TEXT,
    alert_id      TEXT,
    incident_id   TEXT,
    reason        TEXT NOT NULL,
    session_count INT NOT NULL DEFAULT 0,
    sessions      JSONB NOT NULL DEFAULT '[]'::jsonb,
    window_from   TEXT,
    window_to     TEXT,
    files         JSONB NOT NULL DEFAULT '[]'::jsonb,
    total_bytes   BIGINT NOT NULL DEFAULT 0,
    bundle_name   TEXT,
    bundle_sha256 TEXT,
    status        TEXT NOT NULL DEFAULT 'ready',
    error         TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pcap_exports_created ON pcap_exports (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pcap_exports_status  ON pcap_exports (status);

-- Report versions (v0.12): immutable Markdown snapshots of the incident
-- report; version numbers are per-incident, 1-based (max+1).
CREATE TABLE IF NOT EXISTS incident_report_versions (
    id              BIGSERIAL PRIMARY KEY,
    incident_id     TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    version         INT  NOT NULL,
    markdown        TEXT NOT NULL,
    generated_by    TEXT,
    incident_status TEXT,
    severity        TEXT,
    outcome_label   TEXT,
    evidence_count  INT  NOT NULL DEFAULT 0,
    signal_count    INT  NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (incident_id, version)
);
CREATE INDEX IF NOT EXISTS idx_report_versions_incident
    ON incident_report_versions (incident_id, version DESC);

-- ---------------------------------------------------------------- assets (v0.10)
-- Manual asset registry: machines the SOC explicitly registers. Alert
-- enrichment joins on ip so alerts touching a registered asset carry its
-- hostname in the Alert Center.
CREATE TABLE IF NOT EXISTS assets (
    id VARCHAR(36) PRIMARY KEY,
    ip VARCHAR(64) NOT NULL UNIQUE,
    hostname VARCHAR(128) NOT NULL,
    zone VARCHAR(32) NOT NULL DEFAULT 'servers',
    role VARCHAR(128) NOT NULL DEFAULT '',
    criticality VARCHAR(16) NOT NULL DEFAULT 'medium',
    notes TEXT,
    created_by VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets (ip);
