"""SQL-backed IOC store (doc section 6.5 `ti_feeds` / `ti_update_jobs` /
`ioc_records` tables + auditable `ioc_allowlist`).

The API owns feed/job writes (REST + UI); the pipeline consumes jobs,
upserts IOCs and refreshes its matcher from here. Raw parameterized SQL
via SQLAlchemy Core keeps this portable across PostgreSQL (production)
and SQLite (tests) without duplicating ORM models.

Guarantees:
  * IOC dedup on (ioc_type, ioc_value) with provenance retained
  * expiry MARKS rows `expired` - never deletes
  * job claim is atomic (single consumer, conditional UPDATE)
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, text

from app.intel.feeds import default_feed_definitions


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _jload(value, default):
    """Load a JSON column that may arrive as str/bytes (SQLite TEXT) or as
    an ALREADY-DECODED dict/list (Postgres JSONB via psycopg).

    v0.12.5: raw json.loads() on a decoded JSONB value raises TypeError;
    for feed configs the old guard silently REPLACED it with {} (dropping
    e.g. threatfox days:2 on the second run) - same SQLite-vs-Postgres
    class as the correlation store bug.
    """
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS ti_feeds (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE,
    adapter          TEXT NOT NULL,
    url              TEXT,
    config           TEXT NOT NULL DEFAULT '{}',
    enabled          INTEGER NOT NULL DEFAULT 0,
    schedule_min     INTEGER NOT NULL DEFAULT 0,
    ttl_days         INTEGER NOT NULL DEFAULT 14,
    last_success_at  TEXT,
    last_status      TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ti_update_jobs (
    id            TEXT PRIMARY KEY,
    feed_id       TEXT,
    feed_name     TEXT,
    trigger       TEXT NOT NULL DEFAULT 'manual',
    status        TEXT NOT NULL DEFAULT 'queued',
    counts        TEXT NOT NULL DEFAULT '{}',
    error         TEXT,
    created_by    TEXT,
    created_at    TEXT NOT NULL,
    started_at    TEXT,
    finished_at   TEXT
);
CREATE TABLE IF NOT EXISTS ioc_records (
    id            INTEGER PRIMARY KEY,
    ioc_type      TEXT NOT NULL,
    ioc_value     TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active',
    confidence    TEXT NOT NULL DEFAULT 'medium',
    malware       TEXT,
    tags          TEXT NOT NULL DEFAULT '[]',
    provenance    TEXT NOT NULL DEFAULT '[]',
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    published     TEXT,
    expires_at    TEXT,
    UNIQUE (ioc_type, ioc_value)
);
CREATE TABLE IF NOT EXISTS ioc_allowlist (
    id          INTEGER PRIMARY KEY,
    ioc_type    TEXT NOT NULL,
    ioc_value   TEXT NOT NULL,
    reason      TEXT NOT NULL,
    created_by  TEXT,
    created_at  TEXT NOT NULL,
    UNIQUE (ioc_type, ioc_value)
);
CREATE INDEX IF NOT EXISTS idx_ioc_status ON ioc_records (status);
CREATE INDEX IF NOT EXISTS idx_ioc_value  ON ioc_records (ioc_value);
CREATE INDEX IF NOT EXISTS idx_job_status ON ti_update_jobs (status);
"""


class IntelStore:
    def __init__(self, db_url: str):
        self.engine = create_engine(db_url, future=True,
                                    pool_pre_ping=True)
        self.ensure_schema()

    def ensure_schema(self) -> None:
        from sqlalchemy import text as _t
        with self.engine.begin() as conn:
            for stmt in SCHEMA_SQL.split(";"):
                if stmt.strip():
                    conn.execute(_t(stmt))

    def recover_orphan_jobs(self) -> int:
        """Mark jobs stuck in 'running' as failed (v0.12.5).

        A crashed pipeline used to leave orphaned running jobs forever:
        no consumer would ever finish them, and (pre-0.12.5) a poisoned
        counts payload made even the finally-block fail. Best-effort, one
        UPDATE at startup.
        """
        try:
            with self.engine.begin() as conn:
                res = conn.execute(text(
                    "UPDATE ti_update_jobs SET status='failed', "
                    "error='orphaned: pipeline restarted mid-job', "
                    "finished_at=:now WHERE status='running'"),
                    {"now": iso(utcnow())})
                return res.rowcount
        except Exception:  # noqa: BLE001 - TI must not kill ingest
            return 0

    def seed_default_feeds(self) -> int:
        """Insert the starter feed set when ti_feeds is EMPTY (v0.12.5).

        default_feed_definitions() existed but was never called (dead
        code) - fresh installs had zero feeds and TI looked broken. Only
        seeds when the table has no rows at all: deleted starter feeds
        stay deleted, operator-configured feeds are never touched.
        """
        try:
            with self.engine.begin() as conn:
                n = conn.execute(text(
                    "SELECT COUNT(*) FROM ti_feeds")).scalar() or 0
                if n:
                    return 0
                for f in default_feed_definitions():
                    conn.execute(text(
                        "INSERT INTO ti_feeds (id, name, adapter, url, "
                        "config, enabled, schedule_min, ttl_days, "
                        "created_at, updated_at) VALUES (:id, :name, "
                        ":adapter, :url, :config, :enabled, :schedule_min, "
                        ":ttl_days, :now, :now)"), {
                            "id": str(uuid.uuid4()),
                            "name": f["name"], "adapter": f["adapter"],
                            "url": f.get("url"),
                            "config": json.dumps(
                                {k: v for k, v in f.items()
                                 if k in ("days",)} or {}),
                            "enabled": 1 if f.get("enabled") else 0,
                            "schedule_min": int(f.get("schedule_min") or 0),
                            "ttl_days": int(f.get("ttl_days") or 14),
                            "now": iso(utcnow())})
                return len(default_feed_definitions())
        except Exception:  # noqa: BLE001 - TI must not kill ingest
            return 0

    # ------------------------------------------------------------ feeds
    def feeds(self, enabled_only: bool = False) -> list[dict]:
        # bare `WHERE enabled` is portable: SQLite (INTEGER 0/1) and
        # Postgres (BOOLEAN) both accept it - `enabled = 1` errors on
        # Postgres boolean columns.
        sql = "SELECT * FROM ti_feeds" + (" WHERE enabled" if enabled_only else "") \
              + " ORDER BY name"
        with self.engine.connect() as conn:
            rows = conn.execute(text(sql)).mappings().all()
        return [self._feed_row(r) for r in rows]

    @staticmethod
    def _feed_row(r) -> dict:
        d = dict(r)
        d["enabled"] = bool(d.get("enabled"))
        # JSONB (Postgres) already returns a dict - keep it as-is instead
        # of silently replacing non-empty configs with {} on run 2.
        d["config"] = _jload(d.get("config"), {})
        return d

    # ------------------------------------------------------------ jobs
    def claim_queued_job(self) -> dict | None:
        """Atomically claim the oldest queued job (single consumer)."""
        with self.engine.begin() as conn:
            row = conn.execute(text(
                "SELECT * FROM ti_update_jobs WHERE status='queued' "
                "ORDER BY created_at LIMIT 1")).mappings().first()
            if row is None:
                return None
            res = conn.execute(text(
                "UPDATE ti_update_jobs SET status='running', "
                "started_at=:now WHERE id=:id AND status='queued'"),
                {"now": iso(utcnow()), "id": row["id"]})
            if res.rowcount != 1:
                return None
        job = dict(row)
        job["status"] = "running"
        job["counts"] = _jload(job.get("counts"), {})
        return job

    def finish_job(self, job_id: int, status: str, counts: dict,
                   error: str | None = None) -> None:
        # default=str: any non-JSON-serializable value (datetime, etc.)
        # must never blow up the finally-block again and orphan the job.
        with self.engine.begin() as conn:
            conn.execute(text(
                "UPDATE ti_update_jobs SET status=:st, counts=:counts, "
                "error=:err, finished_at=:now WHERE id=:id"),
                {"st": status, "counts": json.dumps(counts, default=str),
                 "err": error, "now": iso(utcnow()), "id": job_id})

    # ------------------------------------------------------------ iocs
    def upsert_iocs(self, feed: dict, iocs: list, ttl_days: int) -> dict:
        """Upsert one fetch result. Returns new/changed/unchanged counts."""
        now = utcnow()
        now_iso = iso(now)
        new = changed = unchanged = 0
        with self.engine.begin() as conn:
            for ioc in iocs:
                row = conn.execute(text(
                    "SELECT id, status, confidence, provenance, first_seen, "
                    "malware FROM ioc_records WHERE ioc_type=:t "
                    "AND ioc_value=:v"),
                    {"t": ioc.ioc_type, "v": ioc.value}).mappings().first()
                base = ioc.published if (ioc.published and ioc.published > now) \
                    else now
                expires = iso(base + timedelta(days=max(1, ttl_days)))
                if row is None:
                    prov = [{"feed": feed["name"],
                             "first_seen": now_iso, "last_seen": now_iso,
                             "confidence": ioc.confidence,
                             "reference": ioc.reference,
                             "malware": ioc.malware}]
                    conn.execute(text(
                        "INSERT INTO ioc_records (ioc_type, ioc_value, status, "
                        "confidence, malware, tags, provenance, first_seen, "
                        "last_seen, published, expires_at) VALUES (:t, :v, "
                        "'active', :c, :m, :tags, :prov, :fs, :ls, :pub, :exp)"),
                        {"t": ioc.ioc_type, "v": ioc.value, "c": ioc.confidence,
                         "m": ioc.malware, "tags": json.dumps(ioc.tags[:4]),
                         "prov": json.dumps(prov[:8]), "fs": now_iso,
                         "ls": now_iso, "pub": iso(ioc.published), "exp": expires})
                    new += 1
                    continue
                prov = row["provenance"]
                if not isinstance(prov, list):
                    # SQLite TEXT -> str; Postgres JSONB already a list.
                    try:
                        prov = json.loads(prov or "[]")
                    except (TypeError, ValueError):
                        prov = []
                entry = next((p for p in prov if p.get("feed") == feed["name"]),
                             None)
                modified = entry is None or entry.get("confidence") != ioc.confidence
                if entry is None:
                    prov.append({"feed": feed["name"],
                                 "first_seen": now_iso, "last_seen": now_iso,
                                 "confidence": ioc.confidence,
                                 "reference": ioc.reference,
                                 "malware": ioc.malware})
                    prov = prov[-8:]
                else:
                    if entry.get("confidence") != ioc.confidence:
                        entry["confidence"] = ioc.confidence
                        modified = True
                    entry["last_seen"] = now_iso
                status = "active"          # a fresh sighting reactivates
                conn.execute(text(
                    "UPDATE ioc_records SET status=:st, confidence=:c, "
                    "malware=:m, provenance=:prov, last_seen=:ls, "
                    "published=COALESCE(:pub, published), expires_at=:exp "
                    "WHERE id=:id"),
                    {"st": status, "c": ioc.confidence, "m": ioc.malware,
                     "prov": json.dumps(prov), "ls": now_iso,
                     "pub": iso(ioc.published), "exp": expires, "id": row["id"]})
                if modified or row["status"] == "expired":
                    changed += 1
                else:
                    unchanged += 1
        return {"new": new, "changed": changed, "unchanged": unchanged,
                "total": len(iocs)}

    def expire_stale(self) -> int:
        """Mark active IOCs past their expires_at (doc 9.2 step 8)."""
        with self.engine.begin() as conn:
            res = conn.execute(text(
                "UPDATE ioc_records SET status='expired' "
                "WHERE status='active' AND expires_at IS NOT NULL "
                "AND expires_at < :now"), {"now": iso(utcnow())})
            return res.rowcount

    def active_iocs(self, limit: int = 200_000) -> list[dict]:
        with self.engine.connect() as conn:
            rows = conn.execute(text(
                "SELECT ioc_type, ioc_value, confidence, malware, "
                "first_seen, last_seen, expires_at FROM ioc_records "
                "WHERE status='active' ORDER BY id LIMIT :lim"),
                {"lim": limit}).mappings().all()
        return [dict(r) for r in rows]

    def counts(self) -> dict:
        with self.engine.connect() as conn:
            by_status = dict(conn.execute(text(
                "SELECT status, COUNT(*) AS c FROM ioc_records "
                "GROUP BY status")).all())
            by_type = dict(conn.execute(text(
                "SELECT ioc_type, COUNT(*) AS c FROM ioc_records "
                "WHERE status='active' GROUP BY ioc_type")).all())
        return {"by_status": by_status, "by_type_active": by_type}

    # -------------------------------------------------------- allowlist
    def allowlist(self) -> list[dict]:
        with self.engine.connect() as conn:
            rows = conn.execute(text(
                "SELECT * FROM ioc_allowlist ORDER BY id")).mappings().all()
        return [dict(r) for r in rows]

    def allowlisted_keys(self) -> set[tuple[str, str]]:
        return {(r["ioc_type"], r["ioc_value"]) for r in self.allowlist()}

    # ---------------------------------------------------------- metrics
    def feed_schedule_due(self, feed: dict, min_gap_seconds: int) -> bool:
        """True when a scheduled run is due (doc 9.3 auto schedule)."""
        if not feed.get("enabled") or not feed.get("schedule_min"):
            return False
        if feed.get("last_status") in ("queued", "running"):
            return False
        if not feed.get("last_success_at"):
            return True
        try:
            last = datetime.fromisoformat(str(feed["last_success_at"]))
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            return (utcnow() - last).total_seconds() >= \
                max(feed["schedule_min"] * 60, min_gap_seconds)
        except ValueError:
            return True
