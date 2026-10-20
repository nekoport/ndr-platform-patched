"""SQL-backed incident store (doc 10.6 - `incidents` tables).

The reconstruction engine (pipeline) owns story writes; the API owns
analyst triage writes (status/notes). Raw parameterized SQL via
SQLAlchemy Core keeps this portable between PostgreSQL (production,
TIMESTAMPTZ via postgres/init) and SQLite (tests).

Guarantees:
  * story persistence is idempotent (full snapshot per flush)
  * analyst notes/history are APPEND-only
  * engine restarts reload open stories within the lookback window
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, text


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS incidents (
    id               TEXT PRIMARY KEY,
    title            TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'open',
    severity         TEXT NOT NULL DEFAULT 'low',
    confidence       INTEGER NOT NULL DEFAULT 0,
    first_seen       TEXT,
    last_seen        TEXT,
    outcome          TEXT NOT NULL DEFAULT '{}',
    phases           TEXT NOT NULL DEFAULT '[]',
    entity_count     INTEGER NOT NULL DEFAULT 0,
    edge_count       INTEGER NOT NULL DEFAULT 0,
    evidence_count   INTEGER NOT NULL DEFAULT 0,
    signal_count     INTEGER NOT NULL DEFAULT 0,
    analyst          TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_nodes (
    id            INTEGER PRIMARY KEY,
    incident_id   TEXT NOT NULL,
    kind          TEXT NOT NULL,
    key           TEXT NOT NULL,
    label         TEXT NOT NULL,
    role          TEXT,
    phase         TEXT,
    confidence    INTEGER NOT NULL DEFAULT 50,
    first_seen    TEXT,
    last_seen     TEXT,
    attrs         TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS incident_edges (
    id            INTEGER PRIMARY KEY,
    incident_id   TEXT NOT NULL,
    src_key       TEXT NOT NULL,
    dst_key       TEXT NOT NULL,
    relation      TEXT NOT NULL,
    phase         TEXT,
    inferred      INTEGER NOT NULL DEFAULT 0,
    first_seen    TEXT,
    last_seen     TEXT,
    evidence_count INTEGER NOT NULL DEFAULT 0,
    confidence    INTEGER NOT NULL DEFAULT 50
);
CREATE TABLE IF NOT EXISTS incident_evidence (
    id            INTEGER PRIMARY KEY,
    incident_id   TEXT NOT NULL,
    ts            TEXT,
    kind          TEXT,
    source        TEXT,
    ref_index     TEXT,
    ref_id        TEXT,
    title         TEXT,
    severity      TEXT,
    phase         TEXT,
    summary       TEXT,
    detail        TEXT NOT NULL DEFAULT '{}',
    stage         TEXT,
    attck         TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS incident_notes (
    id            INTEGER PRIMARY KEY,
    incident_id   TEXT NOT NULL,
    author        TEXT,
    body          TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_history (
    id            INTEGER PRIMARY KEY,
    incident_id   TEXT NOT NULL,
    occurred_at   TEXT NOT NULL,
    actor         TEXT,
    action        TEXT NOT NULL,
    detail        TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_incident_nodes_iid ON incident_nodes (incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_edges_iid ON incident_edges (incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_evidence_iid ON incident_evidence (incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_status ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incident_last_seen ON incidents (last_seen);
CREATE INDEX IF NOT EXISTS idx_incident_notes_iid ON incident_notes (incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_history_iid ON incident_history (incident_id);
"""


class IncidentStore:
    def __init__(self, db_url: str):
        self.engine = create_engine(db_url, future=True, pool_pre_ping=True)
        self.ensure_schema()

    def ensure_schema(self) -> None:
        from sqlalchemy import inspect as _inspect, text as _t
        with self.engine.begin() as conn:
            for stmt in SCHEMA_SQL.split(";"):
                if stmt.strip():
                    conn.execute(_t(stmt))
        # doc 11 migration: dual-framework columns on evidence.
        # Inspector-guarded (v0.12.4): the ALTER only runs when a column
        # is genuinely missing, so boots against an already-migrated DB
        # stay silent - the old try/except flow made Postgres log a
        # duplicate-column ERROR on every pipeline start. Inspector keeps
        # the check dialect-agnostic (SQLite tests / PostgreSQL prod).
        inspector = _inspect(self.engine)
        existing = {c["name"]
                    for c in inspector.get_columns("incident_evidence")}
        missing = [(col, ddl)
                   for col, ddl in (("stage", "TEXT"),
                                    ("attck", "TEXT NOT NULL DEFAULT '[]'"))
                   if col not in existing]
        if missing:
            with self.engine.begin() as conn:
                for col, ddl in missing:
                    conn.execute(_t(
                        f"ALTER TABLE incident_evidence ADD COLUMN "
                        f"{col} {ddl}"))

    # ------------------------------------------------------------ writes
    def save_story(self, story) -> None:
        """Full snapshot upsert of one story (nodes/edges/evidence)."""
        summary = story.to_summary()
        detail = story.to_detail()
        now = iso(utcnow())
        with self.engine.begin() as conn:
            conn.execute(text(
                """
                INSERT INTO incidents (id, title, status, severity,
                    confidence, first_seen, last_seen, outcome, phases,
                    entity_count, edge_count, evidence_count, signal_count,
                    analyst, created_at, updated_at)
                VALUES (:id, :title, :status, :severity, :confidence,
                    :first_seen, :last_seen, :outcome, :phases,
                    :entity_count, :edge_count, :evidence_count,
                    :signal_count, NULL, :created_at, :updated_at)
                ON CONFLICT (id) DO UPDATE SET
                    title = EXCLUDED.title,
                    status = EXCLUDED.status,
                    severity = EXCLUDED.severity,
                    confidence = EXCLUDED.confidence,
                    first_seen = EXCLUDED.first_seen,
                    last_seen = EXCLUDED.last_seen,
                    outcome = EXCLUDED.outcome,
                    phases = EXCLUDED.phases,
                    entity_count = EXCLUDED.entity_count,
                    edge_count = EXCLUDED.edge_count,
                    evidence_count = EXCLUDED.evidence_count,
                    signal_count = EXCLUDED.signal_count,
                    updated_at = EXCLUDED.updated_at
                """), {
                    "id": summary["id"], "title": summary["title"],
                    "status": summary["status"],
                    "severity": summary["severity"],
                    "confidence": summary["confidence"],
                    "first_seen": summary["first_seen"],
                    "last_seen": summary["last_seen"],
                    "outcome": json.dumps({**story.outcome(),
                                           "stage_progression":
                                           story.stage_progression(),
                                           "stage_history":
                                           list(story.stage_history),
                                           "deepest_stage":
                                           story.deepest_stage()}),
                    "phases": json.dumps(summary["phases"]),
                    "entity_count": summary["entity_count"],
                    "edge_count": summary["edge_count"],
                    "evidence_count": summary["evidence_count"],
                    "signal_count": summary["signal_count"],
                    "created_at": now, "updated_at": now,
                })
            conn.execute(text(
                "DELETE FROM incident_nodes WHERE incident_id = :iid"),
                {"iid": story.id})
            conn.execute(text(
                "DELETE FROM incident_edges WHERE incident_id = :iid"),
                {"iid": story.id})
            conn.execute(text(
                "DELETE FROM incident_evidence WHERE incident_id = :iid"),
                {"iid": story.id})
            for n in detail["nodes"]:
                conn.execute(text(
                    """
                    INSERT INTO incident_nodes (incident_id, kind, key,
                        label, role, phase, confidence, first_seen,
                        last_seen, attrs)
                    VALUES (:iid, :kind, :key, :label, :role, :phase,
                        :confidence, :first_seen, :last_seen, :attrs)
                    """), {
                        "iid": story.id, "kind": n["kind"], "key": n["key"],
                        "label": n["label"], "role": n.get("role"),
                        "phase": n.get("phase"),
                        "confidence": int(n.get("confidence") or 50),
                        "first_seen": iso(_epoch_to_dt(n.get("first_seen"))),
                        "last_seen": iso(_epoch_to_dt(n.get("last_seen"))),
                        "attrs": json.dumps(n.get("attrs") or {}),
                    })
            for e in detail["edges"]:
                conn.execute(text(
                    """
                    INSERT INTO incident_edges (incident_id, src_key,
                        dst_key, relation, phase, inferred, first_seen,
                        last_seen, evidence_count, confidence)
                    VALUES (:iid, :src, :dst, :relation, :phase, :inferred,
                        :first_seen, :last_seen, :evidence_count,
                        :confidence)
                    """), {
                        "iid": story.id, "src": e["src"], "dst": e["dst"],
                        "relation": e["relation"],
                        "phase": e.get("phase"),
                        # v0.12.5: Postgres BOOLEAN rejects INTEGER 1/0 in
                        # raw SQL ("column inferred is of type boolean but
                        # expression is of type integer") -> every story
                        # persist rolled back. bool() adapts on both
                        # Postgres (bool) and SQLite (1/0).
                        "inferred": bool(e.get("inferred")),
                        "first_seen": iso(_epoch_to_dt(e.get("first_seen"))),
                        "last_seen": iso(_epoch_to_dt(e.get("last_seen"))),
                        "evidence_count": int(e.get("evidence_count") or 0),
                        "confidence": int(e.get("confidence") or 50),
                    })
            for ev in detail["evidence"]:
                conn.execute(text(
                    """
                    INSERT INTO incident_evidence (incident_id, ts, kind,
                        source, ref_index, ref_id, title, severity, phase,
                        summary, detail, stage, attck)
                    VALUES (:iid, :ts, :kind, :source, :ref_index,
                        :ref_id, :title, :severity, :phase, :summary,
                        :detail, :stage, :attck)
                    """), {
                        "iid": story.id, "ts": ev.get("ts_iso"),
                        "kind": ev.get("kind"), "source": ev.get("source"),
                        "ref_index": ev.get("ref_index"),
                        "ref_id": ev.get("ref_id"),
                        "title": ev.get("title"),
                        "severity": ev.get("severity"),
                        "phase": ev.get("phase"),
                        "summary": ev.get("summary"),
                        "detail": json.dumps(ev.get("detail") or {}),
                        "stage": ev.get("stage") or None,
                        "attck": json.dumps(ev.get("attck") or []),
                    })

    def load_active(self, lookback_hours: int) -> list[dict]:
        """Load stories updated within the lookback window (for restart)."""
        cutoff = iso(utcnow() - timedelta(hours=lookback_hours))
        with self.engine.connect() as conn:
            rows = conn.execute(text(
                "SELECT id FROM incidents "
                "WHERE status IN ('open','confirmed') "
                "AND updated_at >= :cutoff"), {"cutoff": cutoff}).all()
            ids = [r[0] for r in rows]
            out = []
            for iid in ids:
                out.append({
                    "incident": dict(conn.execute(text(
                        "SELECT * FROM incidents WHERE id = :iid"),
                        {"iid": iid}).mappings().first() or {}),
                    "nodes": [dict(r) for r in conn.execute(text(
                        "SELECT * FROM incident_nodes WHERE incident_id "
                        "= :iid"), {"iid": iid}).mappings().all()],
                    "edges": [dict(r) for r in conn.execute(text(
                        "SELECT * FROM incident_edges WHERE incident_id "
                        "= :iid"), {"iid": iid}).mappings().all()],
                    "evidence": [dict(r) for r in conn.execute(text(
                        "SELECT * FROM incident_evidence WHERE incident_id"
                        " = :iid"), {"iid": iid}).mappings().all()],
                })
        return out

    # ------------------------------------------------------------ analyst
    def update_status(self, incident_id: str, status: str,
                      analyst: str, note: str | None) -> bool:
        now = iso(utcnow())
        with self.engine.begin() as conn:
            res = conn.execute(text(
                "UPDATE incidents SET status = :status, analyst = :analyst,"
                " updated_at = :now WHERE id = :iid"),
                {"status": status, "analyst": analyst, "now": now,
                 "iid": incident_id})
            if res.rowcount == 0:
                return False
            self._history(conn, incident_id, "status_change",
                          {"to": status, "note": note}, analyst)
            if note:
                self._note(conn, incident_id, analyst, note)
        return True

    def add_note(self, incident_id: str, author: str, body: str) -> bool:
        with self.engine.begin() as conn:
            exists = conn.execute(text(
                "SELECT 1 FROM incidents WHERE id = :iid"),
                {"iid": incident_id}).first()
            if exists is None:
                return False
            self._note(conn, incident_id, author, body)
            self._history(conn, incident_id, "note_added", {}, author)
        return True

    @staticmethod
    def _note(conn, iid: str, author: str, body: str) -> None:
        conn.execute(text(
            "INSERT INTO incident_notes (incident_id, author, body, "
            "created_at) VALUES (:iid, :author, :body, :now)"),
            {"iid": iid, "author": author, "body": body,
             "now": iso(utcnow())})

    @staticmethod
    def _history(conn, iid: str, action: str, detail: dict,
                 actor: str) -> None:
        conn.execute(text(
            "INSERT INTO incident_history (incident_id, occurred_at, "
            "actor, action, detail) VALUES (:iid, :now, :actor, :action,"
            " :detail)"),
            {"iid": iid, "now": iso(utcnow()), "actor": actor,
             "action": action, "detail": json.dumps(detail or {})})

    def counts(self) -> dict:
        with self.engine.connect() as conn:
            by_status = dict(conn.execute(text(
                "SELECT status, COUNT(*) FROM incidents "
                "GROUP BY status")).all())
            open_sev = dict(conn.execute(text(
                "SELECT severity, COUNT(*) FROM incidents "
                "WHERE status IN ('open','confirmed') "
                "GROUP BY severity")).all())
            total = conn.execute(text(
                "SELECT COUNT(*) FROM incidents")).scalar() or 0
            recent = conn.execute(text(
                "SELECT COUNT(*) FROM incidents WHERE created_at >= "
                ":cutoff"), {"cutoff": iso(utcnow() - timedelta(hours=24))}
            ).scalar() or 0
        return {"total": int(total), "by_status": by_status,
                "open_by_severity": open_sev, "new_24h": int(recent)}


def _epoch_to_dt(ts):
    if not ts:
        return None
    from datetime import datetime, timezone as _tz
    try:
        return datetime.fromtimestamp(float(ts), tz=_tz.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return None
