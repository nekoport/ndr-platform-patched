"""Load-test target: the REAL FastAPI app with a synthetic OpenSearch.

Starts the actual NDR API (app.main:app) against a throwaway SQLite
database seeded with a realistic amount of analyst data (incidents,
campaigns, users). OpenSearch is replaced by an in-memory fake that
returns synthetic hits so event/alert searches exercise the full
guard -> handler -> serialize path without a search cluster.

Usage:
    uvicorn scripts.loadtest_target:app --port 8010 --app-dir scripts/loadtest

Run via scripts/loadtest/run.sh which seeds, starts, waits for health
and tears down. This is a TEST HARNESS - never deploy it.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

PLATFORM = Path(__file__).resolve().parents[2]  # .../ndr-platform
sys.path.insert(0, str(PLATFORM / "api"))

DB_PATH = Path(__file__).resolve().parent / "loadtest.db"
DB_PATH.unlink(missing_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{DB_PATH}"
os.environ.setdefault("JWT_SECRET", "loadtest-secret")
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "loadtest-admin-pass")
# the 30/min per-user search guard is a PRODUCTION protection; on the
# load target we lift it so the generator can exercise the search path
# itself (documented in docs/LOAD-TESTING.md)
os.environ.setdefault("SEARCH_RATE_LIMIT", "1000000")

from app.db import Base, SessionLocal, engine  # noqa: E402
from app.main import app as fastapi_app  # noqa: E402
from app.models import Campaign, Incident, User  # noqa: E402
import app.os_client as _os_client  # noqa: E402
from app.os_client import OSClient  # noqa: E402
from app.security import hash_password  # noqa: E402

# ---------------------------------------------------------------- fake OS
SYNTH_EVENTS = [
    {
        "@timestamp": "2026-10-12T10:00:01Z", "session_id": f"sess-{i}",
        "source_engine": "suricata", "event_type": "alert",
        "source": {"ip": "203.0.113.25"},
        "destination": {"ip": "10.0.20.15", "port": 443},
        "network": {"transport": "tcp", "bytes": 1200 + i},
        "rule": {"name": "ET SCAN Suspected Nmap", "sid": 2009358},
        "severity": 2,
    }
    for i in range(120)
]


class LoadTestOS(OSClient):
    """In-memory OpenSearch stand-in with synthetic data."""

    def __init__(self):
        super().__init__("http://localhost:9200")  # no I/O at init

    def guarded_search(self, **kw):
        self.validate_alias(kw["alias"])
        self.validate_query(kw.get("query") or {})
        self.validate_sort(kw.get("sort"))
        self.build_time_filter(kw.get("time_from"), kw.get("time_to"))
        size = (kw.get("size") or 50)
        hits = SYNTH_EVENTS[:size]
        return {"hits": {"total": {"value": len(SYNTH_EVENTS),
                                   "relation": "eq"},
                         "hits": [{"_index": "ndr-events-2026.10.12",
                                   "_id": h["session_id"],
                                   "_source": h} for h in hits]}}

    def get_by_id(self, alias, doc_id):
        self.validate_alias(alias)
        return None

    def cluster_health(self):
        return {"status": "green", "number_of_nodes": 1,
                "unassigned_shards": 0}

    def latest_health_doc(self):
        return {"sensor_id": "sensor-01", "eps": 842.0,
                "backlog_seconds": 0.8,
                "last_event_time": "2026-10-12T10:05:00Z"}

    def aggregate(self, alias, body):
        self.validate_alias(alias)
        return {"hits": {"total": {"value": len(SYNTH_EVENTS)}},
                "aggregations": {
                    k: {"buckets": [
                        {"key_as_string": "2026-10-12T10:00:00Z",
                         "doc_count": 42}] for k in body.get("aggs", {})}}
                }

    def count(self, alias, query=None):
        self.validate_alias(alias)
        return len(SYNTH_EVENTS)


def seed_db() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.username == "admin").first():
            db.add(User(username="admin",
                        password_hash=hash_password("loadtest-admin-pass"),
                        role="administrator"))
        for i in range(60):
            db.add(Incident(
                id=f"inc-load-{i:03d}",
                title=f"Load story {i}: 203.0.113.0/24 -> srv-{i % 8}",
                status="open" if i % 3 else "confirmed",
                severity=("high" if i % 5 == 0 else
                          "medium" if i % 3 else "low"),
                confidence=40 + (i % 55),
                first_seen="2026-10-12T04:00:00Z",
                last_seen="2026-10-12T10:05:00Z",
                outcome={"label": "attempted"}, phases=[],
                entity_count=3 + (i % 4), edge_count=i % 6,
                evidence_count=2 + (i % 9), signal_count=1 + (i % 5)))
        db.commit()
        for c in range(5):
            db.add(Campaign(id=f"cmp-load-{c:03d}",
                            title=f"Load campaign {c}",
                            description="load-test bookkeeping",
                            status="open", created_by="admin"))
        db.commit()
        # attach every 10th incident to campaign 0 for a non-empty detail
        for i in range(0, 60, 10):
            db.get(Incident, f"inc-load-{i:03d}").campaign_id = "cmp-load-000"
        db.commit()
    finally:
        db.close()


seed_db()
_os_client._client = LoadTestOS()

# The real FastAPI app (startup: create tables, bootstrap skipped since
# the seeded admin exists).
app = fastapi_app
