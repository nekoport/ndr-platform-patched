"""API test fixtures: SQLite-backed app with mocked OpenSearch."""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Test contracts must not be influenced by an inherited environment (e.g.
# a deployment shell that sourced .env): force the known-good values.
os.environ["JWT_SECRET"] = "test-secret"
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "bootstrap-admin-pass-01"
os.environ["TLS_ENABLED"] = "0"
# The sandbox/CI may export a non-SQLAlchemy DATABASE_URL; tests use SQLite.
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from fastapi.testclient import TestClient  # noqa: E402

from app.db import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import User  # noqa: E402
from app.os_client import OSClient, get_os  # noqa: E402
from app.security import hash_password  # noqa: E402


class FakeOS(OSClient):
    """OpenSearch stand-in that STILL runs the real query guard."""

    def __init__(self):
        super().__init__("http://localhost:9200")  # client object only, no I/O

    def guarded_search(self, **kw):
        alias = self.validate_alias(kw["alias"])
        self.validate_query(kw.get("query") or {})
        self.validate_sort(kw.get("sort"))
        self.build_time_filter(kw.get("time_from"), kw.get("time_to"))
        return {"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}

    def get_by_id(self, alias, doc_id):
        self.validate_alias(alias)
        return None

    def search_alert_doc(self, alert_id):
        # v0.12.6 fallback stub: default = alert genuinely not found
        self.validate_alias("ndr-alerts-read")
        return None

    def get_alert_doc(self, alert_id):
        # v0.12.6: mirror the real two-step resolution on the stub so
        # tests monkeypatching get_by_id/search_alert_doc keep working
        doc = self.get_by_id("ndr-alerts-read", alert_id)
        if doc is not None:
            return doc
        return self.search_alert_doc(alert_id)

    def cluster_health(self):
        return {"status": "green", "number_of_nodes": 1,
                "unassigned_shards": 0}

    def latest_health_doc(self):
        return {"sensor_id": "sensor-test", "eps": 12.5,
                "backlog_seconds": 1.0,
                "last_event_time": "2026-10-12T03:00:00Z"}

    def aggregate(self, alias, body):
        self.validate_alias(alias)
        return {"hits": {"total": {"value": 0}},
                "aggregations": {k: {"buckets": []}
                                 for k in body.get("aggs", {})}}

    def guarded_aggregate(self, **kw):
        # v0.12.7: mirror the real guard (alias + query validation) and
        # answer with empty buckets in the same shape as the real route
        alias = self.validate_alias(kw["alias"])
        self.validate_query(kw.get("query") or {})
        self.build_time_filter(kw.get("time_from"), kw.get("time_to"))
        return {"hits": {"total": {"value": 0, "relation": "eq"}},
                "aggregations": {k: {"buckets": []}
                                 for k in (kw.get("aggs") or {})}}

    def count(self, alias, query=None):
        self.validate_alias(alias)
        return 0

    def exact_total(self, alias, query=None):
        # v0.16.1 (P1-4/P2-4): total eksak via agg filter match_all;
        # stub default 0, test spesifik meng-override.
        self.validate_alias(alias)
        return 0

    def update(self, **kw):
        return {}

    class _Nodes:
        def stats(self, metric):
            return {"nodes": {"n1": {"fs": {"total": {
                "total_in_bytes": 3_000_000_000_000,
                "free_in_bytes": 2_000_000_000_000}}}}}

    nodes = _Nodes()


@pytest.fixture(autouse=True)
def _fake_os(monkeypatch):
    fake = FakeOS()
    monkeypatch.setattr("app.os_client._client", fake)
    yield fake


@pytest.fixture()
def client():
    # reset in-memory rate limiters between tests
    from app.routers.auth import login_limiter
    from app.routers.events import search_limiter
    login_limiter._events.clear()
    search_limiter._events.clear()

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def users_seeded():
    db = SessionLocal()
    for username, role in [
        ("analyst", "soc_analyst"),
        ("engineer", "security_engineer"),
        ("viewer", "auditor"),
    ]:
        if not db.query(User).filter(User.username == username).first():
            db.add(User(username=username,
                        password_hash=hash_password("Password-123456"),
                        role=role))
    db.commit()
    db.close()


def login(client, username: str, password: str):
    return client.post("/api/auth/login",
                       json={"username": username, "password": password})
