"""v0.12.5 regression tests - real-VM deployment findings (API side).

Covers: guarded_search no longer emits an empty bool.filter clause (Alerts
page 400), effective sensor status derived from heartbeat freshness, and
the widened ti_feeds.adapter CHECK in postgres/init/001_schema.sql.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.os_client import OSClient  # noqa: E402
from app.routers.admin import effective_sensor_status  # noqa: E402

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


# ------------------------------------------------- guarded_search (§5.9)
def _capturing_client() -> tuple[OSClient, dict]:
    """Real OSClient (guards exercised) with the network call captured."""

    class _Stub:
        def search(self, **kw):  # noqa: ANN001
            captured.update(kw)
            return {"hits": {"total": {"value": 0, "relation": "eq"},
                             "hits": []}}

    captured: dict = {}
    client = OSClient("http://localhost:9200")
    client.client = _Stub()
    return client, captured


def test_guarded_search_skips_empty_query_clause():
    """query={} used to be appended verbatim into bool.filter -> OpenSearch
    400 'empty clause found'; the Alerts default page (no filters) hit it
    on every load."""
    client, captured = _capturing_client()
    client.guarded_search(alias="ndr-alerts-read", query={}, size=10,
                          from_=0, sort=None, time_from=None, time_to=None)
    body = captured["body"]
    filters = body["query"]["bool"]["filter"]
    assert len(filters) == 1, "empty query must be skipped"
    assert "range" in filters[0], \
        "the remaining clause is the @timestamp range filter"

    client2, captured2 = _capturing_client()
    client2.guarded_search(
        alias="ndr-alerts-read",
        query={"bool": {"filter": [{"term": {"severity": "high"}}]}},
        size=10, from_=0, sort=None, time_from=None, time_to=None)
    filters2 = captured2["body"]["query"]["bool"]["filter"]
    assert len(filters2) == 2, "real query must be appended after time filter"


# ------------------------------------------- effective sensor status (§12)
def test_effective_sensor_status_from_freshness():
    now = datetime.now(timezone.utc)
    # fresh heartbeat -> online regardless of stored value
    assert effective_sensor_status(now - timedelta(seconds=30),
                                   "offline") == "online"
    # 5-15 min stale -> degraded
    assert effective_sensor_status(now - timedelta(minutes=8),
                                   "online") == "degraded"
    # very stale -> offline (a dead pipeline can no longer look online)
    assert effective_sensor_status(now - timedelta(hours=2),
                                   "online") == "offline"
    # no heartbeat at all -> stored status / unknown
    assert effective_sensor_status(None, "offline") == "offline"
    assert effective_sensor_status(None, None) == "unknown"
    # naive datetimes (SQLite) are treated as UTC
    assert effective_sensor_status(datetime.utcnow(), "unknown") == "online"


# ------------------------------------- ti_feeds.adapter CHECK widened (§9.22)
def test_schema_adapter_check_includes_standard_adapters():
    """The 4-adapter CHECK made STIX/TAXII/MISP feed creation fail with a
    500 on Postgres (live-verified). Fresh installs must ship the widened
    constraint; existing DBs get the runtime migration in api/app/main.py."""
    with open(os.path.join(REPO, "postgres", "init", "001_schema.sql"),
              encoding="utf-8") as fh:
        schema = fh.read()
    marker = "CHECK (adapter IN"
    idx = schema.find(marker)
    assert idx != -1, "ti_feeds.adapter CHECK missing from schema"
    constraint = schema[idx: idx + 200]
    for adapter in ("urlhaus", "threatfox", "feodo", "file",
                    "stix", "taxii", "misp"):
        assert f"'{adapter}'" in constraint, \
            f"adapter '{adapter}' missing from ti_feeds.adapter CHECK"


def test_ti_adapter_check_migration_registered():
    """The runtime migration must be wired into API startup and be a no-op
    on non-Postgres dialects."""
    from app import main as api_main
    src = open(api_main.__file__, encoding="utf-8").read()
    assert "_migrate_ti_adapter_check()" in src
    assert 'engine.dialect.name != "postgresql"' in src
    assert "'stix','taxii','misp'" in src
