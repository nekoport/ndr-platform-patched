"""DSL guard tests: only safe queries reach OpenSearch (doc 4.5)."""

import pytest

from app.os_client import DSLValidationError, OSClient

os_client = OSClient("http://localhost:9200")


def test_alias_whitelist():
    assert os_client.validate_alias("ndr-events-read") == "ndr-events-read"
    with pytest.raises(DSLValidationError):
        os_client.validate_alias("ndr-alerts-2026.10.01")   # raw index
    with pytest.raises(DSLValidationError):
        os_client.validate_alias("*")                        # all indices
    with pytest.raises(DSLValidationError):
        os_client.validate_alias("_all")


def test_script_rejected():
    with pytest.raises(DSLValidationError):
        os_client.validate_query({"script": {"source": "1==1"}})
    with pytest.raises(DSLValidationError):
        os_client.validate_query({"bool": {"filter": [
            {"script_score": {"script": "doc['x']"}}]}})


def test_regexp_and_fuzzy_rejected():
    for clause in ({"regexp": {"source.ip": ".*"}},
                   {"fuzzy": {"source.ip": "1.2.3.4"}},
                   {"query_string": {"query": "*:*"}},
                   {"wildcard": {"source.ip": "192.*"}},
                   {"nested": {"path": "dns", "query": {"match_all": {}}}}):
        with pytest.raises(DSLValidationError):
            os_client.validate_query(clause)


def test_unknown_clause_rejected():
    with pytest.raises(DSLValidationError):
        os_client.validate_query({"terms_set": {"x": {"terms": [1]}}})


def test_valid_bool_filter_passes():
    os_client.validate_query({"bool": {"filter": [
        {"term": {"source.ip": "203.0.113.25"}},
        {"terms": {"severity": ["high", "critical"]}},
        {"range": {"@timestamp": {"gte": "2026-10-01T00:00:00Z"}}},
    ]}})


def test_leading_wildcard_prefix_rejected():
    with pytest.raises(DSLValidationError):
        os_client.validate_query({"prefix": {"dns.query": "*dga"}})


def test_nesting_depth_capped():
    deep = {"term": {"source.ip": "1.2.3.4"}}
    for _ in range(10):
        deep = {"bool": {"filter": [deep]}}
    with pytest.raises(DSLValidationError):
        os_client.validate_query(deep)


def test_sort_whitelist():
    os_client.validate_sort([{"@timestamp": {"order": "desc"}}])
    with pytest.raises(DSLValidationError):
        os_client.validate_sort([{"password_hash": {"order": "asc"}}])
    with pytest.raises(DSLValidationError):
        os_client.validate_sort([{"@timestamp": {"order": "sideways"}}])


def test_time_range_enforced():
    # missing range -> defaults injected (no raise)
    tf = os_client.build_time_filter(None, None)
    assert "range" in tf
    # beyond retention -> rejected
    with pytest.raises(DSLValidationError):
        os_client.build_time_filter("2020-01-01T00:00:00Z", None)
    # from > to -> rejected
    with pytest.raises(DSLValidationError):
        os_client.build_time_filter("2026-10-12T00:00:00Z",
                                    "2026-10-11T00:00:00Z")


def test_rate_limit(monkeypatch):
    from fastapi import HTTPException
    from app.rate_limit import SlidingWindowLimiter
    limiter = SlidingWindowLimiter(max_events=3)
    for _ in range(3):
        limiter.check("user-x")
    with pytest.raises(HTTPException) as exc:
        limiter.check("user-x")
    assert exc.value.status_code == 429
