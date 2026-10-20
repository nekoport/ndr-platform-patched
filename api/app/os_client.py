"""OpenSearch access layer with query guardrails (doc section 4.5).

Advanced DSL is exposed ONLY through this guard:
  * whitelist of read aliases - raw indices are never queryable
  * query subtree whitelist: bool/term/terms/range/match/match_phrase/
    exists/prefix - script, regexp, fuzzy, query_string rejected
  * leading-wildcard patterns rejected (uncontrolled cost)
  * a time range is enforced: defaults to last 24h, capped at retention
  * result window, timeout and total-hit tracking capped
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from opensearchpy import NotFoundError, OpenSearch

from app.config import config

ALLOWED_QUERY_KEYS = {"bool", "term", "terms", "range", "match",
                      "match_phrase", "exists", "prefix"}
ALLOWED_BOOL_KEYS = {"filter", "must", "should", "must_not",
                     "minimum_should_match"}
FORBIDDEN_KEYS = {"script", "script_score", "regexp", "fuzzy", "query_string",
                  "wildcard", "nested", "more_like_this", "percolate"}
ALLOWED_SORT_FIELDS = {"@timestamp", "ingest_time", "severity_score",
                       "event_count", "last_seen", "first_seen"}
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")


class DSLValidationError(ValueError):
    pass


class OSClient:
    def __init__(self, url: str):
        self.client = OpenSearch(hosts=[url], use_ssl=False, verify_certs=False,
                                 timeout=15)

    # ------------------------------------------------------------ guard
    def validate_alias(self, alias: str) -> str:
        if alias not in config.allowed_read_aliases:
            raise DSLValidationError(
                f"index '{alias}' is not an allowed read alias; "
                f"allowed: {', '.join(config.allowed_read_aliases)}")
        return alias

    def validate_query(self, query: Any, depth: int = 0) -> None:
        if depth > 6:
            raise DSLValidationError("query nesting too deep (max 6)")
        if not isinstance(query, dict):
            raise DSLValidationError("query must be an object")
        for key, value in query.items():
            if key in FORBIDDEN_KEYS:
                raise DSLValidationError(f"query clause '{key}' is not allowed")
            if key not in ALLOWED_QUERY_KEYS:
                raise DSLValidationError(f"query clause '{key}' is not supported")
            if key == "bool":
                if not isinstance(value, dict):
                    raise DSLValidationError("bool must be an object")
                for bk, bv in value.items():
                    if bk not in ALLOWED_BOOL_KEYS:
                        raise DSLValidationError(
                            f"bool clause '{bk}' is not allowed")
                    if isinstance(bv, list):
                        for sub in bv:
                            self.validate_query(sub, depth + 1)
                    elif isinstance(bv, dict):
                        self.validate_query(bv, depth + 1)
            elif key in ("term", "terms", "match", "match_phrase", "exists",
                         "prefix"):
                if not isinstance(value, dict):
                    raise DSLValidationError(f"{key} must be an object")
                if key == "prefix":
                    for _field, fval in value.items():
                        if isinstance(fval, dict):
                            fval = fval.get("value", "")
                        if isinstance(fval, str) and fval.startswith("*"):
                            raise DSLValidationError(
                                "leading wildcard in prefix is not allowed")
            elif key == "range":
                if not isinstance(value, dict):
                    raise DSLValidationError("range must be an object")
                for _field, cond in value.items():
                    if not isinstance(cond, dict):
                        continue
                    if "boost" in cond or "format" in cond:
                        continue

    def validate_sort(self, sort: list[dict] | None) -> list[dict] | None:
        if sort is None:
            return None
        if not isinstance(sort, list) or len(sort) > 3:
            raise DSLValidationError("sort must be a list of max 3 fields")
        for entry in sort:
            if not isinstance(entry, dict):
                raise DSLValidationError("sort entries must be objects")
            for field, spec in entry.items():
                if field not in ALLOWED_SORT_FIELDS:
                    raise DSLValidationError(
                        f"sort field '{field}' not allowed; "
                        f"allowed: {sorted(ALLOWED_SORT_FIELDS)}")
                if isinstance(spec, dict) and "order" in spec:
                    if spec["order"] not in ("asc", "desc"):
                        raise DSLValidationError("sort order must be asc/desc")
        return sort

    def build_time_filter(self, time_from: str | None,
                          time_to: str | None) -> dict:
        now = datetime.now(timezone.utc)
        default_from = now - timedelta(days=1)
        max_back = now - timedelta(days=config.search_max_range_days)

        def parse(value: str | None, fallback: datetime) -> datetime:
            if not value:
                return fallback
            try:
                return datetime.fromisoformat(
                    value.replace("Z", "+00:00")).astimezone(timezone.utc)
            except ValueError:
                raise DSLValidationError(f"invalid time value: {value!r}")

        start = parse(time_from, default_from)
        end = parse(time_to, now)
        if start < max_back:
            raise DSLValidationError(
                f"time range exceeds retention window "
                f"({config.search_max_range_days} days)")
        if start > end:
            raise DSLValidationError("time_from must be before time_to")
        return {"range": {"@timestamp": {
            "gte": start.isoformat().replace("+00:00", "Z"),
            "lte": end.isoformat().replace("+00:00", "Z"),
        }}}

    # ------------------------------------------------------------ search
    def guarded_search(self, *, alias: str, query: dict | None,
                       size: int, from_: int, sort: list | None,
                       time_from: str | None, time_to: str | None) -> dict:
        alias = self.validate_alias(alias)
        query = query or {}
        self.validate_query(query)
        sort = self.validate_sort(sort)
        # An EMPTY query clause inside bool.filter makes OpenSearch reject
        # the whole request with 400 "empty clause found" - the Alerts page
        # default (no filters) sends query={} and hit exactly that
        # (v0.12.5 fix). Skip empty queries; the time filter still applies.
        filters = [self.build_time_filter(time_from, time_to)]
        if query:
            filters.append(query)
        body: dict[str, Any] = {
            "size": min(size, config.search_max_size),
            "from": min(from_, 10000),
            "track_total_hits": 10000,
            "query": {"bool": {"filter": filters}},
            "_source": {"excludes": ["raw_line"]},
        }
        if sort:
            body["sort"] = sort
        else:
            body["sort"] = [{"@timestamp": {"order": "desc"}}]
        return self.client.search(
            index=alias, body=body,
            request_timeout=config.search_timeout_seconds,
        )

    def guarded_aggregate(self, *, alias: str, query: dict | None,
                          aggs: dict, time_from: str | None,
                          time_to: str | None) -> dict:
        """Aggregation-only search over a whitelisted alias (v0.12.7).

        Mirrors guarded_search (same alias whitelist, same query guard,
        same time filter, same track_total_hits ceiling) but always runs
        with size 0 - the response carries ONLY bucket counts, never
        documents. Used by /api/alerts/stats so the Alert Center header
        charts are exact for result sets of any size.
        """
        alias = self.validate_alias(alias)
        query = query or {}
        self.validate_query(query)
        filters = [self.build_time_filter(time_from, time_to)]
        if query:
            filters.append(query)
        body: dict[str, Any] = {
            "size": 0,
            "track_total_hits": 10000,
            "query": {"bool": {"filter": filters}},
            "aggs": aggs,
        }
        return self.client.search(
            index=alias, body=body,
            request_timeout=config.search_timeout_seconds,
        )

    def get_by_id(self, alias: str, doc_id: str) -> dict | None:
        """Direct _id lookup. v0.12.6: ONLY a genuine 404 returns None;
        any other backend failure propagates so callers can answer 502
        instead of a misleading 'not found'."""
        alias = self.validate_alias(alias)
        try:
            return self.client.get(index=alias, id=doc_id)
        except NotFoundError:
            return None

    # v0.12.6: alert resolution used to rely on a bare GET-by-id against
    # the ndr-alerts-read alias. On a live deployment that alias spans one
    # index per day (+ the bootstrap index); if the per-id GET cannot fan
    # out over the multi-index alias, or a doc's _id differs from its
    # alert_id field (older writers), the alert was listable via search
    # but every detail endpoint answered 404 "Alert not found" - exactly
    # what users reported on the PCAP & sessions panel (doc 15).
    def search_alert_doc(self, alert_id: str) -> dict | None:
        """API-constructed term lookup on the alert_id keyword field
        (never user DSL). Split out so test doubles can stub the
        fallback independently of the direct get."""
        alias = self.validate_alias("ndr-alerts-read")
        res = self.client.search(index=alias, body={
            "size": 5,
            "query": {"term": {"alert_id": alert_id}},
            "_source": {"excludes": ["raw_line"]},
        })
        hits = (res.get("hits") or {}).get("hits") or []
        for h in hits:  # prefer a hit whose _id matches too
            if h.get("_id") == alert_id:
                return h
        return hits[0] if hits else None

    def get_alert_doc(self, alert_id: str) -> dict | None:
        """Resolve one alert across the read alias: exact _id get first,
        then a term search on the alert_id field. Returns None only when
        the alert genuinely does not exist; backend failures raise.

        v0.15 deployment note: the read alias can legitimately hold
        MULTIPLE daily indices (ensure-index + downstream); OpenSearch
        then rejects the single-index GET op - degrade to the term
        search instead of failing the alert detail page with a 502.
        """
        try:
            doc = self.get_by_id("ndr-alerts-read", alert_id)
        except Exception as e:  # noqa: BLE001 - multi-index alias is normal
            if "more than one index" not in str(e):
                raise
            doc = None
        if doc is not None:
            return doc
        return self.search_alert_doc(alert_id)

    # ------------------------------------------------------------ ops
    # ------------------------------------------------------- whitelist
    def suppress_alert_docs(self, *, alert_type: str, signature: str | None,
                            entity_field: str, entity_value: str,
                            suppressed_by: int,
                            window_days: int = 7) -> int:
        """v0.14.0 whitelist RETROACTIVE: tag (never delete) existing alert
        docs that match the entry, so a newly-approved whitelist entry also
        silences the noise already sitting in the queue.

        Internal-only query (never user DSL): fixed 7-day window,
        whitelist alias, must_not already-suppressed. Returns the number
        of tagged docs (0 on any backend error - best-effort by design).
        """
        from datetime import datetime, timedelta, timezone as _tz
        alias = self.validate_alias("ndr-alerts-read")
        now = datetime.now(_tz.utc)
        start = (now - timedelta(days=window_days)).isoformat().replace(
            "+00:00", "Z")
        must: list[dict] = [{"term": {"alert_type": alert_type}}]
        if entity_field == "src_ip":
            must.append({"term": {"source.ip": entity_value}})
        elif entity_field == "dst_ip":
            must.append({"term": {"destination.ip": entity_value}})
        else:  # dst_domain
            must.append({"term": {"dns_domains": entity_value}})
        if signature:
            must.append({"term": {"top_rules.signature": signature}})
        query = {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": start}}}] + must,
            "must_not": [{"exists": {"field": "suppressed"}}],
        }}
        body = {
            "query": query,
            "script": {"source": ("ctx._source.suppressed = true; "
                                  "ctx._source.suppressed_by = params.sid"),
                       "lang": "painless",
                       "params": {"sid": int(suppressed_by)}},
            "max_docs": 2000,
            "conflicts": "proceed",
        }
        try:
            result = self.client.update_by_query(index=alias, body=body,
                                                 refresh=True)
            return int(result.get("updated", 0))
        except Exception:  # noqa: BLE001 - best-effort; entry stays usable
            return 0

    def get_docs_by_ids(self, alias: str, ids: list[str]) -> list[dict]:
        """v0.13.0 (backport fix VM): batch ids-query resolution.

        Per-id GET fails on multi-index aliases (day indices) where the
        same _id lives on several shards - the batch ids-query resolves
        them all in one guarded call.
        """
        alias = self.validate_alias(alias)
        ids = [i for i in (ids or []) if i][:500]
        if not ids:
            return []
        try:
            res = self.client.search(index=alias, body={
                "size": len(ids),
                "query": {"ids": {"values": ids}},
                "_source": True,
            })
            return res.get("hits", {}).get("hits", [])
        except Exception:  # noqa: BLE001 - caller degrades to 404/409
            return []

    def cluster_health(self) -> dict:
        return self.client.cluster.health()

    def nodes_fs_stats(self) -> dict:
        return self.client.nodes.stats(metric="fs,indices")

    def count(self, alias: str, query: dict | None = None) -> int:
        alias = self.validate_alias(alias)
        body = {"query": query} if query else None
        return int(self.client.count(index=alias, body=body)["count"])

    def aggregate(self, alias: str, body: dict) -> dict:
        """Aggregations are API-constructed only (never user DSL)."""
        alias = self.validate_alias(alias)
        return self.client.search(index=alias, body=body)

    def latest_health_doc(self) -> dict | None:
        try:
            res = self.client.search(index="ndr-health-read", body={
                "size": 1, "sort": [{"@timestamp": {"order": "desc"}}]})
            hits = res["hits"]["hits"]
            return hits[0]["_source"] if hits else None
        except Exception:
            return None


_client: OSClient | None = None


def get_os() -> OSClient:
    global _client
    if _client is None:
        _client = OSClient(config.opensearch_url)
    return _client
