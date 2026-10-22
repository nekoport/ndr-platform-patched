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

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from opensearchpy import NotFoundError, OpenSearch, RequestError

from app.config import config

# v0.16.1 (P0-5): field teks yang boleh disentuh free-text search yang
# DIBANGUN SERVER (bukan DSL mentah user). IP tidak masuk sini - nilai
# non-IP pada field bertipe ip membuat parser gagal / hasil selalu 0.
FREE_TEXT_FIELDS = (
    "dns.query", "http.host", "http.url", "tls.sni", "alert.signature",
    "dns_domains", "campaign", "title",
)
# fast-path event_type: kata kunci persis ini langsung menjadi filter
# term event_type sehingga preset seperti "All DNS events" menargetkan
# event yang benar SEKALIGUS murah (bukan wildcard lintas 30+ juta dok).
EVENT_TYPE_VALUES = {
    "alert", "dns", "conn", "http", "tls", "files", "notice", "weird",
    "dpd", "software", "ssl", "x509", "ntp", "ssh", "smtp", "snmp",
}
IP_LIKE_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")
GREASE_VALUES = {2570, 3230, 3240, 4865, 4866, 4867, 5248, 5250, 5251,
                 6066, 6067, 6682}

ALLOWED_QUERY_KEYS = {"bool", "term", "terms", "range", "match",
                      "match_phrase", "exists", "prefix", "wildcard"}
ALLOWED_BOOL_KEYS = {"filter", "must", "should", "must_not",
                     "minimum_should_match"}
FORBIDDEN_KEYS = {"script", "script_score", "regexp", "fuzzy", "query_string",
                  "nested", "more_like_this", "percolate"}
# v0.16.0 (req 5): wildcard kini diizinkan HANYA pada field keyword/wildcard
# yang dipetakan eksplisit (termasuk field tipe 'wildcard' OpenSearch yang
# dioptimalkan untuk ini). Leading-wildcard tetap dilarang di prefix.
WILDCARD_FIELDS = {
    "dns.query", "http.host", "http.url", "tls.sni", "tls.ja3",
    "alert.signature", "top_rules.signature", "title", "campaign",
    "dns_domains", "category",
}
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
    def validate_alias(self, alias: str | list[str]) -> str | list[str]:
        """Whitelist alias. v0.16.1: menerima list utk fan-out multi-alias
        (semua elemen tetap wajib ada di whitelist)."""
        if isinstance(alias, list):
            for a in alias:
                if a not in config.allowed_read_aliases:
                    raise DSLValidationError(
                        f"index '{a}' is not an allowed read alias; "
                        f"allowed: {', '.join(config.allowed_read_aliases)}")
            return alias
        if alias not in config.allowed_read_aliases:
            raise DSLValidationError(
                f"index '{alias}' is not an allowed read alias; "
                f"allowed: {', '.join(config.allowed_read_aliases)}")
        return alias

    # ------------------------------------------------- free-text (P0-5)
    @staticmethod
    def build_free_text_query(text: str | None) -> dict | None:
        """Bangun query free-text yang BENAR dari kata kunci analis
        (v0.16.1, P0-5) - dipanggil API, BUKAN dari DSL mentah client.

        Aturan:
        1. Nilai mirip IP/CIDR -> term pada field ip (parser IP valid).
        2. Kata kunci persis nama event_type (dns/http/tls/...) -> term
           event_type (preset 'All DNS events' kini benar + murah).
        3. Selain itu -> wildcard case-insensitive pada whitelist field
           keyword/teks (FREE_TEXT_FIELDS), TIDAK PERNAH pada field ip.

        Query hasilnya API-constructed (tidak lewat validate_query user)
        tetapi tetap dibatasi field whitelist - prinsip guard sama.
        """
        text = (text or "").strip()
        if not text:
            return None
        if len(text) > 256:
            text = text[:256]
        should: list[dict] = []
        if IP_LIKE_RE.match(text):
            try:
                ipaddress.ip_network(text, strict=False)
                # fast-path IP: HANYA term field ip - tanpa wildcard
                # (murah dan tepat; wildcard *ip* di 30jt+ dok mahal)
                should.extend([
                    {"term": {"source.ip": text}},
                    {"term": {"destination.ip": text}},
                ])
                return {"bool": {"minimum_should_match": 1,
                                 "should": should}}
            except ValueError:
                pass  # bukan IP valid -> jatuh ke jalur teks
        low = text.lower()
        if low in EVENT_TYPE_VALUES:
            should.append({"term": {"event_type": low}})
        needle = f"*{low}*"
        for field in FREE_TEXT_FIELDS:
            should.append({"wildcard": {field: {"value": needle}}})
        if not should:
            return None
        return {"bool": {"minimum_should_match": 1, "should": should}}

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
                         "prefix", "wildcard"):
                if not isinstance(value, dict):
                    raise DSLValidationError(f"{key} must be an object")
                if key == "wildcard":
                    for wfield, wval in value.items():
                        if wfield not in WILDCARD_FIELDS:
                            raise DSLValidationError(
                                f"wildcard on field '{wfield}' is not allowed; "
                                f"allowed: {sorted(WILDCARD_FIELDS)}")
                        if isinstance(wval, dict):
                            unknown = set(wval) - {"value", "case_insensitive",
                                                   "boost"}
                            if unknown:
                                raise DSLValidationError(
                                    f"wildcard options not allowed: "
                                    f"{sorted(unknown)}")
                            wval = wval.get("value", "")
                        if not isinstance(wval, str):
                            raise DSLValidationError(
                                "wildcard value must be a string")
                    continue
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
    def guarded_search(self, *, alias: str | list[str], query: dict | None,
                       size: int, from_: int, sort: list | None,
                       time_from: str | None, time_to: str | None,
                       exact_total: bool = False) -> dict:
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
            # v0.16.1 (P2-4): default tetap di-cap 10.000 (murah); client
            # dapat minta exact total untuk analisis/ekspor skala besar.
            "track_total_hits": True if exact_total else 10000,
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

    def guarded_aggregate(self, *, alias: str | list[str], query: dict | None,
                          aggs: dict, time_from: str | None,
                          time_to: str | None) -> dict:
        """Aggregation-only search over a whitelisted alias (v0.12.7).

        Mirrors guarded_search (same alias whitelist, same query guard,
        same time filter, same track_total_hits ceiling) but always runs
        with size 0 - the response carries ONLY bucket counts, never
        documents. Used by /api/alerts/stats so the Alert Center header
        charts are exact for result sets of any size.

        v0.16.1 (P1-5): alias boleh berupa LIST alias whitelist (mis.
        ndr-zeek-tls-read + ndr-suricata-read) sehingga agregasi TLS
        mencakup JA3/issuer dari Suricata EVE juga - fan-out multi-alias
        adalah operasi search normal di OpenSearch.
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
        """Resolve satu dokumen by _id, AMAN untuk alias multi-index.

        v0.16.1 (P0-4): jalur utama kini ids-QUERY (search), bukan GET
        single-index. Akar bug 502: pada alias harian (ndr-alerts-read
        berisi 9+ index), GET by _id ditolak OpenSearch ("alias [...] has
        more than one index ... can't execute a single index op") dan
        guard lama GAGAL menangkapnya karena memeriksa exc.error yang
        berisi 'illegal_argument_exception' (tipe error), BUKAN pesan
        alias. Guard kini memeriksa SELURUH argumen exception.
        """
        alias = self.validate_alias(alias)
        doc_id = str(doc_id or "").strip()
        if not doc_id:
            return None
        try:
            res = self.client.search(index=alias, body={
                "size": 2,
                "query": {"ids": {"values": [doc_id]}},
                "_source": {"excludes": ["raw_line"]},
            })
            hits = (res.get("hits") or {}).get("hits") or []
            for h in hits:  # prefer exact _id match
                if h.get("_id") == doc_id:
                    return h
            return hits[0] if hits else None
        except NotFoundError:
            return None
        except RequestError as exc:
            # v0.16.1: gabungkan SEMUA argumen (status_code, error, info)
            # sehingga pesan alias 'more than one index' benar-benar kena.
            msg = " ".join(str(a) for a in getattr(exc, "args", []) if a)
            if not msg:
                msg = str(exc)
            if "more than one index" in msg or "single index op" in msg:
                return None  # degrade -> caller fallback (search_alert_doc)
            raise

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
        the alert genuinely does not exist; backend failures raise."""
        doc = self.get_by_id("ndr-alerts-read", alert_id)
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

    def count(self, alias: str | list[str], query: dict | None = None) -> int:
        alias = self.validate_alias(alias)
        body = {"query": query} if query else None
        return int(self.client.count(index=alias, body=body)["count"])

    def exact_total(self, alias: str | list[str],
                    query: dict | None = None) -> int:
        """v0.16.1 (P2-4/P1-4): total dokumen EKSAK lewat agg filter
        match_all (hitung agg tidak terpengaruh track_total_hits cap).
        Dipakai DNS/TLS summary agar rasio tidak pernah melebihi 100%."""
        body: dict[str, Any] = {
            "size": 0,
            "track_total_hits": 0,
            "query": query or {"match_all": {}},
            "aggs": {"n": {"filter": {"match_all": {}}}},
        }
        res = self.client.search(index=self.validate_alias(alias), body=body)
        return int(res.get("aggregations", {}).get("n", {})
                   .get("doc_count", 0))

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
