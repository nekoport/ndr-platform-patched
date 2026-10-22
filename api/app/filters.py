"""v0.16.0 - requirement 5: custom filter DSL untuk Alert/Event.

Kosakata tender: and, or, not, is, is one, include, not/exclude (+ range
& CIDR sebagai bonus terkontrol). DSL berupa AST JSON - TIDAK pernah
string query - sehingga injeksi mustahil: builder hanya menghasilkan
bool/term/terms/wildcard/range dan MENOLAK keras field/op di luar
whitelist per konteks (alerts vs events).

Semantik leaf:
  {"field": "...", "op": "is",       "value": "high"}          -> term
  {"field": "...", "op": "is_one",   "value": ["a", "b"]}      -> terms
  {"field": "...", "op": "include",  "value": "judi"}          -> wildcard *v*
  {"field": "...", "op": "exclude",  "value": x | [..]}        -> must_not is/terms
  {"field": "...", "op": "gt|gte|lt|lte", "value": n}          -> range
  {"field": "...", "op": "cidr",     "value": "10.0.0.0/8"}    -> term (ip)

Grup: {"and": [...]}, {"or": [...]}, {"not": {...}} - boleh nested max 6.
"""

from __future__ import annotations

import ipaddress
from typing import Any

# ------------------------------------------------- whitelist per konteks
# Field di luar daftar -> 400 dengan pesan jelas (guard lama tetap berlaku).
ALERT_FILTER_FIELDS: dict[str, set[str]] = {
    "severity": {"is", "is_one", "exclude"},
    "status": {"is", "is_one", "exclude"},
    "outcome": {"is", "is_one", "exclude"},
    "attack_status": {"is", "is_one", "exclude"},
    "detection_engine": {"is", "is_one", "exclude"},
    "alert_type": {"is", "is_one", "exclude"},
    "campaign": {"is", "is_one", "exclude"},
    "kill_chain.stage": {"is", "is_one", "exclude"},
    "cve": {"is", "is_one", "exclude"},
    "dns_domains": {"is", "is_one", "include", "exclude"},
    "network.protocol": {"is", "is_one", "exclude"},
    "network.transport": {"is", "is_one", "exclude"},
    "source.ip": {"is", "is_one", "exclude", "cidr"},
    "destination.ip": {"is", "is_one", "exclude", "cidr"},
    "related_entities": {"is", "exclude"},
    "top_rules.signature": {"is", "is_one", "include", "exclude"},
    "top_rules.signature_id": {"is", "is_one", "exclude"},
    "title": {"include"},
    "sensor_id": {"is"},
}

EVENT_FILTER_FIELDS: dict[str, set[str]] = {
    "event_type": {"is", "is_one", "exclude"},
    "source_engine": {"is", "is_one", "exclude"},
    "campaign": {"is", "is_one", "exclude"},
    "severity": {"is", "is_one", "exclude"},
    "category": {"is", "is_one", "include", "exclude"},
    "signature_id": {"is", "is_one", "exclude"},
    "network_zone": {"is", "is_one", "exclude"},
    "network.protocol": {"is", "is_one", "exclude"},
    "network.transport": {"is", "is_one", "exclude"},
    "dns.query": {"include"},
    "dns.rcode": {"is", "is_one", "exclude"},
    "http.host": {"is", "include", "exclude"},
    "http.status_code": {"is", "gt", "gte", "lt", "lte"},
    "tls.sni": {"is", "include", "exclude"},
    "tls.ja3": {"is", "is_one"},
    "source.ip": {"is", "is_one", "exclude", "cidr"},
    "destination.ip": {"is", "is_one", "exclude", "cidr"},
    "source.geo.country": {"is", "is_one", "exclude"},
}

GROUP_KEYS = {"and", "or", "not"}
LEAF_KEYS = {"field", "op", "value"}
LEAF_OPS = {"is", "is_one", "include", "exclude",
            "gt", "gte", "lt", "lte", "cidr"}
MAX_DEPTH = 6


class FilterError(ValueError):
    pass


def _leaf(node: dict, fields: dict[str, set[str]]) -> dict:
    extra = {k for k in node if k not in LEAF_KEYS}
    if extra:
        raise FilterError(f"unknown leaf keys: {sorted(extra)}")
    field = node.get("field")
    op = node.get("op")
    value = node.get("value")
    if not isinstance(field, str) or field not in fields:
        raise FilterError(
            f"field '{field}' is not filterable; allowed: {sorted(fields)}")
    if op not in LEAF_OPS:
        raise FilterError(
            f"op '{op}' is not supported; allowed: {sorted(LEAF_OPS)}")
    if op not in fields[field]:
        raise FilterError(f"op '{op}' is not allowed on field '{field}'")

    if op == "is":
        if isinstance(value, (list, dict)) or value is None:
            raise FilterError("is expects a scalar value")
        return {"term": {field: value}}
    if op == "is_one":
        if not isinstance(value, list) or not value:
            raise FilterError("is_one expects a non-empty list")
        if any(isinstance(v, (dict, list)) for v in value):
            raise FilterError("is_one values must be scalars")
        return {"terms": {field: value}}
    if op == "include":
        if not isinstance(value, str) or not value.strip():
            raise FilterError("include expects a non-empty string")
        safe = value.replace("\\", "").replace("*", "").replace("?", "")
        if not safe:
            raise FilterError("include value has no searchable characters")
        return {"wildcard": {field: {"value": f"*{safe}*", "case_insensitive": True}}}
    if op == "exclude":
        if isinstance(value, list):
            inner = {"terms": {field: value}}
        elif isinstance(value, str) and value:
            inner = {"term": {field: value}}
        else:
            raise FilterError("exclude expects a string or list of strings")
        return {"bool": {"must_not": [inner]}}
    if op in ("gt", "gte", "lt", "lte"):
        if isinstance(value, (dict, list, str)) and not isinstance(value, str):
            raise FilterError(f"{op} expects a number or date string")
        if isinstance(value, str) and not value:
            raise FilterError(f"{op} expects a non-empty value")
        return {"range": {field: {op: value}}}
    if op == "cidr":
        if not isinstance(value, str):
            raise FilterError("cidr expects a network string")
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise FilterError(f"invalid CIDR '{value}'") from exc
        # field ip menerima term dengan notasi CIDR
        return {"term": {field: value}}
    raise FilterError(f"op '{op}' is not supported")  # unreachable


def build_query(ast: Any, fields: dict[str, set[str]],
                depth: int = 0) -> dict | None:
    """Terjemahkan AST -> query OpenSearch tervalidasi. None utk ast kosong."""
    if ast in (None, {}, []):
        return None
    if depth > MAX_DEPTH:
        raise FilterError("filter nesting too deep (max 6)")
    if not isinstance(ast, dict):
        raise FilterError("filter must be an object")
    keys = set(ast)
    group_keys = keys & GROUP_KEYS
    if group_keys:
        if keys - group_keys:
            raise FilterError(
                f"group cannot mix with other keys: {sorted(keys - group_keys)}")
        if "not" in ast:
            inner = build_query(ast["not"], fields, depth + 1)
            if inner is None:
                raise FilterError("not expects a sub-filter")
            return {"bool": {"must_not": [inner]}}
        clauses: list[dict] = []
        for sub in ast.get("and", []) or []:
            built = build_query(sub, fields, depth + 1)
            if built:
                clauses.append(built)
        for sub in ast.get("or", []) or []:
            built = build_query(sub, fields, depth + 1)
            if built:
                clauses.append(built)
        # and/or boleh satu objek leaf (bukan list) - bungkus
        if not clauses and isinstance(ast.get("and") or ast.get("or"), dict):
            built = build_query(ast.get("and") or ast.get("or"), fields,
                                depth + 1)
            if built:
                clauses.append(built)
        if not clauses:
            return None
        if "and" in ast:
            return {"bool": {"must": clauses}}
        if len(clauses) == 1:
            return clauses[0]
        return {"bool": {"should": clauses, "minimum_should_match": 1}}
    return _leaf(ast, fields)


def combine(base_query: dict | None, filter_query: dict | None) -> dict | None:
    """Gabungkan query guard lama + filter DSL dalam satu bool.must."""
    if base_query and filter_query:
        return {"bool": {"must": [base_query, filter_query]}}
    return base_query or filter_query or None
