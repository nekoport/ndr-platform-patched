"""Normalizers: source-specific parsers -> CommonEvent (doc section 7.1)."""

from __future__ import annotations

from datetime import datetime, timezone

from app.models import (Answer, CommonEvent, compute_ja3, make_dedup_key,
                        make_event_id)

# Suricata alert severity (1..4) -> label + score
SURICATA_SEVERITY = {1: ("critical", 95), 2: ("high", 75),
                     3: ("medium", 50), 4: ("low", 25)}


def _clip(v, n: int):
    """Truncate to n chars; None stays None (never slice None)."""
    if v is None:
        return None
    v = str(v)
    return v[:n]


def _parse_eve_timestamp(value: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt).astimezone(timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


def _ingest_time() -> datetime:
    return datetime.now(timezone.utc)


def parse_suricata(raw: str, sensor_id: str, allowed_types: set[str],
                   max_field_len: int = 2048) -> CommonEvent | None:
    """Parse one EVE JSON line. Returns None for skipped/failed lines."""
    import orjson

    try:
        eve = orjson.loads(raw)
    except Exception:
        return None
    if not isinstance(eve, dict):
        return None

    event_type = eve.get("event_type")
    if not event_type or event_type not in allowed_types:
        return None
    if event_type == "stats":
        return None  # stats are handled via health metrics, not indexed

    ts = _parse_eve_timestamp(eve.get("timestamp", ""))
    if ts is None:
        ts = _ingest_time()

    transport = str(eve.get("proto", "")).lower() or None
    # v0.13.0: some EVE producers emit NON-NUMERIC severity ("high") - the
    # bare int() aborted the whole parse; coerce safely instead
    try:
        _sev_id = int(eve.get("alert", {}).get("severity", 3))
    except (TypeError, ValueError):
        _sev_id = 3
    sev_label, sev_score = SURICATA_SEVERITY.get(_sev_id, ("medium", 50))

    alert = eve.get("alert", {}) or {}
    dns = eve.get("dns", {}) or {}
    http = eve.get("http", {}) or {}
    tls = eve.get("tls", {}) or {}
    fi = eve.get("fileinfo", {}) or {}

    query = dns.get("rrname")
    answers = [
        Answer(name=a.get("rrname"), type=a.get("rrtype"), data=a.get("rdata"))
        for a in (dns.get("answers") or [])
    ] if dns.get("answers") else (
        [Answer(name=query, type=dns.get("rrtype"), data=dns.get("rdata"))]
        if (query and (dns.get("rdata") or dns.get("rrtype"))) else []
    )

    dedup_key = make_dedup_key(
        "suricata", event_type, eve.get("timestamp"), eve.get("flow_id"),
        eve.get("src_ip"), eve.get("src_port"),
        eve.get("dest_ip"), eve.get("dest_port"),
        alert.get("signature_id"), dns.get("rrname"), http.get("url"),
        tls.get("sni"), fi.get("sha256"),
    )

    ev = CommonEvent(
        event_id=make_event_id(dedup_key),
        event_time=ts,
        ingest_time=_ingest_time(),
        sensor_id=sensor_id,
        source_engine="suricata",
        event_type=event_type,
        source_ip=eve.get("src_ip"),
        source_port=eve.get("src_port"),
        destination_ip=eve.get("dest_ip"),
        destination_port=eve.get("dest_port"),
        transport=transport,
        protocol=eve.get("app_proto") or None,
        session_id=str(eve.get("flow_id")) if eve.get("flow_id") is not None else None,
        community_id=eve.get("community_id"),
        signature_id=str(alert.get("signature_id")) if alert.get("signature_id") else None,
        category=alert.get("category"),
        severity=sev_label if event_type == "alert" else None,
        severity_score=sev_score if event_type == "alert" else None,
        alert_signature=alert.get("signature"),
        alert_category=alert.get("category"),
        alert_severity_id=alert.get("severity"),
        dns_query=query,
        dns_qtype=(str(dns.get("rrtype")) if dns.get("rrtype") else None),
        dns_type=dns.get("dns_type") or dns.get("type"),
        dns_rcode=str(dns.get("rcode")) if dns.get("rcode") is not None else None,
        dns_answers=answers,
        http_host=http.get("hostname"),
        http_url=_clip(http.get("url"), max_field_len),
        http_method=http.get("http_method"),
        http_status=http.get("status"),
        http_user_agent=_clip(http.get("http_user_agent"), 512),
        http_referrer=_clip(http.get("http_referer"), max_field_len),
        tls_sni=tls.get("sni"),
        tls_version=tls.get("version"),
        tls_ja3=(tls.get("ja3", {}) or {}).get("hash"),
        tls_subject=_clip(tls.get("subject"), 512),
        tls_issuer=_clip(tls.get("issuer"), 512),
        file_name=fi.get("filename"),
        file_mime=fi.get("magic"),
        file_size=_int_or_none(fi.get("size")),  # v0.13.0: coerce str sizes
        file_md5=fi.get("md5"),
        file_sha1=fi.get("sha1"),
        file_sha256=fi.get("sha256"),
    )
    ev.dedup_key = dedup_key  # v0.13.0: parser-owned
    ev.raw_line = raw
    return ev


# --------------------------------------------------------------- Zeek
def _zeek_ts(value) -> datetime | None:
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _int_or_none(v):
    try:
        return int(v) if v not in (None, "-", "") else None
    except (TypeError, ValueError):
        return None


def parse_zeek(raw: str, sensor_id: str, log_type: str,
               max_field_len: int = 2048) -> CommonEvent | None:
    """Parse one Zeek JSON log line (use_json=T)."""
    import orjson

    try:
        j = orjson.loads(raw)
    except Exception:
        return None
    if not isinstance(j, dict):
        return None

    ts = _zeek_ts(j.get("ts")) or _ingest_time()
    orig = j.get("id.orig_h") or j.get("id", {}).get("orig_h")
    orig_p = j.get("id.orig_p") or j.get("id", {}).get("orig_p")
    resp = j.get("id.resp_h") or j.get("id", {}).get("resp_h")
    resp_p = j.get("id.resp_p") or j.get("id", {}).get("resp_p")
    uid = j.get("uid")

    dedup_key = make_dedup_key("zeek", log_type, j.get("ts"), uid, orig,
                               orig_p, resp, resp_p)

    ev = CommonEvent(
        event_id=make_event_id(dedup_key),
        event_time=ts,
        ingest_time=_ingest_time(),
        sensor_id=sensor_id,
        source_engine="zeek",
        event_type=log_type,
        source_ip=orig,
        source_port=_int_or_none(orig_p),
        destination_ip=resp,
        destination_port=_int_or_none(resp_p),
        transport=str(j.get("proto", "")).lower() or None,
        protocol=j.get("service") or None,
        session_id=uid,
        community_id=j.get("community_id"),
    )

    if log_type == "conn":
        ob = _int_or_none(j.get("orig_bytes"))
        rb = _int_or_none(j.get("resp_bytes"))
        ev.source_bytes = ob
        ev.destination_bytes = rb
        ev.network_bytes = (ob or 0) + (rb or 0) if (ob is not None or rb is not None) else None
        op = _int_or_none(j.get("orig_pkts"))
        rp = _int_or_none(j.get("resp_pkts"))
        ev.network_packets = (op or 0) + (rp or 0) if (op is not None or rp is not None) else None
    elif log_type == "dns":
        ev.dns_query = _clip(j.get("query"), max_field_len)
        ev.dns_type = "query" if j.get("qtype_name") and not j.get("rcode_name") else "response" if j.get("rcode_name") else None
        ev.dns_rcode = j.get("rcode_name")
        # v0.13.0: keep qtype for tunneling detection on Zeek data
        ev.dns_qtype = (str(j.get("qtype_name"))
                        if j.get("qtype_name") else None)
        answers = j.get("answers") or []
        ttls = j.get("TTLs") or []
        ev.dns_answers = [
            Answer(name=ev.dns_query, type=str(j.get("qtype_name") or ""), data=str(a))
            for a in answers[:20]
        ] if answers else []
        _ = ttls  # retained in raw archive only
    elif log_type == "http":
        ev.http_host = j.get("host")
        ev.http_url = _clip(j.get("uri"), max_field_len)
        ev.http_method = j.get("method")
        ev.http_status = _int_or_none(j.get("status_code"))
        ev.http_user_agent = _clip(j.get("user_agent"), 512)
        ev.http_referrer = _clip(j.get("referrer"), max_field_len)
    elif log_type == "tls":
        ev.tls_version = j.get("version")
        ev.tls_sni = j.get("server_name")
        # v0.16.1 (P1-5): Zeek polos tidak punya ja3 - hitung dari bahan
        # client-hello yang Zeek 5+ log (cipher/extension/curve/point
        # format). Kalau suatu hari ada plugin ja3, field itu yang menang.
        ev.tls_ja3 = j.get("ja3") or compute_ja3(
            j.get("version"),
            j.get("client_cipher_suites"),
            j.get("client_extensions"),
            j.get("client_curves"),
            j.get("client_point_formats"))
        ev.tls_subject = _clip(j.get("subject"), 512)
        ev.tls_issuer = _clip(j.get("issuer"), 512)
    elif log_type == "files":
        # v0.13.0: map Zeek files.log so FileTransfer sees Zeek data
        # (previously Zeek file activity NEVER reached the detector);
        # sizes arrive as strings in Zeek JSON - coerce, never crash
        ev.file_name = _clip(j.get("fuid"), max_field_len)
        ev.file_mime = j.get("mime_type")
        ev.file_size = _int_or_none(j.get("size"))
        ev.file_md5 = j.get("md5")
        ev.file_sha1 = j.get("sha1")
        ev.file_sha256 = j.get("sha256")
        conn_uids = j.get("conn_uids") or []
        if conn_uids:
            ev.session_id = conn_uids[0]

    ev.dedup_key = dedup_key  # v0.13.0: parser-owned
    ev.raw_line = raw
    return ev
