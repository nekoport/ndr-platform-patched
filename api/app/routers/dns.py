"""DNS Explorer API (v0.16.0 - requirement 7).

Zeek dns.log memuat pasangan request+response LENGKAP dalam satu record
(compliance 'request response yang lengkap dalam satu capture'); API ini
mengeksposnya: rasio resolved vs gagal (NXDOMAIN/SERVFAIL), domain teratas,
klien teratas, dan pencarian transaksi. Semua lewat guarded_aggregate /
guarded_search di alias ndr-zeek-dns-read (guard lama tetap berlaku).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.audit import audit
from app.db import get_db
from app.filters import EVENT_FILTER_FIELDS, FilterError, build_query, combine
from app.models import User
from app.os_client import DSLValidationError, get_os
from app.security import require_permission
from app.schemas import SearchRequest

router = APIRouter(prefix="/api/dns", tags=["dns"])


@router.get("/summary")
def dns_summary(request: Request,
                hours: int = Query(default=24, ge=1, le=168),
                user: User = Depends(require_permission("search")),
                db: Session = Depends(get_db)):
    """Rasio keberhasilan resolusi + top domain + top klien.

    resolved = dns.rcode NOERROR; gagal = rcode lain (NXDOMAIN/SERVFAIL/
    REFUSED/timeout). Cocok untuk requirement 7 (informasi DNS yang
    berhasil di-resolve dan yang tidak).

    v0.16.1 (P1-4): rasio lama = NOERROR (agg eksak, 913.340) dibagi
    hits.total (CAP track_total_hits 10.000) -> 9133% mustahil. Kini
    KEDUA sisi dihitung dari agregasi yang sama:
      * denominator = dokumen yang BENAR-BENAR punya dns.rcode (agg
        filter exists - eksak, tidak terpengaruh cap);
      * numerator   = bucket NOERROR dari terms agg yang sama.
    Dokumen tanpa rcode (mis. query tanpa response) dilaporkan terpisah
    sebagai no_response - jujur, tidak memompa rasio.
    """
    os = get_os()
    aggs = {
        "by_rcode": {"terms": {"field": "dns.rcode", "size": 12}},
        "has_rcode": {"filter": {"exists": {"field": "dns.rcode"}}},
        "top_queried": {"terms": {"field": "dns.query", "size": 20}},
        "top_clients": {"terms": {"field": "source.ip", "size": 10}},
    }
    time_from = (datetime.now(timezone.utc)
                 - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")
    try:
        result = os.guarded_aggregate(
            alias="ndr-zeek-dns-read", query=None, aggs=aggs,
            time_from=time_from, time_to=None)
        # total EKSAK untuk konteks (bukan lagi penyebut rasio)
        total_val = os.exact_total("ndr-zeek-dns-read")
    except DSLValidationError as e:
        raise HTTPException(400, f"Query rejected: {e}")
    except Exception as e:  # noqa: BLE001 - degrade, jangan 500 halaman
        raise HTTPException(502, f"Search backend unavailable: {e}")

    aggs_out = result.get("aggregations", {})
    rcode = {b.get("key"): b.get("doc_count", 0)
             for b in aggs_out.get("by_rcode", {}).get("buckets", [])}
    transactions = int(aggs_out.get("has_rcode", {}).get("doc_count", 0))
    resolved = rcode.get("NOERROR", 0)
    unresolved = sum(c for k, c in rcode.items()
                     if k != "NOERROR" and c)
    resolved_pct = round(resolved * 100.0 / transactions, 2) \
        if transactions else 0.0
    audit(db, request, action="dns.summary", target_type="index",
          target_id="ndr-zeek-dns-read", actor=user)
    return {
        "hours": hours,
        # v0.16.1: total = seluruh dokumen DNS di jendela (konteks);
        # transactions = dokumen dengan response (penyebut rasio).
        "total": total_val,
        "transactions": transactions,
        "resolved": resolved,
        "unresolved": unresolved,
        "no_response": max(total_val - transactions, 0),
        "resolved_pct": resolved_pct,
        "rcodes": sorted(
            ({"key": k, "count": c,
              "pct": round(c * 100.0 / transactions, 2) if transactions else 0.0}
             for k, c in rcode.items()),
            key=lambda x: -x["count"]),
        "top_queried": [
            {"domain": b.get("key"), "count": b.get("doc_count", 0)}
            for b in aggs_out.get("top_queried", {}).get("buckets", [])],
        "top_clients": [
            {"ip": b.get("key"), "count": b.get("doc_count", 0)}
            for b in aggs_out.get("top_clients", {}).get("buckets", [])],
    }


@router.post("/search")
def dns_search(body: SearchRequest, request: Request,
               user: User = Depends(require_permission("search")),
               db: Session = Depends(get_db)):
    """Tabel transaksi DNS (ts, klien, query, rcode, answers) + filter DSL."""
    if body.index != "ndr-zeek-dns-read":
        body.index = "ndr-zeek-dns-read"
    try:
        filter_query = build_query(body.filter, EVENT_FILTER_FIELDS)
        combined = combine(body.query or None, filter_query)
        result = get_os().guarded_search(
            alias=body.index, query=combined, size=body.size,
            from_=body.from_, sort=body.sort,
            time_from=body.time_from, time_to=body.time_to)
    except FilterError as e:
        raise HTTPException(400, f"Filter rejected: {e}")
    except DSLValidationError as e:
        raise HTTPException(400, f"Query rejected: {e}")
    except Exception as e:
        raise HTTPException(502, f"Search backend unavailable: {e}")
    audit(db, request, action="dns.search", target_type="index",
          target_id="ndr-zeek-dns-read", actor=user)
    hits = []
    for h in result["hits"]["hits"]:
        src = h.get("_source") or {}
        dns = src.get("dns") or {}
        answers = dns.get("answers") or []
        hits.append({
            "id": h.get("_id"),
            "@timestamp": src.get("@timestamp"),
            "client": (src.get("source") or {}).get("ip"),
            "server": (src.get("destination") or {}).get("ip"),
            "query": dns.get("query"),
            "qtype": dns.get("type"),
            "rcode": dns.get("rcode"),
            "resolved": dns.get("rcode") == "NOERROR" and bool(answers),
            "answer_count": len(answers) if isinstance(answers, list) else 0,
            "answers": (answers or [])[:5],
            "campaign": src.get("campaign"),
        })
    total = result["hits"]["total"]
    return {"total": total.get("value", 0),
            "relation": total.get("relation", "eq"), "hits": hits}
