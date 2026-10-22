"""TLS Insights API (v0.16.0 - requirement 9).

Analisis trafik terenkripsi via METADATA (tanpa dekripsi - sesuai bunyi
requirement): distribusi versi TLS, JA3 fingerprint teratas, SNI teratas,
dan issuer sertifikat. Field tls.* sudah dipetakan keyword di template
(tls.ja3 ada sejak 0.12.9) - endpoint ini agregasi-only via guard.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.audit import audit
from app.db import get_db
from app.models import User
from app.os_client import DSLValidationError, get_os
from app.security import require_permission

router = APIRouter(prefix="/api/tls", tags=["tls"])


@router.get("/summary")
def tls_summary(request: Request,
                hours: int = Query(default=24, ge=1, le=168),
                user: User = Depends(require_permission("search")),
                db: Session = Depends(get_db)):
    """Ringkasan metadata TLS: versi, JA3, SNI, issuer, self-signed kandidat.

    v0.16.1 (P1-5): agregasi kini FAN-OUT dua alias
    (ndr-zeek-tls-read + ndr-suricata-read). Sebelumnya hanya alias Zeek
    - JA3/issuer Suricata (tls.ja3.hash + tls.issuerdn yang sudah
    dinormalisasi ke tls.ja3/tls.issuer) tidak pernah terlihat, dan
    Zeek polos tidak menghitung JA3 -> panel kosong. Kini JA3 & issuer
    dari kedua engine teragregasi.
    """
    os = get_os()
    aggs = {
        "by_version": {"terms": {"field": "tls.version", "size": 12}},
        "top_ja3": {"terms": {"field": "tls.ja3", "size": 20}},
        "top_sni": {"terms": {"field": "tls.sni", "size": 20}},
        "by_issuer": {"terms": {"field": "tls.issuer", "size": 12}},
    }
    time_from = (datetime.now(timezone.utc)
                 - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")
    aliases = ["ndr-zeek-tls-read", "ndr-suricata-read"]
    try:
        result = os.guarded_aggregate(
            alias=aliases, query=None, aggs=aggs,
            time_from=time_from, time_to=None)
        total_val = os.exact_total(aliases)
    except DSLValidationError as e:
        raise HTTPException(400, f"Query rejected: {e}")
    except Exception as e:  # noqa: BLE001 - degrade
        raise HTTPException(502, f"Search backend unavailable: {e}")

    def buckets(name: str) -> list[dict]:
        return sorted(
            ({"key": b.get("key"), "count": b.get("doc_count", 0)}
             for b in result.get("aggregations", {})
             .get(name, {}).get("buckets", [])
             if b.get("key")),
            key=lambda x: -x["count"])

    total = result["hits"]["total"]
    cap_total = total.get("value", 0) if isinstance(total, dict) else int(total)
    audit(db, request, action="tls.summary", target_type="index",
          target_id="ndr-zeek-tls-read + ndr-suricata-read", actor=user)
    return {
        "hours": hours,
        # v0.16.1: total EKSAK fan-out 2 alias (bukan cap track_total_hits)
        "total": total_val,
        "capped_total": cap_total,
        "versions": buckets("by_version"),
        "top_ja3": buckets("top_ja3"),
        "top_sni": buckets("top_sni"),
        "issuers": buckets("by_issuer"),
        "self_signed_candidates": [i for i in buckets("by_issuer")
                                   if "self" in str(i["key"]).lower()],
        "sources": aliases,
        "note": "metadata-only analysis (no decryption) - JA3 dari "
                "Suricata EVE (tls.ja3.hash) + pipeline (Zeek client-hello)",
    }
