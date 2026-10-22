"""Rule hit statistics (v0.16.0 - requirements 14 + 15).

Satu implementasi untuk dua poin tender:
  R14 - "mengelola rule sensor" (kolom hit di Rules Manager)
  R15 - "melihat statistik hit per rule"

Arsitektur (patuh blueprint):
  * Thread refresher di API (daemon, default 15 menit, env
    RULE_STATS_REFRESH_MIN, 0 = off) melakukan DUA agregasi terms ke
    ndr-alerts-read (24 jam & 7 hari) pada:
      - top_rules.signature_id  -> source=suricata (rule ET/custom)
      - alert_type (bukan suricata_alert_group) -> source=zeek/pipeline
        (behaviour detector + zeek script alerts)
    Sub-aggregation: severity (max), max(last_seen), top_hits 1
    (sample alert id). Semua guarded (alias whitelist + time filter).
  * Hasil di-UPSERT ke Postgres tabel rule_stats (idempoten via
    ON CONFLICT) sehingga UI murah: kolom Hits 24h/7d/Last hit dibaca
    dari Postgres tanpa mengganyap OpenSearch untuk 53 ribu rule.
  * Fallback jujur: bila tabel masih kosong (baru pasang / refresher
    belum jalan), endpoint stats menjalankan agregasi on-the-fly.

Diet kinerja: agregasi size=0 + terms 5000 - satu query per window,
bukan per rule; diluar hot path UI.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import RuleStat
from app.os_client import get_os

SEVERITY_PRIORITY = ("critical", "high", "medium", "low", "informational")

_SURICATA_AGG_BODY = {
    "size": 0,
    "query": {"bool": {"filter": [
        {"range": {"@timestamp": {"gte": "%WINDOW%"}}},
    ]}},
    "aggs": {
        "by_rule": {
            "terms": {"field": "top_rules.signature_id", "size": 5000},
            "aggs": {
                "sev": {"terms": {"field": "severity", "size": 5}},
                "last_hit": {"max": {"field": "last_seen"}},
                "sample": {"top_hits": {"size": 1,
                                        "_source": ["alert_id", "title"],
                                        "sort": [{"@timestamp":
                                                  {"order": "desc"}}]}},
                "sig_name": {"terms": {"field": "top_rules.signature",
                                       "size": 1}},
            },
        }
    },
}

_BEHAVIOUR_AGG_BODY = {
    "size": 0,
    "query": {"bool": {"filter": [
        {"range": {"@timestamp": {"gte": "%WINDOW%"}}},
        {"bool": {"must_not": [{"term": {"alert_type":
                                         "suricata_alert_group"}}]}},
    ]}},
    "aggs": {
        "by_type": {
            "terms": {"field": "alert_type", "size": 500},
            "aggs": {
                "sev": {"terms": {"field": "severity", "size": 5}},
                "last_hit": {"max": {"field": "last_seen"}},
                "sample": {"top_hits": {"size": 1,
                                        "_source": ["alert_id", "title"],
                                        "sort": [{"@timestamp":
                                                  {"order": "desc"}}]}},
            },
        }
    },
}


def _since(hours: int) -> str:
    return (datetime.now(timezone.utc)
            - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")


def _max_severity(buckets: list[dict]) -> str | None:
    best: str | None = None
    rank = {s: i for i, s in enumerate(SEVERITY_PRIORITY)}
    for b in buckets:
        key = b.get("key")
        if key in rank and (best is None
                            or rank[key] < rank[best]):
            best = key
    return best


def _sample_id(entry: dict) -> str | None:
    hits = ((entry.get("sample") or {}).get("hits") or {}).get("hits") or []
    if hits:
        return hits[0].get("_id")
    return None


def _collect_window(os, hours: int) -> dict[str, dict]:
    """Agregasi satu window -> {rule_key: hit_info} untuk kedua sumber."""
    since = _since(hours)
    out: dict[str, dict] = {}
    try:
        body = _replace_window(_SURICATA_AGG_BODY, since)
        res = os.aggregate("ndr-alerts-read", body)
        for b in (res.get("aggregations") or {}).get("by_rule", {}) \
                .get("buckets", []):
            key = str(b.get("key") or "")
            if not key:
                continue
            name = ""
            nb = (b.get("sig_name") or {}).get("buckets") or []
            if nb:
                name = str(nb[0].get("key") or "")
            out[f"sid:{key}"] = {
                "rule_key": key, "source": "suricata",
                "signature": name or None,
                "hits": int(b.get("doc_count", 0)),
                "sev_max": _max_severity(
                    (b.get("sev") or {}).get("buckets") or []),
                "last_hit_at": (b.get("last_hit") or {}).get("value_as_string"),
                "sample_alert_id": _sample_id(b),
            }
    except Exception:  # noqa: BLE001 - stats degrade, never fatal
        pass
    try:
        body = _replace_window(_BEHAVIOUR_AGG_BODY, since)
        res = os.aggregate("ndr-alerts-read", body)
        for b in (res.get("aggregations") or {}).get("by_type", {}) \
                .get("buckets", []):
            key = str(b.get("key") or "")
            if not key:
                continue
            source = "zeek" if key.startswith("zeek_") else "pipeline"
            out[f"type:{key}"] = {
                "rule_key": key, "source": source,
                "signature": key,
                "hits": int(b.get("doc_count", 0)),
                "sev_max": _max_severity(
                    (b.get("sev") or {}).get("buckets") or []),
                "last_hit_at": (b.get("last_hit") or {}).get("value_as_string"),
                "sample_alert_id": _sample_id(b),
            }
    except Exception:  # noqa: BLE001
        pass
    return out


def _replace_window(body: dict, since: str) -> dict:
    raw = _copy(body)
    filt = (raw["query"]["bool"]["filter"][0]["range"]["@timestamp"])
    filt["gte"] = since
    return raw


def _copy(body: dict) -> dict:
    return _deepcopy(body)


def _deepcopy(v):
    import copy
    return copy.deepcopy(v)


def collect_rule_stats(os=None) -> list[dict]:
    """Gabungkan window 24h + 7d menjadi baris rule_stats mentah."""
    os = os or get_os()
    w24 = _collect_window(os, 24)
    w7 = _collect_window(os, 24 * 7)
    rows: dict[str, dict] = {}
    for key, info in {**w7, **w24}.items():  # 24h menimpa 7d utk field sama
        rows[key] = {
            "rule_key": info["rule_key"],
            "source": info["source"],
            "signature": info.get("signature"),
            "hits_7d": w7.get(key, {}).get("hits", 0),
            "hits_24h": w24.get(key, {}).get("hits", 0),
            "sev_max": info.get("sev_max"),
            "last_hit_at": info.get("last_hit_at"),
            "sample_alert_id": info.get("sample_alert_id"),
        }
    return sorted(rows.values(), key=lambda r: -r["hits_7d"])


def _parse_dt(value: str | None) -> datetime | None:
    """value_as_string OpenSearch (ISO8601, sering 'Z') -> datetime UTC."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def refresh_rule_stats(db: Session, os=None) -> int:
    """Agregasi + upsert Postgres (idempoten, dialect-agnostic).

    Pola select-then-merge (bukan ON CONFLICT) supaya test SQLite dan
    Postgres produksi memakai jalur yang SAMA; interval 15 menit jauh
    di atas biaya upsert ribuan baris.
    """
    rows = collect_rule_stats(os)
    now = datetime.now(timezone.utc)
    keys = [r["rule_key"] for r in rows]
    existing: dict[str, RuleStat] = {}
    if keys:
        for row in db.query(RuleStat).filter(
                RuleStat.rule_key.in_(keys)).all():
            existing[row.rule_key] = row
    for r in rows:
        last = _parse_dt(r.get("last_hit_at"))
        obj = existing.get(r["rule_key"])
        if obj is None:
            obj = RuleStat(rule_key=r["rule_key"])
            db.add(obj)
        obj.source = r["source"]
        obj.signature = r.get("signature")
        obj.hits_24h = int(r.get("hits_24h") or 0)
        obj.hits_7d = int(r.get("hits_7d") or 0)
        obj.sev_max = r.get("sev_max")
        obj.last_hit_at = last
        obj.sample_alert_id = r.get("sample_alert_id")
        obj.updated_at = now
    db.commit()
    return len(rows)


class RuleStatsRefresher(threading.Thread):
    """Daemon: refresh rule_stats tiap N menit (0 = off). Fail-soft:
    error agregasi/DB dicatat lalu dicoba lagi pada siklus berikut -
    statistik tidak boleh mengganggu layanan utama."""

    def __init__(self, refresh_minutes: int = 15):
        super().__init__(daemon=True, name="rule-stats-refresher")
        self.interval = max(1, refresh_minutes) * 60
        self.stop_event = threading.Event()

    def run(self) -> None:
        while not self.stop_event.is_set():
            started = time.time()
            try:
                db = SessionLocal()
                try:
                    n = refresh_rule_stats(db)
                    print(f"[rule-stats] refreshed {n} rules",
                          file=__import__("sys").stderr)
                finally:
                    db.close()
            except Exception as exc:  # noqa: BLE001 - never die
                print(f"[rule-stats] refresh failed: "
                      f"{type(exc).__name__}: {exc}",
                      file=__import__("sys").stderr)
            elapsed = time.time() - started
            self.stop_event.wait(max(5.0, self.interval - elapsed))
