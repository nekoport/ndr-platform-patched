"""Health & stats routers - overview dashboard data (doc sections 11.2, 19.3)."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import config
from app.db import get_db
from app.graph import is_internal_ip
from app.models import Incident, NetworkZone, Sensor, User
from app.os_client import get_os
from app.routers.admin import effective_sensor_status
from app.security import require_permission

router = APIRouter(prefix="/api", tags=["health"])


def _db_ok(db: Session) -> bool:
    try:
        db.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


@router.get("/health")
def health(user: User = Depends(require_permission("view")),
           db: Session = Depends(get_db)):
    os = get_os()
    result: dict = {"time": datetime.now(timezone.utc).isoformat(),
                    "retention_days": config.retention_days}

    # PostgreSQL
    result["postgres"] = {"ok": _db_ok(db)}

    # OpenSearch cluster
    try:
        ch = os.cluster_health()
        result["opensearch"] = {
            "ok": ch.get("status") in ("green", "yellow"),
            "status": ch.get("status"),
            "number_of_nodes": ch.get("number_of_nodes"),
            "unassigned_shards": ch.get("unassigned_shards"),
        }
    except Exception as e:
        result["opensearch"] = {"ok": False, "error": str(e)[:200]}

    # Pipeline freshness from ndr-health docs
    doc = os.latest_health_doc()
    if doc:
        backlog = doc.get("backlog_seconds")
        result["pipeline"] = {
            "ok": backlog is not None and backlog < 300,
            "sensor_id": doc.get("sensor_id"),
            "eps": doc.get("eps"),
            "eps_by_engine": doc.get("eps_by_engine"),
            "events_indexed": doc.get("events_indexed"),
            "parse_errors": doc.get("parse_errors"),
            "duplicates": doc.get("duplicates"),
            "queue_depth": doc.get("queue_depth"),
            "last_event_time": doc.get("last_event_time"),
            "backlog_seconds": backlog,
            # v0.16.1 (P2-1): metrik per-komponen pipeline (tailer/ingest/
            # normalize/detection/sink/correlation) dari health doc.
            "components": doc.get("components") or [],
        }
    else:
        result["pipeline"] = {"ok": False, "error": "no health data yet",
                              "components": []}

    # Disk usage of the OpenSearch data node
    try:
        stats = os.nodes_fs_stats()
        for _node, nd in stats.get("nodes", {}).items():
            fs = nd.get("fs", {}).get("total", {})
            total_in = fs.get("total_in_bytes", 0)
            free_in = fs.get("free_in_bytes", 0)
            if total_in:
                result["disk"] = {
                    "total_gb": round(total_in / 1e9, 1),
                    "free_gb": round(free_in / 1e9, 1),
                    "used_pct": round(100 * (1 - free_in / total_in), 1),
                }
                break
    except Exception:
        pass

    # Sensor freshness (registered sensors + pipeline heartbeat).
    # v0.12.5: status is derived from last_seen_at freshness (5 min window)
    # so a dead pipeline cannot keep a stale row 'online' forever.
    sensors = db.query(Sensor).all()
    result["sensors"] = [{
        "id": s.id, "hostname": s.hostname,
        "status": effective_sensor_status(s.last_seen_at, s.status),
        "last_seen_at": s.last_seen_at.isoformat() if s.last_seen_at else None,
    } for s in sensors]

    overall = all(result.get(k, {}).get("ok", False)
                  for k in ("postgres", "opensearch", "pipeline"))
    result["status"] = "healthy" if overall else "degraded"
    return result


@router.get("/stats/overview")
def stats_overview(user: User = Depends(require_permission("view")),
                   db: Session = Depends(get_db)):
    """Overview dashboard (v0.16.1 - P1-1/P1-2).

    v0.16.0 hanya mengisi alerts_24h/events_24h/alert_trend; Dashboard/
    Topology/Assets/Reports membaca field lain (hosts, zone_traffic,
    protocols, top_dns, mttr, services) yang TIDAK PERNAH dipopulasi ->
    semua tampil nol di mode live. Kini semua field itu diisi dari
    agregasi NYATA OpenSearch + tabel zones/incidents (tanpa fabrikasi;
    setiap bagian degrade ke [] dengan catatan bila backend gagal).
    """
    os = get_os()
    now = datetime.now(timezone.utc)
    day_ago = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    hour_ago = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    week_ago = (now - timedelta(days=7)).isoformat().replace("+00:00", "Z")

    out: dict = {"time": now.isoformat()}

    # alerts by severity (24h)
    try:
        res = os.aggregate("ndr-alerts-read", {
            "size": 0,
            "query": {"range": {"last_seen": {"gte": day_ago}}},
            "aggs": {
                "by_severity": {"terms": {"field": "severity", "size": 5}},
                "by_status": {"terms": {"field": "status", "size": 8}},
                "top_rules": {"terms": {"field": "title", "size": 10}},
            },
        })
        out["alerts_24h"] = res["hits"]["total"]["value"]
        out["alerts_by_severity"] = [
            {"key": b["key"], "count": b["doc_count"]}
            for b in res["aggregations"]["by_severity"]["buckets"]]
        out["alerts_by_status"] = [
            {"key": b["key"], "count": b["doc_count"]}
            for b in res["aggregations"]["by_status"]["buckets"]]
        out["top_alert_titles"] = [
            {"key": b["key"], "count": b["doc_count"]}
            for b in res["aggregations"]["top_rules"]["buckets"]]
    except Exception as e:
        out["alerts_24h"] = 0
        out["alerts_error"] = str(e)[:200]

    # events indexed last hour + last 24h (count API = eksak)
    try:
        out["events_24h"] = os.count("ndr-events-read", {
            "range": {"@timestamp": {"gte": day_ago}}})
        out["events_1h"] = os.count("ndr-events-read", {
            "range": {"@timestamp": {"gte": hour_ago}}})
    except Exception:
        out["events_24h"] = 0
        out["events_1h"] = 0

    # pipeline EPS from latest health doc
    doc = os.latest_health_doc()
    out["eps"] = doc.get("eps") if doc else None
    out["eps_by_engine"] = doc.get("eps_by_engine") if doc else None
    out["pipeline_last_event_time"] = doc.get("last_event_time") if doc else None
    # v0.16.1 (P2-1): komponen pipeline dari health doc (tailer/queue/
    # backlog per engine) - melengkap panel Sensors yang selama ini kosong.
    out["pipeline_components"] = doc.get("components") if doc else None

    # alert trend per hour (24 buckets)
    try:
        res = os.aggregate("ndr-alerts-read", {
            "size": 0,
            "query": {"range": {"last_seen": {"gte": day_ago}}},
            "aggs": {"trend": {"date_histogram": {
                "field": "last_seen", "calendar_interval": "hour"}}}})
        out["alert_trend"] = [
            {"ts": b["key_as_string"], "count": b["doc_count"]}
            for b in res["aggregations"]["trend"]["buckets"]]
    except Exception:
        out["alert_trend"] = []

    # ---------------------------------------------- v0.16.1 rich stats
    # (P1-2) top talkers internal 24h: bytes in/out per host
    host_bytes: dict[str, dict] = {}

    def _absorb_terms(field: str, side: str) -> None:
        agg_name = f"by_{side}"
        for b in (results_events.get("aggregations", {})
                  .get(agg_name, {}).get("buckets", [])):
            ip = b.get("key")
            if not ip or not is_internal_ip(ip):
                continue
            entry = host_bytes.setdefault(ip, {"ip": ip, "bytes_in": 0,
                                               "bytes_out": 0, "conns": 0})
            total_bytes = int(((b.get("bytes") or {}).get("value")) or 0)
            entry["conns"] += int(b.get("doc_count", 0))
            if side == "src":
                entry["bytes_out"] += total_bytes
            else:
                entry["bytes_in"] += total_bytes

    try:
        results_events = os.aggregate("ndr-events-read", {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": day_ago}}},
            "aggs": {
                "by_src": {"terms": {"field": "source.ip", "size": 150},
                           "aggs": {"bytes": {"sum": {
                               "field": "network.bytes"}}}},
                "by_dst": {"terms": {"field": "destination.ip", "size": 150},
                           "aggs": {"bytes": {"sum": {
                               "field": "network.bytes"}}}},
            }})
        _absorb_terms("source.ip", "src")
        _absorb_terms("destination.ip", "dst")
    except Exception:
        out["hosts_error"] = "host aggregation unavailable"

    # alerts per host 24h -> status watch/at_risk (heuristik jujur)
    host_alerts: dict[str, int] = {}
    try:
        res = os.aggregate("ndr-alerts-read", {
            "size": 0,
            "query": {"range": {"last_seen": {"gte": day_ago}}},
            "aggs": {
                "src": {"terms": {"field": "source.ip", "size": 100}},
                "dst": {"terms": {"field": "destination.ip", "size": 100}},
            }})
        for side in ("src", "dst"):
            for b in res["aggregations"][side]["buckets"]:
                ip = b.get("key")
                if ip:
                    host_alerts[ip] = host_alerts.get(ip, 0) \
                        + int(b.get("doc_count", 0))
    except Exception:
        pass

    # zones dari Postgres (opsional - bila kosong, host tetap terdaftar)
    zones: list = []
    try:
        zones = db.query(NetworkZone).all()
    except Exception:
        zones = []

    def _zone_of(ip: str) -> tuple[str, str]:
        for z in zones:
            cidr = (z.cidr or "").strip()
            if not cidr:
                continue
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(
                        cidr, strict=False):
                    return z.name, z.zone_type
            except ValueError:
                continue
        return "internal", "internal"

    hosts_out: list[dict] = []
    for ip, entry in sorted(host_bytes.items(),
                            key=lambda kv: -(kv[1]["bytes_in"]
                                             + kv[1]["bytes_out"]))[:80]:
        alerts_n = host_alerts.get(ip, 0)
        if alerts_n >= 5:
            status = "at_risk"
        elif alerts_n >= 1:
            status = "watch"
        else:
            status = "healthy"
        zone_name, zone_type = _zone_of(ip)
        criticality = ("critical" if zone_type == "dmz"
                       else "medium" if zone_type in ("servers",
                                                      "management")
                       else "low")
        hosts_out.append({
            "ip": ip,
            "hostname": ip,  # tanpa inventaris: label jujur = IP-nya
            "zone": zone_name,
            "role": zone_type,
            "os": None,
            "risk_score": min(100, alerts_n * 15 + (20 if status == "at_risk"
                                                    else 0)),
            "criticality": criticality,
            "open_ports": [],
            "status": status,
            "bytes_in": entry["bytes_in"],
            "bytes_out": entry["bytes_out"],
            "conns_24h": entry["conns"],
            "alerts_24h": alerts_n,
            "traffic_24h": [],
            "last_alert_title": None,
        })
    out["hosts"] = hosts_out
    out["hosts_monitored"] = len(hosts_out)
    out["hosts_at_risk"] = sum(1 for h in hosts_out
                               if h["status"] == "at_risk")
    out["hosts_watch"] = sum(1 for h in hosts_out
                             if h["status"] == "watch")

    # zone throughput (Mbps) dari bytes 24h host yang sudah terklasifikasi
    SECONDS_24H = 86400
    zone_traffic: dict[str, dict] = {}
    for h in hosts_out:
        zt = zone_traffic.setdefault(h["zone"], {
            "zone": h["zone"], "in_mbps": 0.0, "out_mbps": 0.0,
            "hosts": 0, "color": "#38bdf8"})
        zt["in_mbps"] += h["bytes_in"] * 8.0 / SECONDS_24H / 1e6
        zt["out_mbps"] += h["bytes_out"] * 8.0 / SECONDS_24H / 1e6
        zt["hosts"] += 1
    out["zone_traffic"] = sorted(zone_traffic.values(),
                                 key=lambda z: -(z["in_mbps"]
                                                 + z["out_mbps"]))
    out["traffic_24h"] = {"bytes_in": sum(h["bytes_in"]
                                          for h in hosts_out),
                          "bytes_out": sum(h["bytes_out"]
                                           for h in hosts_out)}

    # protocol mix 24h
    try:
        res = os.aggregate("ndr-events-read", {
            "size": 0,
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": day_ago}}},
                {"exists": {"field": "network.protocol"}},
            ]}},
            "aggs": {"prot": {"terms": {"field": "network.protocol",
                                        "size": 8}}}})
        out["protocols"] = [{"name": b["key"], "value": b["doc_count"]}
                            for b in res["aggregations"]["prot"]["buckets"]]
    except Exception:
        out["protocols"] = []

    # top destination ports 24h
    try:
        res = os.aggregate("ndr-events-read", {
            "size": 0,
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": day_ago}}},
                {"exists": {"field": "destination.port"}},
            ]}},
            "aggs": {"ports": {"terms": {"field": "destination.port",
                                         "size": 10}}}})
        out["top_ports"] = [{"key": str(b["key"]), "count": b["doc_count"]}
                            for b in res["aggregations"]["ports"]["buckets"]]
    except Exception:
        out["top_ports"] = []

    # top DNS / HTTP / TLS 24h (per-alias, degrade ke [] bila kosong)
    def _top(alias: str, field: str, keyname: str) -> list[dict]:
        try:
            res = os.aggregate(alias, {
                "size": 0,
                "query": {"bool": {"filter": [
                    {"range": {"@timestamp": {"gte": day_ago}}},
                    {"exists": {"field": field}},
                ]}},
                "aggs": {"t": {"terms": {"field": field, "size": 10}}}})
            return [{"key": b.get(keyname, b["key"]),
                     "count": b["doc_count"]}
                    for b in res["aggregations"]["t"]["buckets"]]
        except Exception:
            return []

    out["top_dns"] = _top("ndr-zeek-dns-read", "dns.query", "key")
    out["top_http_hosts"] = _top("ndr-zeek-http-read", "http.host", "key")
    out["top_tls_sni"] = _top("ndr-zeek-tls-read", "tls.sni", "key")

    # alert daily 7d (Reports) - v0.16.2 (BUG-0161-02): kini dengan split
    # severity per hari (sub-agg terms severity) sehingga chart stacked
    # severity Reports menampilkan data NYATA, bukan nol hardcode UI.
    try:
        res = os.aggregate("ndr-alerts-read", {
            "size": 0,
            "query": {"range": {"last_seen": {"gte": week_ago}}},
            "aggs": {"daily": {"date_histogram": {
                "field": "last_seen", "calendar_interval": "day"},
                "aggs": {"sev": {"terms": {"field": "severity",
                                           "size": 4}}}}}})
        out["alert_daily_7d"] = [
            {"day": b["key_as_string"][:10], "alerts": b["doc_count"],
             "critical": sum(s["doc_count"] for s in
                             b.get("sev", {}).get("buckets", [])
                             if s["key"] == "critical"),
             "high": sum(s["doc_count"] for s in
                         b.get("sev", {}).get("buckets", [])
                         if s["key"] == "high"),
             "medium": sum(s["doc_count"] for s in
                           b.get("sev", {}).get("buckets", [])
                           if s["key"] == "medium"),
             "low": sum(s["doc_count"] for s in
                        b.get("sev", {}).get("buckets", [])
                        if s["key"] == "low")}
            for b in res["aggregations"]["daily"]["buckets"]]
        out["alerts_7d"] = sum(b["doc_count"]
                               for b in res["aggregations"]["daily"]["buckets"])
    except Exception:
        out["alert_daily_7d"] = []
        out["alerts_7d"] = 0

    # events processed 7d (Reports)
    try:
        out["events_7d"] = os.count("ndr-events-read", {
            "range": {"@timestamp": {"gte": week_ago}}})
    except Exception:
        out["events_7d"] = 0

    # MTTR dari insiden yang ditutup 7 hari terakhir (Postgres).
    # updated_at insiden closed = waktu penutupan (status change menulis
    # updated_at). MTTA tidak dihitung di sini (tidak ada timestamp ack
    # terpisah) -> null, UI menampilkan "-" (jujur, tanpa fabrikasi).
    mttr_points: list[dict] = []
    try:
        rows = (db.query(Incident.updated_at, Incident.created_at)
                .filter(Incident.status == "closed",
                        Incident.updated_at >= now - timedelta(days=7))
                .all())
        by_day: dict[str, list[float]] = {}
        for upd, created in rows:
            if not upd or not created:
                continue
            hours = max((upd - created).total_seconds() / 3600.0, 0.0)
            day = upd.date().isoformat()
            by_day.setdefault(day, []).append(hours)
        for day in sorted(by_day):
            vals = by_day[day]
            mttr_points.append({
                "day": day,
                "mttr_hours": round(sum(vals) / len(vals), 2),
                "closed": len(vals),
            })
    except Exception:
        mttr_points = []
    out["mttr"] = mttr_points
    out["mean_time_to_ack_min"] = None
    closed_total = sum(p["closed"] for p in mttr_points)
    out["mttr_hours_avg"] = (round(sum(p["mttr_hours"] * p["closed"]
                                       for p in mttr_points)
                                    / closed_total, 2)
                             if closed_total else 0.0)
    out["closed_7d"] = closed_total

    return out
