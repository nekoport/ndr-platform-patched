"""Pipeline metrics + health publishing (doc sections 11.2, 19.3).

- counters: EPS per engine, parse errors, duplicates, drops, queue depth
- health docs written to ndr-health-* every `health_interval_seconds`
  (idempotent doc id per interval so replays do not double-count)
- tiny HTTP endpoint on METRICS_PORT serving the live counters as JSON
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from opensearchpy import OpenSearch

from app.models import PARSER_VERSION, utcnow


class Metrics:
    def __init__(self, sensor_id: str):
        self.sensor_id = sensor_id
        self._lock = threading.Lock()
        self._counters: dict[str, float] = {}
        self._window_start = time.monotonic()
        self._window_counters: dict[str, float] = {}
        self.gauges: dict[str, float] = {}
        self.per_engine: dict[str, float] = {}
        self.last_event_epoch: float | None = None
        self.started_at = datetime.now(timezone.utc)

    # ------------------------------------------------------------ counters
    def inc(self, name: str, amount: float = 1.0, engine: str | None = None) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0.0) + amount
            self._window_counters[name] = self._window_counters.get(name, 0.0) + amount
            if engine:
                key = f"events_{engine}"
                self.per_engine[key] = self.per_engine.get(key, 0.0) + amount
                self._window_counters[key] = self._window_counters.get(key, 0.0) + amount

    def set_gauge(self, name: str, value: float) -> None:
        with self._lock:
            self.gauges[name] = value

    def note_event(self) -> None:
        self.last_event_epoch = time.time()

    # ------------------------------------------------------------ snapshot
    def snapshot(self) -> dict:
        with self._lock:
            elapsed = max(time.monotonic() - self._window_start, 1e-6)
            eps_total = self._window_counters.get("events_accepted", 0.0) / elapsed
            eps_by_engine = {
                k.replace("events_", ""): v / elapsed
                for k, v in self._window_counters.items()
                if k.startswith("events_") and k != "events_in"
            }
            snap = {
                "sensor_id": self.sensor_id,
                "parser_version": PARSER_VERSION,
                "started_at": self.started_at.isoformat(),
                "uptime_seconds": int(time.time() - self.started_at.timestamp()),
                "counters": dict(self._counters),
                "gauges": dict(self.gauges),
                "eps_total": round(eps_total, 2),
                "eps_by_engine": {k: round(v, 2) for k, v in eps_by_engine.items()},
                "last_event_time": (
                    datetime.fromtimestamp(self.last_event_epoch, tz=timezone.utc).isoformat()
                    if self.last_event_epoch else None),
                "backlog_seconds": (
                    round(time.time() - self.last_event_epoch, 2)
                    if self.last_event_epoch else None),
            }
            # v0.13.0: snapshot() is READ-ONLY. Resetting the EPS window
            # here made every /metrics scrape destroy the rate window
            # (dashboard showed eps 0.0 while ingest was healthy). The
            # window is now rotated EXCLUSIVELY by the health writer via
            # rotate() right before it publishes a doc.
            return snap

    def rotate(self) -> dict:
        """Close the current EPS window. EXCLUSIVE to the health writer."""
        snap = self.snapshot()
        with self._lock:
            self._window_start = time.monotonic()
            self._window_counters = {}
        return snap


class HealthPublisher(threading.Thread):
    """Writes periodic health docs into ndr-health-* and serves /metrics.

    v0.12.5: also heartbeats the Postgres `sensors` table (best-effort)
    so the UI Sensors page shows the pipeline without manual registration;
    the API derives effective status from last_seen_at freshness.
    """

    def __init__(self, metrics: Metrics, cfg, stop_event: threading.Event,
                 db_url: str | None = None):
        super().__init__(daemon=True, name="health-publisher")
        self.metrics = metrics
        self.cfg = cfg
        self._stop = stop_event
        self.client = OpenSearch(hosts=[cfg.opensearch_url], use_ssl=False,
                                 verify_certs=False, timeout=15)
        self._httpd = None
        self._db_url = db_url
        self._db_engine = None

    # -------------------------------------------------------- heartbeat
    def _heartbeat(self) -> None:
        """Upsert one `sensors` row for this pipeline (best-effort).

        Nothing wrote the sensors table before v0.12.5 - the page only
        ever showed manually registered sensors. hostname falls back to
        the container id (the pipeline cannot see the VM hostname);
        override with SENSOR_HOSTNAME if you want a friendlier label.
        """
        if not self._db_url:
            return
        if self._db_engine is None:
            try:
                from sqlalchemy import create_engine
                self._db_engine = create_engine(self._db_url, future=True,
                                                pool_pre_ping=True)
            except Exception:  # noqa: BLE001 - heartbeat is optional
                self._db_url = None
                return
        import os as _os
        import socket as _socket
        from sqlalchemy import text
        now = datetime.now(timezone.utc)
        hostname = _os.environ.get("SENSOR_HOSTNAME") or _socket.gethostname()
        versions = {"pipeline": _os.environ.get("NDR_PIPELINE_VERSION", "")}
        try:
            with self._db_engine.begin() as conn:
                conn.execute(text(
                    "INSERT INTO sensors (id, hostname, status, "
                    "software_versions, last_seen_at, created_at, "
                    "updated_at) VALUES (:sid, :host, 'online', :ver, "
                    ":now, :now, :now) "
                    "ON CONFLICT (id) DO UPDATE SET status='online', "
                    "software_versions=:ver, last_seen_at=:now, "
                    "updated_at=:now"),
                    {"sid": self.cfg.sensor_id, "host": hostname,
                     "ver": json.dumps(versions), "now": now})
        except Exception:  # noqa: BLE001 - heartbeat must never break ingest
            pass

    # -------------------------------------------------------------- http
    def _start_http(self) -> None:
        metrics = self.metrics

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path != "/metrics":
                    self.send_response(404)
                    self.end_headers()
                    return
                body = json.dumps(metrics.snapshot()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):  # silence access log
                return

        try:
            self._httpd = ThreadingHTTPServer(("0.0.0.0", self.cfg.metrics_port), Handler)
            thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
            thread.start()
        except OSError:
            self._httpd = None  # port busy (e.g. dev environment)

    # -------------------------------------------------------------- loop
    def run(self) -> None:
        self._start_http()
        interval = self.cfg.health_interval_seconds
        while not self._stop.wait(interval):
            self._publish()

    def _publish(self) -> None:
        # rotate() = the ONLY window reset point (writer-owned, v0.13.0)
        snap = self.metrics.rotate()
        now = datetime.now(timezone.utc)
        index = f"ndr-health-{now.strftime('%Y.%m.%d')}"
        doc_id = f"{self.cfg.sensor_id}-{now.strftime('%Y%m%d%H%M')}"
        doc = {
            "@timestamp": now.isoformat().replace("+00:00", "Z"),
            "sensor_id": snap["sensor_id"],
            "source_engine": "pipeline",
            "eps": snap["eps_total"],
            "eps_by_engine": snap["eps_by_engine"],
            "events_indexed": snap["counters"].get("events_indexed", 0),
            "parse_errors": snap["counters"].get("parse_errors", 0),
            "duplicates": snap["counters"].get("duplicates", 0),
            "dropped": snap["counters"].get("dropped", 0),
            "queue_depth": snap["gauges"].get("queue_depth", 0),
            "queue_capacity": snap["gauges"].get("queue_capacity", 0),
            "backlog_seconds": snap["backlog_seconds"],
            "last_event_time": snap["last_event_time"],
            "tailer_state": snap["gauges"].get("tailer_state", "unknown"),
            # v0.16.1 (P2-1): metrik per-komponen pipeline. Dulu panel
            # "Capture stack components" kosong karena health doc tidak
            # punya bagian komponen. Ini metrik NYATA dari proses pipeline
            # (bukan CPU% proses sensor yang tidak bisa diamati lintas
            # container - untuk itu pakai `docker stats` di host).
            "components": self._components(snap),
        }
        try:
            self.client.index(index=index, id=doc_id, body=doc, refresh=False)
        except Exception:
            pass  # health is best-effort; OS unavailability is visible elsewhere
        self._heartbeat()

    @staticmethod
    def _components(snap: dict) -> list[dict]:
        """Bangun daftar komponen pipeline dari snapshot metrik (P2-1).

        ok = keadaan internal yang bisa dibuktikan dari metrik sendiri
        (queue tidak penuh, tailer streaming) - TIDAK pernah mengarang
        keadaan proses Zeek/Suricata yang tidak terlihat dari container
        pipeline.
        """
        counters = snap.get("counters", {})
        gauges = snap.get("gauges", {})
        eps_engine = snap.get("eps_by_engine", {})
        queue_depth = int(gauges.get("queue_depth", 0) or 0)
        queue_cap = int(gauges.get("queue_capacity", 0) or 0)
        sink_pending = int(gauges.get("sink_pending", 0) or 0)
        tailer_state = str(gauges.get("tailer_state", "unknown"))
        backlog = snap.get("backlog_seconds")
        backlog_txt = (f"{backlog:.0f}s" if isinstance(backlog, (int, float))
                       else "n/a")

        def eps(engine: str) -> float:
            v = eps_engine.get(engine)
            if v is None:
                v = eps_engine.get(f"events_{engine}", 0)
            try:
                return round(float(v), 2)
            except (TypeError, ValueError):
                return 0.0

        return [
            {"name": "tailer", "ok": tailer_state in ("streaming", "ok"),
             "detail": f"state={tailer_state}; backlog={backlog_txt}"},
            {"name": "ingest-zeek", "ok": True,
             "detail": f"{eps('zeek')} eps", "eps": eps("zeek")},
            {"name": "ingest-suricata", "ok": True,
             "detail": f"{eps('suricata')} eps", "eps": eps("suricata")},
            {"name": "normalize", "ok": True,
             "detail": (f"parse_errors {int(counters.get('parse_errors', 0))}, "
                        f"duplicates {int(counters.get('duplicates', 0))}, "
                        f"dropped {int(counters.get('dropped', 0))}")},
            {"name": "detection", "ok": queue_cap == 0 or queue_depth < queue_cap,
             "detail": f"queue {queue_depth}/{queue_cap or '?'}"},
            {"name": "sink-opensearch", "ok": sink_pending < 10000,
             "detail": f"pending {sink_pending}; indexed "
                       f"{int(counters.get('events_indexed', 0))}"},
            {"name": "correlation",
             "ok": True,
             "detail": (f"stories open {int(gauges.get('recon_open_stories', 0))}, "
                        f"dirty {int(gauges.get('recon_dirty_stories', 0))}")},
        ]

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
