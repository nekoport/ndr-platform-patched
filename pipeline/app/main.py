"""NDR pipeline main entrypoint.

Wiring (doc section 7.1):
  tailer threads  ->  raw queue  ->  process thread (parse/normalize/validate/
  dedup/enrich + raw archive)  ->  detection thread  ->  sink queue  ->
  OpenSearch bulk sink

Backpressure: every queue is bounded; producers block when full.
Malformed input goes to the dead-letter path - never dropped silently.
"""

from __future__ import annotations

import queue
import signal
import sys
import threading

from app import PARSER_VERSION
from app.config import load_config
from app.correlation.service import ReconstructionService
from app.correlation.store import IncidentStore
from app.dedup import DedupStore
from app.detection import DetectionEngine
from app.enrich import GamblingWatchlist, ZoneEnricher
from app.geoip import GeoEnricher
from app.intel.collector import IntelService
from app.intel.matcher import MatcherRefresher
from app.intel.store import IntelStore
from app.metrics import HealthPublisher, Metrics
from app.models import CommonEvent, make_dedup_key, make_event_id
from app.normalize import parse_suricata, parse_zeek
from app.sink.deadletter import DeadLetterWriter
from app.sink.opensearch import OpenSearchSink
from app.sink.raw_archive import RawArchive, RawArchiveMaintainer
from app.tailer import Tailer
from app.validate import validate_event


def build_patterns(cfg) -> list[str]:
    patterns: list[str] = []
    if "suricata" in cfg.sources:
        patterns.append(cfg.suricata_eve_path)
    if "zeek" in cfg.sources:
        for log in cfg.zeek_logs:
            patterns.append(f"{cfg.zeek_current_dir}/{log}.log")
            patterns.append(f"{cfg.zeek_archive_dir}/????-??-??/{log}.log")
    return patterns


def engine_for_path(path: str) -> str:
    if "suricata" in path or path.endswith("eve.json"):
        return "suricata"
    return "zeek"


def zeek_log_type_for_path(path: str) -> str | None:
    for log in ("conn", "dns", "http", "tls", "weird", "files", "ssh", "notice"):
        if path.endswith(f"/{log}.log"):
            return log
    return None


class Pipeline:
    def __init__(self, cfg=None):
        self.cfg = cfg or load_config()
        self.metrics = Metrics(self.cfg.sensor_id)
        self.raw_queue: queue.Queue = queue.Queue(maxsize=self.cfg.queue_capacity)
        self.detect_queue: queue.Queue = queue.Queue(maxsize=self.cfg.queue_capacity)
        self.sink_queue: queue.Queue = queue.Queue(maxsize=self.cfg.queue_capacity)
        self.deadletter = DeadLetterWriter(self.cfg.state_dir)
        self.raw_archive = RawArchive(self.cfg.state_dir, self.cfg.raw_retention_hours)
        self.dedup = DedupStore(capacity=200_000)
        self.zones = ZoneEnricher(self.cfg.zones)
        # ---- v0.16.0: watchlist judi online (req 18) - tag campaign ----
        self.gambling = GamblingWatchlist(self.cfg.gambling_keywords,
                                          self.cfg.gambling_domains_file)
        if self.gambling.keywords or self.gambling.domains:
            print(f"[ndr-pipeline] gambling watchlist enabled "
                  f"(keywords={len(self.gambling.keywords)}, "
                  f"domains={len(self.gambling.domains)})", file=sys.stderr)
        # ---- geoip enrichment (Phase 5, optional, off by default) ----
        self.geo = GeoEnricher(self.cfg.geoip_mmdb_path,
                               self.cfg.geoip_json_path)
        if self.geo.enabled:
            print(f"[ndr-pipeline] geoip enrichment enabled "
                  f"({self.geo.backend.name})", file=sys.stderr)
        self.tailer = Tailer(
            patterns=build_patterns(self.cfg),
            out_queue=self.raw_queue,
            checkpoint_path=f"{self.cfg.state_dir}/checkpoints.json",
            name="log-tailer")
        self.detection = DetectionEngine(self.cfg, self.detect_queue,
                                         self.sink_queue,
                                         geo_enricher=self.geo)
        # v0.13.0: detection drop counter feeds the same metrics registry
        self.detection.metrics = self.metrics
        self.sink = OpenSearchSink(
            self.cfg.opensearch_url, self.sink_queue, self.cfg, self.metrics,
            deadletter=self.deadletter, flush_seconds=self.cfg.bulk_flush_seconds,
            max_items=self.cfg.bulk_max_items, max_retries=self.cfg.bulk_max_retries)
        self.raw_maintainer = RawArchiveMaintainer(self.raw_archive)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = [
            self.tailer, self.detection, self.sink, self.raw_maintainer]
        # ---- threat intelligence (doc section 9, Phase 3) -------------
        self.intel: IntelService | None = None
        if self.cfg.ti_enabled:
            try:
                store = IntelStore(self.cfg.ti_database_url)
                # v0.12.5: fail jobs orphaned by a crash (stuck 'running'
                # forever) and seed the starter feeds on empty tables.
                store.recover_orphan_jobs()
                store.seed_default_feeds()
                self.intel = IntelService(self.cfg, self.metrics, store=store)
                self._threads.append(self.intel)
                self._threads.append(MatcherRefresher(
                    self.intel.matcher, self.cfg.ti_reload_seconds))
                print("[ndr-pipeline] threat intelligence enabled",
                      file=sys.stderr)
            except Exception as exc:  # noqa: BLE001 - TI must not kill ingest
                print(f"[ndr-pipeline] TI disabled: {exc}", file=sys.stderr)
                self.intel = None
        self.health = HealthPublisher(self.metrics, self.cfg, self._stop,
                                      db_url=self.cfg.ti_database_url)
        self._threads.append(self.health)
        # ---- attack reconstruction (doc section 10, Phase 4) ----------
        self.recon: ReconstructionService | None = None
        if self.cfg.recon_enabled:
            try:
                incident_store = IncidentStore(self.cfg.ti_database_url)
                self.recon = ReconstructionService(self.cfg, self.metrics,
                                                   store=incident_store)
                self.detection.set_recon_hook(
                    lambda doc: self.recon.on_alert(doc))
                self._threads.append(self.recon)
                print("[ndr-pipeline] attack reconstruction enabled",
                      file=sys.stderr)
            except Exception as exc:  # noqa: BLE001 - recon must not kill ingest
                print(f"[ndr-pipeline] reconstruction disabled: {exc}",
                      file=sys.stderr)
                self.recon = None

    # -------------------------------------------------------------- process
    def _process_one(self, path: str, line: str) -> None:
        self.metrics.inc("events_in")
        engine = engine_for_path(path)

        if engine == "suricata":
            ev = parse_suricata(line, self.cfg.sensor_id,
                                set(self.cfg.suricata_types),
                                max_field_len=self.cfg.max_field_len)
        else:
            log_type = zeek_log_type_for_path(path)
            if log_type is None or log_type not in self.cfg.zeek_logs:
                self.metrics.inc("skipped")
                return
            ev = parse_zeek(line, self.cfg.sensor_id, log_type,
                            max_field_len=self.cfg.max_field_len)

        if ev is None:
            self.metrics.inc("parse_errors")
            self.deadletter.write("parse_error", raw=line)
            return

        ok, reason = validate_event(
            ev, max_clock_skew_seconds=self.cfg.max_clock_skew_seconds,
            max_event_age_days=self.cfg.max_event_age_days)
        if not ok:
            self.metrics.inc("quarantined")
            self.deadletter.write(f"validation:{reason}", raw=line)
            return

        # v0.13.0: dedup key is PARSER-OWNED (ev.dedup_key, set during
        # normalization). Recomputing it here merged DIFFERENT events
        # that happened to share flow/ts - silent data loss.
        dedup_key = ev.dedup_key or make_dedup_key(ev.source_engine, ev.event_type, ev.session_id,
                                   ev.event_time.isoformat(), ev.source_ip,
                                   ev.source_port, ev.destination_ip,
                                   ev.destination_port, ev.signature_id)
        ev.event_id = make_event_id(dedup_key)

        if self.dedup.seen_before(ev.event_id):
            self.metrics.inc("duplicates")
            return

        self.metrics.note_event()
        self.metrics.inc("events_accepted", engine=ev.source_engine)

        ev.raw_event_ref = self.raw_archive.store(engine, line)
        self.zones.enrich(ev)
        self.geo.enrich_event(ev)
        self.gambling.enrich(ev)

        index_date = ev.event_time.strftime("%Y.%m.%d")
        if ev.source_engine == "suricata":
            index = f"ndr-suricata-{index_date}"
        else:
            index = f"ndr-zeek-{ev.event_type}-{index_date}"

        if self.intel is not None:
            matches = self.intel.match(ev)
            if matches:
                ev.matched_ioc = matches
                self.metrics.inc("ti_matches",
                                 engine=matches[0]["ioc_type"])
                self._emit_ioc_matches(ev, index)

        if self.recon is not None:
            try:
                self.recon.on_event(ev, index)
            except Exception:  # noqa: BLE001 - recon must not break ingest
                self.metrics.inc("recon_errors")

        self.metrics.set_gauge("queue_depth", self.detect_queue.qsize())
        self.metrics.set_gauge("queue_capacity", self.cfg.queue_capacity)
        self.metrics.set_gauge("tailer_state", "streaming")
        self.detect_queue.put((ev, index))

    def _emit_ioc_matches(self, ev: CommonEvent, event_index: str) -> None:
        """Index one ndr-ioc-matches doc per (event, ioc) - replay-safe ids."""
        index_date = ev.event_time.strftime("%Y.%m.%d")
        index = f"ndr-ioc-matches-{index_date}"
        for m in ev.matched_ioc[:3]:
            doc_id = make_event_id(f"iocmatch|{ev.event_id}|"
                                   f"{m['ioc_type']}|{m['ioc_value']}")
            doc = {
                "@timestamp": ev.event_time.isoformat().replace("+00:00", "Z"),
                "event_id": ev.event_id,
                "event_index": event_index,
                "sensor_id": ev.sensor_id,
                "ioc_type": m["ioc_type"],
                "ioc_value": m["ioc_value"],
                "ioc_source": m.get("ioc_source") or "threat-intel",
                "ioc_confidence": m.get("confidence") or "medium",
                "match_field": m.get("match_field"),
                "first_seen": m.get("first_seen"),
                "last_seen": m.get("last_seen"),
                "expires_at": m.get("expires_at"),
                "zone": ev.zone,
            }
            if ev.source_ip:
                doc["source_ip"] = ev.source_ip
            if ev.destination_ip:
                doc["destination_ip"] = ev.destination_ip
            self.sink_queue.put((index, doc_id, doc))

    def _process_loop(self) -> None:
        while not self._stop.is_set() or not self.raw_queue.empty():
            try:
                path, line = self.raw_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._process_one(path, line)
            except Exception as exc:  # noqa: BLE001 - never kill the loop
                self.metrics.inc("processing_errors")
                try:
                    self.deadletter.write(f"processing_error:{exc}", raw=line)
                except Exception:
                    pass
            finally:
                self.raw_queue.task_done()

    # -------------------------------------------------------------- control
    def start(self) -> None:
        proc = threading.Thread(target=self._process_loop, name="processor",
                                daemon=True)
        self._threads.append(proc)
        self._proc_thread = proc
        for t in self._threads:
            t.start()

    def run_forever(self) -> None:
        self.start()
        try:
            while self._proc_thread.is_alive() or not self.raw_queue.empty():
                self._proc_thread.join(timeout=1.0)
                if self._stop.is_set() and self.raw_queue.empty():
                    break
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    def stop_signal(self, *_args) -> None:
        self._stop.set()

    def shutdown(self) -> None:
        self._stop.set()
        for t in self._threads:
            stop = getattr(t, "stop", None)
            if callable(stop):
                try:
                    stop()
                except Exception:
                    pass
        # drain: wait bounded time for queues to empty
        deadline = 30.0
        while deadline > 0 and (not self.raw_queue.empty()
                                or not self.detect_queue.empty()
                                or not self.sink_queue.empty()):
            import time as _t
            _t.sleep(0.5)
            deadline -= 0.5
        self.raw_archive.close()
        print("[ndr-pipeline] shutdown complete", file=sys.stderr)


def main() -> int:
    print(f"[ndr-pipeline] starting, parser {PARSER_VERSION}", file=sys.stderr)
    cfg = load_config()
    print(f"[ndr-pipeline] sensor={cfg.sensor_id} sources={cfg.sources} "
          f"os={cfg.opensearch_url}", file=sys.stderr)
    pipe = Pipeline(cfg)
    signal.signal(signal.SIGTERM, pipe.stop_signal)
    signal.signal(signal.SIGINT, pipe.stop_signal)
    pipe.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
