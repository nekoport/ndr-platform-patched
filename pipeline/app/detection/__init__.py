"""Detection engine wiring: routes events to rules and sweeps periodically.

Phase 4: rules also tag `attack_phase` on every alert doc and push alert
documents into an optional reconstruction hook (`set_recon_hook`) so the
correlation engine can grow attack stories without re-reading alerts
from OpenSearch.
"""

from __future__ import annotations

import sys
import threading
import time

from app.config import Config
from app.models import CommonEvent
from app.detection.rules import (BeaconingDetector, IocMatchDetector,
                                 NXDomainBurstDetector, PortscanDetector,
                                 SuricataAlertGrouper)
from app.detection.behavior import (DGADetector, DnsTunnelingDetector,
                                    FileTransferDetector,
                                    InternalLateralDetector,
                                    LargeOutboundDetector)
from app.detection.allowlist import AlertAllowlistProvider


def _alert_index_factory(base: str = "ndr-alerts"):
    def index_for(timestamp_iso: str) -> str:
        return f"{base}-{timestamp_iso[:10].replace('-', '.')}"
    return index_for


class DetectionEngine(threading.Thread):
    """Consumes normalized events, feeds rules, passes everything downstream.

    Detection never blocks or drops events: if its output queue is full it
    blocks, propagating backpressure upstream (doc 7.3).
    """

    SWEEP_INTERVAL = 30.0

    def __init__(self, cfg: Config, in_queue, out_queue):
        super().__init__(daemon=True, name="detection")
        self.cfg = cfg
        self.in_queue = in_queue
        self.out_queue = out_queue
        self._stop = threading.Event()
        self._recon_hook = None          # set via set_recon_hook()
        index_for = _alert_index_factory()

        win = cfg.detect_alert_window_min * 60
        self.alert_grouper = SuricataAlertGrouper(
            window_seconds=win, max_keys=cfg.detect_max_tracked_keys,
            sensor_id=cfg.sensor_id, sink_queue=self.out_queue, index_for_alert=index_for)
        self.portscan = PortscanDetector(
            unique_ports=cfg.detect_portscan_unique_ports,
            unique_hosts=cfg.detect_portscan_unique_hosts,
            window_min=cfg.detect_portscan_window_min,
            max_keys=cfg.detect_max_tracked_keys,
            sensor_id=cfg.sensor_id, sink_queue=self.out_queue, index_for_alert=index_for)
        self.nxdomain = NXDomainBurstDetector(
            min_count=cfg.detect_nxdomain_min_count, ratio=cfg.detect_nxdomain_ratio,
            window_min=cfg.detect_nxdomain_window_min,
            max_keys=cfg.detect_max_tracked_keys,
            sensor_id=cfg.sensor_id, sink_queue=self.out_queue, index_for_alert=index_for)
        self.beaconing = BeaconingDetector(
            min_connections=cfg.detect_beacon_min_connections,
            interval_min_sec=cfg.detect_beacon_interval_min_sec,
            interval_max_sec=cfg.detect_beacon_interval_max_sec,
            jitter_max=cfg.detect_beacon_jitter_max,
            window_min=cfg.detect_beacon_window_min,
            max_keys=cfg.detect_max_tracked_keys,
            sensor_id=cfg.sensor_id, sink_queue=self.out_queue, index_for_alert=index_for)
        self.rules = [self.alert_grouper, self.portscan, self.nxdomain,
                      self.beaconing]

        # ---- Phase 4 behavior rules (attack-phase coverage) -----------
        self.file_transfer = FileTransferDetector(
            min_bytes=cfg.detect_file_min_bytes, window_min=cfg.detect_window_min,
            max_keys=cfg.detect_max_tracked_keys,
            sensor_id=cfg.sensor_id, sink_queue=self.out_queue,
            index_for_alert=index_for)
        self.dga = DGADetector(
            min_unique=cfg.detect_dga_min_unique,
            entropy_min=cfg.detect_dga_entropy_min,
            window_min=cfg.detect_window_min,
            max_keys=cfg.detect_max_tracked_keys,
            sensor_id=cfg.sensor_id, sink_queue=self.out_queue,
            index_for_alert=index_for,
            allowlist_extra=cfg.detect_dga_allowlist)
        self.tunnel = DnsTunnelingDetector(
            min_count=cfg.detect_tunnel_min_count,
            min_label_len=cfg.detect_tunnel_min_label_len,
            window_min=cfg.detect_window_min,
            max_keys=cfg.detect_max_tracked_keys,
            sensor_id=cfg.sensor_id, sink_queue=self.out_queue,
            index_for_alert=index_for)
        self.lateral = InternalLateralDetector(
            ports=cfg.detect_lateral_ports,
            min_conns=cfg.detect_lateral_min_conns,
            cross_zone_min=cfg.detect_lateral_cross_zone_min,
            window_min=cfg.detect_window_min,
            max_keys=cfg.detect_max_tracked_keys,
            sensor_id=cfg.sensor_id, sink_queue=self.out_queue,
            index_for_alert=index_for, zones=cfg.zones)
        self.outbound = LargeOutboundDetector(
            min_bytes=cfg.detect_exfil_min_bytes,
            window_min=cfg.detect_window_min,
            max_keys=cfg.detect_max_tracked_keys,
            sensor_id=cfg.sensor_id, sink_queue=self.out_queue,
            index_for_alert=index_for, zones=cfg.zones)
        self.rules += [self.file_transfer, self.dga, self.tunnel,
                       self.lateral, self.outbound]

        self.ioc_match: IocMatchDetector | None = None
        if cfg.detect_ioc_match:
            self.ioc_match = IocMatchDetector(
                window_min=cfg.detect_ioc_window_min,
                max_keys=cfg.detect_max_tracked_keys,
                sensor_id=cfg.sensor_id, sink_queue=self.out_queue,
                index_for_alert=index_for)
            self.rules.append(self.ioc_match)

        # every rule fans out emitted alert docs to the recon hook
        for rule in self.rules:
            rule.recon_sink = self.emit_alert_doc

        # ---- v0.14.0 alert whitelist (allowlist) provider -------------
        # Optional: requires DATABASE_URL (the same Postgres the API owns).
        # Detection NEVER depends on it: on any failure the provider keeps
        # the last snapshot and emit() behaves as before.
        self.allowlist: AlertAllowlistProvider | None = None
        if getattr(cfg, "ti_database_url", ""):
            try:
                self.allowlist = AlertAllowlistProvider(cfg.ti_database_url)
                for rule in self.rules:
                    rule.allowlist_check = self.allowlist.check
                    rule.allowlist_hit = self.allowlist.bump
            except Exception as exc:  # noqa: BLE001 - stay up, stay loud
                print(f"[detection] whitelist provider disabled: {exc}",
                      file=sys.stderr)

    def set_recon_hook(self, hook) -> None:
        """Register `hook(doc)` invoked for every emitted alert doc.

        The hook MUST be non-blocking and exception-safe: detection
        correctness must never depend on the reconstruction engine.
        """
        self._recon_hook = hook

    def stop(self) -> None:
        self._stop.set()
        # v0.14.0: persist pending whitelist hit counters on shutdown
        if self.allowlist is not None:
            try:
                self.allowlist.close()
            except Exception:  # noqa: BLE001
                pass

    def run(self) -> None:
        last_sweep = time.time()
        while not self._stop.is_set():
            try:
                item = self.in_queue.get(timeout=1.0)
            except Exception:
                item = None
            if item is not None:
                ev, index_name = item
                self._feed(ev, index_name)
                # forward the event itself downstream (it is indexed anyway)
                self.out_queue.put((index_name, ev.event_id, ev.to_doc()))
                self.in_queue.task_done()
            # v0.12.5: use the WALL clock (time.time) everywhere. The
            # previous mix (monotonic() - last_sweep[wall]) was always
            # negative, so the sweep NEVER ran -> zero behavioral alerts
            # forever (36k Suricata alerts, 0 NDR alerts on the live VM).
            # Rules compare `now` against event epoch timestamps
            # (ev.event_time.timestamp()) and last_flush, so the sweep
            # cutoff must be epoch too.
            if time.time() - last_sweep >= self.SWEEP_INTERVAL:
                last_sweep = time.time()
                now = time.time()
                for rule in self.rules:
                    try:
                        rule.sweep(now)
                    except Exception:  # noqa: BLE001 - detection must not die
                        continue
                # v0.14.0: periodic whitelist reload + hit-counter flush
                if self.allowlist is not None:
                    try:
                        self.allowlist.load()
                        self.allowlist.maybe_flush(now)
                    except Exception:  # noqa: BLE001
                        pass

    def _feed(self, ev: CommonEvent, index_name: str) -> None:
        try:
            if ev.source_engine == "suricata" and ev.event_type == "alert":
                self.alert_grouper.feed(ev, index_name)
            elif ev.event_type == "conn":
                self.portscan.feed(ev, index_name)
                self.beaconing.feed(ev, index_name)
                self.lateral.feed(ev, index_name)
                self.outbound.feed(ev, index_name)
            elif ev.event_type == "dns":
                self.nxdomain.feed(ev, index_name)
                self.dga.feed(ev, index_name)
                self.tunnel.feed(ev, index_name)
            elif ev.event_type == "fileinfo":
                self.file_transfer.feed(ev, index_name)
            if self.ioc_match is not None and ev.matched_ioc:
                self.ioc_match.feed(ev, index_name)
        except Exception:  # noqa: BLE001 - detection must not die, but the
            # drop is now COUNTED (v0.13.0) instead of silently eaten
            m = getattr(self, "metrics", None)
            if m is not None:
                try:
                    m.inc("detection_dropped")
                except Exception:
                    pass

    def emit_alert_doc(self, doc: dict) -> None:
        """Internal helper used by BaseRule.emit to fan out to recon."""
        if self._recon_hook is not None:
            try:
                self._recon_hook(doc)
            except Exception:  # noqa: BLE001 - hook must not break detection
                pass
