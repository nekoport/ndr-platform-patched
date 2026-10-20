"""Attack-phase behavior rules (Phase 4 - attack reconstruction, doc 10).

Fill the phase coverage gaps needed by the correlation engine while
keeping the Phase 2 guardrails: explainable rationale, no overclaim,
heuristic-uncalibrated confidence, bounded memory.

  1. file_transfer_suspected    - Phase 3 (payload delivery candidates)
  2. dga_suspected              - Phase 4 (C2 infrastructure candidates)
  3. dns_tunneling_suspected    - Phase 4 (C2 / exfil channel candidates)
  4. internal_lateral_suspected - Phase 5 (lateral movement candidates)
  5. large_outbound_transfer    - Phase 6 (exfiltration candidates)

Every alert tags the suspected attack phase (`attack_phase`) so the
reconstruction engine can place it on the kill chain.
"""

from __future__ import annotations

import math
import time
from collections import Counter
from datetime import datetime, timezone

from app.models import CommonEvent
from app.detection.rules import BaseRule, build_alert_doc, make_alert_id
from app.detection.taxonomy import is_internal_check

EXECUTABLE_MIMES = {
    "application/x-dosexec", "application/x-executable",
    "application/x-msdownload", "application/x-msi",
    "application/x-elf", "application/vnd.microsoft.portable-executable",
    "application/x-sharedlib", "application/java-archive",
    "application/x-jar", "application/vnd.android.package-archive",
}

REMOTE_SERVICE_PORTS = {22, 135, 139, 445, 3389, 5985, 5986}

TUNNEL_QTYPES = {"TXT", "NULL", "CNAME", "MX", "SRV", "ANY"}

# v0.12.9 DGA false-positive allowlist (reference practice: Splunk 2022
# notes CDN domains trigger entropy detections; Elastic/Splunk guidance
# filters popular/CDN domains before scoring - Tranco-style allowlist).
# Suffix-matched on the FULL query ("www.google.com" matches
# "google.com"). Extend at runtime via DETECT_DGA_ALLOWLIST env
# (comma-separated). DNS tunneling is a SEPARATE detector - hiding
# tunnel payloads under popular domains does NOT reduce its coverage.
DEFAULT_DGA_ALLOWLIST = frozenset({
    # search / OS / cloud
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "youtube.com", "ytimg.com", "microsoft.com", "office.com", "office365.com",
    "outlook.com", "live.com", "windows.com", "azure.com", "azureedge.net",
    "msn.com", "bing.com", "amazon.com", "amazonaws.com", "cloudfront.net",
    "apple.com", "icloud.com", "cdn-apple.com", "akamaihd.net",
    "akamaiedge.net", "cloudflare-dns.com", "cloudflare.com",
    # social / messaging
    "facebook.com", "instagram.com", "whatsapp.com", "twitter.com", "x.com",
    "linkedin.com", "tiktok.com", "reddit.com", "redd.it", "twimg.com",
    # productivity / collaboration
    "wikipedia.org", "wikimedia.org", "github.com", "githubusercontent.com",
    "github.io", "stackoverflow.com", "zoom.us", "dropbox.com", "box.com",
    "slack.com", "notion.so", "atlassian.net", "adobe.com",
    # common in ID/regional + consumer
    "yahoo.com", "baidu.com", "qq.com", "weibo.com", "netflix.com",
    "spotify.com", "ebay.com", "paypal.com", "samsung.com", "huawei.com",
    "xiaomi.com", "oppo.com", "vivo.com", "tokopedia.com", "tokocrypto.com",
    "detik.com", "kompas.com", "gridoto.com", "shopee.co.id", "shopee.com",
    "lazada.co.id", "blibli.com", "or.id", "ac.id", "go.id", "co.id",
    "sch.id", "web.id", "my.id", "biz.id",
})


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


class FileTransferDetector(BaseRule):
    """Executable or oversized file downloads (Phase 3 - delivery)."""

    name = "file_transfer_suspected"

    def __init__(self, min_bytes: int, window_min: int, max_keys: int,
                 sensor_id: str, sink_queue, index_for_alert):
        super().__init__(window_min * 60, max_keys, sensor_id, sink_queue,
                         index_for_alert)
        self.min_bytes = min_bytes
        self._buffer = WindowShim(self.window_seconds * 2, max_keys)

    def feed(self, ev: CommonEvent, index_name: str) -> None:
        # v0.13.0: Zeek files.log arrives as event_type "files" - previously
        # this detector NEVER ran on Zeek data (fileinfo-only gate).
        if ev.event_type not in ("fileinfo", "files") or ev.source_ip is None:
            return
        mime = (ev.file_mime or "").lower()
        # v0.13.0: file_size is int-or-None after normalization; the bare
        # comparison used to raise TypeError on coerced-None and the sweep
        # silently skipped the whole key
        size = ev.file_size if isinstance(ev.file_size, (int, float)) else 0
        interesting = mime in EXECUTABLE_MIMES or (
            self.min_bytes and size >= self.min_bytes)
        if not interesting:
            return
        reason = "executable mime" if mime in EXECUTABLE_MIMES else "large size"
        self._buffer.add(ev.source_ip, ev.event_time.timestamp(),
                         (ev, reason, index_name))

    def sweep(self, now: float) -> None:
        if not self.flush_due(now):
            return
        cutoff = now - self.window_seconds
        for key in self._buffer.keys():
            buf = self._buffer.prune_key(key, now)
            if not buf:
                continue
            if buf[-1][0] > cutoff:
                continue
            self._buffer.drop_key(key)
            events = [payload[0] for _, payload in buf]
            reasons_seen = {payload[1] for _, payload in buf}
            indexes = {payload[2] for _, payload in buf}
            mimes = sorted({e.file_mime for e in events if e.file_mime})
            names = [e.file_name for e in events if e.file_name][:5]
            total = sum(e.file_size or 0 for e in events)
            first = events[0].event_time
            last = events[-1].event_time
            doc = build_alert_doc(
                alert_id=make_alert_id(self.name, key, first),
                alert_type=self.name, attack_phase="delivery",
                title=f"File download candidate from {key} "
                      f"({len(events)} files)",
                group_key=key, severity="medium",
                rationale=(
                    f"Host {key} downloaded {len(events)} flagged files "
                    f"({', '.join(sorted(reasons_seen)) or 'flagged'}) within "
                    f"the window. Download alone does not prove execution; "
                    f"correlate with C2 activity and threat intelligence "
                    f"hash matches before escalation."),
                reasons=[
                    f"files: {len(events)}, total bytes: {total}",
                    f"mime types: {', '.join(mimes) or 'unknown'}",
                    f"sample names: {', '.join(n or 'n/a' for n in names)}",
                    f"min size threshold: {self.min_bytes} bytes",
                ],
                first_seen=first, last_seen=last, sensor_id=self.sensor_id,
                event_count=len(events), source_count=1,
                destination_count=len({e.destination_ip for e in events
                                       if e.destination_ip}),
                source_ip=key,
                destination_ip=next((e.destination_ip for e in events
                                     if e.destination_ip), None),
                transport=None, protocol=None,
                top_sources=[(key, len(events))],
                top_destinations=Counter(
                    e.destination_ip for e in events
                    if e.destination_ip).most_common(),
                top_rules=[(m or "unknown-mime", 1) for m in mimes[:5]],
                evidence=[{"event_id": e.event_id,
                           "index": next(iter(indexes), "ndr-zeek-files"),
                           "@timestamp": _iso(e.event_time)}
                          for e in events[:10]],
            )
            self.emit(doc)


class DGADetector(BaseRule):
    """Many unique high-entropy domains queried by one source (Phase 4).

    v0.12.9: popular/CDN domains are allowlisted (suffix match) and
    EXCLUDED from the unique-domain count and entropy average - the
    industry-standard FP control for entropy-based DGA detection
    (Splunk 2022 DGA blog; Tranco allowlist practice). Sampled queries
    now carry their PER-DOMAIN entropy so the analyst sees the score,
    not only the mean (Elastic DGA integration presents per-domain
    probability the same way). Known limitation, documented on the UI:
    dictionary-based DGAs (Gozi/Matsnu class) keep label entropy below
    the threshold - combine with dns_nxdomain_burst and IOC matches.
    """

    name = "dga_suspected"

    def __init__(self, min_unique: int, entropy_min: float, window_min: int,
                 max_keys: int, sensor_id: str, sink_queue, index_for_alert,
                 allowlist_extra: list[str] | str | None = None):
        super().__init__(window_min * 60, max_keys, sensor_id, sink_queue,
                         index_for_alert)
        self.min_unique = min_unique
        self.entropy_min = entropy_min
        if isinstance(allowlist_extra, str):
            allowlist_extra = [x.strip() for x in allowlist_extra.split(",")
                               if x.strip()]
        self.allowlist = (DEFAULT_DGA_ALLOWLIST
                          | frozenset(allowlist_extra or []))
        self._buffer = WindowShim(self.window_seconds * 2, max_keys)

    @staticmethod
    def _label_entropy(domain: str) -> float:
        """Entropy of the longest non-TLD label (DGA noise lives there)."""
        labels = domain.rstrip(".").lower().split(".")
        if len(labels) < 2:
            return 0.0
        candidate = max(labels[:-1], key=len)
        return shannon_entropy(candidate)

    def _allowlisted(self, domain: str) -> bool:
        """Suffix match: 'www.google.com' is covered by 'google.com'."""
        return any(domain == d or domain.endswith("." + d)
                   for d in self.allowlist)

    def feed(self, ev: CommonEvent, index_name: str) -> None:
        if ev.event_type != "dns" or ev.source_ip is None:
            return
        q = (ev.dns_query or "").lower().rstrip(".")
        if not q or "." not in q:
            return
        # allowlisted domains stay buffered but flagged, so the alert can
        # honestly report how many common domains were skipped in-window
        self._buffer.add(ev.source_ip, ev.event_time.timestamp(),
                         (q, self._label_entropy(q),
                          self._allowlisted(q)))

    def sweep(self, now: float) -> None:
        if not self.flush_due(now):
            return
        cutoff = now - self.window_seconds
        for key in self._buffer.keys():
            buf = self._buffer.prune_key(key, now)
            if not buf:
                continue
            if buf[-1][0] > cutoff:
                continue
            self._buffer.drop_key(key)
            unique = {}
            skipped_allowlisted = 0
            for _, (q, ent, allow) in buf:
                if allow:
                    skipped_allowlisted += 1
                    continue
                unique.setdefault(q, ent)
            if len(unique) < self.min_unique:
                continue
            mean_entropy = sum(unique.values()) / len(unique)
            if mean_entropy < self.entropy_min:
                continue
            high = [f"{q} ({e:.2f})" for q, e in
                    sorted(unique.items(), key=lambda kv: -kv[1])
                    if e >= self.entropy_min][:8]
            first = datetime.fromtimestamp(buf[0][0], tz=timezone.utc)
            last = datetime.fromtimestamp(buf[-1][0], tz=timezone.utc)
            doc = build_alert_doc(
                alert_id=make_alert_id(self.name, key, first),
                alert_type=self.name, attack_phase="c2",
                title=f"Possible DGA queries from {key} "
                      f"({len(unique)} unique domains)",
                group_key=key, severity="medium",
                rationale=(
                    f"Host {key} queried {len(unique)} unique non-allowlisted "
                    f"domains with mean label entropy {mean_entropy:.2f} in "
                    f"the window. High-entropy unique domain bursts are "
                    f"consistent with algorithmically generated C2 domains, "
                    f"but CDN/BYOD apps and monitoring agents can look "
                    f"similar. Treat as a C2 candidate, not a verdict."),
                reasons=[
                    f"unique non-allowlisted domains: {len(unique)} >= "
                    f"{self.min_unique}",
                    f"mean label entropy {mean_entropy:.2f} >= "
                    f"{self.entropy_min}",
                    f"sample high-entropy queries: {', '.join(high[:4])}",
                    *(  # v0.12.9: transparency for the allowlist FP control
                        [f"allowlisted common domains skipped in window: "
                         f"{skipped_allowlisted}"]
                        if skipped_allowlisted else []),
                ],
                first_seen=first, last_seen=last, sensor_id=self.sensor_id,
                event_count=len(buf), source_count=1, destination_count=0,
                source_ip=key, destination_ip=None, transport="udp",
                protocol="dns", top_sources=[(key, len(buf))],
                top_destinations=[], top_rules=[],
                evidence=[],
                # v0.14.0: structured domain list for whitelist matching
                dns_domains=list(unique.keys()),
            )
            self.emit(doc)


class DnsTunnelingDetector(BaseRule):
    """Long-label / rare-qtype DNS queries (Phase 4 - C2 channel)."""

    name = "dns_tunneling_suspected"

    def __init__(self, min_count: int, min_label_len: int, window_min: int,
                 max_keys: int, sensor_id: str, sink_queue, index_for_alert):
        super().__init__(window_min * 60, max_keys, sensor_id, sink_queue,
                         index_for_alert)
        self.min_count = min_count
        self.min_label_len = min_label_len
        self._buffer = WindowShim(self.window_seconds * 2, max_keys)

    def feed(self, ev: CommonEvent, index_name: str) -> None:
        if ev.event_type != "dns" or ev.source_ip is None:
            return
        q = (ev.dns_query or "").lower().rstrip(".")
        if not q or "." not in q:
            return
        labels = q.split(".")
        max_label = max(len(l) for l in labels[:-1]) if len(labels) > 1 else 0
        qtype = (ev.dns_type or "").upper()
        flagged = (max_label >= self.min_label_len
                   or (qtype in TUNNEL_QTYPES
                       and max_label >= self.min_label_len // 2))
        if not flagged:
            return
        self._buffer.add(ev.source_ip, ev.event_time.timestamp(),
                         (q, max_label, qtype or "?"))

    def sweep(self, now: float) -> None:
        if not self.flush_due(now):
            return
        cutoff = now - self.window_seconds
        for key in self._buffer.keys():
            buf = self._buffer.prune_key(key, now)
            if not buf:
                continue
            if buf[-1][0] > cutoff:
                continue
            self._buffer.drop_key(key)
            if len(buf) < self.min_count:
                continue
            samples = [payload[0] for _, payload in buf][:6]
            max_label = max(payload[1] for _, payload in buf)
            qtypes = sorted({payload[2] for _, payload in buf})
            first = datetime.fromtimestamp(buf[0][0], tz=timezone.utc)
            last = datetime.fromtimestamp(buf[-1][0], tz=timezone.utc)
            doc = build_alert_doc(
                alert_id=make_alert_id(self.name, key, first),
                alert_type=self.name, attack_phase="c2",
                title=f"Possible DNS tunneling from {key} ({len(buf)} queries)",
                group_key=key, severity="high",
                rationale=(
                    f"Host {key} issued {len(buf)} DNS queries with long "
                    f"labels (max {max_label} chars) and rare record types "
                    f"({', '.join(qtypes)}). Long-label rare-qtype patterns "
                    f"are consistent with DNS tunneling (C2 or exfiltration "
                    f"channel) but also with security tools and CDNs using "
                    f"encoded subdomains. Verify before containment."),
                reasons=[
                    f"flagged queries: {len(buf)} >= {self.min_count}",
                    f"max subdomain label length: {max_label}",
                    f"query types: {', '.join(qtypes)}",
                    f"sample queries: {', '.join(samples[:4])}",
                ],
                first_seen=first, last_seen=last, sensor_id=self.sensor_id,
                event_count=len(buf), source_count=1, destination_count=0,
                source_ip=key, destination_ip=None, transport="udp",
                protocol="dns", top_sources=[(key, len(buf))],
                top_destinations=[], top_rules=[],
                evidence=[],
                # v0.14.0: structured domain list for whitelist matching
                dns_domains=samples,
            )
            self.emit(doc)


class InternalLateralDetector(BaseRule):
    """Internal-to-internal remote service access (Phase 5 - lateral)."""

    name = "internal_lateral_suspected"

    def __init__(self, ports: set[int], min_conns: int, cross_zone_min: int,
                 window_min: int, max_keys: int, sensor_id: str, sink_queue,
                 index_for_alert, zones: list[tuple[str, str]]):
        super().__init__(window_min * 60, max_keys, sensor_id, sink_queue,
                         index_for_alert)
        self.ports = ports
        self.min_conns = min_conns
        self.cross_zone_min = cross_zone_min
        self._is_internal = is_internal_check(zones)
        self._zone_nets: list[tuple[object, str]] = []
        try:
            import ipaddress as _ipa
            for cidr, zname in zones:
                try:
                    self._zone_nets.append(
                        (_ipa.ip_network(cidr, strict=False), zname))
                except ValueError:
                    continue
        except Exception:  # noqa: BLE001 - zone labels are best-effort
            self._zone_nets = []
        self._buffer = WindowShim(self.window_seconds * 2, max_keys)

    def feed(self, ev: CommonEvent, index_name: str) -> None:
        if ev.event_type != "conn":
            return
        src, dst = ev.source_ip, ev.destination_ip
        if not src or not dst or src == dst:
            return
        if not (self._is_internal(src) and self._is_internal(dst)):
            return
        if ev.destination_port not in self.ports:
            return
        key = f"{src}|{dst}|{ev.destination_port}"
        self._buffer.add(key, ev.event_time.timestamp(), None)

    def sweep(self, now: float) -> None:
        if not self.flush_due(now):
            return
        cutoff = now - self.window_seconds
        for key in self._buffer.keys():
            buf = self._buffer.prune_key(key, now)
            if not buf:
                continue
            if buf[-1][0] > cutoff:
                continue
            self._buffer.drop_key(key)
            conns = len(buf)
            src, dst, dport = key.split("|")
            cross_zone = (self._zone_of(src) != self._zone_of(dst))
            threshold = self.cross_zone_min if cross_zone else self.min_conns
            if conns < threshold:
                continue
            first = datetime.fromtimestamp(buf[0][0], tz=timezone.utc)
            last = datetime.fromtimestamp(buf[-1][0], tz=timezone.utc)
            doc = build_alert_doc(
                alert_id=make_alert_id(self.name, key, first),
                alert_type=self.name, attack_phase="lateral",
                title=f"Internal lateral access {src} -> {dst}:{dport}",
                group_key=key,
                severity="high" if cross_zone else "medium",
                rationale=(
                    f"{conns} connections from internal host {src} to "
                    f"internal host {dst} on remote-service port {dport}"
                    f"{' across zone boundaries' if cross_zone else ''} "
                    f"within the window. Remote-service patterns fit "
                    f"lateral movement but also legit admin traffic and "
                    f"file shares - validate against asset roles."),
                reasons=[
                    f"connections: {conns} >= threshold {threshold}",
                    f"remote service port: {dport}",
                    f"zone crossing: {'yes' if cross_zone else 'no'}",
                ],
                first_seen=first, last_seen=last, sensor_id=self.sensor_id,
                event_count=conns, source_count=1, destination_count=1,
                source_ip=src, destination_ip=dst, transport="tcp",
                protocol=None, top_sources=[(src, conns)],
                top_destinations=[(dst, conns)], top_rules=[],
                evidence=[],
            )
            self.emit(doc)

    def _zone_of(self, ip: str) -> str:
        """Best-effort zone label from configured CIDRs (for cross-zone
        heuristics only - never used as a security boundary)."""
        try:
            import ipaddress as _ipa
            addr = _ipa.ip_address(ip)
        except ValueError:
            return "unzoned"
        for net, zname in self._zone_nets:
            if addr in net:
                return zname
        return "unzoned"


class LargeOutboundDetector(BaseRule):
    """Large internal->external byte volume (Phase 6 - exfil candidate)."""

    name = "large_outbound_transfer"

    def __init__(self, min_bytes: int, window_min: int, max_keys: int,
                 sensor_id: str, sink_queue, index_for_alert,
                 zones: list[tuple[str, str]]):
        super().__init__(window_min * 60, max_keys, sensor_id, sink_queue,
                         index_for_alert)
        self.min_bytes = min_bytes
        self._is_internal = is_internal_check(zones)
        self._buffer = WindowShim(self.window_seconds * 2, max_keys)

    def feed(self, ev: CommonEvent, index_name: str) -> None:
        if ev.event_type != "conn":
            return
        src, dst = ev.source_ip, ev.destination_ip
        if not src or not dst:
            return
        if not (self._is_internal(src) and not self._is_internal(dst)):
            return
        # v0.13.0: count bytes the host SENT only (source_bytes/orig_bytes).
        # The old network_bytes (ob+rb) flagged huge DOWNLOADS as exfil.
        sent = ev.source_bytes
        if sent is None or sent <= 0:
            return
        self._buffer.add(f"{src}|{dst}", ev.event_time.timestamp(), sent)

    def sweep(self, now: float) -> None:
        if not self.flush_due(now):
            return
        cutoff = now - self.window_seconds
        for key in self._buffer.keys():
            buf = self._buffer.prune_key(key, now)
            if not buf:
                continue
            if buf[-1][0] > cutoff:
                continue
            self._buffer.drop_key(key)
            total = sum(b for _, b in buf)
            if total < self.min_bytes:
                continue
            src, dst = key.split("|")
            first = datetime.fromtimestamp(buf[0][0], tz=timezone.utc)
            last = datetime.fromtimestamp(buf[-1][0], tz=timezone.utc)
            gb = total / 1_000_000_000
            doc = build_alert_doc(
                alert_id=make_alert_id(self.name, key, first),
                alert_type=self.name, attack_phase="impact",
                title=f"Large outbound transfer {src} -> {dst} "
                      f"({gb:.2f} GB)",
                group_key=key, severity="medium",
                rationale=(
                    f"Internal host {src} sent {gb:.2f} GB to external "
                    f"{dst} across {len(buf)} connections within the "
                    f"window. Volume alone does not prove exfiltration - "
                    f"backups, replication and cloud sync produce similar "
                    f"patterns. Correlate with the attack chain and asset "
                    f"criticality before escalating."),
                reasons=[
                    f"total outbound bytes: {total} "
                    f"(threshold {self.min_bytes})",
                    f"connections: {len(buf)}",
                    f"direction: {src} (internal) -> {dst} (external)",
                ],
                first_seen=first, last_seen=last, sensor_id=self.sensor_id,
                event_count=len(buf), source_count=1, destination_count=1,
                source_ip=src, destination_ip=dst, transport="tcp",
                protocol=None, top_sources=[(src, total)],
                top_destinations=[(dst, total)], top_rules=[],
                evidence=[],
            )
            self.emit(doc)


class WindowShim:
    """Minimal LRU + time-window buffer (same contract as WindowBuffer
    but stores arbitrary payloads without extra imports at module load)."""

    def __init__(self, window_seconds: int, max_keys: int):
        from collections import OrderedDict, deque
        self._OrderedDict = OrderedDict
        self._deque = deque
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._buffers = OrderedDict()

    def add(self, key: str, ts_epoch: float, payload) -> None:
        buf = self._buffers.get(key)
        if buf is None:
            buf = self._deque()
            self._buffers[key] = buf
        buf.append((ts_epoch, payload))
        self._buffers.move_to_end(key)
        self._prune(key, buf)
        while len(self._buffers) > self.max_keys:
            self._buffers.popitem(last=False)

    def prune_key(self, key: str, now: float | None = None):
        buf = self._buffers.get(key)
        if buf is None:
            return None
        self._prune(key, buf, now)
        return buf

    def drop_key(self, key: str) -> None:
        self._buffers.pop(key, None)

    def keys(self) -> list[str]:
        return list(self._buffers.keys())

    def _prune(self, key: str, buf, now: float | None = None) -> None:
        cutoff = (now if now is not None else time.time()) - self.window_seconds
        while buf and buf[0][0] < cutoff:
            buf.popleft()
        if not buf:
            self._buffers.pop(key, None)
