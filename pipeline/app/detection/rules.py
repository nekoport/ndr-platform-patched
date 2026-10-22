"""Baseline detection heuristics - Phase 2 (doc sections 8.1, 8.7).

Scope and guardrails:
  * Explainable: every alert carries rationale + reasons + evidence refs.
  * No overclaim: output is "suspicious", never "confirmed compromise".
  * Confidence is explicitly labeled heuristic and uncalibrated.
  * Aggregation groups many REAL events; deduplication happens upstream.

Rules:
  1. suricata_alert_group  - group repeated signature alerts (same rule+src)
  2. portscan_suspected    - many unique ports/hosts touched by one source
  3. dns_nxdomain_burst    - NXDOMAIN ratio burst (weak DGA signal)
  4. beaconing_possible    - periodic low-jitter connection pattern
"""

from __future__ import annotations

import re
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from statistics import fmean

from app.models import CommonEvent
from app.detection.taxonomy import (phase_for_ioc, phase_for_rule,
                                    phase_for_suricata_category)
from app.detection.killchain import (STAGE_LABELS, classify_ioc,
                                     classify_rule, classify_suricata)
from app.detection.windows import WindowBuffer, jitter

ALERT_NS = uuid.uuid5(uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"), "ndr/alert/v1")

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
SEVERITY_SCORE = {"critical": 95, "high": 75, "medium": 50, "low": 25, "informational": 10}

# ---------------------------------------------------------------- v0.10 attack result
# Alert-level attack-result verdict (same vocabulary as the incident-level
# outcome labels; `strong_success` is reserved for the correlation engine).
# Determination at detection time, from the evidence the alert itself carries:
#   suspected_success - a SERVER-REACTION signature fired (ET/GPL
#     ATTACK_RESPONSE family, classtype attack-response): the target reacted
#     in a way consistent with the action having taken effect.
#   attempted - exploit/attack-class signature observed; the signature alone
#     proves the attempt, never that it succeeded.
#   indeterminate - recon/scan/policy signatures and all behavioral rules:
#     the activity itself may be benign, so no attack outcome is claimed.
_SUCCESS_CATEGORIES = ("attack-response", "attack_response")
_MALWARE_CATEGORIES = ("trojan", "malware", "botnet", "c2", "virus", "worm")
_RECON_CATEGORIES = ("recon", "scan")
_ATTEMPT_CATEGORIES = ("attempted", "exploit", "web-application", "attack")
_INDETERMINATE_CATEGORIES = ("policy", "activity", "misc", "bad-unknown",
                             "unknown", "default")
_SUCCESS_SIGNATURES = ("ATTACK_RESPONSE", "ATTACK-RESPONSE")


# ---------------------------------------------------------------- v0.16.0
# requirement 3: status keberhasilan anomali dengan kosakata tender
# (Compromise / Attempt / Failure / Attack Successful) selain kosakata
# internal v0.10 (suspected_success / attempted / indeterminate).
#   attempt            - bukti percobaan saja (signature kelas exploit)
#   failure            - server MENOLAK: bukti respons HTTP 4xx (auth/404)
#                        atau kelas policy yang jelas-ditolak
#   attack_successful  - server BEREAKSI: signature server-reaction
#                        (ATTACK_RESPONSE) atau respons HTTP 2xx/3xx pada
#                        kelas serangan. BUKAN klaim kompromi.
#   compromise         - TIDAK pernah diberikan di level deteksi.
#                        Kompromi adalah klaim insiden (correlation engine
#                        strong_success + TI C2) - lihat /api/incidents
#                        tender_status. No-overclaim.
_ATTACK_STATUS_LABELS = {
    "attempt": "Attempt",
    "failure": "Failure",
    "attack_successful": "Attack Successful",
    "compromise": "Compromise",
    "indeterminate": "Indeterminate",
}

def attack_status_for(alert_type: str, suricata_category: str | None = None,
                      top_signature: str | None = None,
                      http_statuses: list[int] | None = None) -> str:
    """Tender-vocabulary status (v0.16.0, requirement 3).

    Menggabungkan verdict v0.10 (kategori signature) dengan bukti respons
    HTTP yang terbawa event alert (EVE alert memuat blok http bila app-layer
    tercatat). Failure hanya dari bukti penolakan eksplisit; kompromi tidak
    pernah diklaim di level alert.
    """
    outcome = outcome_for_alert(alert_type, suricata_category, top_signature)
    statuses = [int(s) for s in (http_statuses or []) if s]
    # 1. bukti reaksi server dari respons HTTP menang lebih dulu
    if statuses:
        if any(200 <= s < 400 for s in statuses):
            cat = (suricata_category or "").lower()
            sig = (top_signature or "").upper()
            if (any(c in cat for c in _SUCCESS_CATEGORIES)
                    or any(s in sig for s in _SUCCESS_SIGNATURES)
                    or any(c in cat for c in _MALWARE_CATEGORIES)):
                return "attack_successful"
            return "attempt"
        if all(s >= 400 for s in statuses):
            return "failure"
    # 2. tanpa respons HTTP: peta dari verdict v0.10
    return {"suspected_success": "attack_successful",
            "attempted": "attempt",
            "indeterminate": "indeterminate"}.get(outcome, "indeterminate")


def detection_engine_for(alert_type: str) -> str:
    """requirement 1: label asal deteksi (signature/behaviour/intel).

    Rules custom Suricata berlabel 'proprietary' di Rules Manager (API tahu
    sumbernya); di level alert pemisahan utamanya signature vs behaviour
    vs intel-match.
    """
    if alert_type == "suricata_alert_group":
        return "signature"
    if alert_type == "ioc_match":
        return "intel"
    return "behaviour"


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def cve_for(top_signature: str | None,
            reasons: list[str] | None = None) -> list[str]:
    """requirement 10: ekstrak CVE dari nama signature/reason (ET
    menuliskan CVE pada msg rule, mis. '... CVE-2021-44228 ...').
    Dedup + urut stabil; field keyword agar bisa difilter/agregasi.
    """
    found: list[str] = []
    for text in [top_signature or "", *(reasons or [])]:
        for m in _CVE_RE.findall(text or ""):
            up = m.upper()
            if up not in found:
                found.append(up)
    return found[:8]


def explanation_for(*, title: str, attack_status: str, stage: str,
                    stage_label: str, mitre: list[dict], source_ip: str | None,
                    destination_ip: str | None, protocol: str | None,
                    event_count: int, cve: list[str]) -> str:
    """requirement 10: penjelasan anomali satu kalimat terstruktur.

    Human-readable, deterministic (template - bukan LLM), dan jujur:
    selalu menyatakan status sebagai bukti-level-jaringan. Disimpan
    'index':false - tidak untuk pencarian, hanya tampilan detail.
    """
    tech = ", ".join(sorted({f"{m.get('technique_id')} {m.get('technique')}"
                             for m in (mitre or [])
                             if isinstance(m, dict) and m.get("technique_id")}))
    path = f"{source_ip or '?'} -> {destination_ip or '?'}"
    if protocol:
        path = f"{path} ({protocol})"
    parts = [
        f"Anomali '{title}' terdeteksi pada {path} "
        f"dari {event_count} event.",
        f"Tahapan: {stage_label} ({stage}).",
    ]
    if tech:
        parts.append(f"Teknik MITRE ATT&CK: {tech}.")
    parts.append(
        f"Status keberhasilan: {_ATTACK_STATUS_LABELS.get(attack_status, attack_status)} "
        f"- kesimpulan berbasis bukti jaringan, bukan verifikasi endpoint.")
    if cve:
        parts.append(f"Referensi kerentanan: {', '.join(cve)}.")
    return " ".join(parts)


def outcome_for_alert(alert_type: str, suricata_category: str | None = None,
                      top_signature: str | None = None) -> str:
    """Attack-result verdict for a single alert (v0.10).

    Deliberately conservative: only a server-reaction signature upgrades an
    alert past `attempted`; recon/scan and everything behavioral stay
    `indeterminate`.
    """
    if alert_type == "suricata_alert_group":
        cat = (suricata_category or "").lower()
        sig = (top_signature or "").upper()
        # 1. server reaction observed -> the action likely took effect
        if any(c in cat for c in _SUCCESS_CATEGORIES) \
                or any(s in sig for s in _SUCCESS_SIGNATURES):
            return "suspected_success"
        # 2. known-malware activity (trojan/C2 signatures) -> attempted
        if any(c in cat for c in _MALWARE_CATEGORIES):
            return "attempted"
        # 3. recon/scan activity may be perfectly benign -> indeterminate
        #    (checked BEFORE "attempted": ET classtypes like
        #    'attempted-recon' describe recon attempts)
        if any(c in cat for c in _RECON_CATEGORIES):
            return "indeterminate"
        # 4. exploit/attack-class signatures prove the attempt only
        if any(c in cat for c in _ATTEMPT_CATEGORIES):
            return "attempted"
        # 5. policy/other-noise classes -> indeterminate
        if any(c in cat for c in _INDETERMINATE_CATEGORIES) or not cat:
            return "indeterminate"
        # known classtype outside the sets: treat as attempted (signature
        # fired on attack traffic class)
        return "attempted"
    # behavioral rules (portscan/nxdomain/beaconing) and ioc_match: the
    # activity may be benign, so no attack outcome is claimed
    return "indeterminate"


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def make_alert_id(alert_type: str, group_key: str, window_start: datetime) -> str:
    """Stable alert id per window -> replay-safe (same doc id on re-ingest)."""
    window_tag = window_start.strftime("%Y%m%dT%H%M")
    return str(uuid.uuid5(ALERT_NS, f"{alert_type}|{group_key}|{window_tag}"))


def build_alert_doc(*, alert_id: str, alert_type: str, title: str, group_key: str,
                    severity: str, rationale: str, reasons: list[str],
                    first_seen: datetime, last_seen: datetime, sensor_id: str,
                    event_count: int, source_count: int, destination_count: int,
                    source_ip: str | None, destination_ip: str | None,
                    transport: str | None, protocol: str | None,
                    top_sources: list[tuple[str, int]],
                    top_destinations: list[tuple[str, int]],
                    top_rules: list[tuple[str, int]],
                    evidence: list[dict],
                    matched_iocs: list[dict] | None = None,
                    attack_phase: str | None = None,
                    suricata_category: str | None = None,
                    ioc_type: str | None = None,
                    dns_domains: list[str] | None = None,
                    http_statuses: list[int] | None = None,
                    dga_score: float | None = None,
                    campaign: str | None = None,
                    force_status: str | None = None) -> dict:
    now = datetime.now(timezone.utc)
    # Dual-framework classification (doc 11): kill-chain stage + MITRE
    # ATT&CK techniques computed once and carried on the alert doc.
    if alert_type == "suricata_alert_group":
        kc_stage, kc_attck = classify_suricata(
            suricata_category,
            top_rules[0][0] if top_rules else None)
        kc_basis = (f"suricata category "
                    f"'{suricata_category or 'unknown'}'")
    elif alert_type == "ioc_match":
        kc_stage, kc_attck = classify_ioc(ioc_type)
        kc_basis = f"ioc type '{ioc_type or 'unknown'}'"
    else:
        kc_stage, kc_attck = classify_rule(alert_type)
        kc_basis = f"detection rule '{alert_type}'"
    doc = {
        "alert_id": alert_id,
        "alert_type": alert_type,
        "title": title,
        "group_key": group_key,
        "severity": severity,
        "severity_score": SEVERITY_SCORE.get(severity, 10),
        "status": "new",
        "assignee": None,
        "confidence": "heuristic-uncalibrated",
        "attack_phase": attack_phase or phase_for_rule(alert_type),
        "kill_chain": {
            "stage": kc_stage,
            "stage_label": STAGE_LABELS.get(kc_stage, kc_stage),
            "basis": kc_basis,
            "reason": f"{kc_basis} classified as "
                      f"{STAGE_LABELS.get(kc_stage, kc_stage)} by "
                      f"rule/behavior mapping (doc 11)",
        },
        "mitre": kc_attck,
        "rationale": rationale,
        "reasons": reasons[:12],
        "event_count": event_count,
        "source_count": source_count,
        "destination_count": destination_count,
        # v0.12.5: the API always time-filters + sorts on @timestamp;
        # alert docs without it died with "No mapping found for
        # [@timestamp] in order to sort on". Same pattern as the
        # ioc_match builder below.
        "@timestamp": _iso(last_seen),
        "first_seen": _iso(first_seen),
        "last_seen": _iso(last_seen),
        "created_at": _iso(now),
        "updated_at": _iso(now),
        "updated_by": "ndr-pipeline",
        "sensor_id": sensor_id,
        "source": {"ip": source_ip} if source_ip else None,
        "destination": {"ip": destination_ip} if destination_ip else None,
        "network": {"transport": transport, "protocol": protocol},
        "top_sources": [{"ip": ip, "count": c} for ip, c in top_sources[:10]],
        "top_destinations": [{"ip": ip, "count": c} for ip, c in top_destinations[:10]],
        "top_rules": [
            # v0.16.0: entry 2- atau 3-elemen (signature, count[, sid]) -
            # signature_id diperlukan agregasi hit per rule (req 14/15).
            {"signature": entry[0], "count": entry[1],
             **({"signature_id": str(entry[2])}
                if len(entry) > 2 and entry[2] else {})}
            for entry in top_rules[:10]
        ],
        "evidence": evidence[:10],
        "related_entities": sorted({ip for ip in
                                    [source_ip, destination_ip] if ip}),
        # v0.10: attack-result verdict (see outcome_for_alert)
        "outcome": outcome_for_alert(alert_type, suricata_category,
                                     top_rules[0][0] if top_rules else None),
    }
    # ---------------------------------------------------------------- v0.16.0
    # requirements 1/3/10/18: label mesin deteksi, status keberhasilan
    # (kosakata tender), CVE, penjelasan, skor DGA, dan campaign watchlist.
    _top_sig = top_rules[0][0] if top_rules else None
    # v0.16.0: detector tertentu (mis. auth_bruteforce) punya makna status
    # yang jelas dari buktinya sendiri - boleh force, selain itu hitung.
    attack_status = force_status or attack_status_for(
        alert_type, suricata_category, _top_sig, http_statuses)
    cves = cve_for(_top_sig, reasons)
    doc["attack_status"] = attack_status
    doc["detection_engine"] = detection_engine_for(alert_type)
    doc["explanation"] = explanation_for(
        title=title, attack_status=attack_status, stage=kc_stage,
        stage_label=STAGE_LABELS.get(kc_stage, kc_stage), mitre=kc_attck,
        source_ip=source_ip, destination_ip=destination_ip,
        protocol=protocol, event_count=event_count, cve=cves)
    # explanation TIDAK untuk pencarian (diet indeks - pelajaran §19);
    # template menandai index:false.
    if cves:
        doc["cve"] = cves
    if dga_score is not None:
        doc["dga_score"] = round(float(dga_score), 1)
    if campaign:
        doc["campaign"] = campaign
    if matched_iocs:
        doc["matched_iocs"] = matched_iocs[:5]
    # v0.14.0: structured sampled domains (DGA/NXDOMAIN/tunneling) so
    # domain-entity whitelist entries can match on the alert doc itself
    # (mapping: bootstrap ALERT_FIELDS dns_domains keyword).
    if dns_domains:
        doc["dns_domains"] = sorted({d.lower().strip() for d in dns_domains
                                     if d})[:10]
    return doc


def _evidence_refs(events: list[CommonEvent], index_name: str) -> list[dict]:
    refs = []
    for ev in events[:10]:
        refs.append({
            "event_id": ev.event_id,
            "index": index_name,
            "@timestamp": _iso(ev.event_time),
        })
    return refs


class BaseRule:
    """Common plumbing: window flush cadence + key lifetime management."""

    name = "base"

    def __init__(self, window_seconds: int, max_keys: int, sensor_id: str,
                 sink_queue, index_for_alert: str):
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self.sensor_id = sensor_id
        self.sink_queue = sink_queue
        self.index_for_alert = index_for_alert
        self.last_flush = time.time()
        # v0.14.0 alert whitelist (allowlist) - injected by the engine:
        #   allowlist_check(doc) -> ("L0"|"L1", entry_id) | None
        #   allowlist_hit(entry_id) -> counts one suppressed/tagged alert
        # Both are optional; when unset, emit() behaves exactly as before.
        self.allowlist_check = None
        self.allowlist_hit = None

    def sweep(self, now: float) -> None:
        raise NotImplementedError

    def flush_due(self, now: float, interval: float = 30.0) -> bool:
        if now - self.last_flush >= interval:
            self.last_flush = now
            return True
        return False

    def emit(self, doc: dict) -> None:
        # v0.14.0 whitelist gate (BEFORE indexing; story stays intact):
        #   L0 -> the alert is NOT indexed (noise control), the doc still
        #         reaches the recon fan-out below so correlation keeps its
        #         signal, tagged suppressed=True for story provenance.
        #   L1 -> the alert IS indexed but tagged; the UI keeps it out of
        #         the default triage queue (full record preserved).
        check = self.allowlist_check
        if check is not None:
            verdict = None
            try:
                verdict = check(doc)
            except Exception:  # noqa: BLE001 - whitelist must not kill detection
                verdict = None
            if verdict is not None:
                layer, entry_id = verdict
                doc["suppressed"] = True
                doc["suppressed_by"] = int(entry_id)
                hit = self.allowlist_hit
                if hit is not None:
                    try:
                        hit(int(entry_id))
                    except Exception:  # noqa: BLE001
                        pass
                if layer == "L0":
                    hook = getattr(self, "recon_sink", None)
                    if hook is not None:
                        try:
                            hook(doc)
                        except Exception:  # noqa: BLE001
                            pass
                    return  # do NOT index - this is the whole point of L0
        index = self.index_for_alert(doc["last_seen"])
        self.sink_queue.put((index, doc["alert_id"], doc))
        # Fan out to the attack reconstruction engine (Phase 4).
        # Non-blocking and exception-safe by contract (set via
        # DetectionEngine wiring).
        hook = getattr(self, "recon_sink", None)
        if hook is not None:
            try:
                hook(doc)
            except Exception:  # noqa: BLE001 - recon must not break detection
                pass


class SuricataAlertGrouper(BaseRule):
    """Group repeated Suricata signature alerts for the same source.

    Key = signature_id + source_ip (NOT signature alone - doc 8.1).
    Flush after `window_seconds` of inactivity.
    """

    name = "suricata_alert_group"

    def __init__(self, window_seconds: int, max_keys: int, sensor_id: str,
                 sink_queue, index_for_alert: str):
        super().__init__(window_seconds, max_keys, sensor_id, sink_queue, index_for_alert)
        self._buffer = WindowBuffer(self.window_seconds * 2, max_keys)

    def feed(self, ev: CommonEvent, index_name: str) -> None:
        key = f"{ev.signature_id or 'unknown'}|{ev.source_ip or 'unknown'}"
        ts = ev.event_time.timestamp()
        self._buffer.add(key, ts, (ev, index_name))

    def sweep(self, now: float) -> None:
        if not self.flush_due(now):
            return
        cutoff = now - self.window_seconds
        for key in self._buffer.keys():
            buf = self._buffer.prune_key(key, now)
            if not buf:
                continue
            last_ts = buf[-1][0]
            if last_ts > cutoff:
                continue  # still active
            events = [payload[0] for _, payload in buf]
            indexes = {payload[1] for _, payload in buf}
            self._buffer.drop_key(key)
            self._emit(key, events, indexes)

    def _emit(self, key: str, events: list[CommonEvent], indexes: set[str]) -> None:
        sig_ids = {e.signature_id for e in events if e.signature_id}
        sig_names = {e.alert_signature for e in events if e.alert_signature}
        src_ips = Counter(e.source_ip for e in events if e.source_ip)
        dst_ips = Counter(e.destination_ip for e in events if e.destination_ip)
        severities = [e.severity for e in events if e.severity]
        top_severity = max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0),
                           default="medium")
        first = events[0].event_time
        last = events[-1].event_time
        sig_label = next(iter(sig_names), "unknown signature")
        sig_id = next(iter(sig_ids), "")
        suricata_cat = next(iter({e.alert_category for e in events
                                  if e.alert_category}), None)
        # v0.16.0: bukti respons HTTP (EVE alert membawa blok http bila
        # app-layer tercatat) untuk attack_status req 3, campaign req 18.
        statuses = [e.http_status for e in events if e.http_status]
        campaign = next((e.campaign for e in events if e.campaign), None)
        window_start = first

        alert_id = make_alert_id(self.name, key, window_start)
        reasons = [
            f"{len(events)} alert events with the same signature_id "
            f"{sig_id or 'n/a'} from source {next(iter(src_ips), 'unknown')}",
            f"window: {first.isoformat()} .. {last.isoformat()}",
            f"severity: highest observed = {top_severity}",
        ]
        doc = build_alert_doc(
            alert_id=alert_id, alert_type=self.name,
            attack_phase=phase_for_suricata_category(suricata_cat, sig_label),
            suricata_category=suricata_cat,
            title=f"Suricata: {sig_label}",
            group_key=key, severity=top_severity,
            rationale=(
                f"Suricata raised {len(events)} events for signature "
                f"'{sig_label}' from the same source within the grouping "
                f"window. Signature alert indicates an attempt was observed; "
                f"it does not by itself prove exploitation succeeded."),
            reasons=reasons, first_seen=first, last_seen=last,
            sensor_id=self.sensor_id,
            event_count=len(events),
            source_count=len(src_ips), destination_count=len(dst_ips),
            source_ip=next(iter(src_ips), None),
            destination_ip=dst_ips.most_common(1)[0][0] if dst_ips else None,
            transport=events[0].transport, protocol=events[0].protocol,
            top_sources=src_ips.most_common(),
            top_destinations=dst_ips.most_common(),
            # v0.16.0: sid disertakan utk statistik hit per rule (req 14/15)
            top_rules=[(sig_label, len(events), sig_id)] if sig_label else [],
            evidence=_evidence_refs(events, next(iter(indexes), "ndr-suricata")),
            http_statuses=statuses, campaign=campaign,
        )
        self.emit(doc)


class PortscanDetector(BaseRule):
    """Many unique destination ports/hosts touched by one source."""

    name = "portscan_suspected"

    def __init__(self, unique_ports: int, unique_hosts: int, window_min: int,
                 max_keys: int, sensor_id: str, sink_queue, index_for_alert: str):
        super().__init__(window_min * 60, max_keys, sensor_id, sink_queue, index_for_alert)
        self.unique_ports = unique_ports
        self.unique_hosts = unique_hosts
        self._buffer = WindowBuffer(self.window_seconds * 2, max_keys)

    def feed(self, ev: CommonEvent, index_name: str) -> None:
        if ev.source_ip is None:
            return
        key = ev.source_ip
        payload = (ev.destination_port, ev.destination_ip)
        self._buffer.add(key, ev.event_time.timestamp(), payload)

    def sweep(self, now: float) -> None:
        if not self.flush_due(now):
            return
        cutoff = now - self.window_seconds
        for key in self._buffer.keys():
            buf = self._buffer.prune_key(key, now)
            if not buf:
                continue
            last_ts = buf[-1][0]
            if last_ts > cutoff:
                continue
            self._buffer.drop_key(key)
            ports = {p for _, (p, _) in buf if p is not None}
            hosts = {h for _, (_, h) in buf if h is not None}
            reasons = [
                f"unique destination ports in window: {len(ports)} "
                f"(threshold {self.unique_ports})",
                f"unique destination hosts in window: {len(hosts)} "
                f"(threshold {self.unique_hosts})",
            ]
            if len(ports) < self.unique_ports and len(hosts) < self.unique_hosts:
                continue
            first = datetime.fromtimestamp(buf[0][0], tz=timezone.utc)
            last = datetime.fromtimestamp(last_ts, tz=timezone.utc)
            alert_id = make_alert_id(self.name, key, first)
            doc = build_alert_doc(
                alert_id=alert_id, alert_type=self.name,
                attack_phase="recon",
                title=f"Port scan suspected from {key}",
                group_key=key, severity="medium",
                rationale=(
                    f"Source {key} touched {len(ports)} unique ports on "
                    f"{len(hosts)} hosts within the window. This pattern is "
                    f"consistent with reconnaissance; benign scanners and "
                    f"inventory tools can also trigger it - verify before "
                    f"escalation."),
                reasons=reasons, first_seen=first, last_seen=last,
                sensor_id=self.sensor_id,
                event_count=len(buf), source_count=1,
                destination_count=len(hosts), source_ip=key,
                destination_ip=None, transport=None, protocol=None,
                top_sources=[(key, len(buf))],
                top_destinations=Counter(h for _, (_, h) in buf if h).most_common(),
                top_rules=[],
                evidence=[],
            )
            self.emit(doc)


class NXDomainBurstDetector(BaseRule):
    """High NXDOMAIN ratio from one source - weak DGA signal (doc 8.7)."""

    name = "dns_nxdomain_burst"

    def __init__(self, min_count: int, ratio: float, window_min: int,
                 max_keys: int, sensor_id: str, sink_queue, index_for_alert: str):
        super().__init__(window_min * 60, max_keys, sensor_id, sink_queue, index_for_alert)
        self.min_count = min_count
        self.ratio = ratio
        self._buffer = WindowBuffer(self.window_seconds * 2, max_keys)

    def feed(self, ev: CommonEvent, index_name: str) -> None:
        if ev.source_ip is None:
            return
        nxdomain = (ev.dns_rcode or "").upper() == "NXDOMAIN"
        key = ev.source_ip
        self._buffer.add(key, ev.event_time.timestamp(),
                         (nxdomain, ev.dns_query))

    def sweep(self, now: float) -> None:
        if not self.flush_due(now):
            return
        cutoff = now - self.window_seconds
        for key in self._buffer.keys():
            buf = self._buffer.prune_key(key, now)
            if not buf:
                continue
            last_ts = buf[-1][0]
            if last_ts > cutoff:
                continue
            self._buffer.drop_key(key)
            total = len(buf)
            # buf entries: (ts, (nxdomain, query))
            nx = sum(1 for _, (nx_flag, _) in buf if nx_flag)
            if total < self.min_count:
                continue
            ratio = nx / total
            if ratio < self.ratio:
                continue
            queries = [q for _, (_, q) in buf if q][:20]
            first = datetime.fromtimestamp(buf[0][0], tz=timezone.utc)
            last = datetime.fromtimestamp(last_ts, tz=timezone.utc)
            alert_id = make_alert_id(self.name, key, first)
            doc = build_alert_doc(
                alert_id=alert_id, alert_type=self.name,
                attack_phase="recon",
                title=f"NXDOMAIN burst from {key}",
                group_key=key, severity="low",
                rationale=(
                    f"Source {key} produced {nx}/{total} NXDOMAIN DNS "
                    f"responses (ratio {ratio:.2f}) within the window. "
                    f"High NXDOMAIN volume is a weak DGA indicator; "
                    f"misconfigured resolvers and applications can also "
                    f"cause it. Score is heuristic and uncalibrated."),
                reasons=[
                    f"NXDOMAIN ratio {ratio:.2f} >= threshold {self.ratio}",
                    f"minimum count {total} >= threshold {self.min_count}",
                    f"sample queries: {', '.join(q for q in queries[:5])}",
                ],
                first_seen=first, last_seen=last,
                sensor_id=self.sensor_id,
                event_count=total, source_count=1, destination_count=0,
                source_ip=key, destination_ip=None, transport="udp",
                protocol="dns", top_sources=[(key, total)],
                top_destinations=[], top_rules=[], evidence=[],
                dns_domains=[q for _, (_, q) in buf if q],
            )
            self.emit(doc)


class IocMatchDetector(BaseRule):
    """Threat-intel IOC match (doc section 9, Phase 3).

    Groups events that touched the same IOC from the same source within
    the window. Output is explicitly labeled contextual evidence - an
    IOC match NEVER proves compromise by itself (doc 9.2).
    """

    name = "ioc_match"

    CONFIDENCE_SEVERITY = {"high": "high", "medium": "medium", "low": "low"}

    def __init__(self, window_min: int, max_keys: int, sensor_id: str,
                 sink_queue, index_for_alert: str):
        super().__init__(window_min * 60, max_keys, sensor_id, sink_queue,
                         index_for_alert)
        self._buffer = WindowBuffer(self.window_seconds * 2, max_keys)

    def feed(self, ev: CommonEvent, index_name: str) -> None:
        if not ev.matched_ioc or ev.source_ip is None:
            return
        key = ev.source_ip
        for m in ev.matched_ioc[:3]:
            self._buffer.add(f"{key}|{m['ioc_type']}|{m['ioc_value']}",
                             ev.event_time.timestamp(), (m, ev, index_name))

    def sweep(self, now: float) -> None:
        if not self.flush_due(now):
            return
        cutoff = now - self.window_seconds
        for key in self._buffer.keys():
            buf = self._buffer.prune_key(key, now)
            if not buf:
                continue
            last_ts = buf[-1][0]
            if last_ts > cutoff:
                continue
            self._buffer.drop_key(key)
            first_meta = buf[0][1][0]
            ioc_type, ioc_value = first_meta["ioc_type"], first_meta["ioc_value"]
            severity = self.CONFIDENCE_SEVERITY.get(
                first_meta.get("confidence", "medium"), "medium")
            events = [payload[1] for _, payload in buf]
            indexes = {payload[2] for _, payload in buf}
            fields = sorted({payload[0].get("match_field", "?")
                             for _, payload in buf})
            first = datetime.fromtimestamp(buf[0][0], tz=timezone.utc)
            last = datetime.fromtimestamp(last_ts, tz=timezone.utc)
            alert_id = make_alert_id(self.name, key, first)
            doc = build_alert_doc(
                alert_id=alert_id, alert_type=self.name,
                attack_phase=phase_for_ioc(ioc_type),
                ioc_type=ioc_type,
                title=f"IOC match: {ioc_value} ({ioc_type})",
                group_key=key, severity=severity,
                rationale=(
                    f"{len(events)} events from {key} matched threat "
                    f"intelligence IOC '{ioc_value}' ({ioc_type}) observed "
                    f"on {', '.join(fields)}. IOC matches are contextual "
                    f"evidence collected from external feeds with an "
                    f"expiry policy - they support investigation but do "
                    f"NOT prove host compromise (doc section 9.2)."),
                reasons=[
                    f"ioc: {ioc_type} {ioc_value}",
                    f"feed confidence: {first_meta.get('confidence', 'medium')} "
                    f"(uncalibrated)",
                    f"matched fields: {', '.join(fields)}",
                    f"events in window: {len(events)}",
                ],
                first_seen=first, last_seen=last,
                sensor_id=self.sensor_id,
                event_count=len(events), source_count=1,
                destination_count=len({e.destination_ip for e in events
                                       if e.destination_ip}),
                source_ip=events[0].source_ip,
                destination_ip=first_meta.get("match_field") == "destination"
                and events[0].destination_ip or None,
                transport=events[0].transport, protocol=events[0].protocol,
                top_sources=[(events[0].source_ip or "unknown", len(events))],
                top_destinations=[],
                top_rules=[(f"ioc:{ioc_value}", len(events))],
                evidence=_evidence_refs(events, next(iter(indexes),
                                                     "ndr-zeek-conn")),
                matched_iocs=[first_meta],
            )
            self.emit(doc)


class BeaconingDetector(BaseRule):
    """Periodic, low-jitter connections between one source/dest/port pair."""

    name = "beaconing_possible"

    def __init__(self, min_connections: int, interval_min_sec: int,
                 interval_max_sec: int, jitter_max: float, window_min: int,
                 max_keys: int, sensor_id: str, sink_queue, index_for_alert: str):
        super().__init__(window_min * 60, max_keys, sensor_id, sink_queue, index_for_alert)
        self.min_connections = min_connections
        self.interval_min = interval_min_sec
        self.interval_max = interval_max_sec
        self.jitter_max = jitter_max
        self._buffer = WindowBuffer(self.window_seconds * 2, max_keys)

    def feed(self, ev: CommonEvent, index_name: str) -> None:
        if ev.source_ip is None or ev.destination_ip is None:
            return
        key = f"{ev.source_ip}|{ev.destination_ip}|{ev.destination_port or 0}"
        self._buffer.add(key, ev.event_time.timestamp(), None)

    def sweep(self, now: float) -> None:
        if not self.flush_due(now):
            return
        cutoff = now - self.window_seconds
        for key in self._buffer.keys():
            buf = self._buffer.prune_key(key, now)
            if not buf:
                continue
            last_ts = buf[-1][0]
            if last_ts > cutoff:
                continue
            self._buffer.drop_key(key)
            stamps = [ts for ts, _ in buf]
            if len(stamps) < self.min_connections:
                continue
            intervals = [b - a for a, b in zip(stamps, stamps[1:])]
            if not intervals:
                continue
            mean_iv = fmean(intervals)
            if not (self.interval_min <= mean_iv <= self.interval_max):
                continue
            jit = jitter(intervals)
            if jit > self.jitter_max:
                continue
            src, dst, dport = key.split("|")
            first = datetime.fromtimestamp(stamps[0], tz=timezone.utc)
            last = datetime.fromtimestamp(last_ts, tz=timezone.utc)
            alert_id = make_alert_id(self.name, key, first)
            doc = build_alert_doc(
                alert_id=alert_id, alert_type=self.name,
                attack_phase="c2",
                title=f"Possible beaconing {src} -> {dst}:{dport}",
                group_key=key, severity="medium",
                rationale=(
                    f"{len(stamps)} connections from {src} to {dst}:{dport} "
                    f"with mean interval {mean_iv:.0f}s and jitter "
                    f"coefficient {jit:.2f}. Consistent with C2 beaconing "
                    f"but also with monitoring agents and keepalives. "
                    f"Connection existence does not prove host compromise."),
                reasons=[
                    f"connections: {len(stamps)} >= {self.min_connections}",
                    f"mean interval {mean_iv:.0f}s within "
                    f"[{self.interval_min}, {self.interval_max}]s",
                    f"jitter {jit:.2f} <= {self.jitter_max}",
                ],
                first_seen=first, last_seen=last,
                sensor_id=self.sensor_id,
                event_count=len(stamps), source_count=1, destination_count=1,
                source_ip=src, destination_ip=dst, transport=None,
                protocol=None, top_sources=[(src, len(stamps))],
                top_destinations=[(dst, len(stamps))], top_rules=[],
                evidence=[],
            )
            self.emit(doc)
