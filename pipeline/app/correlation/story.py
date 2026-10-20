"""AttackStory: one reconstructed incident candidate (doc 10.4/10.5).

A story is a living evidence graph:

  nodes   - entities observed in the chain (ip / domain / hash)
  edges   - observed or inferred relations between entities
  evidence- time-ordered signal + context records (alerts, IOC events,
            DNS answers, TLS/HTTP context) with source references

Key guarantees:
  * Evidence-first: every node/edge/phase claim points at evidence.
  * No overclaim: outcome labels separate ATTEMPTED vs SUSPECTED vs
    STRONG evidence of success; network-only blindness is explicit
    (process execution / data content are NOT observable here).
  * Replay-safe: signals deduplicate on (ref_index, ref_id).
"""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass, field

from app.detection.killchain import (STAGES, STAGE_LABELS, assess_stages,
                                     stage_for_phase)
from app.detection.taxonomy import PHASES, phase_rank
from app.correlation.entities import split_entity_key

STORY_NS = uuid.uuid5(uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
                      "ndr/story/v1")

# v0.12.7 specificity caps: reconstructed graphs on the live VM grew so
# large that the incident attack graph looked like "every alert the
# system ever fired" instead of ONE correlated attack chain. The
# context/dns/tracker enrichment is decoration around the SIGNAL chain,
# so it now gets a hard node budget and much tighter per-signal limits;
# the evidence list keeps the full picture even when graph nodes are
# capped (no overclaim is lost - only the drawing gets focused).
MAX_NODES = 80
MAX_EDGES = 120
MAX_EVIDENCE = 400
MAX_CTX_NODES = 36
MAX_TRACKER_DOMAINS = 3
MAX_DNS_ANSWER_NODES = 2

# Evidence-based relation naming per phase (deliberately cautious).
RELATION_FOR_PHASE = {
    "recon": "probed",
    "initial_access": "targeted",
    "delivery": "delivered_to",
    "c2": "contacted",
    "lateral": "lateral_to",
    "impact": "transferred_to",
    "unknown": "connected_to",
}

NODE_ROLES_BY_PHASE = {
    "recon": {"ip": "attacker"},
    "initial_access": {"ip": "attacker"},
    "c2": {"ip": "c2_infra", "domain": "c2_infra"},
    "delivery": {"hash": "payload", "domain": "delivery_infra"},
    "lateral": {"ip": "compromised_host"},
    "impact": {"ip": "exfil_target"},
}

# Confidence weights for outcome markers (doc 10.4 - heuristic).
MARKER_WEIGHTS = {
    "recon_observed": 1,
    "access_attempted": 2,
    "delivery_observed": 3,
    "c2_observed": 3,
    "c2_ioc_high": 5,
    "payload_ioc_high": 5,
    "lateral_observed": 3,
    "impact_observed": 3,
}

SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3,
                 "critical": 4}


@dataclass
class StoryNode:
    kind: str                     # ip | domain | hash | ioc
    key: str                      # full entity key
    label: str
    role: str = "entity"
    phase: str = "unknown"
    confidence: int = 50
    first_seen: float = 0.0
    last_seen: float = 0.0
    attrs: dict = field(default_factory=dict)
    evidence_count: int = 0


@dataclass
class StoryEdge:
    src: str
    dst: str
    relation: str
    phase: str = "unknown"
    inferred: bool = False
    first_seen: float = 0.0
    last_seen: float = 0.0
    evidence_count: int = 0
    confidence: int = 50


@dataclass
class EvidenceItem:
    ts_epoch: float
    ts_iso: str
    kind: str                     # alert | ioc_event | context
    source: str                   # zeek | suricata | threat-intel | pipeline
    ref_index: str = ""
    ref_id: str = ""
    title: str = ""
    severity: str = "informational"
    phase: str = "unknown"
    summary: str = ""
    detail: dict = field(default_factory=dict)
    # Dual-framework classification (doc 11): LM kill-chain stage +
    # MITRE ATT&CK techniques supporting this item.
    stage: str = ""               # LM stage (derived from phase when empty)
    attck: list = field(default_factory=list)


class AttackStory:
    """Mutable attack story. Not thread-safe: guarded by the service."""

    def __init__(self, story_id: str, gap_seconds: int,
                 max_evidence: int = MAX_EVIDENCE):
        self.id = story_id
        self.gap_seconds = gap_seconds
        self.max_evidence = max_evidence
        self.title = "Attack story"
        self.status = "open"          # open|confirmed|benign|closed
        self.severity = "low"
        self.confidence_weight = 0
        self.created_at = 0.0
        self.first_seen = float("inf")
        self.last_seen = 0.0
        self.updated_at = 0.0
        self.signal_count = 0
        self.context_count = 0
        self.nodes: dict[str, StoryNode] = {}
        self.edges: dict[tuple[str, str, str], StoryEdge] = {}
        self.evidence: list[EvidenceItem] = []
        self._evidence_refs: set[tuple[str, str]] = set()
        self.entity_keys: set[str] = set()
        # v0.12.7: number of nodes created by CONTEXT enrichment
        # (dns/tls/http/fileinfo/trackers) - capped by MAX_CTX_NODES
        self.ctx_nodes = 0
        self.dirty = True
        self.seed_title = ""
        # Stage Progression Engine (doc 11): evidence-based 7-stage
        # assessment history. Not a mandatory sequence - stages may be
        # missing, parallel, or undeterminable. The baseline (no
        # evidence) assessment seeds status tracking so the history
        # records meaningful transitions (not_observed -> observed).
        self.stage_history: list[dict] = []
        self._stage_status: dict[str, str] = {
            s["stage"]: s["status"] for s in assess_stages([])}

    # ------------------------------------------------------------ factory
    @classmethod
    def from_signal(cls, signal, gap_seconds: int,
                    max_evidence: int = MAX_EVIDENCE) -> "AttackStory":
        minute_bucket = int(signal.ts_epoch // 60)
        story_id = str(uuid.uuid5(STORY_NS, f"{signal.ref_id}|{minute_bucket}"))
        story = cls(story_id, gap_seconds, max_evidence)
        story.seed_title = signal.title
        return story

    # ------------------------------------------------------------ helpers
    def _ensure_node(self, key: str, ts: float, phase: str,
                     role_hint: str | None = None,
                     attrs: dict | None = None) -> StoryNode | None:
        if len(self.nodes) >= MAX_NODES and key not in self.nodes:
            return None
        kind, value = split_entity_key(key)
        node = self.nodes.get(key)
        if node is None:
            node = StoryNode(kind=kind, key=key, label=value,
                             first_seen=ts, last_seen=ts)
            self.nodes[key] = node
        if ts < node.first_seen or node.first_seen == 0:
            node.first_seen = ts
        node.last_seen = max(node.last_seen, ts)
        node.evidence_count += 1
        if phase_rank(phase) > phase_rank(node.phase):
            node.phase = phase
        if role_hint and node.role in ("entity", ""):
            node.role = NODE_ROLES_BY_PHASE.get(phase, {}).get(
                kind, role_hint)
        if attrs:
            node.attrs.update(attrs)
        self.entity_keys.add(key)
        return node

    def _ctx_node(self, key: str, ts: float, phase: str,
                  role_hint: str | None = None,
                  attrs: dict | None = None) -> StoryNode | None:
        """Node creation from CONTEXT enrichment (never from signals).
        Context entities are supporting decoration around the signal
        chain - capped so a chatty story cannot drown the attack path
        (v0.12.7). Evidence items are unaffected by this cap."""
        if key not in self.nodes and self.ctx_nodes >= MAX_CTX_NODES:
            return None
        was_new = key not in self.nodes
        node = self._ensure_node(key, ts, phase, role_hint, attrs)
        if node is not None and was_new:
            self.ctx_nodes += 1
        return node

    def _ensure_edge(self, src: str, dst: str, relation: str, ts: float,
                     phase: str, inferred: bool = False) -> StoryEdge | None:
        if src == dst:
            return None
        if (len(self.edges) >= MAX_EDGES
                and (src, dst, relation) not in self.edges):
            return None
        edge = self.edges.get((src, dst, relation))
        if edge is None:
            edge = StoryEdge(src=src, dst=dst, relation=relation,
                             phase=phase, inferred=inferred,
                             first_seen=ts, last_seen=ts)
            self.edges[(src, dst, relation)] = edge
        edge.last_seen = max(edge.last_seen, ts)
        edge.evidence_count += 1
        if phase_rank(phase) > phase_rank(edge.phase):
            edge.phase = phase
        if inferred:
            edge.inferred = True
        return edge

    def add_evidence(self, item: EvidenceItem) -> bool:
        ref = (item.ref_index, item.ref_id)
        if ref in self._evidence_refs:
            return False
        self._evidence_refs.add(ref)
        self.evidence.append(item)
        if len(self.evidence) > self.max_evidence:
            # drop oldest non-seed evidence; keep the ref so replays do
            # not resurrect it
            self.evidence.pop(1)
        self._track_stage_change(item)
        return True

    # ------------------------------------------------ stage progression
    def _track_stage_change(self, item: EvidenceItem) -> None:
        """Record assessment changes over time (doc 11: "perubahan
        penilaian dari waktu ke waktu"). A transition is recorded only
        when a stage's evidence-based status actually changes."""
        if not item.stage or item.stage not in STAGES:
            return
        assessment = {s["stage"]: s["status"]
                      for s in assess_stages(self._stage_evidence())}
        for stage, status in assessment.items():
            prev = self._stage_status.get(stage)
            if prev != status:
                self.stage_history.append({
                    "ts_epoch": item.ts_epoch,
                    "ts": item.ts_iso or _iso(item.ts_epoch),
                    "stage": stage,
                    "from": prev,
                    "to": status,
                    "evidence_ref": item.ref_id,
                })
                self._stage_status[stage] = status

    def _stage_evidence(self) -> list[dict]:
        return [{"kind": e.kind, "stage": e.stage or stage_for_phase(e.phase),
                 "phase": e.phase, "severity": e.severity,
                 "attck": e.attck}
                for e in self.evidence]

    # ------------------------------------------------------------ growth
    def ingest_signal(self, signal, trackers=None) -> bool:
        """Merge a Signal into the story. Returns False when duplicate."""
        ts = signal.ts_epoch or self.last_seen or self.created_at

        # Dual-framework evidence (doc 11): carry the LM kill-chain
        # stage + ATT&CK techniques from the alert doc onto the item.
        stage = signal.kill_chain_stage or stage_for_phase(signal.phase)
        ev = EvidenceItem(
            ts_epoch=ts, ts_iso=signal.ts_iso, kind=signal.kind,
            source="threat-intel" if signal.kind == "ioc_event"
            else "suricata" if "suricata" in signal.attack_type
            else "pipeline",
            ref_index=signal.ref_index, ref_id=signal.ref_id,
            title=signal.title, severity=signal.severity,
            phase=signal.phase, summary=signal.summary,
            detail=dict(signal.detail),
            stage=stage, attck=list(signal.attck))
        if not self.add_evidence(ev):
            return False

        self.signal_count += 1
        self.confidence_weight += signal.base_confidence
        self.first_seen = min(self.first_seen, ts)
        end_ts = getattr(signal, "end_ts_epoch", 0) or ts
        self.last_seen = max(self.last_seen, end_ts)
        self.updated_at = ts
        self.dirty = True

        sev_rank = SEVERITY_RANK.get(signal.severity, 0)
        if sev_rank > SEVERITY_RANK.get(self.severity, 0):
            self.severity = signal.severity

        for key in signal.entities:
            kind, _ = split_entity_key(key)
            role = NODE_ROLES_BY_PHASE.get(signal.phase, {}).get(kind)
            attrs = {}
            if signal.kind == "ioc_event" and kind in ("domain", "hash"):
                attrs["ti_match"] = True
            self._ensure_node(key, ts, signal.phase, role, attrs)

        # primary edge: src -> dst (or src -> domain/hash when no dst)
        rel = RELATION_FOR_PHASE.get(signal.phase, "connected_to")
        src_key = f"ip:{signal.src_ip}" if signal.src_ip else None
        dst_key = f"ip:{signal.dst_ip}" if signal.dst_ip else None
        if src_key:
            targets = [dst_key] if dst_key else []
            if not targets:
                targets = [k for k in signal.entities
                           if k.startswith(("domain:", "hash:"))][:2]
            for tgt in targets:
                self._ensure_edge(src_key, tgt, rel, ts, signal.phase)

        # cross-log entity correlation (doc 10.3): attach domains the
        # involved IPs resolved to / talked to
        if trackers is not None:
            self._link_trackers(trackers, ts, {f"ip:{signal.src_ip}"
                                               if signal.src_ip else None,
                                               f"ip:{signal.dst_ip}"
                                               if signal.dst_ip else None})

        self._retitre()
        return True

    def _link_trackers(self, trackers, ts: float,
                       ip_keys: set[str | None]) -> None:
        for ip_key in ip_keys:
            if not ip_key:
                continue
            ip = split_entity_key(ip_key)[1]
            domains = trackers.answer.domains_for_ip(ip) \
                | trackers.sni.domains_for_ip(ip)
            # v0.12.7: 6 -> 3 domains per IP - the tracker link flood was
            # the single biggest source of graph noise (every DNS/TLS
            # domain the host ever touched became a node + 2-3 edges)
            for domain in list(domains)[:MAX_TRACKER_DOMAINS]:
                dkey = f"domain:{domain}"
                node = self._ctx_node(dkey, ts, "c2", "c2_infra",
                                      {"via": "dns/tls context"})
                if node is None:
                    continue
                # host contacted domain; domain resolved back to ip
                self._ensure_edge(ip_key, dkey, "contacted", ts, "c2",
                                  inferred=True)
                self._ensure_edge(dkey, ip_key, "resolved_to", ts, "c2",
                                  inferred=True)
                for answer_ip in trackers.answer.ips_for_domain(domain):
                    akey = f"ip:{answer_ip}"
                    if akey != ip_key and akey in self.entity_keys:
                        self._ensure_edge(dkey, akey, "resolved_to", ts,
                                          "c2", inferred=True)

    def ingest_context(self, ctx: dict) -> bool:
        """Fold a plain-event context record into an existing story.

        Context never creates stories and never extends the time
        window - it only enriches evidence and entity resolution.
        """
        ts = ctx.get("ts") or 0
        # v0.13.0: context must RESPECT THE TIME GAP. The old behaviour
        # attached ANY context touching a story entity - polluting the
        # timeline with unrelated history from hours/days around it.
        if ts and self.first_seen != float("inf"):
            gap = self.gap_seconds
            if ts < (self.first_seen - gap) or ts > (self.last_seen + gap):
                return False
        etype = ctx.get("etype")
        ref = ("ctx", f"{etype}|{ts}|{ctx.get('query') or ctx.get('domain')
                       or ctx.get('name') or ctx.get('sha256') or ''}")
        if ref in self._evidence_refs:
            return False
        src_ip = ctx.get("src")
        dst_ip = ctx.get("dst")
        involved = {f"ip:{ip}" for ip in (src_ip, dst_ip) if ip}
        entity_hit = bool(involved & self.entity_keys)

        if etype == "dns":
            query = ctx.get("query")
            answers = ctx.get("answers") or []
            qkey = f"domain:{query}" if query else None
            relevant = (qkey in self.entity_keys
                        or any(f"ip:{a['data']}" in self.entity_keys
                               for a in answers))
            if not (relevant or entity_hit):
                return False
            detail = {"query": query,
                      "answers": answers[:6],
                      "source_ip": src_ip}
            item = EvidenceItem(
                ts_epoch=ts, ts_iso=_iso(ts), kind="context",
                source="zeek", ref_index="ctx", ref_id=ref[1],
                title=f"DNS resolution: {query or '(no query)'}"
                if query else "DNS resolution",
                severity="informational", phase="c2",
                stage=stage_for_phase("c2"),
                summary=f"{query} -> "
                        f"{', '.join(a['data'] for a in answers[:4])}"
                if answers else f"query {query}",
                detail=detail)
            self.add_evidence(item)
            self.context_count += 1
            if qkey:
                self._ctx_node(qkey, ts, "c2", "c2_infra")
                # v0.12.7: create graph nodes for at most the first 2
                # answer addresses (was 4) - the rest stay in the
                # evidence detail
                for a in answers[:MAX_DNS_ANSWER_NODES]:
                    akey = f"ip:{a['data']}"
                    self._ctx_node(akey, ts, "c2")
                    self._ensure_edge(qkey, akey, "resolved_to", ts, "c2",
                                      inferred=True)
                if src_ip and qkey in self.entity_keys:
                    skey = f"ip:{src_ip}"
                    self._ctx_node(skey, ts, "c2")
                    self._ensure_edge(skey, qkey, "queried", ts, "c2",
                                      inferred=True)
            self.dirty = True
            return True

        if etype in ("tls", "http"):
            dkey = f"domain:{ctx.get('domain')}" if ctx.get("domain") else None
            relevant = (dkey in self.entity_keys
                        or f"ip:{src_ip}" in self.entity_keys
                        or f"ip:{dst_ip}" in self.entity_keys)
            if not relevant:
                return False
            label = (f"TLS session to {ctx.get('domain')}" if etype == "tls"
                     else f"HTTP {ctx.get('method') or ''} "
                          f"{ctx.get('url') or ctx.get('domain')}".strip())
            ev_phase = "c2" if etype == "tls" else "delivery"
            self.add_evidence(EvidenceItem(
                ts_epoch=ts, ts_iso=_iso(ts), kind="context",
                source="zeek", ref_index="ctx", ref_id=ref[1],
                title=label, severity="informational",
                phase=ev_phase, stage=stage_for_phase(ev_phase),
                summary=label,
                detail={"host": ctx.get("domain"),
                        "sni": ctx.get("domain") if etype == "tls" else None,
                        "url": ctx.get("url"), "status": ctx.get("status"),
                        "src": src_ip, "dst": dst_ip}))
            self.context_count += 1
            if dkey:
                self._ctx_node(dkey, ts, "c2", "c2_infra")
                anchor = f"ip:{src_ip}" if (src_ip
                                            and f"ip:{src_ip}"
                                            in self.entity_keys) else (
                    f"ip:{dst_ip}" if dst_ip else None)
                if anchor:
                    self._ctx_node(anchor, ts, "c2")
                    self._ensure_edge(anchor, dkey, "contacted", ts, "c2",
                                      inferred=True)
            self.dirty = True
            return True

        if etype == "fileinfo":
            relevant = (f"ip:{src_ip}" in self.entity_keys
                        or f"ip:{dst_ip}" in self.entity_keys)
            if not relevant:
                return False
            h = ctx.get("sha256") or ctx.get("sha1") or ctx.get("md5")
            detail = {"file_name": ctx.get("name"),
                      "mime_type": ctx.get("mime"),
                      "size": ctx.get("size"),
                      "sha256": ctx.get("sha256"), "src": src_ip,
                      "dst": dst_ip}
            self.add_evidence(EvidenceItem(
                ts_epoch=ts, ts_iso=_iso(ts), kind="context",
                source="zeek", ref_index="ctx", ref_id=ref[1],
                title=f"File transfer: {ctx.get('name') or h or 'unknown'}",
                severity="low", phase="delivery",
                stage=stage_for_phase("delivery"),
                summary=f"{ctx.get('name')} ({ctx.get('mime')}, "
                        f"{ctx.get('size')} bytes)",
                detail=detail))
            self.context_count += 1
            if h:
                hkey = f"hash:{h}"
                self._ctx_node(hkey, ts, "delivery", "payload",
                               {"file_name": ctx.get("name"),
                                "mime": ctx.get("mime")})
                host = None
                for cand in (f"ip:{src_ip}", f"ip:{dst_ip}"):
                    if cand and cand in self.entity_keys:
                        host = cand
                        break
                if host:
                    self._ensure_edge(host, hkey, "downloaded", ts,
                                      "delivery", inferred=True)
            self.dirty = True
            return True

        return False

    # ------------------------------------------------------------ view
    def _retitre(self) -> None:
        """Recompute title from the current chain shape."""
        attackers = [n.label for n in self.nodes.values()
                     if n.role == "attacker"]
        victims = [n.label for n in self.nodes.values()
                   if n.role in ("compromised_host",)]
        phases_hit = sorted(
            {e.phase for e in self.evidence if e.phase in PHASES},
            key=phase_rank)
        if attackers:
            head = attackers[0]
        else:
            head = "unknown source"
        if victims:
            head = f"{head} -> {victims[0]}"
        chain = " > ".join(_SHORT.get(p, p) for p in phases_hit) or "activity"
        self.title = f"{head} ({chain})"

    # confidence: saturating heuristic (doc 10.4) - explicitly
    # UNCALIBRATED, capped at 97 to leave room for analyst confirmation.
    def confidence(self) -> int:
        return min(97, round(100 * (1 - math.exp(
            -self.confidence_weight / 120))))

    def phase_progression(self) -> list[dict]:
        out = []
        for phase in PHASES:
            items = [e for e in self.evidence if e.phase == phase]
            direct = [e for e in items if e.kind in ("alert", "ioc_event")]
            inferred = [e for e in items if e.kind == "context"]
            status = "none"
            if direct:
                status = "observed"
            elif inferred:
                status = "suspected"
            out.append({
                "phase": phase,
                "status": status,
                "evidence_count": len(items),
                "signal_count": len(direct),
                "context_count": len(inferred),
            })
        return out

    def stage_progression(self) -> list[dict]:
        """Evidence-based LM kill-chain assessment (doc 11).

        Four statuses over the 7 Lockheed Martin stages - deliberately
        NOT a filled-in sequence: stages may be not_observed (telemetry
        covers them but nothing arrived) or insufficient_telemetry
        (network-only data cannot assess them at all).
        """
        return assess_stages(self._stage_evidence())

    def markers(self) -> set[str]:
        m: set[str] = set()
        phases = {e.phase for e in self.evidence}
        if "recon" in phases:
            m.add("recon_observed")
        if "initial_access" in phases:
            m.add("access_attempted")
        if "delivery" in phases:
            m.add("delivery_observed")
        if "c2" in phases:
            m.add("c2_observed")
        if "lateral" in phases:
            m.add("lateral_observed")
        if "impact" in phases:
            m.add("impact_observed")
        for e in self.evidence:
            if e.kind == "ioc_event" and e.severity in ("high", "critical"):
                if e.phase == "delivery":
                    m.add("payload_ioc_high")
                elif e.phase == "c2":
                    m.add("c2_ioc_high")
        return m

    def outcome(self) -> dict:
        """Attack outcome assessment (doc 10.5).

        Separates PROVEN (directly observed), SUSPECTED (chain-inferred)
        and UNKNOWN (network-only blindness: process execution, actual
        data content, persistence).
        """
        m = self.markers()
        proven: list[str] = []
        suspected: list[str] = []
        unknown: list[str] = [
            "Process/payload execution on host (not visible from network)",
            "Whether transferred data was sensitive (content not inspected)",
            "Persistence or further attacker access",
        ]
        if m & {"recon_observed"}:
            proven.append("Reconnaissance activity was observed "
                          "against the target network")
        if m & {"access_attempted"}:
            proven.append("An exploitation/access attempt was observed")
            if not (m & {"c2_observed", "delivery_observed",
                         "lateral_observed", "impact_observed"}):
                suspected.append("The attempt may have failed - no "
                                 "post-access activity was observed")
        if m & {"delivery_observed"}:
            proven.append("File transfer consistent with payload "
                          "delivery was observed")
        if m & {"c2_observed"}:
            if m & {"payload_ioc_high"}:
                proven.append("A file hash matched high-confidence "
                              "threat intelligence")
            if m & {"c2_ioc_high"}:
                proven.append("Communication matched high-confidence "
                              "C2 threat intelligence")
                suspected.append("Host compromise is strongly supported "
                                 "by TI, pending endpoint validation")
            else:
                suspected.append("Periodic/structured outbound patterns "
                                 "are consistent with C2; benign agents "
                                 "can look similar")
        if m & {"lateral_observed"}:
            proven.append("Internal remote-service activity consistent "
                          "with lateral movement was observed")
        if m & {"impact_observed"}:
            suspected.append("Large outbound transfer observed - "
                             "exfiltration candidate requiring validation "
                             "(content not inspected)")

        # outcome label (deliberately conservative)
        if m & {"payload_ioc_high", "c2_ioc_high"} and \
                (m & {"c2_observed", "delivery_observed"}):
            label = "strong_success"
        elif (m & {"access_attempted"}) and \
                (m & {"c2_observed", "delivery_observed",
                      "lateral_observed", "impact_observed"}):
            label = "suspected_success"
        elif m & {"access_attempted", "delivery_observed", "c2_observed",
                  "lateral_observed", "impact_observed"}:
            label = "attempted"
        else:
            label = "indeterminate"

        return {
            "label": label,
            "proven": proven,
            "suspected": suspected,
            "unknown": unknown,
            "markers": sorted(m),
            "disclaimer": "Network-only assessment: proves observed "
                          "traffic, not host state. Endpoint or server "
                          "logs are required to confirm execution and "
                          "data sensitivity (doc 10.2).",
        }

    def to_summary(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "severity": self.severity,
            "confidence": self.confidence(),
            "confidence_basis": "heuristic-uncalibrated",
            "first_seen": _iso(self.first_seen) if math.isfinite(
                self.first_seen) else None,
            "last_seen": _iso(self.last_seen) if self.last_seen else None,
            "updated_at": _iso(self.updated_at) if self.updated_at else None,
            "entity_count": len(self.nodes),
            "edge_count": len(self.edges),
            "evidence_count": len(self.evidence),
            "signal_count": self.signal_count,
            "phases": [p for p in self.phase_progression()
                       if p["status"] != "none"],
            "stages": [{"stage": s["stage"], "label": s["label"],
                        "status": s["status"],
                        "confidence": s["confidence"]}
                       for s in self.stage_progression()],
            "deepest_stage": self.deepest_stage(),
            "outcome_label": self.outcome()["label"],
        }

    def to_detail(self) -> dict:
        return {
            **self.to_summary(),
            "nodes": [vars(n) for n in self.nodes.values()],
            "edges": [vars(e) for e in self.edges.values()],
            "evidence": [vars(e) for e in self.evidence],
            "phase_progression": self.phase_progression(),
            "stage_progression": self.stage_progression(),
            "stage_history": list(self.stage_history),
            "outcome": self.outcome(),
        }

    def deepest_stage(self) -> str:
        """Deepest stage with an observed/suspected assessment."""
        best = ""
        for s in self.stage_progression():
            if s["status"] in ("observed", "suspected"):
                best = s["stage"]
        return best or "reconnaissance"


_SHORT = {
    "recon": "Recon",
    "initial_access": "Initial Access",
    "delivery": "Delivery",
    "c2": "C2",
    "lateral": "Lateral",
    "impact": "Impact",
}


def _iso(ts: float) -> str:
    from datetime import datetime, timezone
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() \
            .replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return ""
