"""ReconstructionService: the attack reconstruction engine (doc 10).

Consumes, in-process:
  * alert docs fanned out by detection rules (`on_alert`)
  * IOC-matched events + DNS/TLS/HTTP/fileinfo context (`on_event`)

Layers implemented (doc 10.3):
  1. entity correlation   - normalized entity intersection + DNS answer
                            / SNI trackers across logs
  2. temporal correlation - bounded join gap (RECON_MAX_GAP_SECONDS),
                            stories stay extendable for late evidence
  3. behavior correlation - phase-tagged behavior rules drive the chain
  4. TI correlation       - IOC-matched events/attaches feed context
  5. evidence correlation - proven / suspected / unknown split per phase

Failure isolation: the engine NEVER blocks ingest. Its input queue is
bounded and drops context (best-effort) when full; alerts enqueue with
drop-oldest semantics so detection throughput is unaffected.
"""

from __future__ import annotations

from collections import OrderedDict
import queue
import threading
import time

from app.correlation.entities import (Signal, extract_context,
                                      extract_from_alert,
                                      extract_from_event)
from app.correlation.story import EvidenceItem, AttackStory
from app.correlation.trackers import AnswerTracker, SniTracker


class _Trackers:
    answer = AnswerTracker()
    sni = SniTracker()


class StoryIndex:
    """Entity -> open stories map with time-gap aware matching."""

    def __init__(self, gap_seconds: int, max_stories: int):
        self.gap_seconds = gap_seconds
        self.max_stories = max_stories
        self._by_entity: dict[str, set[str]] = {}
        self.stories: dict[str, AttackStory] = {}

    def register(self, story: AttackStory) -> None:
        self.stories[story.id] = story
        for key in story.entity_keys:
            self._by_entity.setdefault(key, set()).add(story.id)

    def unregister(self, story_id: str) -> None:
        story = self.stories.pop(story_id, None)
        if story is None:
            return
        for key in story.entity_keys:
            ids = self._by_entity.get(key)
            if ids:
                ids.discard(story_id)
                if not ids:
                    self._by_entity.pop(key, None)

    def candidates(self, signal: Signal) -> list[AttackStory]:
        """Stories sharing an entity AND inside the time gap."""
        seen: set[str] = set()
        out: list[AttackStory] = []
        for key in signal.entities:
            for sid in self._by_entity.get(key, ()):
                if sid in seen:
                    continue
                seen.add(sid)
                story = self.stories.get(sid)
                if story is None:
                    continue
                lo = story.first_seen - self.gap_seconds
                hi = story.last_seen + self.gap_seconds
                if lo <= signal.ts_epoch <= hi:
                    out.append(story)
        out.sort(key=lambda s: -s.signal_count)
        return out

    def merge(self, keep: AttackStory, absorb: AttackStory) -> None:
        """Fold `absorb` into `keep` (bigger story wins)."""
        for ev in list(absorb.evidence):
            absorb_ref = (ev.ref_index, ev.ref_id)
            if absorb_ref not in {(e.ref_index, e.ref_id)
                                  for e in keep.evidence}:
                keep.evidence.append(ev)
                keep._evidence_refs.add(absorb_ref)
        keep.signal_count += absorb.signal_count
        keep.context_count += absorb.context_count
        keep.confidence_weight += absorb.confidence_weight
        keep.first_seen = min(keep.first_seen, absorb.first_seen)
        keep.last_seen = max(keep.last_seen, absorb.last_seen)
        for key, node in absorb.nodes.items():
            if key not in keep.nodes:
                keep.nodes[key] = node
                keep.entity_keys.add(key)
        for ekey, edge in absorb.edges.items():
            keep.edges.setdefault(ekey, edge)
        for key in absorb.entity_keys:
            ids = self._by_entity.setdefault(key, set())
            ids.discard(absorb.id)
            ids.add(keep.id)
        # v0.13.0: no empty entity sets left behind (they accumulated
        # silently and leaked memory on long runs)
        for key in list(self._by_entity):
            if not self._by_entity[key]:
                self._by_entity.pop(key, None)
        keep.dirty = True
        self.unregister(absorb.id)

    def over_capacity(self) -> list[AttackStory]:
        """Oldest stories to retire when above max_stories."""
        if len(self.stories) <= self.max_stories:
            return []
        ordered = sorted(self.stories.values(),
                         key=lambda s: s.last_seen or 0)
        return ordered[:len(self.stories) - self.max_stories]


class ReconstructionService(threading.Thread):
    def __init__(self, cfg, metrics, store):
        super().__init__(daemon=True, name="attack-reconstruction")
        self.cfg = cfg
        self.metrics = metrics
        self.store = store
        self.index = StoryIndex(cfg.recon_max_gap_seconds,
                                cfg.recon_max_active_stories)
        self._queue: queue.Queue = queue.Queue(maxsize=cfg.recon_queue_capacity)
        self._stop = threading.Event()
        self._dirty: set[str] = set()
        self.status = "starting"   # starting | idle | rebuilding
        # v0.13.0: global ref dedup is a DETERMINISTIC LRU (OrderedDict).
        # The old "discard the oldest half" of an unordered SET discarded a
        # RANDOM half and could re-admit duplicates right after eviction.
        self._signals_seen: "OrderedDict[tuple[str, str], bool]" = OrderedDict()
        # v0.13.0: ingest-timeline per story (monotonic) - the sweep closes
        # stories idle in INGEST time, not wall-clock vs event ts (which
        # closed every REPLAYED story instantly)
        self._story_ingest: dict[str, float] = {}

    # ------------------------------------------------------------- inputs
    def on_alert(self, doc: dict, index_name: str = "ndr-alerts") -> None:
        """Alert fan-out entrypoint (called on the detection thread)."""
        try:
            signal = extract_from_alert(doc, index_name)
        except Exception:  # noqa: BLE001
            self.metrics.inc("recon_errors")
            return
        if signal is None:
            return
        try:
            self._queue.put_nowait(("signal", signal))
        except queue.Full:
            # drop the OLDEST queued item to keep fresh signals flowing
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._queue.put_nowait(("signal", signal))
            except queue.Full:
                self.metrics.inc("recon_dropped")

    def on_event(self, ev, index_name: str) -> None:
        """Event entrypoint (called on the processor thread)."""
        if ev.matched_ioc:
            try:
                signal = extract_from_event(ev, index_name)
            except Exception:  # noqa: BLE001
                self.metrics.inc("recon_errors")
                return
            if signal is not None:
                try:
                    self._queue.put_nowait(("signal", signal))
                except queue.Full:
                    self.metrics.inc("recon_dropped")
                    return
        try:
            ctx = extract_context(ev)
        except Exception:  # noqa: BLE001
            return
        if ctx is not None:
            try:
                self._queue.put_nowait(("context", ctx))
            except queue.Full:
                # context is best-effort - dropping never blocks ingest
                self.metrics.inc("recon_ctx_dropped")

    # ------------------------------------------------------------- thread
    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        self._reload_from_store()
        last_flush = time.monotonic()
        while not self._stop.is_set():
            try:
                kind, payload = self._queue.get(timeout=0.5)
            except queue.Empty:
                kind, payload = None, None
            if kind == "signal":
                self._handle_signal(payload)
            elif kind == "context":
                self._handle_context(payload)
            if time.monotonic() - last_flush >= self.cfg.recon_persist_seconds:
                last_flush = time.monotonic()
                self._flush()
                self._sweep()
        self._flush()

    # ------------------------------------------------------------- logic
    def _handle_signal(self, signal: Signal) -> None:
        ref = (signal.ref_index, signal.ref_id)
        if ref in self._signals_seen:
            self._signals_seen.move_to_end(ref)   # LRU refresh
            return
        self._signals_seen[ref] = True
        if len(self._signals_seen) > 50_000:
            # bounded LRU: evict the OLDEST refs deterministically
            for _ in range(25_000):
                self._signals_seen.popitem(last=False)

        candidates = self.index.candidates(signal)
        if not candidates:
            story = AttackStory.from_signal(
                signal, self.cfg.recon_max_gap_seconds,
                self.cfg.recon_max_evidence)
            story.ingest_signal(signal, self._trackers())
            self.index.register(story)
            self._dirty.add(story.id)
            self._story_ingest[story.id] = time.monotonic()
            self.metrics.inc("recon_stories_created")
        else:
            story = candidates[0]
            changed = story.ingest_signal(signal, self._trackers())
            self._story_ingest[story.id] = time.monotonic()
            if changed:
                self._dirty.add(story.id)
            # merge overlapping stories (doc 10.5: one incident, not N)
            for other in candidates[1:]:
                if other.id == story.id:
                    continue
                self.index.merge(story, other)
                self._dirty.add(story.id)
                self.metrics.inc("recon_merges")
        self.metrics.inc("recon_signals")
        self._retitre_title(story)

    def _trackers(self) -> _Trackers:
        return _Trackers

    def _handle_context(self, ctx: dict) -> None:
        # update trackers (cheap; also serves future stories)
        if ctx.get("etype") == "dns":
            _Trackers.answer.record(ctx.get("query"), ctx.get("answers") or [],
                                    ctx.get("ts") or 0)
        if ctx.get("etype") in ("tls", "http") and ctx.get("dst"):
            _Trackers.sni.record(ctx.get("dst"), ctx.get("domain"),
                                 ctx.get("ts") or 0)

        # attach to matching existing stories only
        involved = {ctx.get("src"), ctx.get("dst")}
        keys = {f"ip:{ip}" for ip in involved if ip}
        if ctx.get("etype") == "dns" and ctx.get("query"):
            keys.add(f"domain:{ctx['query']}")
        if ctx.get("etype") in ("tls", "http") and ctx.get("domain"):
            keys.add(f"domain:{ctx['domain']}")
        touched: set[str] = set()
        for key in keys:
            for sid in list(self.index._by_entity.get(key, ())):
                story = self.index.stories.get(sid)
                if story is None or story.id in touched:
                    continue
                touched.add(story.id)
                if story.ingest_context(ctx):
                    self._dirty.add(story.id)
                    self.metrics.inc("recon_ctx_attached")

    def _retitre_title(self, story: AttackStory) -> None:
        story._retitre()

    def _flush(self) -> None:
        if not self._dirty:
            return
        for sid in list(self._dirty):
            story = self.index.stories.get(sid)
            if story is None:
                self._dirty.discard(sid)
                continue
            try:
                self.store.save_story(story)
                story.dirty = False
                self._dirty.discard(sid)
            except Exception:  # noqa: BLE001 - retry next flush
                self.metrics.inc("recon_errors")
        self.metrics.set_gauge("recon_open_stories", len(self.index.stories))
        self.metrics.set_gauge("recon_dirty_stories", len(self._dirty))

    def _sweep(self) -> None:
        # v0.13.0: idle stories are closed based on INGEST timeline
        # (monotonic time since the story last received a signal). The old
        # wall-clock-vs-event-ts check closed every REPLAYED story instantly.
        now_mono = time.monotonic()
        idle_cutoff = self.cfg.recon_max_gap_seconds * 2
        for story in list(self.index.stories.values()):
            if story.status != "open":
                self.index.unregister(story.id)
                self._story_ingest.pop(story.id, None)
                continue
            last_in = self._story_ingest.get(story.id)
            if last_in is not None and now_mono - last_in > idle_cutoff:
                try:
                    self.store.save_story(story)
                except Exception:  # noqa: BLE001
                    self.metrics.inc("recon_errors")
                self.index.unregister(story.id)
                self._story_ingest.pop(story.id, None)
        # defensive: entity buckets must never hold empty sets
        for key in [k for k, v in self.index._by_entity.items() if not v]:
            self.index._by_entity.pop(key, None)
        for story in self.index.over_capacity():
            try:
                self.store.save_story(story)
            except Exception:  # noqa: BLE001
                self.metrics.inc("recon_errors")
            self.index.unregister(story.id)

    def _reload_from_store(self) -> None:
        """Rebuild open stories after a restart (late evidence support)."""
        self.status = "rebuilding"
        try:
            rows = self.store.load_active(self.cfg.recon_lookback_hours)
        except Exception:  # noqa: BLE001 - DB may not be up yet
            rows = []
        for row in rows:
            story = self._story_from_row(row)
            if story is not None:
                self.index.register(story)
        self.status = "idle"

    def _story_from_row(self, row: dict) -> AttackStory | None:
        from datetime import datetime

        def _ts(value):
            if not value:
                return 0.0
            try:
                return datetime.fromisoformat(
                    str(value).replace("Z", "+00:00")).timestamp()
            except (ValueError, TypeError):
                return 0.0

        inc = row["incident"]
        story = AttackStory(inc["id"], self.cfg.recon_max_gap_seconds,
                            self.cfg.recon_max_evidence)
        story.title = inc.get("title") or "Attack story"
        story.status = inc.get("status") or "open"
        story.severity = inc.get("severity") or "low"
        story.confidence_weight = _weight_from_confidence(
            int(inc.get("confidence") or 0))
        story.first_seen = _ts(inc.get("first_seen")) or float("inf")
        story.last_seen = _ts(inc.get("last_seen"))
        outcome = _jload(inc.get("outcome"), {})
        for h in outcome.get("stage_history") or []:
            story.stage_history.append(dict(h))
        # seed the no-evidence baseline, then replay recorded statuses so
        # stages without transitions keep their current assessment
        for s in story.stage_progression():
            story._stage_status[s["stage"]] = s["status"]
        for s in story.stage_history:
            if s.get("stage") and s.get("to"):
                story._stage_status[s["stage"]] = s["to"]
        for n in row["nodes"]:
            key = n["key"]
            story.entity_keys.add(key)
            story.nodes[key] = _node_from_row(n, _ts)
        for e in row["edges"]:
            story.edges[(e["src_key"], e["dst_key"], e["relation"])] = \
                _edge_from_row(e, _ts)
        for ev_row in row["evidence"]:
            detail = _jload(ev_row.get("detail"), {})
            attck = _jload(ev_row.get("attck"), [])
            item = EvidenceItem(
                ts_epoch=_ts(ev_row.get("ts")),
                ts_iso=ev_row.get("ts") or "",
                kind=ev_row.get("kind") or "alert",
                source=ev_row.get("source") or "pipeline",
                ref_index=ev_row.get("ref_index") or "",
                ref_id=ev_row.get("ref_id") or "",
                title=ev_row.get("title") or "",
                severity=ev_row.get("severity") or "informational",
                phase=ev_row.get("phase") or "unknown",
                summary=ev_row.get("summary") or "",
                detail=detail,
                stage=ev_row.get("stage") or "",
                attck=[t for t in attck
                       if isinstance(t, dict) and t.get("technique_id")])
            story.evidence.append(item)
            story._evidence_refs.add((item.ref_index, item.ref_id))
        story.signal_count = int(inc.get("signal_count") or 0)
        story.context_count = sum(
            1 for e in story.evidence if e.kind == "context")
        return story


# ---------------------------------------------------------------- helpers
def _jload(value, default):
    """Load a JSON column that may arrive as str/bytes (SQLite TEXT) or
    as an ALREADY-DECODED dict/list (Postgres JSONB via psycopg).

    v0.12.5: json.loads() on a decoded JSONB value raises TypeError, and
    the old except-JSONDecodeError guards let it escape - the recon
    thread died silently and incidents/edges stopped persisting
    (live-verified on the deployment VM).
    """
    import json as _json
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    if not value:
        return default
    try:
        return _json.loads(value)
    except (ValueError, TypeError):
        return default


def _weight_from_confidence(confidence: int) -> int:
    """Invert the saturating confidence curve for reload continuity."""
    import math
    if confidence >= 97:
        return 10_000
    if confidence <= 0:
        return 0
    ratio = confidence / 100.0
    if ratio >= 1:
        return 10_000
    return int(-120 * math.log(1 - ratio))


def _node_from_row(n: dict, _ts) -> "StoryNode":
    from app.correlation.story import StoryNode
    attrs = _jload(n.get("attrs"), {})
    return StoryNode(kind=n["kind"], key=n["key"], label=n["label"],
                     role=n.get("role") or "entity",
                     phase=n.get("phase") or "unknown",
                     confidence=int(n.get("confidence") or 50),
                     first_seen=_ts(n.get("first_seen")),
                     last_seen=_ts(n.get("last_seen")),
                     attrs=attrs)


def _edge_from_row(e: dict, _ts) -> "StoryEdge":
    from app.correlation.story import StoryEdge
    return StoryEdge(src=e["src_key"], dst=e["dst_key"],
                     relation=e["relation"],
                     phase=e.get("phase") or "unknown",
                     inferred=bool(e.get("inferred")),
                     first_seen=_ts(e.get("first_seen")),
                     last_seen=_ts(e.get("last_seen")),
                     evidence_count=int(e.get("evidence_count") or 0),
                     confidence=int(e.get("confidence") or 50))
