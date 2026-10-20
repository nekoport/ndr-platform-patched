"""IntelService: job-queue consumer + scheduler (doc 9.2 / 9.3).

The API (UI "Update Now" button / schedule) inserts rows with status
`queued` into ti_update_jobs; this thread claims them, runs the feed
adapter, upserts IOCs, sweeps expiry, writes the job result and nudges
the matcher to reload.

Job status lifecycle: queued -> running -> success | partial_success | failed
  * success         - all rows ingested, no warnings
  * partial_success - ingested but with warnings (skipped rows etc.)
  * failed          - transport/schema error; NO ioc changes are applied
                      (a failed feed never expires or deletes valid IOCs)

An optional scheduled pass enqueues due feeds (trigger='schedule').
"""

from __future__ import annotations

import threading
import traceback
import uuid
from datetime import datetime, timezone

from app.intel.feeds import run_feed
from app.intel.matcher import IntelMatcher
from app.intel.store import IntelStore, iso, utcnow


class IntelService(threading.Thread):
    def __init__(self, cfg, metrics, store: IntelStore | None = None):
        super().__init__(daemon=True, name="intel-collector")
        self.cfg = cfg
        self.metrics = metrics
        self.store = store or IntelStore(cfg.ti_database_url)
        self.matcher = IntelMatcher(self.store,
                                    reload_seconds=cfg.ti_reload_seconds)
        self.refresh_lock = threading.Lock()   # serialize pipeline reloads
        self._stop = threading.Event()
        self._last_sweep = 0.0
        self.status = "starting"               # starting | idle | running-job

    # ------------------------------------------------------------- control
    def stop(self) -> None:
        self._stop.set()
        self.matcher.request_reload()

    def match(self, ev) -> list[dict]:
        return self.matcher.match(ev)

    def snapshot_size(self) -> int:
        return self.matcher.snapshot_size()

    # ------------------------------------------------------------- run
    def run(self) -> None:
        try:
            self.matcher.reload()
        except Exception:  # noqa: BLE001 - DB may not be up yet
            self.metrics.inc("ti_errors")
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:  # noqa: BLE001 - service must not die
                self.metrics.inc("ti_errors")
            self._stop.wait(self.cfg.ti_job_poll_seconds)

    def _tick(self) -> None:
        job = self.store.claim_queued_job()
        if job is not None:
            self._run_job(job)
            return
        if self.cfg.ti_auto_schedule:
            self._maybe_enqueue_scheduled()
        self.status = "idle"

    # ------------------------------------------------------------- jobs
    def _run_job(self, job: dict) -> None:
        self.status = "running-job"
        # v0.12.5: created_at arrives as a datetime on Postgres and used to
        # be stuffed into counts raw - json.dumps in finish_job then raised
        # TypeError, the finally-block never committed, and the job stayed
        # 'running' forever. Stringify here; finish_job adds a default=str
        # safety net on top.
        counts = {"queued_at": str(job.get("created_at") or "")}
        error: str | None = None
        status = "success"
        try:
            feed = self._feed_by_id(job["feed_id"])
            if feed is None:
                raise ValueError(f"feed {job['feed_id']} no longer exists")
            result = run_feed(
                {"name": feed["name"], "adapter": feed["adapter"],
                 "url": feed.get("url"), **(feed.get("config") or {})},
                timeout=self.cfg.ti_http_timeout,
                verify=self.cfg.ti_verify_tls)
            upsert = self.store.upsert_iocs(
                {"name": feed["name"]}, result.iocs, feed.get("ttl_days", 14))
            expired = self.store.expire_stale()
            counts.update(upsert)
            counts["expired_total"] = expired
            counts["warnings"] = result.warnings
            counts["feed_version"] = {
                k: v for k, v in (result.version or {}).items() if v}
            if result.warnings:
                status = "partial_success"
            self._touch_feed(feed["id"], "success")
            self.metrics.inc("ti_updates_ok")
        except Exception as exc:  # noqa: BLE001 - job failure is recorded
            status = "failed"
            error = f"{type(exc).__name__}: {exc}"
            counts["traceback"] = traceback.format_exc(limit=4)
            self._touch_feed(job.get("feed_id"), "failed")
            self.metrics.inc("ti_updates_failed")
        finally:
            self.store.finish_job(job["id"], status, counts, error)
            # reload synchronously so the very next event uses fresh IOCs
            try:
                self.matcher.reload()
            except Exception:  # noqa: BLE001
                self.metrics.inc("ti_errors")
            self.metrics.inc(f"ti_job_{status}")
            self.status = "idle"

    def _feed_by_id(self, feed_id: str | None) -> dict | None:
        if not feed_id:
            return None
        for feed in self.store.feeds():
            if feed["id"] == feed_id:
                return feed
        return None

    def _touch_feed(self, feed_id: str | None, status: str) -> None:
        if not feed_id:
            return
        from sqlalchemy import text
        with self.store.engine.begin() as conn:
            conn.execute(text(
                "UPDATE ti_feeds SET last_status=:st, "
                "last_success_at=CASE WHEN :st='success' THEN :now "
                "ELSE last_success_at END, updated_at=:now WHERE id=:id"),
                {"st": status, "now": iso(utcnow()), "id": feed_id})

    # -------------------------------------------------------- scheduler
    def _maybe_enqueue_scheduled(self) -> None:
        now = datetime.now(timezone.utc).timestamp()
        if now - self._last_sweep < 60.0:
            return
        self._last_sweep = now
        try:
            due = [f for f in self.store.feeds()
                   if self.store.feed_schedule_due(
                       f, self.cfg.ti_job_poll_seconds * 4)]
        except Exception:  # noqa: BLE001
            return
        for feed in due:
            self.enqueue_job(feed["id"], feed["name"], trigger="schedule")

    def enqueue_job(self, feed_id: str, feed_name: str,
                    trigger: str = "manual") -> int | None:
        from sqlalchemy import text
        with self.store.engine.begin() as conn:
            res = conn.execute(text(
                "INSERT INTO ti_update_jobs (id, feed_id, feed_name, trigger, "
                "status, counts, created_at) VALUES (:id, :fid, :fname, "
                ":trigger, 'queued', '{}', :now)"),
                {"id": uuid.uuid4().hex[:16], "fid": feed_id,
                 "fname": feed_name, "trigger": trigger,
                 "now": iso(utcnow())})
            return res.rowcount or None
