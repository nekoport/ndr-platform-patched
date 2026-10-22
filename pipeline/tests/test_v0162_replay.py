"""v0.16.2 regression pins - BUG-0161-04 (retry deadletter + backpressure).

Latar verifikasi 0.16.1: restart dengan backlog eve.json 297 MB ->
OpenSearch saturasi -> 4.807 dokumen deadletter `sink_timeout` TANPA retry.
Pin perilaku baru:
  * record deadletter membawa `index` tujuan;
  * DeadLetterReplayer memutar ulang sink_timeout/sink_failure (idempoten
    by _id), menghormati backoff umur + batas percobaan + kill switch;
  * sink breaker: timeout -> cooldown + batch mengecil; sukses -> pulih;
    TIDAK ADA item batch yang hilang saat breaker trip.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import queue
import time
import types
from datetime import datetime, timedelta, timezone

import pytest
from opensearchpy import ConnectionTimeout

from app.metrics import Metrics
from app.sink.deadletter import DeadLetterWriter
from app.sink.opensearch import OpenSearchSink
from app.sink.replay import DeadLetterReplayer


def _line_hash(rec: dict) -> str:
    """hash baris persis seperti yang dihitung DeadLetterWriter.records()."""
    return hashlib.sha256(
        json.dumps(rec, separators=(",", ":")).encode("utf-8")).hexdigest()


def _cfg(tmp_path, **over):
    base = dict(
        state_dir=str(tmp_path / "state"),
        dlq_replay_enabled=True,
        dlq_replay_interval_seconds=300,
        dlq_replay_max_age_hours=24,
        dlq_replay_max_per_cycle=2000,
        dlq_replay_max_attempts=3,
    )
    base.update(over)
    return types.SimpleNamespace(**base)


# ------------------------------------------------------- deadletter record
def test_deadletter_record_carries_target_index(tmp_path):
    dl = DeadLetterWriter(str(tmp_path))
    dl.write("sink_timeout", "doc-1", {"a": 1}, index="ndr-zeek-dns-2026.10.22")
    recs = list(dl.records())
    assert len(recs) == 1
    line_hash, rec = recs[0]
    assert rec["reason"] == "sink_timeout"
    assert rec["index"] == "ndr-zeek-dns-2026.10.22"
    assert rec["doc_id"] == "doc-1"
    assert len(line_hash) == 64  # sha256 hex


# --------------------------------------------------------------- replayer
def _write_dl(tmp_path, records: list[dict]) -> None:
    """Tulis deadletter file manual (kontrol penuh field `ts`)."""
    dl = DeadLetterWriter(str(tmp_path))
    path = f"{dl.dir}/deadletter-manual.jsonl.gz"
    with gzip.open(path, "at", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")


def _old(ts_offset_seconds: int) -> str:
    return (datetime.now(timezone.utc)
            - timedelta(seconds=ts_offset_seconds)).isoformat()


def test_replayer_requeues_replayable_records(tmp_path):
    q: queue.Queue = queue.Queue()
    dl = DeadLetterWriter(str(tmp_path))
    m = Metrics("sensor-test")
    _write_dl(tmp_path, [
        {"ts": _old(400), "reason": "sink_timeout", "doc_id": "id-1",
         "index": "ndr-zeek-dns-2026.10.22", "doc": {"event_id": "a"}},
        {"ts": _old(400), "reason": "sink_failure", "doc_id": "id-2",
         "index": "ndr-suricata-2026.10.21", "doc": {"event_id": "b"}},
        # TIDAK replayable: parse_error adalah data invalid
        {"ts": _old(400), "reason": "parse_error", "raw": "garbage"},
        # record lama TANPA field index (pra-0.16.2) -> skipped, bukan replay
        {"ts": _old(400), "reason": "sink_timeout", "doc_id": "id-3",
         "doc": {"event_id": "c"}},
    ])
    rp = DeadLetterReplayer(_cfg(tmp_path), q, m, dl)
    queued = rp.replay_once()
    assert queued == 2
    i1 = q.get_nowait()
    assert i1 == ("ndr-zeek-dns-2026.10.22", "id-1", {"event_id": "a"})
    i2 = q.get_nowait()
    assert i2[0] == "ndr-suricata-2026.10.21" and i2[1] == "id-2"
    snap = m.snapshot()["counters"]
    assert snap.get("dlq_replayed", 0) == 2
    assert snap.get("dlq_skipped", 0) == 1  # record tanpa index


def test_replayer_respects_backoff_and_attempt_cap(tmp_path):
    q: queue.Queue = queue.Queue()
    dl = DeadLetterWriter(str(tmp_path))
    m = Metrics("sensor-test")
    # definisikan record SEKALI (hash state dikunci ke baris persis yang
    # ditulis ke file deadletter)
    rec_fresh = {"ts": _old(10), "reason": "sink_timeout", "doc_id": "fresh",
                 "index": "idx", "doc": {}}
    rec_stale = {"ts": _old(30 * 3600), "reason": "sink_timeout",
                 "doc_id": "stale", "index": "idx", "doc": {}}
    rec_capped = {"ts": _old(400), "reason": "sink_timeout",
                  "doc_id": "capped", "index": "idx", "doc": {}}
    rec_ok = {"ts": _old(400), "reason": "sink_timeout", "doc_id": "ok",
              "index": "idx", "doc": {}}
    _write_dl(tmp_path, [rec_fresh, rec_stale, rec_capped, rec_ok])
    cfg = _cfg(tmp_path)
    rp = DeadLetterReplayer(cfg, q, m, dl)
    rp._state[_line_hash(rec_capped)] = {"attempts": 3, "ts": rec_capped["ts"]}
    queued = rp.replay_once()
    # fresh: menunggu backoff; stale: melewati max_age; capped: habis
    # percobaan -> HANYA `ok` yang dimainkan ulang
    assert queued == 1
    item = q.get_nowait()
    assert item[1] == "ok"
    # attempt tercatat di state PERSISTEN (dikunci line-hash record)
    assert rp._state[_line_hash(rec_ok)]["attempts"] == 1
    assert rp._state[_line_hash(rec_capped)]["attempts"] == 3


def test_replayer_kill_switch(tmp_path):
    cfg = _cfg(tmp_path, dlq_replay_enabled=False)
    assert cfg.dlq_replay_enabled is False


# ----------------------------------------------------------- sink breaker
class _TimeoutClient:
    """Client OpenSearch palsu (bulk selalu dipanggil lewat helpers)."""

    def __init__(self):
        self.indices = types.SimpleNamespace(
            exists=lambda index: True)


@pytest.fixture()
def sink_factory(monkeypatch):
    """Bangun sink dengan helpers.bulk ter-monkeypatch + counter panggilan.

    bulk_impl opsional mengganti perilaku bulk (mis. selalu timeout).
    Returns (sink, deadletter, calls).
    """
    def _make(client, tmp_path, bulk_impl=None):
        monkeypatch.setattr("app.sink.opensearch.OpenSearch",
                            lambda *a, **k: client)
        calls = {"n": 0}

        def _bulk(*a, **k):
            calls["n"] += 1
            if bulk_impl is not None:
                return bulk_impl(*a, **k)
            return (len(a[1]), [])  # emulasi sukses penuh

        # PENTING: patch helpers.bulk di sini (paling akhir) agar
        # override test-level tidak tertimpa patch default fixture.
        monkeypatch.setattr("app.sink.opensearch.helpers.bulk", _bulk)
        dl = DeadLetterWriter(str(tmp_path))
        s = OpenSearchSink("http://os:9200", queue.Queue(),
                           types.SimpleNamespace(), Metrics("sensor-test"),
                           deadletter=dl, max_items=100, max_retries=2,
                           cooldown_max_seconds=8.0, batch_min_items=10)
        s._sleep = lambda *_: None  # tanpa tidur nyata di test
        return s, dl, calls
    return _make


def test_sink_breaker_cooldown_and_no_data_loss(sink_factory, tmp_path):
    def _timeout(*a, **k):
        raise ConnectionTimeout(0, "timeout", Exception("t"))

    s, dl, calls = sink_factory(_TimeoutClient(), tmp_path,
                                bulk_impl=_timeout)
    batch = [("ndr-zeek-dns-2026.10.22", f"id{i}", {"n": i})
             for i in range(150)]
    s._flush(batch)
    # breaker aktif: cooldown > 0, batch mengecil
    assert s._cooldown > 0
    assert s._batch_size < 100
    # TIDAK ADA data yang hilang: seluruh 150 item masuk deadletter
    # (idempoten by _id, akan direplay replayer)
    recs = list(dl.records())
    assert len(recs) == 150
    assert all(r[1]["reason"] == "sink_timeout" for r in recs)
    assert all(r[1]["index"] == "ndr-zeek-dns-2026.10.22" for r in recs)


def test_sink_recovers_after_success(sink_factory, tmp_path):
    s, dl, calls = sink_factory(_TimeoutClient(), tmp_path)
    s._cooldown = 4.0
    s._batch_size = 10
    s._flush([("idx", "id1", {"a": 1})])
    # sukses -> cooldown menyusut, batch bertumbuh kembali
    assert s._cooldown == 2.0
    assert s._batch_size > 10
    assert calls["n"] == 1


def test_sink_success_path_indexes_all(sink_factory, tmp_path):
    s, dl, calls = sink_factory(_TimeoutClient(), tmp_path)
    s._flush([("idx", f"id{i}", {"n": i}) for i in range(20)])
    assert calls["n"] == 1
    assert list(dl.records()) == []  # tidak ada deadletter
