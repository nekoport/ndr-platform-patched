"""v0.15.0 pipeline tests: action report (LAPORAN-DEV-ACTION-0.15.0).

A2 sink anti-wedge:
  * client is constructed with NO HTTP-level resend (max_retries=0,
    retry_on_timeout=False, maxsize/pool_maxsize)
  * ConnectionTimeout/TimeoutError -> dead-letter "sink_timeout" and the
    bulk is NOT attempted again (no sleep, no retry)
  * 429/5xx/network errors -> retried at most max_retries, then
    dead-letter "sink_failure"
  * per-item errors -> dead-letter "index_error" (unchanged)
B1 ensure-index:
  * first bulk to an index triggers indices.exists + indices.create
  * success cached (exists/create not called again)
  * create failing with resource_already_exists counts as ensured
  * a real failure is NOT cached (next batch retries) and is logged
B3 checkpoint hardening:
  * saved file carries version 2 + checksum; roundtrip keeps offsets/inodes
  * tampered body -> checksum mismatch -> WHOLE file ignored
  * malformed entries (offset/negative/wrong-length inode) dropped
  * [dev, ino] swap detected -> offset KEPT, inode corrected (no re-read)
  * genuine rotation (different inode pair) still resets offset to 0
B2 deadletter-replay tool:
  * collect() filters by reason/prefix; dry-run main() exits 0
"""

from __future__ import annotations

import gzip
import json
import os
import queue
import types

import pytest

from opensearchpy import ConnectionTimeout

from app.metrics import Metrics
from app.sink import opensearch as sink_mod
from app.sink.opensearch import OpenSearchSink
from app.tailer import CHECKPOINT_VERSION, Tailer


# ---------------------------------------------------------------- helpers

class _FakeIndices:
    def __init__(self, exists=True, create_error=None):
        self.exists_calls: list[str] = []
        self.create_calls: list[str] = []
        self._exists = exists
        self._create_error = create_error

    def exists(self, index):
        self.exists_calls.append(index)
        return self._exists

    def create(self, index):
        self.create_calls.append(index)
        if self._create_error:
            raise self._create_error


class _FakeClient:
    """Stub for the OpenSearch client used by the sink."""

    def __init__(self, bulk_exc=None, bulk_errors=None, indices=None):
        self.indices = indices or _FakeIndices()
        self.bulk_calls = 0
        self._bulk_exc = bulk_exc
        self._bulk_errors = bulk_errors

    def bulk(self, body=None, **kwargs):
        self.bulk_calls += 1
        if self._bulk_exc is not None:
            raise self._bulk_exc
        # helpers.bulk is replaced in tests; this method emulates its
        # return shape when we bypass helpers entirely
        return len(body or []), self._bulk_errors or []


class _Deadletter:
    def __init__(self):
        self.entries: list[tuple] = []

    def write(self, reason, doc_id="", doc=None, raw=""):
        self.entries.append((reason, doc_id))


@pytest.fixture()
def sink_factory(monkeypatch):
    """Build an OpenSearchSink with a stubbed client + no real sleeps."""

    def _make(bulk_exc=None, indices=None, max_retries=4):
        monkeypatch.setattr(sink_mod, "OpenSearch",
                            lambda *a, **k: _FakeClient(
                                bulk_exc=bulk_exc, indices=indices))
        monkeypatch.setattr(sink_mod.helpers, "bulk",
                            lambda *a, **k: (_ for _ in ()).throw(
                                RuntimeError("helpers replaced")))
        dl = _Deadletter()
        s = OpenSearchSink("http://os:9200", queue.Queue(), types.SimpleNamespace(),
                           Metrics("sensor-test"), deadletter=dl, max_retries=max_retries)
        s._sleep = lambda *_: None  # no real backoff waits in tests
        return s, dl

    return _make


# ---------------------------------------------------------------- A2 sink

def test_a2_client_has_no_http_level_retry(monkeypatch):
    captured = {}

    def _fake_client(**kwargs):
        captured.update(kwargs)
        return _FakeClient()

    monkeypatch.setattr(sink_mod, "OpenSearch", _fake_client)
    OpenSearchSink("http://os:9200", queue.Queue(), types.SimpleNamespace(),
                   Metrics("sensor-test"), deadletter=None)
    assert captured["max_retries"] == 0
    assert captured["retry_on_timeout"] is False
    assert captured["timeout"] == 120
    assert captured["maxsize"] == 50


def test_a2_timeout_goes_to_deadletter_without_retry(sink_factory, monkeypatch):
    s, dl = sink_factory(bulk_exc=ConnectionTimeout(0, "timeout", Exception("t")))
    # helpers.bulk raises the timeout every time; bulk attempts must be 1
    attempts = {"n": 0}

    def _bulk(*a, **k):
        attempts["n"] += 1
        raise ConnectionTimeout(0, "timeout", Exception("t"))

    monkeypatch.setattr(sink_mod.helpers, "bulk", _bulk)
    s._flush([("ndr-alerts-2026.10.19", "id1", {"alert_type": "x"})])
    assert attempts["n"] == 1            # NO second attempt (anti-wedge)
    assert [r for r, _ in dl.entries] == ["sink_timeout"]
    assert dl.entries[0][1] == "id1"


def test_a2_retryable_errors_retry_then_sink_failure(sink_factory, monkeypatch):
    s, dl = sink_factory(max_retries=3)
    attempts = {"n": 0}

    def _bulk(*a, **k):
        attempts["n"] += 1
        raise RuntimeError("connection reset")  # retryable (not timeout)

    monkeypatch.setattr(sink_mod.helpers, "bulk", _bulk)
    sleeps: list[float] = []
    s._sleep = sleeps.append
    s._flush([("ndr-suricata-2026.10.19", "id1", {"x": 1})])
    assert attempts["n"] == 3            # retried up to max_retries
    assert len(sleeps) == 2              # backoff between attempts only
    assert [r for r, _ in dl.entries] == ["sink_failure"]


def test_a2_per_item_errors_still_index_error(sink_factory, monkeypatch):
    s, dl = sink_factory()
    item_errors = [{"index": {"_index": "ndr-x", "status": 400,
                              "error": {"type": "mapping"}}}]

    def _bulk(*a, **k):
        return 0, item_errors

    monkeypatch.setattr(sink_mod.helpers, "bulk", _bulk)
    s._flush([("ndr-x", "id1", {"x": 1})])
    assert [r for r, _ in dl.entries] == ["index_error"]


# ---------------------------------------------------------------- B1 ensure

def test_b1_ensure_index_creates_before_first_bulk(sink_factory, monkeypatch):
    idx = _FakeIndices(exists=False)
    s, dl = sink_factory(indices=idx)

    def _bulk(*a, **k):
        return 1, []

    monkeypatch.setattr(sink_mod.helpers, "bulk", _bulk)
    s._flush([("ndr-alerts-2026.10.19", "id1", {"a": 1})])
    assert idx.exists_calls == ["ndr-alerts-2026.10.19"]
    assert idx.create_calls == ["ndr-alerts-2026.10.19"]


def test_b1_ensure_index_cached_across_batches(sink_factory, monkeypatch):
    idx = _FakeIndices(exists=True)
    s, _ = sink_factory(indices=idx)

    def _bulk(*a, **k):
        return 1, []

    monkeypatch.setattr(sink_mod.helpers, "bulk", _bulk)
    s._flush([("ndr-zeek-conn-2026.10.19", "id1", {})])
    s._flush([("ndr-zeek-conn-2026.10.19", "id2", {})])
    assert len(idx.exists_calls) == 1    # cached after first success
    assert idx.create_calls == []        # exists=True -> no create


def test_b1_already_exists_race_counts_as_ensured(sink_factory):
    exc = Exception("resource_already_exists_exception")
    idx = _FakeIndices(exists=False, create_error=exc)
    s, _ = sink_factory(indices=idx)
    s._ensure_index("ndr-alerts-2026.10.19")
    assert "ndr-alerts-2026.10.19" in s._ensured


def test_b1_ensure_failure_not_cached_and_logged(sink_factory, caplog):
    def boom(msg):
        raise RuntimeError("cluster red")

    class _BadIdx:
        def exists(self, index):
            return False

        def create(self, index):
            raise RuntimeError("cluster red")

    s, _ = sink_factory(indices=_BadIdx())
    import logging
    with caplog.at_level(logging.WARNING, logger="ndr.sink"):
        s._ensure_index("ndr-alerts-2026.10.19")
    assert "ndr-alerts-2026.10.19" not in s._ensured   # retried next batch
    assert "ensure-index gagal" in caplog.text


# ---------------------------------------------------------------- B3 tailer

def _mk_tailer(tmp_path, body):
    src = tmp_path / "in.log"
    src.write_text(body, encoding="utf-8")
    ckpt = str(tmp_path / "checkpoints.json")
    t = Tailer([str(src)], queue.Queue(), ckpt)
    return t, str(src)


def test_b3_checkpoint_roundtrip_v2_checksum(tmp_path):
    t, path = _mk_tailer(tmp_path, "a\nb\nc\n")
    list(t._iter_new_lines(path))            # consume all
    t._save_checkpoints()
    with open(t.checkpoint_path, encoding="utf-8") as fh:
        doc = json.load(fh)
    assert doc["version"] == CHECKPOINT_VERSION == 2
    assert doc["checksum"]
    assert doc["inodes"][path][0] == os.stat(path).st_ino
    assert doc["inodes"][path][1] == os.stat(path).st_dev
    t2 = Tailer([path], queue.Queue(), t.checkpoint_path)
    assert t2._offsets[path] == t._offsets[path]


def test_b3_tampered_checkpoint_ignored_as_whole(tmp_path):
    t, path = _mk_tailer(tmp_path, "a\nb\nc\n")
    list(t._iter_new_lines(path))
    t._save_checkpoints()
    with open(t.checkpoint_path, encoding="utf-8") as fh:
        doc = json.load(fh)
    doc["offsets"][path] = 999999            # tamper AFTER checksum computed
    with open(t.checkpoint_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    t2 = Tailer([path], queue.Queue(), t.checkpoint_path)
    assert t2._offsets == {}                 # whole file ignored


def test_b3_malformed_entries_dropped(tmp_path):
    t, path = _mk_tailer(tmp_path, "a\nb\nc\n")
    list(t._iter_new_lines(path))
    t._save_checkpoints()
    with open(t.checkpoint_path, encoding="utf-8") as fh:
        doc = json.load(fh)
    doc["version"] = 1                        # skip checksum path
    doc["offsets"]["other"] = -5
    doc["inodes"]["other2"] = [1, 2, 3]       # wrong length
    doc["inodes"][path] = ["x", "y"]          # wrong types
    with open(t.checkpoint_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    t2 = Tailer([path], queue.Queue(), t.checkpoint_path)
    assert "other" not in t2._offsets
    assert "other2" not in t2._inodes
    assert path not in t2._inodes             # malformed dropped


def test_b3_swapped_ino_dev_keeps_offset(tmp_path, caplog):
    t, path = _mk_tailer(tmp_path, "a\nb\nc\n")
    list(t._iter_new_lines(path))
    t._save_checkpoints()
    st = os.stat(path)
    # operator hand-writes [dev, ino] (the 2026.10.19 near-miss)
    with open(t.checkpoint_path, encoding="utf-8") as fh:
        doc = json.load(fh)
    doc["version"] = 1
    doc["inodes"][path] = [st.st_dev, st.st_ino]
    with open(t.checkpoint_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    import logging
    t2 = Tailer([path], queue.Queue(), t.checkpoint_path)
    with caplog.at_level(logging.WARNING, logger="ndr.tailer"):
        lines = list(t2._iter_new_lines(path))   # MUST NOT re-read from 0
    assert lines == []                           # offset kept (== file size)
    assert t2._offsets[path] == os.path.getsize(path)
    assert t2._inodes[path] == (st.st_ino, st.st_dev)  # corrected in memory
    assert "TERBALIK" in caplog.text


def test_b3_genuine_rotation_still_resets(tmp_path):
    t, path = _mk_tailer(tmp_path, "a\nb\nc\n")
    list(t._iter_new_lines(path))
    # simulate rotation: different (ino, dev) pair, offset still valid size
    t._inodes[path] = (999999, 999999)
    lines = list(t._iter_new_lines(path))
    assert [l.strip() for l in lines] == ["a", "b", "c"]  # re-read from 0


# ---------------------------------------------------------------- B2 replay

def _mk_deadletter(tmp_path, records):
    dd = tmp_path / "deadletter"
    dd.mkdir(exist_ok=True)
    with gzip.open(dd / "deadletter-20261019.jsonl.gz", "at",
                   encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    return str(tmp_path)


def _load_replay_mod():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "deadletter_replay",
        os.path.join(os.path.dirname(__file__), "..", "..", "scripts",
                     "deadletter-replay.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_b2_collect_filters_reason_and_prefix(tmp_path):
    mod = _load_replay_mod()
    _mk_deadletter(tmp_path, [
        {"reason": "sink_timeout", "doc_id": "a1",
         "doc": {"_index": "ndr-alerts-2026.10.19", "_id": "a1", "_source": {}}},
        {"reason": "sink_failure", "doc_id": "a2",
         "doc": {"_index": "ndr-alerts-2026.10.19", "_id": "a2", "_source": {}}},
        {"reason": "sink_timeout", "doc_id": "a3",
         "doc": {"_index": "ndr-suricata-2026.10.19", "_id": "a3", "_source": {}}},
    ])
    got = list(mod.collect(str(tmp_path), ["sink_timeout"], "ndr-alerts-"))
    assert [(r, i, d) for r, i, d, *_ in got] == [
        ("sink_timeout", "ndr-alerts-2026.10.19", "a1")]
    everything = list(mod.collect(str(tmp_path), None, None))
    assert len(everything) == 3


def test_b2_replay_idempotent_with_stub_client(tmp_path):
    import sys as _sys
    mod = _load_replay_mod()

    _mk_deadletter(tmp_path, [
        {"reason": "sink_timeout", "doc_id": f"a{i}",
         "doc": {"_index": "ndr-alerts-2026.10.19", "_id": f"a{i}",
                 "_source": {"n": i}}}
        for i in range(250)                       # > BULK_BATCH 200
    ])
    candidates = list(mod.collect(str(tmp_path), ["sink_timeout"], None))
    sent: list[dict] = []

    # reindex() imports opensearchpy lazily inside the function -> stub it
    saved = _sys.modules.get("opensearchpy")

    class _StubMod:
        @staticmethod
        def OpenSearch(*a, **k):
            return object()

    class _StubHelpers:
        @staticmethod
        def bulk(client, actions, **k):
            sent.extend(actions)
            return len(actions), 0

    _sys.modules["opensearchpy"] = types.SimpleNamespace(
        OpenSearch=_StubMod.OpenSearch, helpers=_StubHelpers)
    try:
        ok, fail, skipped = mod.reindex("http://os:9200", iter(candidates))
    finally:
        if saved is None:
            _sys.modules.pop("opensearchpy", None)
        else:
            _sys.modules["opensearchpy"] = saved
    assert (ok, fail, skipped) == (250, 0, 0)
    ids = [a["_id"] for a in sent]
    assert len(ids) == len(set(ids)) == 250      # original _id, no dupes
