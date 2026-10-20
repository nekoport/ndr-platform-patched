"""Async HTTP load generator for the NDR API (v0.12).

Mixed-traffic scenario that mirrors the SOC console: incident lists,
summaries, campaign views, guarded event search, alerts, graph and
health. Login happens once; all VUs reuse the session cookie.

Usage:
    python load_api.py --base-url http://127.0.0.1:8010 \
        --vus 25 --duration 30 --username admin --password '...'

Output: per-scenario request count, error count, p50/p95/p99 latency
and overall throughput. Exit code 0 unless error rate > 5%.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import time
from collections import defaultdict

import httpx

SCENARIOS: list[tuple[str, int, str, str]] = [
    # (name, weight %, method, path)
    ("incidents_list", 20, "GET", "/api/incidents?limit=50"),
    ("incidents_summary", 15, "GET", "/api/incidents/summary"),
    ("campaigns_list", 10, "GET", "/api/campaigns?limit=50"),
    ("campaign_detail", 10, "GET", "/api/campaigns/cmp-load-000"),
    ("events_search", 20, "POST", "/api/events/search"),
    ("alerts_search", 15, "POST", "/api/alerts/search"),
    ("graph_relationships", 5, "GET", "/api/graph/relationships?limit=100"),
    ("health_overview", 5, "GET", "/api/stats/overview"),
]
_WEIGHTS = [(n, w) for n, w, _, _ in SCENARIOS]
_NAMES = [n for n, _, _, _ in SCENARIOS]
_PATHS = {n: (m, p) for n, _, m, p in SCENARIOS}

# guarded search bodies (doc 4.5): empty query = match_all inside the
# time/alias guard; both endpoints go through validate_query + the
# serializer exactly like the console does
_POST_BODIES: dict[str, dict] = {
    "events_search": {"index": "ndr-events-read", "query": {},
                      "size": 50, "from": 0},
    "alerts_search": {"index": "ndr-alerts-read", "query": {},
                      "size": 50, "from": 0},
}


def pick_scenario(rng: random.Random) -> str:
    names, weights = zip(*_WEIGHTS)
    return rng.choices(list(names), weights=list(weights), k=1)[0]


def percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    k = min(len(sorted_vals) - 1, max(0, int(round((p / 100)
                                                   * (len(sorted_vals) - 1)))))
    return sorted_vals[k]


async def vu_worker(vu_id: int, client: httpx.AsyncClient, deadline: float,
                    rng: random.Random, lat: dict[str, list[float]],
                    errs: dict[str, int], counts: dict[str, int],
                    lock: asyncio.Lock) -> None:
    while time.monotonic() < deadline:
        name = pick_scenario(rng)
        method, path = _PATHS[name]
        t0 = time.perf_counter()
        try:
            if method == "POST":
                r = await client.post(path, json=_POST_BODIES[name])
            else:
                r = await client.get(path)
            ok = r.status_code < 400
        except Exception:  # noqa: BLE001 - connection errors count as fails
            r = None
            ok = False
        dt = (time.perf_counter() - t0) * 1000.0
        async with lock:
            counts[name] += 1
            if ok:
                lat[name].append(dt)
            else:
                errs[name] += 1
        # small think time keeps concurrency realistic (console paging)
        await asyncio.sleep(rng.uniform(0.01, 0.06))


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8010")
    ap.add_argument("--vus", type=int, default=25)
    ap.add_argument("--duration", type=int, default=30,
                    help="seconds of steady-state load")
    ap.add_argument("--username", default="admin")
    ap.add_argument("--password", default="loadtest-admin-pass")
    args = ap.parse_args()

    async with httpx.AsyncClient(base_url=args.base_url, timeout=10.0) as c:
        t0 = time.perf_counter()
        r = await c.post("/api/auth/login", json={
            "username": args.username, "password": args.password})
        login_ms = (time.perf_counter() - t0) * 1000
        if r.status_code != 200:
            print(f"LOGIN FAILED: HTTP {r.status_code}: {r.text[:200]}")
            return 2
        print(f"login ok in {login_ms:.1f} ms "
              f"(cookie {'set' if r.cookies else 'absent'})")

        # session cookie lives in THIS client's cookie jar; all VUs share it
        lat: dict[str, list[float]] = defaultdict(list)
        errs: dict[str, int] = defaultdict(int)
        counts: dict[str, int] = defaultdict(int)
        lock = asyncio.Lock()
        rng = random.Random(42)

        deadline = time.monotonic() + args.duration
        started = time.perf_counter()
        await asyncio.gather(*[
            vu_worker(i, c, deadline, rng, lat, errs, counts, lock)
            for i in range(args.vus)])
        wall = time.perf_counter() - started

    total = sum(counts.values())
    total_err = sum(errs.values())
    all_lat = sorted(x for v in lat.values() for x in v)

    print(f"\n=== NDR API load test: {args.vus} VUs x {args.duration}s "
          f"@ {args.base_url} ===")
    print(f"wall time      : {wall:.1f}s")
    print(f"requests       : {total} ({total / wall:.1f} req/s)")
    print(f"errors         : {total_err} "
          f"({(100 * total_err / total if total else 0):.2f}%)")
    if all_lat:
        print(f"latency p50/p95/p99 : "
              f"{percentile(all_lat, 50):.1f} / "
              f"{percentile(all_lat, 95):.1f} / "
              f"{percentile(all_lat, 99):.1f} ms")
    print("\nper scenario:")
    print(f"  {'scenario':<22}{'reqs':>8}{'err':>6}"
          f"{'p50 ms':>10}{'p95 ms':>10}{'p99 ms':>10}")
    for name in _NAMES:
        vals = sorted(lat[name])
        print(f"  {name:<22}{counts[name]:>8}{errs[name]:>6}"
              f"{percentile(vals, 50):>10.1f}{percentile(vals, 95):>10.1f}"
              f"{percentile(vals, 99):>10.1f}")

    result = {
        "vus": args.vus, "duration_s": args.duration,
        "wall_s": round(wall, 1), "requests": total,
        "rps": round(total / wall, 1) if wall else 0,
        "errors": total_err,
        "error_pct": round(100 * total_err / total, 2) if total else 0,
        "latency_ms": {
            "p50": round(percentile(all_lat, 50), 1),
            "p95": round(percentile(all_lat, 95), 1),
            "p99": round(percentile(all_lat, 99), 1)},
        "scenarios": {name: {
            "count": counts[name], "errors": errs[name],
            "p50_ms": round(percentile(sorted(lat[name]), 50), 1),
            "p95_ms": round(percentile(sorted(lat[name]), 95), 1),
            "p99_ms": round(percentile(sorted(lat[name]), 99), 1),
        } for name in _NAMES},
    }
    print("\nJSON result:")
    print(json.dumps(result, indent=2))
    err_rate = (100 * total_err / total) if total else 100
    return 0 if err_rate <= 5.0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
