"""Synthetic access logs for training and evaluating the detector.

IMPORTANT: this is simulated data. A real deployment would train on its own history.
The numbers below describe a made-up "normal" user (a few requests per five minutes,
mostly during the working day) and four kinds of misuse.
"""

import math
import random

WINDOW_SECONDS = 300
BASE_DAY = 1_767_571_200  # 2026-01-05 00:00:00 UTC (a Monday)
ATTACK_KINDS = ("bulk_download", "brute_force", "night_access", "moderate_scrape")


def _poisson(rng: random.Random, lam: float) -> int:
    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


def _size(rng: random.Random, median: float) -> int:
    return max(1, int(rng.lognormvariate(math.log(median), 0.9)))


def _event(kind: str, ts: float, file_id: str | None, nbytes: int = 0) -> dict:
    details = {"bytes": nbytes}
    if file_id:
        details["file_id"] = file_id
    return {"ts": round(ts, 3), "event": kind, "actor": "sim", "details": details}


def _file_ids(rng: random.Random, pool: int, count: int, distinct: bool) -> list[str]:
    ids = [f"{i:032x}" for i in range(pool)]
    return rng.sample(ids, count) if distinct else [rng.choice(ids) for _ in range(count)]


def _pick_start(rng: random.Random, hour_choices: list[tuple[float, float, float]]) -> float:
    lo, hi = rng.choices(
        [(a, b) for a, b, _ in hour_choices], weights=[w for _, _, w in hour_choices]
    )[0]
    day = rng.randrange(0, 60)
    slot = rng.randrange(int(lo * 3600 // WINDOW_SECONDS), int(hi * 3600 // WINDOW_SECONDS))
    return BASE_DAY + day * 86_400 + slot * WINDOW_SECONDS


NORMAL_HOURS = [(7, 9, 0.10), (9, 18, 0.75), (18, 22, 0.15)]
ANY_DAYTIME = [(7, 22, 1.0)]
NIGHT_HOURS = [(0, 5, 1.0)]


def simulate_window(kind: str, rng: random.Random) -> tuple[float, list[dict]]:
    """Return (window_start, events) for one five-minute window of the given kind."""
    events: list[dict] = []

    def at(start: float) -> float:
        return start + rng.uniform(0, WINDOW_SECONDS - 1)

    if kind == "normal":
        start = _pick_start(rng, NORMAL_HOURS)
        events.append(_event("unlock", at(start), None))
        for _ in range(max(1, _poisson(rng, 2.5))):
            action = rng.choices(["download", "upload", "delete"], [0.5, 0.42, 0.08])[0]
            fid = _file_ids(rng, 40, 1, False)[0]
            events.append(_event(action, at(start), fid, _size(rng, 150_000) if action != "delete" else 0))
        if rng.random() < 0.03:
            events.append(_event("unlock_failed", at(start), None))
    elif kind == "bulk_download":
        start = _pick_start(rng, ANY_DAYTIME)
        n = rng.randint(25, 70)
        for fid in _file_ids(rng, 120, n, True):
            events.append(_event("download", at(start), fid, _size(rng, 1_500_000)))
    elif kind == "brute_force":
        start = _pick_start(rng, ANY_DAYTIME)
        for _ in range(rng.randint(8, 60)):
            events.append(_event("unlock_failed", at(start), None))
    elif kind == "night_access":
        start = _pick_start(rng, NIGHT_HOURS)
        events.append(_event("unlock", at(start), None))
        for fid in _file_ids(rng, 40, rng.randint(2, 6), False):
            events.append(_event("download", at(start), fid, _size(rng, 200_000)))
    elif kind == "moderate_scrape":
        # Quiet-ish copying: not enough to trip the fixed thresholds on its own.
        start = _pick_start(rng, ANY_DAYTIME)
        events.append(_event("unlock", at(start), None))
        for fid in _file_ids(rng, 60, rng.randint(9, 14), True):
            events.append(_event("download", at(start), fid, _size(rng, 700_000)))
    else:
        raise ValueError(f"unknown kind: {kind}")
    events.sort(key=lambda e: e["ts"])
    return start, events
