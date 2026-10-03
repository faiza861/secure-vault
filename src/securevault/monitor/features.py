"""Turn raw audit events into per-window numbers that rules and the AI model can read."""

import math
from collections import defaultdict
from dataclasses import dataclass

# Events that count as "someone is using the vault". Alerts and scans are excluded so
# the monitor never reacts to its own output.
ACTIVITY_EVENTS = frozenset({"upload", "download", "delete", "unlock", "unlock_failed"})
TRANSFER_EVENTS = frozenset({"upload", "download"})

FEATURE_NAMES = [
    "hour_sin",  # time of day as a point on a circle, so 23:55 and 00:05 are close
    "hour_cos",
    "requests",
    "mb_transferred",
    "failed_unlocks",
    "distinct_files",
]


@dataclass(frozen=True)
class WindowStats:
    window_start: float
    local_hour: float  # 0 <= h < 24
    requests: int
    downloads: int
    deletes: int
    mb_transferred: float
    failed_unlocks: int
    distinct_files: int


def local_hour(ts: float, tz_offset_hours: float = 0) -> float:
    return ((ts / 3600.0) + tz_offset_hours) % 24.0


def summarize(
    events: list[dict], window_start: float, tz_offset_hours: float = 0
) -> WindowStats:
    activity = [e for e in events if e["event"] in ACTIVITY_EVENTS]
    files = {e["details"].get("file_id") for e in activity if e["details"].get("file_id")}
    moved = sum(e["details"].get("bytes", 0) for e in activity if e["event"] in TRANSFER_EVENTS)
    return WindowStats(
        window_start=window_start,
        local_hour=local_hour(window_start, tz_offset_hours),
        requests=len(activity),
        downloads=sum(1 for e in activity if e["event"] == "download"),
        deletes=sum(1 for e in activity if e["event"] == "delete"),
        mb_transferred=moved / 1_000_000,
        failed_unlocks=sum(1 for e in activity if e["event"] == "unlock_failed"),
        distinct_files=len(files),
    )


def to_vector(stats: WindowStats) -> list[float]:
    angle = 2 * math.pi * stats.local_hour / 24.0
    return [
        math.sin(angle),
        math.cos(angle),
        float(stats.requests),
        stats.mb_transferred,
        float(stats.failed_unlocks),
        float(stats.distinct_files),
    ]


def tumbling_windows(
    entries: list[dict], window_seconds: int, tz_offset_hours: float = 0
) -> list[WindowStats]:
    """Split the log into fixed, non-overlapping windows and summarise each busy one."""
    buckets: dict[int, list[dict]] = defaultdict(list)
    for entry in entries:
        if entry["event"] in ACTIVITY_EVENTS:
            buckets[int(entry["ts"] // window_seconds)].append(entry)
    return [
        summarize(buckets[b], b * window_seconds, tz_offset_hours) for b in sorted(buckets)
    ]
