"""Layer 1 of the monitor: explicit, explainable rules."""

from dataclasses import dataclass

from securevault.monitor.features import WindowStats


@dataclass(frozen=True)
class RuleThresholds:
    max_requests: int = 30  # per window
    max_failed_unlocks: int = 5
    max_mb_transferred: float = 50.0
    max_distinct_files: int = 15
    night_start_hour: float = 0.0  # inclusive, local time
    night_end_hour: float = 5.0  # exclusive, local time


@dataclass(frozen=True)
class Alert:
    source: str  # "rule" or "ml"
    rule: str
    severity: str  # "medium" or "high"
    message: str
    window_start: float
    score: float | None = None

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "window_start": self.window_start,
            "score": self.score,
        }


def evaluate_rules(stats: WindowStats, t: RuleThresholds = RuleThresholds()) -> list[Alert]:
    alerts: list[Alert] = []
    ws = stats.window_start
    if stats.failed_unlocks >= t.max_failed_unlocks:
        alerts.append(Alert("rule", "failed_unlocks", "high",
                            f"{stats.failed_unlocks} failed unlock attempts in one window (possible brute force)", ws))
    if stats.requests > t.max_requests:
        alerts.append(Alert("rule", "request_burst", "high",
                            f"{stats.requests} requests in one window (limit {t.max_requests})", ws))
    if stats.mb_transferred > t.max_mb_transferred:
        alerts.append(Alert("rule", "bulk_transfer", "high",
                            f"{stats.mb_transferred:.0f} MB moved in one window (limit {t.max_mb_transferred:.0f} MB)", ws))
    if stats.distinct_files > t.max_distinct_files:
        alerts.append(Alert("rule", "many_files", "medium",
                            f"{stats.distinct_files} different files touched in one window (limit {t.max_distinct_files})", ws))
    if (stats.downloads or stats.deletes) and t.night_start_hour <= stats.local_hour < t.night_end_hour:
        alerts.append(Alert("rule", "night_access", "medium",
                            f"Files read or deleted at {stats.local_hour:04.1f}h local time, outside normal hours", ws))
    return alerts
