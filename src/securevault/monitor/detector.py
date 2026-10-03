"""Hybrid detector: fixed rules first, Isolation Forest second."""

from dataclasses import dataclass

from securevault.monitor.features import WindowStats, to_vector, tumbling_windows
from securevault.monitor.model import AnomalyModel
from securevault.monitor.rules import Alert, RuleThresholds, evaluate_rules


@dataclass(frozen=True)
class ScanResult:
    windows_scanned: int
    alerts: list[Alert]
    model_loaded: bool

    def to_dict(self) -> dict:
        return {
            "windows_scanned": self.windows_scanned,
            "model_loaded": self.model_loaded,
            "alerts": [a.to_dict() for a in self.alerts],
        }


class Detector:
    def __init__(
        self,
        model: AnomalyModel | None = None,
        thresholds: RuleThresholds = RuleThresholds(),
        window_seconds: int = 300,
        tz_offset_hours: float = 0,
    ) -> None:
        self.model = model
        self.thresholds = thresholds
        self.window_seconds = window_seconds
        self.tz_offset_hours = tz_offset_hours

    def analyze_window(self, stats: WindowStats) -> list[Alert]:
        alerts = evaluate_rules(stats, self.thresholds)
        if self.model is not None and stats.requests > 0:
            score = self.model.score(to_vector(stats))
            if score > self.model.threshold:
                alerts.append(
                    Alert(
                        "ml", "isolation_forest", "medium",
                        f"Unusual access pattern (anomaly score {score:.2f}, threshold {self.model.threshold:.2f})",
                        stats.window_start, round(score, 4),
                    )
                )
        return alerts

    def scan(self, entries: list[dict]) -> ScanResult:
        windows = tumbling_windows(entries, self.window_seconds, self.tz_offset_hours)
        alerts = [a for w in windows for a in self.analyze_window(w)]
        return ScanResult(len(windows), alerts, self.model is not None)
