"""Measure the anomaly detector on freshly simulated data it has never seen.

Compares three detectors: rules only, Isolation Forest only, and the hybrid.
Usage:  python scripts/evaluate_detector.py [--normal 2000] [--per-attack 300]
"""

import argparse
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securevault.config import get_settings
from securevault.monitor.detector import Detector
from securevault.monitor.features import summarize
from securevault.monitor.model import load_model
from securevault.monitor.simulate import ATTACK_KINDS, simulate_window


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--normal", type=int, default=2000)
    p.add_argument("--per-attack", type=int, default=300)
    p.add_argument("--seed", type=int, default=2026)  # differs from the training seed on purpose
    args = p.parse_args()

    model = load_model(get_settings().model_path)
    if model is None:
        sys.exit("No model found. Train one first:  python -m securevault.monitor.train")
    detector = Detector(model=model)

    rng = random.Random(args.seed)
    plan = [("normal", args.normal)] + [(k, args.per_attack) for k in ATTACK_KINDS]
    flagged = {kind: {"rules": 0, "ml": 0, "hybrid": 0} for kind, _ in plan}
    for kind, count in plan:
        for _ in range(count):
            start, events = simulate_window(kind, rng)
            alerts = detector.analyze_window(summarize(events, start))
            rule = any(a.source == "rule" for a in alerts)
            ml = any(a.source == "ml" for a in alerts)
            flagged[kind]["rules"] += rule
            flagged[kind]["ml"] += ml
            flagged[kind]["hybrid"] += rule or ml

    print(f"\nModel: Isolation Forest, {len(model.trees)} trees, threshold {model.threshold:.3f}")
    print("Data:  simulated (never seen during training)\n")
    print(f"{'window type':<18}{'n':>6}   {'rules':>8}{'AI only':>10}{'hybrid':>9}")
    for kind, count in plan:
        f = flagged[kind]
        label = "normal (false +)" if kind == "normal" else kind + " (hit)"
        print(f"{label:<18}{count:>6}   " + "".join(
            f"{100 * f[k] / count:>{w}.1f}%" for k, w in (("rules", 7), ("ml", 9), ("hybrid", 8))))
    attacks = sum(c for k, c in plan if k != "normal")
    for name in ("rules", "ml", "hybrid"):
        hit = sum(flagged[k][name] for k in ATTACK_KINDS)
        fp = flagged["normal"][name]
        tp_rate, fp_rate = hit / attacks, fp / args.normal
        precision = hit / (hit + fp) if hit + fp else 0.0
        print(f"\n{name:>7}: recall {tp_rate:.1%}  false-positive rate {fp_rate:.1%}  precision {precision:.1%}")


if __name__ == "__main__":
    main()
