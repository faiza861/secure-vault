"""Train the anomaly model on simulated NORMAL behaviour and save it to models/.

Run:  python -m securevault.monitor.train
Needs scikit-learn and numpy (see requirements-ml.txt).
"""

import argparse
import random

from securevault.config import get_settings
from securevault.monitor.features import FEATURE_NAMES, summarize, to_vector
from securevault.monitor.model import save_model, train_model
from securevault.monitor.simulate import simulate_window


def build_training_matrix(rows: int, seed: int, tz_offset_hours: float = 0) -> list[list[float]]:
    rng = random.Random(seed)
    vectors = []
    for _ in range(rows):
        start, events = simulate_window("normal", rng)
        vectors.append(to_vector(summarize(events, start, tz_offset_hours)))
    return vectors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=4000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    settings = get_settings()
    vectors = build_training_matrix(args.rows, args.seed)
    model = train_model(
        vectors, FEATURE_NAMES, seed=args.seed,
        info={"data": "simulated normal windows (securevault.monitor.simulate)"},
    )
    digest = save_model(model, settings.model_path)
    print(f"Trained on {len(vectors)} simulated normal windows")
    print(f"Saved {settings.model_path}  (sha256 {digest[:16]}..., threshold {model.threshold:.4f})")


if __name__ == "__main__":
    main()
