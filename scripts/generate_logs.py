"""Write simulated audit-style logs to a JSONL file (for inspection or experiments).

Usage:  python scripts/generate_logs.py --normal 200 --attacks 20 --out data/sim_logs.jsonl
"""

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from securevault.monitor.simulate import ATTACK_KINDS, simulate_window


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--normal", type=int, default=200)
    p.add_argument("--attacks", type=int, default=20, help="windows per attack kind")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--out", default="data/sim_logs.jsonl")
    args = p.parse_args()

    rng = random.Random(args.seed)
    rows = []
    plan = [("normal", args.normal)] + [(k, args.attacks) for k in ATTACK_KINDS]
    for kind, count in plan:
        for _ in range(count):
            start, events = simulate_window(kind, rng)
            rows.append({"label": kind, "window_start": start, "events": events})
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    print(f"Wrote {len(rows)} windows to {out}")


if __name__ == "__main__":
    main()
