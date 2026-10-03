"""Layer 2 of the monitor: an Isolation Forest.

Idea: anomalies are "few and different", so a random tree isolates them with fewer
splits than normal points. The shorter the average path, the higher the anomaly score.

    score(x) = 2 ** ( -E[path_length(x)] / c(psi) )      (Liu, Ting & Zhou, 2008)

We TRAIN with scikit-learn (dev machine only) and SERVE with the ~40-line pure-Python
scorer below. The trained model is exported as plain JSON, which means:
  * the deployed app does not need numpy/scikit-learn (they are too big for Vercel), and
  * we never unpickle a model file, which would be a code-execution risk.
"""

import json
import math
import struct
from dataclasses import dataclass
from pathlib import Path

from securevault.core.integrity import constant_time_equal, sha256_hex
from securevault.utils.exceptions import IntegrityError

EULER_GAMMA = 0.5772156649015329


def _f32(value: float) -> float:
    """scikit-learn trees compare in float32; mimic that so scores match exactly."""
    return struct.unpack("f", struct.pack("f", value))[0]


def average_path_length(n: float) -> float:
    """c(n): average path length of an unsuccessful search in a binary search tree."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (math.log(n - 1.0) + EULER_GAMMA) - 2.0 * (n - 1.0) / n


@dataclass
class AnomalyModel:
    feature_names: list[str]
    trees: list[dict]
    max_samples: int
    threshold: float  # score above this = anomaly
    info: dict

    def score(self, x: list[float]) -> float:
        """Anomaly score in (0, 1]. Near 1 = very unusual, below ~0.5 = normal."""
        if len(x) != len(self.feature_names):
            raise ValueError("wrong number of features")
        xf = [_f32(v) for v in x]
        total = 0.0
        for tree in self.trees:
            feat, thr, left, right, size = (tree[k] for k in ("f", "t", "l", "r", "n"))
            node, depth = 0, 0
            while left[node] != -1:
                node = left[node] if xf[feat[node]] <= thr[node] else right[node]
                depth += 1
            total += depth + average_path_length(size[node])
        mean_path = total / len(self.trees)
        return 2.0 ** (-mean_path / average_path_length(self.max_samples))

    def is_anomaly(self, x: list[float]) -> bool:
        return self.score(x) > self.threshold

    # persistence ----------------------------------------------------------
    def to_json(self) -> str:
        return json.dumps(
            {
                "format": 1,
                "algorithm": "isolation-forest",
                "feature_names": self.feature_names,
                "max_samples": self.max_samples,
                "threshold": self.threshold,
                "info": self.info,
                "trees": self.trees,
            },
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, text: str) -> "AnomalyModel":
        d = json.loads(text)
        if d.get("format") != 1 or d.get("algorithm") != "isolation-forest":
            raise IntegrityError("unsupported model file")
        return cls(d["feature_names"], d["trees"], d["max_samples"], d["threshold"], d.get("info", {}))


def save_model(model: AnomalyModel, path: Path) -> str:
    """Write the model and a sidecar file holding its SHA-256. Returns the hash."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = model.to_json()
    path.write_text(text, encoding="utf-8")
    digest = sha256_hex(text.encode("utf-8"))
    Path(str(path) + ".sha256").write_text(digest + "\n", encoding="utf-8")
    return digest


def load_model(path: Path) -> AnomalyModel | None:
    """Load a model, verifying its SHA-256 sidecar. Returns None if no model file exists."""
    path = Path(path)
    if not path.exists():
        return None
    raw = path.read_bytes()
    sidecar = Path(str(path) + ".sha256")
    if not sidecar.exists():
        raise IntegrityError("model checksum file is missing")
    if not constant_time_equal(sha256_hex(raw), sidecar.read_text().strip()):
        raise IntegrityError("model file does not match its checksum (modified or corrupt)")
    return AnomalyModel.from_json(raw.decode("utf-8"))


def train_model(
    vectors: list[list[float]],
    feature_names: list[str],
    *,
    n_estimators: int = 100,
    max_samples: int = 128,
    contamination: float = 0.01,
    seed: int = 42,
    info: dict | None = None,
) -> AnomalyModel:
    """Fit scikit-learn's IsolationForest and export it to our portable format."""
    import numpy as np  # imported lazily: training machines only
    from sklearn.ensemble import IsolationForest

    forest = IsolationForest(
        n_estimators=n_estimators,
        max_samples=max_samples,
        contamination=contamination,
        random_state=seed,
    ).fit(np.asarray(vectors, dtype=float))

    trees = []
    for estimator, features in zip(forest.estimators_, forest.estimators_features_):
        t = estimator.tree_
        # map each node's feature index back to the column of the original matrix
        mapped = [int(features[f]) if f >= 0 else -2 for f in t.feature]
        trees.append(
            {
                "f": mapped,
                "t": [float(v) for v in t.threshold],
                "l": [int(v) for v in t.children_left],
                "r": [int(v) for v in t.children_right],
                "n": [int(v) for v in t.n_node_samples],
            }
        )
    return AnomalyModel(
        feature_names=list(feature_names),
        trees=trees,
        max_samples=int(forest.max_samples_),
        threshold=float(-forest.offset_),
        info={"n_estimators": n_estimators, "contamination": contamination,
              "training_rows": len(vectors), "seed": seed, **(info or {})},
    )
