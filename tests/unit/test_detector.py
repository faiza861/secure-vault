import random

import pytest

from securevault.monitor import features, simulate
from securevault.monitor.detector import Detector
from securevault.monitor.model import AnomalyModel, average_path_length, load_model, save_model, train_model
from securevault.monitor.rules import RuleThresholds, evaluate_rules
from securevault.utils.exceptions import IntegrityError


def ev(kind, ts, fid=None, nbytes=0):
    d = {"bytes": nbytes}
    if fid:
        d["file_id"] = fid
    return {"index": 0, "ts": ts, "event": kind, "actor": "t", "details": d}


def window(events, start=1_767_571_200 + 10 * 3600):  # 10:00 UTC
    return features.summarize(events, start)


def test_summarize_counts_and_ignores_alerts():
    s = window([ev("download", 1, "a", 2_000_000), ev("upload", 2, "b", 1_000_000),
                ev("unlock_failed", 3), ev("alert", 4), ev("rotate_keys", 5)])
    assert (s.requests, s.downloads, s.failed_unlocks, s.distinct_files) == (3, 1, 1, 2)
    assert s.mb_transferred == pytest.approx(3.0)


def test_hour_features_wrap_around_midnight():
    a = features.to_vector(features.summarize([], 23.9 * 3600))
    b = features.to_vector(features.summarize([], 0.1 * 3600))
    assert abs(a[0] - b[0]) < 0.1 and abs(a[1] - b[1]) < 0.1  # 12 minutes apart, far from 12 hours apart


def test_timezone_offset_shifts_local_hour():
    assert features.local_hour(10 * 3600, 5) == pytest.approx(15.0)
    assert features.local_hour(22 * 3600, 5) == pytest.approx(3.0)


def test_tumbling_windows_group_by_time():
    entries = [ev("download", 10, "a"), ev("download", 20, "b"), ev("download", 400, "c")]
    ws = features.tumbling_windows(entries, 300)
    assert [w.requests for w in ws] == [2, 1]


def test_no_rule_fires_on_calm_daytime_window():
    assert evaluate_rules(window([ev("unlock", 1), ev("download", 2, "a", 100_000)])) == []


def test_each_rule_fires():
    t = RuleThresholds()
    brute = window([ev("unlock_failed", i) for i in range(5)])
    assert {a.rule for a in evaluate_rules(brute, t)} == {"failed_unlocks"}
    burst = window([ev("upload", i, "a") for i in range(31)])
    assert "request_burst" in {a.rule for a in evaluate_rules(burst, t)}
    big = window([ev("download", 1, "a", 60_000_000)])
    assert "bulk_transfer" in {a.rule for a in evaluate_rules(big, t)}
    many = window([ev("download", i, f"f{i}") for i in range(16)])
    assert "many_files" in {a.rule for a in evaluate_rules(many, t)}
    night = features.summarize([ev("download", 1, "a")], 1_767_571_200 + 3 * 3600)
    assert "night_access" in {a.rule for a in evaluate_rules(night, t)}
    night_upload = features.summarize([ev("upload", 1, "a")], 1_767_571_200 + 3 * 3600)
    assert evaluate_rules(night_upload, t) == []


def test_average_path_length_values():
    assert average_path_length(1) == 0 and average_path_length(2) == 1
    assert average_path_length(256) == pytest.approx(10.2447, abs=1e-3)


@pytest.fixture(scope="module")
def trained():
    pytest.importorskip("sklearn")
    rng = random.Random(3)
    X = []
    for _ in range(800):
        start, events = simulate.simulate_window("normal", rng)
        X.append(features.to_vector(features.summarize(events, start)))
    return train_model(X, features.FEATURE_NAMES, n_estimators=40, seed=3), X


def test_pure_python_scorer_matches_scikit_learn(trained):
    import numpy as np
    from sklearn.ensemble import IsolationForest

    model, X = trained
    forest = IsolationForest(n_estimators=40, max_samples=128, contamination=0.01, random_state=3).fit(np.asarray(X))
    rng = random.Random(9)
    probes = X[:100] + [[0.5, 0.5, rng.randint(0, 90), rng.random() * 500, rng.randint(0, 40), rng.randint(0, 70)] for _ in range(100)]
    reference = -forest.score_samples(np.asarray(probes))
    ours = [model.score(p) for p in probes]
    assert max(abs(a - b) for a, b in zip(reference, ours)) < 1e-9
    assert model.threshold == pytest.approx(-forest.offset_)


def test_model_separates_normal_from_attack(trained):
    model, _ = trained
    rng = random.Random(11)
    def rate(kind, n=150):
        hits = 0
        for _ in range(n):
            start, events = simulate.simulate_window(kind, rng)
            hits += model.is_anomaly(features.to_vector(features.summarize(events, start)))
        return hits / n
    assert rate("normal") < 0.05
    assert rate("bulk_download") > 0.95
    assert rate("moderate_scrape") > 0.9


def test_hybrid_catches_what_rules_alone_miss(trained):
    model, _ = trained
    rng = random.Random(12)
    rules_only, hybrid = Detector(None), Detector(model)
    missed_by_rules = caught_by_hybrid = 0
    for _ in range(100):
        start, events = simulate.simulate_window("moderate_scrape", rng)
        s = features.summarize(events, start)
        if not rules_only.analyze_window(s):
            missed_by_rules += 1
            caught_by_hybrid += bool(hybrid.analyze_window(s))
    assert missed_by_rules > 80 and caught_by_hybrid > 0.9 * missed_by_rules


def test_model_save_load_and_tamper_detection(trained, tmp_path):
    model, X = trained
    path = tmp_path / "m.json"
    save_model(model, path)
    loaded = load_model(path)
    assert loaded.score(X[0]) == model.score(X[0])
    path.write_text(path.read_text().replace('"threshold":', '"threshold": 0.0, "x":', 1))
    with pytest.raises(IntegrityError):
        load_model(path)


def test_load_missing_model_returns_none(tmp_path):
    assert load_model(tmp_path / "nope.json") is None


def test_unknown_model_format_rejected():
    with pytest.raises(IntegrityError):
        AnomalyModel.from_json('{"format": 99}')
