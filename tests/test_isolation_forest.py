import pytest
pytest.importorskip("sklearn")
from src.ml.features import FEATURE_NAMES, SessionFeatures, build_session_features
from src.ml.isolation_forest import MIN_SESSIONS, SessionAnomalyDetector
from src.ml.synthetic import generate_dataset


def dataset(n=300, ratio=0.15, seed=42):
    data = generate_dataset(n, ratio, seed)
    return data, build_session_features(data.events)


def test_too_few_sessions_are_rejected():
    _, features = dataset(n=MIN_SESSIONS - 5)
    with pytest.raises(ValueError):
        SessionAnomalyDetector().fit(features)


def test_scoring_before_fit_fails():
    _, features = dataset(n=30)
    with pytest.raises(RuntimeError):
        SessionAnomalyDetector().score(features)


def test_same_seed_gives_same_scores():
    _, features = dataset()
    a = SessionAnomalyDetector(random_state=1).fit(features).score(features)
    b = SessionAnomalyDetector(random_state=1).fit(features).score(features)
    assert a == b


def test_output_matches_input_sessions():
    _, features = dataset()
    scores = SessionAnomalyDetector().fit(features).score(features)
    assert [(s.source, s.session_id) for s in scores] == [
        (f.source, f.session_id) for f in features
    ]


def test_flagged_share_is_close_to_contamination():
    _, features = dataset(n=200)
    scores = SessionAnomalyDetector(contamination=0.1).fit(features).score(features)
    flagged = sum(s.is_anomaly for s in scores)
    assert 15 <= flagged <= 25


def test_obvious_attacks_score_higher_than_quiet_normal_sessions():
    data, features = dataset()
    scores = SessionAnomalyDetector().fit(features).score(features)
    by_kind = {}
    for s in scores:
        by_kind.setdefault(data.kinds[(s.source, s.session_id)], []).append(s.anomaly_score)
    mean = lambda values: sum(values) / len(values)
    assert mean(by_kind["attack_obvious"]) > mean(by_kind["normal_quiet"])


def test_flags_are_consistent_with_scores():
    _, features = dataset()
    scores = SessionAnomalyDetector().fit(features).score(features)
    flagged = [s.anomaly_score for s in scores if s.is_anomaly]
    normal = [s.anomaly_score for s in scores if not s.is_anomaly]
    assert flagged and normal
    assert min(flagged) >= max(normal)


@pytest.mark.parametrize("value", [0, -0.1, 0.6])
def test_invalid_contamination_is_rejected(value):
    with pytest.raises(ValueError):
        SessionAnomalyDetector(contamination=value)


def test_non_finite_values_are_rejected():
    bad = [
        SessionFeatures("cowrie", f"s{i}", {name: float("nan") for name in FEATURE_NAMES})
        for i in range(MIN_SESSIONS + 5)
    ]
    with pytest.raises(ValueError):
        SessionAnomalyDetector().fit(bad)


def test_empty_scoring_input_gives_empty_list():
    _, features = dataset(n=30)
    assert SessionAnomalyDetector().fit(features).score([]) == []


def test_model_can_score_new_sessions():
    _, train = dataset(seed=1)
    _, new = dataset(n=50, seed=2)
    scores = SessionAnomalyDetector().fit(train).score(new)
    assert len(scores) == len(new)


def test_identical_sessions_do_not_crash():
    same = [
        SessionFeatures("cowrie", f"s{i}", {name: 1.0 for name in FEATURE_NAMES})
        for i in range(MIN_SESSIONS + 5)
    ]
    scores = SessionAnomalyDetector().fit(same).score(same)
    assert len(scores) == len(same)
    assert all(s.anomaly_score == s.anomaly_score for s in scores)  # pas de NaN