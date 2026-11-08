import pytest

from src.ml.dbscan import (
    MIN_SESSIONS,
    NOISE,
    cluster_report,
    cluster_sessions,
    noise_sessions,
    suggest_eps,
)
from src.ml.features import FEATURE_NAMES, SessionFeatures, build_session_features
from src.ml.synthetic import generate_dataset


def dataset(n=300, seed=42):
    data = generate_dataset(n, 0.15, seed)
    return data, build_session_features(data.events)


def blob(prefix, center, count):
    """Sessions très proches d'un centre (toutes les features = center + petit décalage)."""
    return [
        SessionFeatures("cowrie", f"{prefix}{i}",
                        {name: center + i * 0.001 for name in FEATURE_NAMES})
        for i in range(count)
    ]


def test_two_separated_blobs_make_two_clusters():
    features = blob("a", 0.0, 30) + blob("b", 100.0, 30)
    result = cluster_sessions(features, eps=0.5, min_samples=5)
    assert result.n_clusters == 2
    assert result.n_noise == 0


def test_isolated_point_is_noise():
    features = blob("a", 0.0, 30) + blob("far", 1000.0, 1)
    result = cluster_sessions(features, eps=0.5, min_samples=5)
    assert noise_sessions(result) == {("cowrie", "far0")}


def test_output_matches_input_sessions():
    _, features = dataset()
    result = cluster_sessions(features)
    assert [(a.source, a.session_id) for a in result.assignments] == [
        (f.source, f.session_id) for f in features
    ]


def test_clustering_is_deterministic():
    _, features = dataset()
    assert cluster_sessions(features) == cluster_sessions(features)


def test_suggest_eps_is_positive_and_label_free():
    _, features = dataset()
    assert suggest_eps(features) > 0


def test_identical_sessions_do_not_crash():
    same = blob("s", 1.0, 5)
    same = [SessionFeatures("cowrie", f"s{i}", {n: 1.0 for n in FEATURE_NAMES})
            for i in range(MIN_SESSIONS + 5)]
    result = cluster_sessions(same)
    assert result.eps > 0
    assert result.n_clusters == 1


def test_too_few_sessions_are_rejected():
    _, features = dataset(n=MIN_SESSIONS - 5)
    with pytest.raises(ValueError):
        cluster_sessions(features)


@pytest.mark.parametrize("kwargs", [{"eps": 0}, {"eps": -1.0}, {"min_samples": 1}])
def test_invalid_parameters_are_rejected(kwargs):
    _, features = dataset(n=60)
    with pytest.raises(ValueError):
        cluster_sessions(features, **kwargs)


def test_non_finite_values_are_rejected():
    bad = [SessionFeatures("cowrie", f"s{i}", {n: float("nan") for n in FEATURE_NAMES})
           for i in range(MIN_SESSIONS + 5)]
    with pytest.raises(ValueError):
        cluster_sessions(bad, eps=1.0)


def test_report_covers_every_session():
    data, features = dataset()
    report = cluster_report(cluster_sessions(features), data.labels)
    assert sum(r["size"] for r in report) == len(features)
    assert sum(r["attacks"] for r in report) == sum(data.labels.values())
    assert all(0.0 <= r["attack_share"] <= 1.0 for r in report)


def test_report_rejects_unlabelled_session():
    _, features = dataset(n=60)
    with pytest.raises(ValueError):
        cluster_report(cluster_sessions(features), {})


def test_obvious_attacks_are_not_mostly_in_the_biggest_cluster():
    # Données SYNTHÉTIQUES : vérifie le code, ne mesure aucune performance.
    data, features = dataset()
    result = cluster_sessions(features)
    biggest = max(
        (r for r in cluster_report(result, data.labels) if r["cluster"] != NOISE),
        key=lambda r: r["size"],
    )
    assert biggest["attack_share"] < 0.15