from datetime import datetime

import pytest

from src.detection.engine import DetectionEngine
from src.ml.features import build_session_features
from src.ml.synthetic import SYNTHETIC_SCENARIO_ID, generate_dataset


def test_same_seed_gives_same_data():
    assert generate_dataset(50, 0.2, seed=7) == generate_dataset(50, 0.2, seed=7)


def test_different_seed_gives_different_data():
    a = generate_dataset(50, 0.2, seed=1)
    b = generate_dataset(50, 0.2, seed=2)
    assert a.events != b.events


def test_every_event_is_marked_synthetic():
    data = generate_dataset(30)
    assert data.events
    assert all(e["scenario_id"] == SYNTHETIC_SCENARIO_ID for e in data.events)
    assert all(e["test_run_id"].startswith("SYNTHETIC") for e in data.events)


def test_attack_ratio_is_respected():
    data = generate_dataset(200, 0.15, seed=42)
    assert len(data.labels) == 200
    assert sum(data.labels.values()) == 30


def test_at_least_one_attack_when_ratio_is_positive():
    data = generate_dataset(5, 0.01, seed=3)
    assert sum(data.labels.values()) == 1


def test_zero_ratio_gives_no_attack():
    data = generate_dataset(20, 0.0)
    assert sum(data.labels.values()) == 0


def test_labels_match_the_sessions_seen_by_the_features():
    data = generate_dataset(60, 0.2)
    features = build_session_features(data.events)
    assert {(f.source, f.session_id) for f in features} == set(data.labels)


def test_event_ids_are_unique():
    data = generate_dataset(100)
    ids = [e["event_id"] for e in data.events]
    assert len(ids) == len(set(ids))


def test_timestamps_are_timezone_aware():
    data = generate_dataset(20)
    assert all(isinstance(e["event_timestamp"], datetime) for e in data.events)
    assert all(e["event_timestamp"].tzinfo is not None for e in data.events)


def test_overlap_zone_exists():
    data = generate_dataset(400, 0.15, seed=1)
    assert {"normal_quiet", "normal_noisy", "attack_obvious", "attack_discreet"} <= set(
        data.kinds.values()
    )
    failed = {(f.source, f.session_id): f.values["login_failed_count"]
              for f in build_session_features(data.events)}
    attack_min = min(v for k, v in failed.items() if data.labels[k] == 1)
    normal_max = max(v for k, v in failed.items() if data.labels[k] == 0)
    assert attack_min <= normal_max   # les classes se chevauchent


def test_obvious_attacks_have_more_failures_than_any_normal_session():
    data = generate_dataset(400, 0.15, seed=1)
    failed = {(f.source, f.session_id): f.values["login_failed_count"]
              for f in build_session_features(data.events)}
    obvious = [v for k, v in failed.items() if data.kinds[k] == "attack_obvious"]
    normal = [v for k, v in failed.items() if data.labels[k] == 0]
    assert obvious and min(obvious) >= 8
    assert max(normal) <= 4


@pytest.mark.parametrize(
    "kwargs",
    [{"n_sessions": 0}, {"attack_ratio": -0.1}, {"attack_ratio": 1.5}],
)
def test_invalid_parameters_are_rejected(kwargs):
    with pytest.raises(ValueError):
        generate_dataset(**kwargs)


def test_no_command_text_or_password_in_events():
    text = str(generate_dataset(30).events)
    assert "password" not in text
    assert "command'" not in text


def test_brute_force_rule_only_fires_on_attack_sessions():
    data = generate_dataset(200, 0.15, seed=5)
    detections = DetectionEngine().analyze(data.events)
    brute = [d for d in detections if d.rule_id == "COWRIE_BRUTE_FORCE_SESSION"]
    assert brute
    for d in brute:
        assert data.labels[("cowrie", d.evidence["session_id"])] == 1