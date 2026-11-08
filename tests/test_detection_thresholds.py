from datetime import datetime, timedelta, timezone
import random

import pytest

from src.detection.engine import DetectionEngine
from src.detection.rules import ThresholdRule

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
T0 = datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)
BRUTE = "COWRIE_BRUTE_FORCE_SESSION"


def failed(i, session="sess-1", seconds=0, ip="10.0.0.5", **overrides):
    event = {
        "event_id": f"evt-{session}-{i}",
        "event_type": "cowrie.login.failed",
        "session_id": session,
        "src_ip": ip,
        "event_timestamp": T0 + timedelta(seconds=seconds),
    }
    event.update(overrides)
    return event


def brute(detections):
    return [d for d in detections if d.rule_id == BRUTE]


def test_five_failures_in_window_trigger_brute_force():
    events = [failed(i, seconds=i * 10) for i in range(5)]
    found = brute(DetectionEngine().analyze(events, now=NOW))
    assert len(found) == 1
    assert found[0].severity == "medium"
    assert len(found[0].source_event_ids) == 5
    assert found[0].evidence["session_id"] == "sess-1"


def test_four_failures_do_not_trigger():
    events = [failed(i, seconds=i) for i in range(4)]
    assert brute(DetectionEngine().analyze(events)) == []


def test_failures_too_spread_out_do_not_trigger():
    events = [failed(i, seconds=i * 300) for i in range(5)]
    assert brute(DetectionEngine().analyze(events)) == []


def test_same_ip_different_sessions_do_not_trigger():
    events = [failed(i, session=f"sess-{i}", seconds=i) for i in range(5)]
    assert brute(DetectionEngine().analyze(events)) == []


def test_events_without_session_are_ignored():
    events = [failed(i, seconds=i, session_id=None) for i in range(5)]
    assert brute(DetectionEngine().analyze(events)) == []


def test_duplicate_event_counts_once():
    same = failed(0)
    events = [same, same, same, failed(1, seconds=1), failed(2, seconds=2)]
    assert brute(DetectionEngine().analyze(events)) == []


def test_naive_timestamps_are_ignored():
    events = [failed(i, event_timestamp=datetime(2026, 11, 8, 10, 0, i)) for i in range(5)]
    assert brute(DetectionEngine().analyze(events)) == []


def test_result_does_not_depend_on_input_order():
    events = [failed(i, seconds=i * 5) for i in range(7)]
    shuffled = events[:]
    random.Random(1).shuffle(shuffled)
    a = brute(DetectionEngine().analyze(events, now=NOW))
    b = brute(DetectionEngine().analyze(shuffled, now=NOW))
    assert a[0].detection_id == b[0].detection_id


def test_two_sessions_give_two_detections():
    events = [failed(i, session="A", seconds=i) for i in range(5)]
    events += [failed(i, session="B", seconds=i) for i in range(5)]
    assert len(brute(DetectionEngine().analyze(events))) == 2


@pytest.mark.parametrize(
    "kwargs",
    [
        {"severity": "urgent", "threshold": 5, "window_seconds": 60},
        {"severity": "medium", "threshold": 1, "window_seconds": 60},
        {"severity": "medium", "threshold": 5, "window_seconds": 0},
    ],
)
def test_invalid_threshold_rule_is_rejected(kwargs):
    with pytest.raises(ValueError):
        ThresholdRule("X", "desc", event_types=frozenset({"a"}), **kwargs)