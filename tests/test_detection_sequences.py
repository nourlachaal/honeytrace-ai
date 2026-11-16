from datetime import datetime, timedelta, timezone

import pytest

from src.detection.engine import DetectionEngine
from src.detection.rules import SequenceRule

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
T0 = datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)
RULE = "COWRIE_SUCCESS_AFTER_FAILURES"


def ev(kind, i, session="s1", seconds=0, **extra):
    event = {
        "event_id": f"{kind}-{session}-{i}",
        "event_type": f"cowrie.login.{kind}",
        "session_id": session,
        "src_ip": "10.0.0.5",
        "event_timestamp": T0 + timedelta(seconds=seconds),
    }
    event.update(extra)
    return event


def seq(detections):
    return [d for d in detections if d.rule_id == RULE]


def test_success_after_three_failures_triggers():
    events = [ev("failed", i, seconds=i) for i in range(3)] + [ev("success", 0, seconds=10)]
    found = seq(DetectionEngine().analyze(events, now=NOW))
    assert len(found) == 1
    assert found[0].severity == "high"
    assert len(found[0].source_event_ids) == 4
    assert found[0].source_event_ids[-1] == "success-s1-0"


def test_two_failures_are_not_enough():
    events = [ev("failed", i, seconds=i) for i in range(2)] + [ev("success", 0, seconds=10)]
    assert seq(DetectionEngine().analyze(events)) == []


def test_success_before_failures_does_not_trigger():
    events = [ev("success", 0, seconds=0)] + [ev("failed", i, seconds=10 + i) for i in range(3)]
    assert seq(DetectionEngine().analyze(events)) == []


def test_same_timestamp_is_not_ordered_so_no_trigger():
    events = [ev("failed", i, seconds=5) for i in range(3)] + [ev("success", 0, seconds=5)]
    assert seq(DetectionEngine().analyze(events)) == []


def test_failures_outside_window_do_not_count():
    events = [ev("failed", i, seconds=i) for i in range(3)] + [ev("success", 0, seconds=1000)]
    assert seq(DetectionEngine().analyze(events)) == []


def test_failures_and_success_in_different_sessions_do_not_trigger():
    events = [ev("failed", i, session="A", seconds=i) for i in range(3)]
    events.append(ev("success", 0, session="B", seconds=10))
    assert seq(DetectionEngine().analyze(events)) == []


def test_missing_session_is_ignored():
    events = [ev("failed", i, seconds=i, session_id=None) for i in range(3)]
    events.append(ev("success", 0, seconds=10, session_id=None))
    assert seq(DetectionEngine().analyze(events)) == []


def test_detection_id_is_stable_across_runs_and_order():
    events = [ev("failed", i, seconds=i) for i in range(3)] + [ev("success", 0, seconds=10)]
    a = seq(DetectionEngine().analyze(events, now=NOW))[0]
    b = seq(DetectionEngine().analyze(list(reversed(events)), now=NOW))[0]
    assert a.detection_id == b.detection_id


def test_evidence_contains_no_password_field():
    events = [ev("failed", i, seconds=i, password="example-secret") for i in range(3)]
    events.append(ev("success", 0, seconds=10, password="example-secret"))
    found = seq(DetectionEngine().analyze(events, now=NOW))
    assert "example-secret" not in str(found)


def test_invalid_sequence_rule_is_rejected():
    same = frozenset({"a"})
    with pytest.raises(ValueError):
        SequenceRule("X", "d", "high", same, 3, same, 60)
    with pytest.raises(ValueError):
        SequenceRule("X", "d", "urgent", frozenset({"a"}), 3, frozenset({"b"}), 60)