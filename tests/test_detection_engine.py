from datetime import datetime, timezone

import pytest

from src.detection.engine import DetectionEngine
from src.detection.rules import Rule
from src.normalization.normalize import normalize_event

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)


def make_event(event_type="cowrie.login.failed", event_id="evt-1", **overrides):
    event = {
        "event_id": event_id,
        "source": "cowrie",
        "event_type": event_type,
        "session_id": "sess-1",
        "src_ip": "10.0.0.5",
        "username": "root",
    }
    event.update(overrides)
    return event


def test_rule_triggers_on_failed_login():
    detections = DetectionEngine().analyze_event(make_event(), now=NOW)
    assert len(detections) == 1
    d = detections[0]
    assert d.rule_id == "COWRIE_LOGIN_FAILED"
    assert d.severity == "low"
    assert d.source_event_ids == ("evt-1",)
    assert d.created_at == NOW


def test_normal_event_does_not_trigger():
    assert DetectionEngine().analyze_event(make_event("cowrie.session.connect")) == []


def test_detection_id_is_stable():
    first = DetectionEngine().analyze_event(make_event(), now=NOW)[0]
    later = datetime(2027, 1, 1, tzinfo=timezone.utc)
    second = DetectionEngine().analyze_event(make_event(), now=later)[0]
    assert first.detection_id == second.detection_id


def test_same_event_twice_gives_one_detection():
    events = [make_event(), make_event()]
    assert len(DetectionEngine().analyze(events)) == 1


@pytest.mark.parametrize(
    "bad",
    [None, "text", 42, {}, {"event_id": "x"}, {"event_type": "cowrie.login.failed"},
     {"event_id": "", "event_type": "cowrie.login.failed"}],
)
def test_invalid_events_are_ignored(bad):
    assert DetectionEngine().analyze_event(bad) == []


def test_invalid_severity_is_rejected():
    with pytest.raises(ValueError):
        Rule("X", "desc", "urgent", frozenset({"a"}))


def test_works_with_real_normalizer_and_leaks_no_secret():
    raw = {
        "eventid": "cowrie.login.failed",
        "timestamp": "2026-10-28T10:00:00Z",
        "session": "sess-9",
        "src_ip": "10.0.0.9",
        "username": "root",
        "password": "example-secret",
    }
    event = normalize_event(raw)
    detections = DetectionEngine().analyze([event], now=NOW)
    assert len(detections) == 1
    assert detections[0].source_event_ids == (event["event_id"],)
    assert "example-secret" not in str(detections)