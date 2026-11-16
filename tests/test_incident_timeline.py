from datetime import datetime, timedelta, timezone

from src.correlation.timeline import build_timeline
from src.detection.engine import Detection

T0 = datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)


def ev(event_id, seconds, **extra):
    event = {
        "event_id": event_id,
        "source": "cowrie",
        "event_type": "cowrie.login.failed",
        "event_timestamp": T0 + timedelta(seconds=seconds),
    }
    event.update(extra)
    return event


def test_timeline_is_chronological_whatever_the_input_order():
    events = [ev("c", 30), ev("a", 10), ev("b", 20)]
    assert [e.event_id for e in build_timeline(events)] == ["a", "b", "c"]
    assert [e.event_id for e in build_timeline(list(reversed(events)))] == ["a", "b", "c"]


def test_timeline_keeps_references_to_original_events():
    entry = build_timeline([ev("a", 1)])[0]
    assert entry.event_id == "a"
    assert entry.event_type == "cowrie.login.failed"
    assert entry.source == "cowrie"
    assert entry.timestamp == T0 + timedelta(seconds=1)


def test_duplicate_event_appears_once():
    assert len(build_timeline([ev("a", 1), ev("a", 1)])) == 1


def test_invalid_and_naive_events_are_skipped():
    events = [
        ev("ok", 1),
        ev("naive", 2, event_timestamp=datetime(2026, 11, 8, 10, 0, 2)),
        ev("no-ts", 3, event_timestamp=None),
        {"event_type": "x", "event_timestamp": T0},
        None,
        "text",
    ]
    assert [e.event_id for e in build_timeline(events)] == ["ok"]


def test_detection_ids_are_attached_to_entries():
    detection = Detection("d1", "R", "desc", "medium", ("a",), {}, None)
    entries = {e.event_id: e for e in build_timeline([ev("a", 1), ev("b", 2)], [detection])}
    assert entries["a"].detection_ids == ("d1",)
    assert entries["b"].detection_ids == ()


def test_empty_input_gives_empty_timeline():
    assert build_timeline([]) == ()