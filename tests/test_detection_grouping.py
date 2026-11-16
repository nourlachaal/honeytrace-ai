from datetime import datetime, timedelta, timezone

from src.detection.engine import DetectionEngine

T0 = datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)
BRUTE = "COWRIE_BRUTE_FORCE_SESSION"
SEQ = "COWRIE_SUCCESS_AFTER_FAILURES"


def ev(i, kind, source, seconds, session="s1"):
    return {
        "event_id": f"{source}-{kind}-{i}",
        "event_type": kind,
        "source": source,
        "session_id": session,
        "src_ip": "10.0.0.5",
        "event_timestamp": T0 + timedelta(seconds=seconds),
    }


def rule_ids(events):
    return {d.rule_id for d in DetectionEngine().analyze(events)}


def test_threshold_rule_does_not_mix_sources_with_same_session_id():
    events = [
        ev(i, "cowrie.login.failed", "cowrie" if i % 2 == 0 else "other", i)
        for i in range(6)
    ]
    assert BRUTE not in rule_ids(events)


def test_threshold_rule_still_fires_within_one_source():
    events = [ev(i, "cowrie.login.failed", "cowrie", i) for i in range(5)]
    assert BRUTE in rule_ids(events)


def test_sequence_rule_does_not_mix_sources_with_same_session_id():
    events = [ev(i, "cowrie.login.failed", "cowrie", i) for i in range(3)]
    events.append(ev(0, "cowrie.login.success", "other", 10))
    assert SEQ not in rule_ids(events)
    events[-1] = ev(0, "cowrie.login.success", "cowrie", 10)
    assert SEQ in rule_ids(events)