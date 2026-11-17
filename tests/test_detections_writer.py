import re
from datetime import datetime, timezone
from types import SimpleNamespace

from src.storage.detections_writer import (
    INSERT_DETECTION_SQL,
    UPSERT_INCIDENT_SQL,
    detection_params,
    incident_params,
    write_results,
)
from tests.test_export import pipeline


class FakeCursor:
    def __init__(self, log):
        self.log = log
        self.rowcount = 1

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.log.append((sql, params))


class FakeConnection:
    def __init__(self):
        self.log = []
        self.transactions = 0

    def transaction(self):
        outer = self

        class Ctx:
            def __enter__(self):
                outer.transactions += 1

            def __exit__(self, *exc):
                return False

        return Ctx()

    def cursor(self):
        return FakeCursor(self.log)


def set_clause():
    return UPSERT_INCIDENT_SQL.split("DO UPDATE SET", 1)[1]


def test_upsert_never_assigns_status():
    assert re.search(r"(?m)^\s*status\s*=", set_clause()) is None


def test_upsert_never_sets_has_new_evidence_to_false():
    assert re.search(r"has_new_evidence\s*=\s*false", set_clause(), re.I) is None
    assert "incidents.has_new_evidence" in set_clause()


def test_detections_use_do_nothing():
    assert "ON CONFLICT (detection_id) DO NOTHING" in INSERT_DETECTION_SQL


def test_incident_params_have_valid_ids_and_no_status():
    _, incidents = pipeline()
    params = incident_params(incidents[0])
    assert re.fullmatch(r"[0-9a-f]{64}", params["incident_id"])
    assert "status" not in params
    assert "has_new_evidence" not in params
    assert "username" not in str(params["timeline"].obj)


def test_detection_params_split_public_and_internal_evidence():
    detections, _ = pipeline()
    with_user = [d for d in detections if "username" in d.evidence]
    assert with_user
    params = detection_params(with_user[0])
    assert "username" not in params["evidence_public"].obj
    assert "username" in params["evidence_internal"].obj


def test_write_results_uses_one_transaction_and_writes_detections_first():
    detections, incidents = pipeline()
    connection = FakeConnection()
    result = write_results(connection, detections, incidents)
    assert connection.transactions == 1
    assert result == {
        "detections_inserted": len(detections),
        "incidents_upserted": len(incidents),
        "incidents_skipped": 0,
    }
    kinds = ["detections" if "INTO detections" in sql else "incidents"
             for sql, _ in connection.log]
    assert kinds == ["detections"] * len(detections) + ["incidents"] * len(incidents)


def test_incident_with_pipe_in_session_is_skipped_not_written():
    _, incidents = pipeline()
    bad = SimpleNamespace(source="cowrie", session_id="a|b")
    connection = FakeConnection()
    result = write_results(connection, [], [bad] + list(incidents))
    assert result["incidents_skipped"] == 1
    assert result["incidents_upserted"] == len(incidents)