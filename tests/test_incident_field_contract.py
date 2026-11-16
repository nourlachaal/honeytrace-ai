"""Contract tests for the incident API's public field allowlist.

The 14 names below are the agreed contract from section 7 of
docs/integration-contract.md and the column grants in sql/004. They are
hardcoded on purpose: importing them from the implementation would let a
widened contract update its own test.
"""

import json
import re
from collections.abc import Iterator
from datetime import datetime, timezone

import psycopg
import pytest
from fastapi.testclient import TestClient

from src.api.incidents import SELECT_COLUMNS
from src.api.main import app
from src.api.models import IncidentPage, IncidentSummary, TimelineEntry

APPROVED_FIELDS = {
    "incident_id",
    "source",
    "session_id",
    "title",
    "summary",
    "severity",
    "status",
    "has_new_evidence",
    "detection_ids",
    "event_ids",
    "missing_event_ids",
    "timeline",
    "created_at",
    "updated_at",
}

FORBIDDEN_FIELDS = (
    "evidence_internal",
    "evidence_raw",
    "username",
    "command",
    "message",
    "raw_event",
    "metadata",
)

INCIDENT_ID = "a" * 64
TIMESTAMP = datetime(2026, 11, 8, 10, 0, tzinfo=timezone.utc)


class _RecordingCursor:
    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows
        self.executed: list[tuple[str, dict | None]] = []

    def __enter__(self) -> "_RecordingCursor":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def execute(self, sql: str, params: dict | None = None) -> None:
        self.executed.append((sql, params))

    def fetchall(self) -> list[dict]:
        return self._rows

    def fetchone(self) -> dict | None:
        return self._rows[0] if self._rows else None


class _FakeConnection:
    def __init__(self, rows: list[dict]) -> None:
        self.cursor_obj = _RecordingCursor(rows)

    def __enter__(self) -> "_FakeConnection":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def cursor(self, **kwargs: object) -> _RecordingCursor:
        return self.cursor_obj


@pytest.fixture()
def client() -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


def _timeline_entry(**overrides: object) -> dict:
    entry = {
        "timestamp": TIMESTAMP,
        "event_id": "e" * 64,
        "event_type": "cowrie.login.failed",
        "source": "cowrie",
        "detection_ids": ["d" * 64],
    }
    entry.update(overrides)
    return entry


def _row(**overrides: object) -> dict:
    row = {
        "incident_id": INCIDENT_ID,
        "source": "cowrie",
        "session_id": "abc123",
        "title": "Repeated authentication failures",
        "summary": "2 detections, 7 events",
        "severity": "high",
        "status": "open",
        "has_new_evidence": False,
        "detection_ids": ["d" * 64],
        "event_ids": ["e" * 64],
        "missing_event_ids": [],
        "timeline": [_timeline_entry()],
        "created_at": TIMESTAMP,
        "updated_at": TIMESTAMP,
    }
    row.update(overrides)
    return row


def _use_fake_database(
    monkeypatch: pytest.MonkeyPatch, rows: list[dict]
) -> _FakeConnection:
    monkeypatch.setenv("API_DATABASE_URL", "postgresql://readonly@127.0.0.1:5433/honeytrace")
    connection = _FakeConnection(rows)
    monkeypatch.setattr(psycopg, "connect", lambda *args, **kwargs: connection)
    return connection


def _refuse_with(exc: Exception):
    def refuse(*args: object, **kwargs: object) -> None:
        raise exc

    return refuse


def test_incident_summary_exposes_exactly_the_approved_fields() -> None:
    assert set(IncidentSummary.model_fields) == APPROVED_FIELDS


def test_incident_summary_rejects_unknown_fields() -> None:
    assert IncidentSummary.model_config.get("extra") == "forbid"


def test_timeline_entry_rejects_unknown_fields() -> None:
    assert TimelineEntry.model_config.get("extra") == "forbid"


def test_incident_page_adds_no_incident_fields() -> None:
    assert set(IncidentPage.model_fields) == {"items", "next_cursor"}


def test_select_columns_match_the_approved_fields() -> None:
    assert set(SELECT_COLUMNS) == APPROVED_FIELDS


def test_select_columns_never_include_internal_evidence() -> None:
    assert "evidence_internal" not in SELECT_COLUMNS
    assert "evidence_raw" not in SELECT_COLUMNS


def test_openapi_document_never_mentions_forbidden_fields() -> None:
    document = json.dumps(app.openapi())

    for field in FORBIDDEN_FIELDS:
        assert field not in document, f"{field} leaked into the OpenAPI document"


def test_list_incidents_returns_only_approved_fields(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_fake_database(monkeypatch, [_row()])

    response = client.get("/incidents")

    assert response.status_code == 200
    item = response.json()["items"][0]
    assert set(item) == APPROVED_FIELDS
    for forbidden in FORBIDDEN_FIELDS:
        assert forbidden not in item


def test_list_query_never_selects_forbidden_columns(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = _use_fake_database(monkeypatch, [_row()])

    client.get("/incidents")

    sql = connection.cursor_obj.executed[0][0].lower()
    pattern = (
        r"\b(evidence_internal|evidence_raw|username|command|message|raw_event|metadata)\b"
    )
    assert re.search(pattern, sql) is None


def test_list_binds_filters_as_parameters(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = _use_fake_database(monkeypatch, [_row()])

    client.get(
        "/incidents",
        params={"status": "open", "source": "cowrie", "limit": 10},
    )

    sql, params = connection.cursor_obj.executed[0]
    assert params is not None
    assert params["incident_status"] == "open"
    assert params["source"] == "cowrie"
    assert params["limit"] == 11
    assert "open" not in sql


@pytest.mark.parametrize("bad_status", ["OPEN", "acknowledged", "closed"])
def test_list_rejects_unknown_status(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, bad_status: str
) -> None:
    _use_fake_database(monkeypatch, [])

    response = client.get("/incidents", params={"status": bad_status})

    assert response.status_code == 422


def test_list_rejects_invalid_cursor(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_fake_database(monkeypatch, [])

    response = client.get("/incidents", params={"cursor": "not-a-valid-cursor"})

    assert response.status_code == 400
    assert response.json() == {"detail": "invalid_cursor"}


def test_detail_returns_only_approved_fields(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_fake_database(monkeypatch, [_row()])

    response = client.get(f"/incidents/{INCIDENT_ID}")

    assert response.status_code == 200
    assert set(response.json()) == APPROVED_FIELDS


def test_detail_returns_404_for_unknown_incident(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_fake_database(monkeypatch, [])

    response = client.get(f"/incidents/{INCIDENT_ID}")

    assert response.status_code == 404
    assert response.json() == {"detail": "incident_not_found"}


@pytest.mark.parametrize(
    "bad_id",
    ["abc", "a" * 63, "a" * 65, "z" * 64, "A" * 64],
)
def test_detail_rejects_malformed_incident_id(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, bad_id: str
) -> None:
    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("must not query the database for a malformed id")

    monkeypatch.setattr(psycopg, "connect", fail_if_called)

    response = client.get(f"/incidents/{bad_id}")

    assert response.status_code == 422


def test_missing_table_maps_to_503(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("API_DATABASE_URL", "postgresql://readonly@127.0.0.1:5433/honeytrace")
    monkeypatch.setattr(
        psycopg,
        "connect",
        _refuse_with(psycopg.errors.UndefinedTable("relation does not exist")),
    )

    response = client.get("/incidents")

    assert response.status_code == 503
    assert response.json() == {"detail": "incidents_table_missing"}


def test_not_granted_maps_to_503(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("API_DATABASE_URL", "postgresql://readonly@127.0.0.1:5433/honeytrace")
    monkeypatch.setattr(
        psycopg,
        "connect",
        _refuse_with(psycopg.errors.InsufficientPrivilege("permission denied")),
    )

    response = client.get("/incidents")

    assert response.status_code == 503
    assert response.json() == {"detail": "incidents_not_granted"}


def test_database_unavailable_maps_to_503(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("API_DATABASE_URL", "postgresql://readonly@127.0.0.1:1/honeytrace")
    monkeypatch.setattr(
        psycopg, "connect", _refuse_with(psycopg.OperationalError("could not connect"))
    )

    response = client.get("/incidents")

    assert response.status_code == 503
    assert response.json() == {"detail": "incidents_unavailable"}


def test_not_configured_maps_to_503(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("API_DATABASE_URL", raising=False)

    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("must not connect without API_DATABASE_URL")

    monkeypatch.setattr(psycopg, "connect", fail_if_called)

    response = client.get("/incidents")

    assert response.status_code == 503
    assert response.json() == {"detail": "incidents_not_configured"}


def test_timeline_with_a_forbidden_key_never_reaches_the_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_fake_database(
        monkeypatch,
        [_row(timeline=[_timeline_entry(username="root")])],
    )

    with TestClient(app, raise_server_exceptions=False) as strict_client:
        response = strict_client.get("/incidents")

    assert response.status_code == 500
    assert "username" not in response.text
    assert "root" not in response.text