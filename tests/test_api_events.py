import re
from collections.abc import Iterator
from datetime import datetime, timezone

import psycopg
import pytest
from fastapi.testclient import TestClient

from src.api.events import decode_cursor
from src.api.main import app

APPROVED_FIELDS = {
    "event_id",
    "source",
    "event_timestamp",
    "collected_at",
    "event_type",
    "session_id",
    "scenario_id",
    "test_run_id",
    "src_ip",
    "protocol",
    "http_method",
    "route",
    "status_code",
}

FORBIDDEN_COLUMNS = ("raw_event", "metadata", "command", "message", "username")

EVENT_ID_1 = "a" * 64
EVENT_ID_2 = "b" * 64
EVENT_ID_3 = "c" * 64
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


def _row(event_id: str, timestamp: datetime = TIMESTAMP, **overrides: object) -> dict:
    row = {
        "event_id": event_id,
        "source": "cowrie",
        "event_timestamp": timestamp,
        "collected_at": timestamp,
        "event_type": "cowrie.command.input",
        "session_id": "session-1",
        "scenario_id": None,
        "test_run_id": None,
        "src_ip": "10.0.0.5",
        "protocol": "ssh",
        "http_method": None,
        "route": None,
        "status_code": None,
    }
    row.update(overrides)
    return row


def _use_fake_database(monkeypatch: pytest.MonkeyPatch, rows: list[dict]) -> _FakeConnection:
    monkeypatch.setenv("API_DATABASE_URL", "postgresql://readonly@127.0.0.1:5433/honeytrace")
    connection = _FakeConnection(rows)
    monkeypatch.setattr(psycopg, "connect", lambda *args, **kwargs: connection)
    return connection


def test_events_returns_503_when_database_is_not_configured(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("API_DATABASE_URL", raising=False)

    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("must not connect without API_DATABASE_URL")

    monkeypatch.setattr(psycopg, "connect", fail_if_called)

    response = client.get("/events")

    assert response.status_code == 503
    assert response.json() == {"detail": "database_not_configured"}


def test_events_returns_only_approved_fields(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_fake_database(monkeypatch, [_row(EVENT_ID_1)])

    response = client.get("/events")

    assert response.status_code == 200
    item = response.json()["items"][0]
    assert set(item) == APPROVED_FIELDS
    for forbidden in FORBIDDEN_COLUMNS:
        assert forbidden not in item


def test_events_query_never_selects_sensitive_columns(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = _use_fake_database(monkeypatch, [_row(EVENT_ID_1)])

    client.get("/events")

    sql = connection.cursor_obj.executed[0][0].lower()
    pattern = r"\b(raw_event|metadata|command|message|username)\b"
    assert re.search(pattern, sql) is None


def test_events_binds_values_as_parameters(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = _use_fake_database(monkeypatch, [_row(EVENT_ID_1)])

    client.get("/events", params={"src_ip": "10.0.0.5", "limit": 10})

    sql, params = connection.cursor_obj.executed[0]
    assert params is not None
    assert params["src_ip"] == "10.0.0.5"
    assert params["limit"] == 11
    assert "10.0.0.5" not in sql


@pytest.mark.parametrize("limit", [0, 201])
def test_events_rejects_limit_outside_bounds(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, limit: int
) -> None:
    _use_fake_database(monkeypatch, [])

    response = client.get("/events", params={"limit": limit})

    assert response.status_code == 422


def test_events_returns_next_cursor_when_another_page_exists(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_fake_database(
        monkeypatch,
        [_row(EVENT_ID_1), _row(EVENT_ID_2), _row(EVENT_ID_3)],
    )

    response = client.get("/events", params={"limit": 2})

    body = response.json()
    assert len(body["items"]) == 2
    assert body["next_cursor"] is not None

    timestamp, event_id = decode_cursor(body["next_cursor"])
    assert event_id == EVENT_ID_2
    assert timestamp == TIMESTAMP


def test_events_has_no_next_cursor_on_last_page(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_fake_database(monkeypatch, [_row(EVENT_ID_1), _row(EVENT_ID_2)])

    response = client.get("/events", params={"limit": 2})

    body = response.json()
    assert len(body["items"]) == 2
    assert body["next_cursor"] is None


def test_events_rejects_invalid_cursor(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_fake_database(monkeypatch, [])

    response = client.get("/events", params={"cursor": "not-a-valid-cursor"})

    assert response.status_code == 400
    assert response.json() == {"detail": "invalid_cursor"}


def test_events_rejects_naive_timestamps(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_fake_database(monkeypatch, [])

    response = client.get("/events", params={"since": "2026-11-08T10:00:00"})

    assert response.status_code == 400
    assert response.json() == {"detail": "timestamp_must_include_timezone"}


def test_events_returns_503_when_database_is_unavailable(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("API_DATABASE_URL", "postgresql://readonly@127.0.0.1:1/honeytrace")

    def refuse(*args: object, **kwargs: object) -> None:
        raise psycopg.OperationalError("could not connect")

    monkeypatch.setattr(psycopg, "connect", refuse)

    response = client.get("/events")

    assert response.status_code == 503
    assert response.json() == {"detail": "database_unavailable"}
