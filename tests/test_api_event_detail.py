import re
from collections.abc import Iterator
from datetime import datetime, timezone

import psycopg
import pytest
from fastapi.testclient import TestClient

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

EVENT_ID = "a" * 64
TIMESTAMP = datetime(2026, 11, 8, 10, 0, tzinfo=timezone.utc)


class _RecordingCursor:
    def __init__(self, row: dict | None) -> None:
        self._row = row
        self.executed: list[tuple[str, dict | None]] = []

    def __enter__(self) -> "_RecordingCursor":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def execute(self, sql: str, params: dict | None = None) -> None:
        self.executed.append((sql, params))

    def fetchone(self) -> dict | None:
        return self._row


class _FakeConnection:
    def __init__(self, row: dict | None) -> None:
        self.cursor_obj = _RecordingCursor(row)

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


def _row(event_id: str = EVENT_ID, **overrides: object) -> dict:
    row = {
        "event_id": event_id,
        "source": "cowrie",
        "event_timestamp": TIMESTAMP,
        "collected_at": TIMESTAMP,
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


def _use_fake_database(
    monkeypatch: pytest.MonkeyPatch, row: dict | None
) -> _FakeConnection:
    monkeypatch.setenv("API_DATABASE_URL", "postgresql://readonly@127.0.0.1:5433/honeytrace")
    connection = _FakeConnection(row)
    monkeypatch.setattr(psycopg, "connect", lambda *args, **kwargs: connection)
    return connection


def test_event_detail_returns_only_approved_fields(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_fake_database(monkeypatch, _row())

    response = client.get(f"/events/{EVENT_ID}")

    assert response.status_code == 200
    body = response.json()
    assert set(body) == APPROVED_FIELDS
    for forbidden in FORBIDDEN_COLUMNS:
        assert forbidden not in body


def test_event_detail_query_never_selects_sensitive_columns(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = _use_fake_database(monkeypatch, _row())

    client.get(f"/events/{EVENT_ID}")

    sql = connection.cursor_obj.executed[0][0].lower()
    pattern = r"\b(raw_event|metadata|command|message|username)\b"
    assert re.search(pattern, sql) is None


def test_event_detail_binds_event_id_as_parameter(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = _use_fake_database(monkeypatch, _row())

    client.get(f"/events/{EVENT_ID}")

    sql, params = connection.cursor_obj.executed[0]
    assert params == {"event_id": EVENT_ID}
    assert EVENT_ID not in sql


def test_event_detail_returns_404_for_unknown_event(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_fake_database(monkeypatch, None)

    response = client.get(f"/events/{EVENT_ID}")

    assert response.status_code == 404
    assert response.json() == {"detail": "event_not_found"}


@pytest.mark.parametrize(
    "bad_id",
    ["abc", "a" * 63, "a" * 65, "z" * 64, "A" * 64],
)
def test_event_detail_rejects_malformed_event_id(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, bad_id: str
) -> None:
    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("must not query the database for a malformed id")

    monkeypatch.setattr(psycopg, "connect", fail_if_called)

    response = client.get(f"/events/{bad_id}")

    assert response.status_code == 422


def test_event_detail_returns_503_when_database_is_not_configured(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("API_DATABASE_URL", raising=False)

    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("must not connect without API_DATABASE_URL")

    monkeypatch.setattr(psycopg, "connect", fail_if_called)

    response = client.get(f"/events/{EVENT_ID}")

    assert response.status_code == 503
    assert response.json() == {"detail": "database_not_configured"}


def test_event_detail_returns_503_when_database_is_unavailable(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("API_DATABASE_URL", "postgresql://readonly@127.0.0.1:1/honeytrace")

    def refuse(*args: object, **kwargs: object) -> None:
        raise psycopg.OperationalError("could not connect")

    monkeypatch.setattr(psycopg, "connect", refuse)

    response = client.get(f"/events/{EVENT_ID}")

    assert response.status_code == 503
    assert response.json() == {"detail": "database_unavailable"}
