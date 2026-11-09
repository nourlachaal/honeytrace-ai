from collections.abc import Iterator

import psycopg
import pytest
from fastapi.testclient import TestClient

from src.api.main import app


class _FakeCursor:
    def __enter__(self) -> "_FakeCursor":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def execute(self, sql: str, params: object = None) -> None:
        self.sql = sql

    def fetchone(self) -> tuple[int]:
        return (1,)


class _FakeConnection:
    def __enter__(self) -> "_FakeConnection":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def cursor(self) -> _FakeCursor:
        return _FakeCursor()


@pytest.fixture()
def client() -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


def test_health_db_is_not_configured_without_url(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("API_DATABASE_URL", raising=False)

    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("must not connect without API_DATABASE_URL")

    monkeypatch.setattr(psycopg, "connect", fail_if_called)

    response = client.get("/health/db")

    assert response.status_code == 503
    assert response.json() == {"status": "not_configured"}


def test_health_db_returns_ok_when_select_succeeds(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("API_DATABASE_URL", "postgresql://readonly@127.0.0.1:5433/honeytrace")
    monkeypatch.setattr(psycopg, "connect", lambda *args, **kwargs: _FakeConnection())

    response = client.get("/health/db")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_db_reports_unavailable_without_leaking_credentials(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "API_DATABASE_URL", "postgresql://readonly:secret-password@127.0.0.1:5433/honeytrace"
    )

    def refuse(*args: object, **kwargs: object) -> None:
        raise psycopg.OperationalError(
            "connection failed for postgresql://readonly:secret-password@127.0.0.1:5433/honeytrace"
        )

    monkeypatch.setattr(psycopg, "connect", refuse)

    response = client.get("/health/db")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}
    assert "secret-password" not in response.text
