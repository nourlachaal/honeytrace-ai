from collections.abc import Iterator

import psycopg
import pytest
from fastapi.testclient import TestClient

from src.api.main import app


@pytest.fixture()
def client() -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


def test_health_returns_ok(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_returns_json(client: TestClient) -> None:
    response = client.get("/health")

    assert response.headers["content-type"].startswith("application/json")


def test_health_is_documented_in_openapi(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()

    assert "/health" in schema["paths"]
    assert "get" in schema["paths"]["/health"]
    assert "200" in schema["paths"]["/health"]["get"]["responses"]


def test_health_does_not_open_database_connection(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("GET /health must not connect to PostgreSQL")

    monkeypatch.setattr(psycopg, "connect", fail_if_called)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
