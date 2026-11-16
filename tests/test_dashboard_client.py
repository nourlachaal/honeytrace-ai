import io
import urllib.error

import pytest

from src.dashboard.api_client import (
    ApiError,
    build_events_url,
    build_incidents_url,
    fetch_event,
    fetch_events,
    fetch_incident,
    fetch_incidents,
)

BASE = "http://127.0.0.1:8000"


def test_build_events_url_sends_only_active_filters() -> None:
    url = build_events_url(base_url=BASE, limit=10)

    assert url == f"{BASE}/events?limit=10"


def test_build_events_url_includes_every_active_filter() -> None:
    url = build_events_url(
        base_url=BASE + "/",
        limit=25,
        cursor="abc",
        source="cowrie",
        event_type="cowrie.login.failed",
        src_ip="10.0.0.9",
        since="2026-11-08T00:00:00+00:00",
        until="2026-11-09T00:00:00+00:00",
    )

    assert url.startswith(f"{BASE}/events?")
    for fragment in (
        "limit=25",
        "cursor=abc",
        "source=cowrie",
        "event_type=cowrie.login.failed",
        "src_ip=10.0.0.9",
        "since=2026-11-08T00%3A00%3A00%2B00%3A00",
        "until=2026-11-09T00%3A00%3A00%2B00%3A00",
    ):
        assert fragment in url


def test_fetch_events_returns_the_api_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"items": [{"event_id": "a" * 64}], "next_cursor": "next"}
    seen: list[str] = []

    def fake_get(url: str, timeout: float = 0) -> dict:
        seen.append(url)
        return payload

    monkeypatch.setattr("src.dashboard.api_client._get_json", fake_get)

    result = fetch_events(base_url=BASE, limit=2)

    assert result == payload
    assert seen == [f"{BASE}/events?limit=2"]


def test_fetch_events_surfaces_status_and_detail(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_http_error(url: str, timeout: float | None = None) -> None:
        raise urllib.error.HTTPError(
            url,
            400,
            "Bad Request",
            {},
            io.BytesIO(b'{"detail": "invalid_cursor"}'),
        )

    monkeypatch.setattr("urllib.request.urlopen", raise_http_error)

    with pytest.raises(ApiError) as caught:
        fetch_events(base_url=BASE)

    assert caught.value.status_code == 400
    assert str(caught.value) == "invalid_cursor"


def test_fetch_events_reports_api_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(url: str, timeout: float | None = None) -> None:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", refuse)

    with pytest.raises(ApiError) as caught:
        fetch_events(base_url=BASE)

    assert caught.value.status_code is None
    assert str(caught.value) == "api_unavailable"


def test_fetch_events_rejects_unexpected_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "src.dashboard.api_client._get_json", lambda url, timeout=0: {"oops": True}
    )

    with pytest.raises(ApiError) as caught:
        fetch_events(base_url=BASE)

    assert str(caught.value) == "unexpected_response"


def test_fetch_event_builds_the_detail_path(monkeypatch: pytest.MonkeyPatch) -> None:
    event_id = "b" * 64
    seen: list[str] = []

    def fake_get(url: str, timeout: float = 0) -> dict:
        seen.append(url)
        return {"event_id": event_id}

    monkeypatch.setattr("src.dashboard.api_client._get_json", fake_get)

    result = fetch_event(event_id, base_url=BASE)

    assert result == {"event_id": event_id}
    assert seen == [f"{BASE}/events/{event_id}"]


def test_fetch_event_propagates_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_not_found(url: str, timeout: float | None = None) -> None:
        raise urllib.error.HTTPError(
            url,
            404,
            "Not Found",
            {},
            io.BytesIO(b'{"detail": "event_not_found"}'),
        )

    monkeypatch.setattr("urllib.request.urlopen", raise_not_found)

    with pytest.raises(ApiError) as caught:
        fetch_event("c" * 64, base_url=BASE)

    assert caught.value.status_code == 404
    assert str(caught.value) == "event_not_found"


def test_build_incidents_url_sends_only_the_limit_by_default() -> None:
    url = build_incidents_url(base_url=BASE, limit=10)

    assert url == f"{BASE}/incidents?limit=10"


def test_build_incidents_url_includes_every_active_filter() -> None:
    url = build_incidents_url(
        base_url=BASE + "/",
        limit=25,
        cursor="abc",
        source="cowrie",
        status="under_review",
        severity="high",
    )

    assert url.startswith(f"{BASE}/incidents?")
    for fragment in (
        "limit=25",
        "cursor=abc",
        "source=cowrie",
        "status=under_review",
        "severity=high",
    ):
        assert fragment in url


def test_fetch_incidents_returns_the_api_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"items": [{"incident_id": "d" * 64}], "next_cursor": None}
    seen: list[str] = []

    def fake_get(url: str, timeout: float = 0) -> dict:
        seen.append(url)
        return payload

    monkeypatch.setattr("src.dashboard.api_client._get_json", fake_get)

    result = fetch_incidents(base_url=BASE, limit=5, severity="critical")

    assert result == payload
    assert seen == [f"{BASE}/incidents?limit=5&severity=critical"]


def test_fetch_incidents_keeps_the_503_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_unavailable(url: str, timeout: float | None = None) -> None:
        raise urllib.error.HTTPError(
            url,
            503,
            "Service Unavailable",
            {},
            io.BytesIO(b'{"detail": "incidents_table_missing"}'),
        )

    monkeypatch.setattr("urllib.request.urlopen", raise_unavailable)

    with pytest.raises(ApiError) as caught:
        fetch_incidents(base_url=BASE)

    assert caught.value.status_code == 503
    assert str(caught.value) == "incidents_table_missing"


def test_fetch_incidents_rejects_unexpected_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "src.dashboard.api_client._get_json", lambda url, timeout=0: {"oops": True}
    )

    with pytest.raises(ApiError) as caught:
        fetch_incidents(base_url=BASE)

    assert str(caught.value) == "unexpected_response"


def test_fetch_incident_builds_the_detail_path(monkeypatch: pytest.MonkeyPatch) -> None:
    incident_id = "e" * 64
    seen: list[str] = []

    def fake_get(url: str, timeout: float = 0) -> dict:
        seen.append(url)
        return {"incident_id": incident_id}

    monkeypatch.setattr("src.dashboard.api_client._get_json", fake_get)

    result = fetch_incident(incident_id, base_url=BASE)

    assert result == {"incident_id": incident_id}
    assert seen == [f"{BASE}/incidents/{incident_id}"]


def test_fetch_incident_propagates_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_not_found(url: str, timeout: float | None = None) -> None:
        raise urllib.error.HTTPError(
            url,
            404,
            "Not Found",
            {},
            io.BytesIO(b'{"detail": "incident_not_found"}'),
        )

    monkeypatch.setattr("urllib.request.urlopen", raise_not_found)

    with pytest.raises(ApiError) as caught:
        fetch_incident("f" * 64, base_url=BASE)

    assert caught.value.status_code == 404
    assert str(caught.value) == "incident_not_found"
