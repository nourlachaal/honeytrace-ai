"""Smoke tests that execute the Streamlit dashboard script.

These use Streamlit's own AppTest harness, so they catch a broken script
(bad imports, session-state errors, unhandled exceptions) without a browser.

The fake API is URL-aware: the dashboard renders every tab on each run, so the
events and incidents endpoints answer different payloads in the same script run.
"""

import urllib.error
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from src.dashboard.api_client import ApiError

APP_PATH = Path(__file__).resolve().parents[1] / "src" / "dashboard" / "app.py"

ROW = {
    "event_id": "a" * 64,
    "source": "cowrie",
    "event_timestamp": "2026-11-08T10:00:00Z",
    "collected_at": "2026-11-08T10:00:01Z",
    "event_type": "cowrie.login.failed",
    "session_id": "s1",
    "scenario_id": None,
    "test_run_id": None,
    "src_ip": "10.0.0.9",
    "protocol": "ssh",
    "http_method": None,
    "route": None,
    "status_code": None,
}

INCIDENT = {
    "incident_id": "f" * 64,
    "source": "cowrie",
    "session_id": "s1",
    "title": "Brute force then successful login",
    "summary": "Six failed logins followed by a success from the same address.",
    "severity": "high",
    "status": "open",
    "has_new_evidence": True,
    "detection_ids": ["d1", "d2"],
    "event_ids": ["e1"],
    "missing_event_ids": [],
    "timeline": [
        {
            "timestamp": "2026-11-08T10:00:00Z",
            "event_id": "e1",
            "event_type": "cowrie.login.failed",
            "source": "cowrie",
            "detection_ids": ["d1"],
        }
    ],
    "created_at": "2026-11-08T10:05:00Z",
    "updated_at": "2026-11-08T10:06:00Z",
}

EVENTS_PAGE = {"items": [ROW], "next_cursor": None}
EMPTY_INCIDENTS = {"items": [], "next_cursor": None}


def _install_api(
    monkeypatch: pytest.MonkeyPatch,
    *,
    events=None,
    incidents=None,
    incident=None,
) -> None:
    """Patch the client's single HTTP seam with a URL-aware fake."""
    events = EVENTS_PAGE if events is None else events
    incidents = EMPTY_INCIDENTS if incidents is None else incidents

    def fake_get(url: str, timeout: float = 0):
        if "/incidents/" in url:
            if incident is None:
                raise ApiError("incident_not_found", status_code=404)
            return incident
        if "/incidents" in url:
            if isinstance(incidents, ApiError):
                raise incidents
            return incidents
        if isinstance(events, ApiError):
            raise events
        return events

    monkeypatch.setattr("src.dashboard.api_client._get_json", fake_get)


def _markdown(app: AppTest) -> str:
    return "\n".join(block.value for block in app.markdown)


def test_dashboard_reports_api_unavailable_without_crashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(url: str, timeout: float | None = None) -> None:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", refuse)

    app = AppTest.from_file(str(APP_PATH), default_timeout=30)
    app.run()

    assert not app.exception
    assert any("Cannot reach the API" in error.value for error in app.error)


def test_dashboard_renders_a_page_of_events(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_api(monkeypatch)

    app = AppTest.from_file(str(APP_PATH), default_timeout=30)
    app.run()

    assert not app.exception
    assert not app.error
    assert len(app.dataframe) == 1
    assert any("1 event(s) loaded" in caption.value for caption in app.caption)


def test_incidents_tab_explains_the_missing_migration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_api(
        monkeypatch,
        incidents=ApiError("incidents_table_missing", status_code=503),
    )

    app = AppTest.from_file(str(APP_PATH), default_timeout=30)
    app.run()

    assert not app.exception
    assert "Waiting for the database migration" in _markdown(app)
    assert any(
        "API reason: incidents_table_missing" in caption.value
        for caption in app.caption
    )


@pytest.mark.parametrize(
    ("code", "title"),
    [
        ("incidents_not_granted", "The API role cannot read incidents"),
        ("incidents_not_configured", "The incident API is not configured"),
        ("incidents_unavailable", "The incident tables are not readable"),
    ],
)
def test_incidents_tab_maps_every_503_reason(
    monkeypatch: pytest.MonkeyPatch, code: str, title: str
) -> None:
    _install_api(monkeypatch, incidents=ApiError(code, status_code=503))

    app = AppTest.from_file(str(APP_PATH), default_timeout=30)
    app.run()

    assert not app.exception
    assert title in _markdown(app)
    assert any(f"API reason: {code}" in caption.value for caption in app.caption)


def test_incidents_tab_reports_an_empty_page(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_api(monkeypatch, incidents=EMPTY_INCIDENTS)

    app = AppTest.from_file(str(APP_PATH), default_timeout=30)
    app.run()

    assert not app.exception
    assert "No incidents yet" in _markdown(app)


def test_incidents_tab_renders_rows_and_the_new_evidence_badge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_api(monkeypatch, incidents={"items": [INCIDENT], "next_cursor": None})

    app = AppTest.from_file(str(APP_PATH), default_timeout=30)
    app.run()

    assert not app.exception
    assert "Brute force then successful login" in _markdown(app)
    assert "new evidence" in _markdown(app)
    assert any("1 incident(s) loaded" in caption.value for caption in app.caption)

    metrics = {metric.label: metric.value for metric in app.metric}
    assert metrics["Incidents"] == "1"
    assert metrics["Open"] == "1"
    assert metrics["New evidence"] == "1"


def test_incident_detail_renders_the_timeline(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_api(
        monkeypatch,
        incidents={"items": [INCIDENT], "next_cursor": None},
        incident=INCIDENT,
    )

    app = AppTest.from_file(str(APP_PATH), default_timeout=30)
    app.session_state["incident_detail"] = INCIDENT["incident_id"]
    app.run()

    assert not app.exception
    assert "Incident detail" in _markdown(app)
    assert "cowrie.login.failed" in _markdown(app)
    assert any(
        "2 detection(s), 1 event(s), 0 missing event(s)" in caption.value
        for caption in app.caption
    )
