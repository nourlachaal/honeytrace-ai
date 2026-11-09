"""Smoke tests that execute the Streamlit dashboard script.

These use Streamlit's own AppTest harness, so they catch a broken script
(bad imports, session-state errors, unhandled exceptions) without a browser.
"""

import urllib.error
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

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
    monkeypatch.setattr(
        "src.dashboard.api_client._get_json",
        lambda url, timeout=0: {"items": [ROW], "next_cursor": None},
    )

    app = AppTest.from_file(str(APP_PATH), default_timeout=30)
    app.run()

    assert not app.exception
    assert not app.error
    assert len(app.dataframe) == 1
    assert any("1 event(s) loaded" in caption.value for caption in app.caption)
