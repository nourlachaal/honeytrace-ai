"""HTTP client for the HoneyTrace read-only API.

The dashboard never talks to PostgreSQL. Every read goes through the API so the
approved field contract is exercised, and so the column-level grants on
``honeytrace_api`` remain the only database access path.

Uses only the standard library: no extra HTTP dependency beyond Streamlit.
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

DEFAULT_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_TIMEOUT_SECONDS = 10.0

SOURCES = ("cowrie", "juice_shop")

# Mirrors the API's Literal types. Duplicated on purpose: the dashboard talks to
# the API over HTTP, so it must not import the API's internal modules.
INCIDENT_STATUSES = ("open", "under_review", "resolved", "false_positive")
SEVERITIES = ("low", "medium", "high", "critical")


class ApiError(RuntimeError):
    """The API could not be reached, or returned an error response."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def api_base_url() -> str:
    """Return the API root, e.g. http://127.0.0.1:8000 (no trailing slash)."""
    return os.getenv("API_BASE_URL", DEFAULT_BASE_URL).rstrip("/")


def _error_detail(exc: urllib.error.HTTPError) -> str:
    """Extract the API's short error code without assuming a JSON body."""
    try:
        payload = json.loads(exc.read().decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return f"http_{exc.code}"

    detail = payload.get("detail") if isinstance(payload, dict) else None
    return detail if isinstance(detail, str) else f"http_{exc.code}"


def _get_json(url: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> Any:
    """GET a JSON document. Raises ApiError on any failure."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise ApiError(_error_detail(exc), status_code=exc.code) from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise ApiError("api_unavailable") from exc


def build_events_url(
    *,
    base_url: str | None = None,
    limit: int = 50,
    cursor: str | None = None,
    source: str | None = None,
    event_type: str | None = None,
    src_ip: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> str:
    """Build the /events URL. Only non-empty filters are sent."""
    params: dict[str, Any] = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    if source:
        params["source"] = source
    if event_type:
        params["event_type"] = event_type
    if src_ip:
        params["src_ip"] = src_ip
    if since:
        params["since"] = since
    if until:
        params["until"] = until

    root = (base_url or api_base_url()).rstrip("/")
    return f"{root}/events?{urllib.parse.urlencode(params)}"


def fetch_events(
    *,
    base_url: str | None = None,
    limit: int = 50,
    cursor: str | None = None,
    source: str | None = None,
    event_type: str | None = None,
    src_ip: str | None = None,
    since: str | None = None,
    until: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Fetch one page of events. Returns {"items": [...], "next_cursor": ...}."""
    url = build_events_url(
        base_url=base_url,
        limit=limit,
        cursor=cursor,
        source=source,
        event_type=event_type,
        src_ip=src_ip,
        since=since,
        until=until,
    )
    payload = _get_json(url, timeout=timeout)

    if not isinstance(payload, dict) or "items" not in payload:
        raise ApiError("unexpected_response")
    return payload


def fetch_event(
    event_id: str,
    *,
    base_url: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Fetch one event by id. Raises ApiError with status 404 when unknown."""
    root = (base_url or api_base_url()).rstrip("/")
    url = f"{root}/events/{urllib.parse.quote(event_id, safe='')}"
    payload = _get_json(url, timeout=timeout)

    if not isinstance(payload, dict) or "event_id" not in payload:
        raise ApiError("unexpected_response")
    return payload


def build_incidents_url(
    *,
    base_url: str | None = None,
    limit: int = 50,
    cursor: str | None = None,
    source: str | None = None,
    status: str | None = None,
    severity: str | None = None,
) -> str:
    """Build the /incidents URL. Only non-empty filters are sent."""
    params: dict[str, Any] = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    if source:
        params["source"] = source
    if status:
        params["status"] = status
    if severity:
        params["severity"] = severity

    root = (base_url or api_base_url()).rstrip("/")
    return f"{root}/incidents?{urllib.parse.urlencode(params)}"


def fetch_incidents(
    *,
    base_url: str | None = None,
    limit: int = 50,
    cursor: str | None = None,
    source: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Fetch one page of incidents.

    Raises ApiError with status 503 while the tables are missing. The message is
    the API's detail string: incidents_table_missing, incidents_not_granted,
    incidents_unavailable or incidents_not_configured.
    """
    url = build_incidents_url(
        base_url=base_url,
        limit=limit,
        cursor=cursor,
        source=source,
        status=status,
        severity=severity,
    )
    payload = _get_json(url, timeout=timeout)

    if not isinstance(payload, dict) or "items" not in payload:
        raise ApiError("unexpected_response")
    return payload


def fetch_incident(
    incident_id: str,
    *,
    base_url: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Fetch one incident by id. Raises ApiError with status 404 when unknown."""
    root = (base_url or api_base_url()).rstrip("/")
    url = f"{root}/incidents/{urllib.parse.quote(incident_id, safe='')}"
    payload = _get_json(url, timeout=timeout)

    if not isinstance(payload, dict) or "incident_id" not in payload:
        raise ApiError("unexpected_response")
    return payload
