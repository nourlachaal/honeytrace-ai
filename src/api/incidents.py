"""Read-only incident queries for the API.

`incidents` is created by sql/003 and written by the detection pipeline. Until
that migration is applied, queries raise IncidentsUnavailable and the routes
answer 503 instead of crashing.
"""

import re
from datetime import datetime
from typing import Any

import psycopg
from psycopg.rows import dict_row

from src.api.config import api_database_url

CONNECT_TIMEOUT_SECONDS = 2
STATEMENT_TIMEOUT_MS = 5000

INCIDENT_ID_REGEX = r"^[0-9a-f]{64}$"
INCIDENT_ID_PATTERN = re.compile(INCIDENT_ID_REGEX)

# Mirrors the column grants in sql/004 and section 7 of the integration
# contract. evidence_internal must never appear here.
SELECT_COLUMNS = (
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
)

_BASE_QUERY = f"SELECT {', '.join(SELECT_COLUMNS)} FROM incidents"
_ORDER_AND_LIMIT = " ORDER BY updated_at DESC, incident_id DESC LIMIT %(limit)s"

# SQLSTATE codes meaning "the schema is not what sql/003 and sql/004 promise".
_MISSING_SCHEMA = {"42P01", "42703"}  # undefined_table, undefined_column
_NOT_GRANTED = {"42501"}  # insufficient_privilege


class IncidentsUnavailable(RuntimeError):
    """Incidents cannot be served yet.

    reason is one of: not_configured, table_missing, not_granted, unavailable.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _connect(url: str) -> psycopg.Connection:
    return psycopg.connect(
        url,
        connect_timeout=CONNECT_TIMEOUT_SECONDS,
        application_name="honeytrace-api",
        options=f"-c statement_timeout={STATEMENT_TIMEOUT_MS}",
    )


def _translate(exc: psycopg.Error) -> IncidentsUnavailable:
    """Turn a database error into a reason the route can report safely."""
    if exc.sqlstate in _MISSING_SCHEMA:
        return IncidentsUnavailable("table_missing")
    if exc.sqlstate in _NOT_GRANTED:
        return IncidentsUnavailable("not_granted")
    return IncidentsUnavailable("unavailable")


def fetch_incidents(
    *,
    limit: int,
    cursor: tuple[datetime, str] | None = None,
    source: str | None = None,
    incident_status: str | None = None,
    severity: str | None = None,
) -> list[dict[str, Any]]:
    """Fetch up to limit + 1 incident rows, most recently updated first.

    The extra row lets the caller detect whether another page exists without a
    second query. Only fixed SQL fragments are concatenated; every value is
    bound as a parameter.
    """
    url = api_database_url()
    if not url:
        raise IncidentsUnavailable("not_configured")

    conditions: list[str] = []
    params: dict[str, Any] = {"limit": limit + 1}

    if cursor is not None:
        conditions.append("(updated_at, incident_id) < (%(cursor_ts)s, %(cursor_id)s)")
        params["cursor_ts"] = cursor[0]
        params["cursor_id"] = cursor[1]

    if source is not None:
        conditions.append("source = %(source)s")
        params["source"] = source

    if incident_status is not None:
        conditions.append("status = %(incident_status)s")
        params["incident_status"] = incident_status

    if severity is not None:
        conditions.append("severity = %(severity)s")
        params["severity"] = severity

    query = _BASE_QUERY
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += _ORDER_AND_LIMIT

    try:
        with _connect(url) as connection:
            with connection.cursor(row_factory=dict_row) as cursor_obj:
                cursor_obj.execute(query, params)
                return list(cursor_obj.fetchall())
    except psycopg.Error as exc:
        raise _translate(exc) from exc


def fetch_incident(incident_id: str) -> dict[str, Any] | None:
    """Fetch one incident by id, or None when no such row exists.

    Same column allowlist as fetch_incidents. The id is bound as a parameter
    and is already validated as 64 lowercase hex characters by the route.
    """
    url = api_database_url()
    if not url:
        raise IncidentsUnavailable("not_configured")

    query = _BASE_QUERY + " WHERE incident_id = %(incident_id)s"

    try:
        with _connect(url) as connection:
            with connection.cursor(row_factory=dict_row) as cursor_obj:
                cursor_obj.execute(query, {"incident_id": incident_id})
                return cursor_obj.fetchone()
    except psycopg.Error as exc:
        raise _translate(exc) from exc