import base64
import binascii
import re
from datetime import datetime
from typing import Any

import psycopg
from psycopg.rows import dict_row

from src.api.config import api_database_url

CONNECT_TIMEOUT_SECONDS = 2
STATEMENT_TIMEOUT_MS = 5000

EVENT_ID_REGEX = r"^[0-9a-f]{64}$"
EVENT_ID_PATTERN = re.compile(EVENT_ID_REGEX)

# Mirrors docs/api-field-policy.md and the column grants in sql/002.
SELECT_COLUMNS = (
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
)

_BASE_QUERY = f"SELECT {', '.join(SELECT_COLUMNS)} FROM security_events"
_ORDER_AND_LIMIT = " ORDER BY event_timestamp DESC, event_id DESC LIMIT %(limit)s"


class CursorError(ValueError):
    """The pagination cursor is malformed or unparseable."""


class DatabaseNotConfigured(RuntimeError):
    """API_DATABASE_URL is absent."""


class DatabaseUnavailable(RuntimeError):
    """The read-only database could not be reached or queried."""


def _connect(url: str) -> psycopg.Connection:
    return psycopg.connect(
        url,
        connect_timeout=CONNECT_TIMEOUT_SECONDS,
        application_name="honeytrace-api",
        options=f"-c statement_timeout={STATEMENT_TIMEOUT_MS}",
    )


def encode_cursor(event_timestamp: datetime, event_id: str) -> str:
    raw = f"{event_timestamp.isoformat()}|{event_id}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    padding = "=" * (-len(cursor) % 4)
    try:
        raw = base64.urlsafe_b64decode(cursor + padding).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise CursorError("invalid cursor") from exc

    timestamp, separator, event_id = raw.partition("|")
    if not separator or not EVENT_ID_PATTERN.match(event_id):
        raise CursorError("invalid cursor")

    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise CursorError("invalid cursor") from exc

    if parsed.tzinfo is None:
        raise CursorError("invalid cursor")

    return parsed, event_id


def fetch_events(
    *,
    limit: int,
    cursor: tuple[datetime, str] | None = None,
    source: str | None = None,
    event_type: str | None = None,
    src_ip: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[dict[str, Any]]:
    """Fetch up to limit + 1 approved event rows, newest first.

    The extra row lets the caller detect whether another page exists without a
    second query. Only fixed SQL fragments are concatenated; every value is bound
    as a parameter.
    """
    url = api_database_url()
    if not url:
        raise DatabaseNotConfigured

    conditions: list[str] = []
    params: dict[str, Any] = {"limit": limit + 1}

    if cursor is not None:
        conditions.append("(event_timestamp, event_id) < (%(cursor_ts)s, %(cursor_id)s)")
        params["cursor_ts"] = cursor[0]
        params["cursor_id"] = cursor[1]

    if source is not None:
        conditions.append("source = %(source)s")
        params["source"] = source

    if event_type is not None:
        conditions.append("event_type = %(event_type)s")
        params["event_type"] = event_type

    if src_ip is not None:
        conditions.append("src_ip = %(src_ip)s")
        params["src_ip"] = src_ip

    if since is not None:
        conditions.append("event_timestamp >= %(since)s")
        params["since"] = since

    if until is not None:
        conditions.append("event_timestamp < %(until)s")
        params["until"] = until

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
        raise DatabaseUnavailable from exc


def fetch_event(event_id: str) -> dict[str, Any] | None:
    """Fetch one approved event row by id, or None when no such row exists.

    Same column allowlist as fetch_events. The id is bound as a parameter and
    is already validated as 64 lowercase hex characters by the route.
    """
    url = api_database_url()
    if not url:
        raise DatabaseNotConfigured

    query = _BASE_QUERY + " WHERE event_id = %(event_id)s"

    try:
        with _connect(url) as connection:
            with connection.cursor(row_factory=dict_row) as cursor_obj:
                cursor_obj.execute(query, {"event_id": event_id})
                return cursor_obj.fetchone()
    except psycopg.Error as exc:
        raise DatabaseUnavailable from exc
