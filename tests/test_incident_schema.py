"""Acceptance tests for sql/003 (tables) and sql/004 (grants).

They need a database that already has sql/001..004 applied, so they are marked
``db``:

    pytest -m db tests/test_incident_schema.py

This is the objective definition of "the migrations are done": columns,
constraints and the grant boundary are checked, not assumed. When the database
is unreachable every test skips instead of failing.
"""

import os
from collections.abc import Iterator

import psycopg
import pytest
from psycopg import errors

from src.api.config import api_database_url  # also loads .env

pytestmark = pytest.mark.db

INCIDENT_COLUMNS = {
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
}

DETECTION_COLUMNS = {
    "detection_id",
    "rule_id",
    "description",
    "severity",
    "source_event_ids",
    "evidence_public",
    "evidence_internal",
    "detector_version",
    "created_at",
}

ARRAY_COLUMNS = ("detection_ids", "event_ids", "missing_event_ids")
STATUSES = ("open", "under_review", "resolved", "false_positive")
SEVERITIES = ("low", "medium", "high", "critical")

INSERT_SQL = "INSERT INTO incidents (incident_id) VALUES (%s)"
UPDATE_SQL = "UPDATE incidents SET status = status WHERE false"
DELETE_SQL = "DELETE FROM incidents WHERE false"


def _connect(url: str) -> psycopg.Connection:
    return psycopg.connect(url, connect_timeout=2)


@pytest.fixture(scope="module")
def owner_connection() -> Iterator[psycopg.Connection]:
    """Connection as the write account, used to inspect the schema itself."""
    url = os.getenv("DATABASE_URL")
    if not url:
        pytest.skip("DATABASE_URL is not configured")

    try:
        conn = _connect(url)
    except psycopg.Error as exc:
        # Class name only: never render the DSN, which contains the password.
        pytest.skip(f"database unavailable: {type(exc).__name__}")

    yield conn
    conn.close()


@pytest.fixture(scope="module")
def api_connection() -> Iterator[psycopg.Connection]:
    """Connection as the read-only API role, used to test the grant boundary."""
    url = api_database_url()
    if not url:
        pytest.skip("API_DATABASE_URL is not configured")

    try:
        conn = _connect(url)
    except psycopg.Error as exc:
        pytest.skip(f"database unavailable: {type(exc).__name__}")

    yield conn
    conn.close()


def _column_types(connection: psycopg.Connection, table: str) -> dict[str, tuple[str, str]]:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT column_name, data_type, is_nullable
              FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = %s
            """,
            (table,),
        )
        return {
            name: (data_type, is_nullable)
            for name, data_type, is_nullable in cursor.fetchall()
        }


def _column_default(
    connection: psycopg.Connection, table: str, column: str
) -> str | None:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT column_default
              FROM information_schema.columns
             WHERE table_schema = 'public'
               AND table_name = %s
               AND column_name = %s
            """,
            (table, column),
        )
        row = cursor.fetchone()
        return row[0] if row else None


def _constraint_definitions(
    connection: psycopg.Connection, table: str, contype: str
) -> list[str]:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT pg_get_constraintdef(oid)
              FROM pg_constraint
             WHERE conrelid = %s::regclass AND contype = %s
            """,
            (f"public.{table}", contype),
        )
        return [row[0] for row in cursor.fetchall()]


def test_incidents_table_exists(owner_connection: psycopg.Connection) -> None:
    with owner_connection.cursor() as cursor:
        cursor.execute("SELECT to_regclass('public.incidents')")
        assert cursor.fetchone()[0] is not None


def test_detections_table_exists(owner_connection: psycopg.Connection) -> None:
    with owner_connection.cursor() as cursor:
        cursor.execute("SELECT to_regclass('public.detections')")
        assert cursor.fetchone()[0] is not None


def test_incidents_has_exactly_the_agreed_columns(
    owner_connection: psycopg.Connection,
) -> None:
    assert set(_column_types(owner_connection, "incidents")) == INCIDENT_COLUMNS


def test_detections_has_exactly_the_agreed_columns(
    owner_connection: psycopg.Connection,
) -> None:
    assert set(_column_types(owner_connection, "detections")) == DETECTION_COLUMNS


def test_incident_id_is_the_primary_key(owner_connection: psycopg.Connection) -> None:
    with owner_connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT a.attname
              FROM pg_index i
              JOIN pg_attribute a
                ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey)
             WHERE i.indrelid = 'public.incidents'::regclass
               AND i.indisprimary
            """
        )
        assert [row[0] for row in cursor.fetchall()] == ["incident_id"]


def test_source_and_session_id_are_unique_together(
    owner_connection: psycopg.Connection,
) -> None:
    definitions = _constraint_definitions(owner_connection, "incidents", "u")
    assert any("UNIQUE (source, session_id)" in d for d in definitions)


@pytest.mark.parametrize("column", ARRAY_COLUMNS)
def test_incident_id_array_is_a_not_null_text_array(
    owner_connection: psycopg.Connection, column: str
) -> None:
    columns = _column_types(owner_connection, "incidents")
    assert columns[column] == ("ARRAY", "NO")


def test_timeline_is_a_not_null_jsonb(owner_connection: psycopg.Connection) -> None:
    columns = _column_types(owner_connection, "incidents")
    assert columns["timeline"] == ("jsonb", "NO")


def test_has_new_evidence_is_a_not_null_boolean_defaulting_to_false(
    owner_connection: psycopg.Connection,
) -> None:
    columns = _column_types(owner_connection, "incidents")
    assert columns["has_new_evidence"] == ("boolean", "NO")
    assert _column_default(owner_connection, "incidents", "has_new_evidence") == "false"


def test_status_defaults_to_open(owner_connection: psycopg.Connection) -> None:
    default = _column_default(owner_connection, "incidents", "status")
    assert default is not None
    assert "open" in default


def test_status_check_allows_exactly_the_four_statuses(
    owner_connection: psycopg.Connection,
) -> None:
    definitions = _constraint_definitions(owner_connection, "incidents", "c")
    status_checks = [d for d in definitions if "status" in d]

    assert len(status_checks) == 1
    for value in STATUSES:
        assert value in status_checks[0]


def test_severity_check_on_incidents_lists_the_four_severities(
    owner_connection: psycopg.Connection,
) -> None:
    definitions = _constraint_definitions(owner_connection, "incidents", "c")
    severity_checks = [d for d in definitions if "severity" in d]

    assert len(severity_checks) == 1
    for value in SEVERITIES:
        assert value in severity_checks[0]


def test_severity_check_on_detections_lists_the_four_severities(
    owner_connection: psycopg.Connection,
) -> None:
    definitions = _constraint_definitions(owner_connection, "detections", "c")
    severity_checks = [d for d in definitions if "severity" in d]

    assert len(severity_checks) == 1
    for value in SEVERITIES:
        assert value in severity_checks[0]


def test_api_role_can_select_the_granted_incident_columns(
    api_connection: psycopg.Connection,
) -> None:
    columns = ", ".join(sorted(INCIDENT_COLUMNS))
    with api_connection.transaction(force_rollback=True):
        with api_connection.cursor() as cursor:
            cursor.execute(f"SELECT {columns} FROM incidents LIMIT 0")


def test_api_role_can_select_evidence_public_on_detections(
    api_connection: psycopg.Connection,
) -> None:
    with api_connection.transaction(force_rollback=True):
        with api_connection.cursor() as cursor:
            cursor.execute("SELECT evidence_public FROM detections LIMIT 0")


def test_api_role_cannot_select_evidence_internal_on_detections(
    api_connection: psycopg.Connection,
) -> None:
    with api_connection.transaction(force_rollback=True):
        with pytest.raises(errors.InsufficientPrivilege):
            with api_connection.cursor() as cursor:
                cursor.execute("SELECT evidence_internal FROM detections LIMIT 0")


@pytest.mark.parametrize("table", ["detections"])
def test_api_role_cannot_select_every_column(
    api_connection: psycopg.Connection, table: str
) -> None:
    with api_connection.transaction(force_rollback=True):
        with pytest.raises(errors.InsufficientPrivilege):
            with api_connection.cursor() as cursor:
                cursor.execute(f"SELECT * FROM {table} LIMIT 0")
@pytest.mark.parametrize("table", ["incidents", "detections"])
def test_api_role_has_no_table_level_select(api_connection, table):
    with api_connection.cursor() as cursor:
        cursor.execute(
            "SELECT has_table_privilege(current_user, %s, 'SELECT')", (table,)
        )
        assert cursor.fetchone()[0] is False

@pytest.mark.parametrize(
    "statement",
    [INSERT_SQL, UPDATE_SQL, DELETE_SQL],
    ids=["insert", "update", "delete"],
)
def test_api_role_cannot_write(
    api_connection: psycopg.Connection, statement: str
) -> None:
    params = ("0" * 64,) if statement is INSERT_SQL else None

    with api_connection.transaction(force_rollback=True):
        with pytest.raises(errors.InsufficientPrivilege):
            with api_connection.cursor() as cursor:
                cursor.execute(statement, params)