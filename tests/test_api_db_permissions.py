"""PostgreSQL permission tests for the read-only ``honeytrace_api`` role.

These tests need the Docker database, so they are marked ``db``. The ordinary
suite stays Docker-free:

    pytest -m "not db"

When ``API_DATABASE_URL`` is missing or the database is unreachable, every
test in this module skips instead of failing.
"""

from collections.abc import Iterator

import psycopg
import pytest
from psycopg import errors

from src.api.config import api_database_url

pytestmark = pytest.mark.db

APPROVED_COLUMN = "event_id"

RESTRICTED_COLUMNS = (
    "raw_event",
    "metadata",
    "command",
    "message",
    "username",
    "source_event_id",
)

# Only the public `event_id` column is referenced, so this tests table-level
# INSERT privilege rather than a restricted column. force_rollback makes it
# harmless even if the grant were unexpectedly present.
INSERT_SQL = "INSERT INTO security_events (event_id) VALUES (%s)"

# `WHERE false` matches no rows even if the privilege were granted.
UPDATE_SQL = "UPDATE security_events SET src_ip = src_ip WHERE false"
DELETE_SQL = "DELETE FROM security_events WHERE false"


@pytest.fixture(scope="module")
def connection() -> Iterator[psycopg.Connection]:
    """A connection as the API role, or skip when the database is absent."""
    url = api_database_url()
    if not url:
        pytest.skip("API_DATABASE_URL is not configured")

    try:
        conn = psycopg.connect(url, connect_timeout=2)
    except psycopg.Error as exc:
        # Class name only: never render the DSN, which contains the password.
        pytest.skip(f"database unavailable: {type(exc).__name__}")

    yield conn
    conn.close()


def test_connection_uses_the_read_only_api_role(connection: psycopg.Connection) -> None:
    with connection.transaction(force_rollback=True):
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_user")
            assert cursor.fetchone() == ("honeytrace_api",)


def test_api_role_can_select_an_approved_column(connection: psycopg.Connection) -> None:
    with connection.transaction(force_rollback=True):
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT {APPROVED_COLUMN} FROM security_events LIMIT 0")


@pytest.mark.parametrize("column", RESTRICTED_COLUMNS)
def test_api_role_cannot_select_a_restricted_column(
    connection: psycopg.Connection, column: str
) -> None:
    # `column` comes from the fixed tuple above, never from user input.
    with connection.transaction(force_rollback=True):
        with pytest.raises(errors.InsufficientPrivilege):
            with connection.cursor() as cursor:
                cursor.execute(f"SELECT {column} FROM security_events LIMIT 0")


def test_api_role_cannot_select_every_column(connection: psycopg.Connection) -> None:
    with connection.transaction(force_rollback=True):
        with pytest.raises(errors.InsufficientPrivilege):
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM security_events LIMIT 0")


def test_api_role_cannot_insert(connection: psycopg.Connection) -> None:
    with connection.transaction(force_rollback=True):
        with pytest.raises(errors.InsufficientPrivilege):
            with connection.cursor() as cursor:
                cursor.execute(INSERT_SQL, ("0" * 64,))


def test_api_role_cannot_update(connection: psycopg.Connection) -> None:
    with connection.transaction(force_rollback=True):
        with pytest.raises(errors.InsufficientPrivilege):
            with connection.cursor() as cursor:
                cursor.execute(UPDATE_SQL)


def test_api_role_cannot_delete(connection: psycopg.Connection) -> None:
    with connection.transaction(force_rollback=True):
        with pytest.raises(errors.InsufficientPrivilege):
            with connection.cursor() as cursor:
                cursor.execute(DELETE_SQL)
