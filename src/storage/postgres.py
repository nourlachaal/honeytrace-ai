
import os
from pathlib import Path
from typing import Any, Iterable

import psycopg
from dotenv import load_dotenv
from psycopg.types.json import Jsonb


# Load the .env file from the project root, regardless of the current directory.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")


INSERT_SQL = """
INSERT INTO security_events (
    event_id,
    source,
    source_event_id,
    event_timestamp,
    event_type,
    session_id,
    scenario_id,
    test_run_id,
    src_ip,
    protocol,
    username,
    command,
    http_method,
    route,
    status_code,
    message,
    metadata,
    raw_event
)
VALUES (
    %(event_id)s,
    %(source)s,
    %(source_event_id)s,
    %(event_timestamp)s,
    %(event_type)s,
    %(session_id)s,
    %(scenario_id)s,
    %(test_run_id)s,
    %(src_ip)s,
    %(protocol)s,
    %(username)s,
    %(command)s,
    %(http_method)s,
    %(route)s,
    %(status_code)s,
    %(message)s,
    %(metadata)s,
    %(raw_event)s
)
ON CONFLICT (event_id) DO NOTHING
"""


def get_database_url() -> str:
    """Return the configured database URL without printing credentials."""
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError(
            "DATABASE_URL is missing. Configure it in the project-root .env file."
        )
    return database_url


def insert_events(events: Iterable[dict[str, Any]]) -> tuple[int, int]:
    """
    Insert normalized events in one transaction.

    Returns (inserted_count, duplicate_count).
    Duplicate event IDs are safely ignored.
    """
    inserted = 0
    duplicates = 0

    with psycopg.connect(get_database_url()) as connection:
        with connection.cursor() as cursor:
            for event in events:
                parameters = dict(event)
                parameters["metadata"] = Jsonb(event["metadata"])
                parameters["raw_event"] = Jsonb(event["raw_event"])

                cursor.execute(INSERT_SQL, parameters)

                if cursor.rowcount == 1:
                    inserted += 1
                else:
                    duplicates += 1

    return inserted, duplicates


def insert_event(event: dict[str, Any]) -> bool:
    """Insert one normalized event; return False if it was already stored."""
    inserted, _duplicates = insert_events([event])
    return inserted == 1
