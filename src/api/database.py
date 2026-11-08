import os
from pathlib import Path

import psycopg
from dotenv import load_dotenv

READINESS_TIMEOUT_SECONDS = 2

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")


def database_status() -> str:
    """Return 'ok', 'not_configured', or 'unavailable'. Never raises, never logs the URL."""
    url = os.getenv("API_DATABASE_URL")
    if not url:
        return "not_configured"

    try:
        with psycopg.connect(url, connect_timeout=READINESS_TIMEOUT_SECONDS) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
    except psycopg.Error:
        return "unavailable"

    return "ok"
