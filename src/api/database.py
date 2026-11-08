import psycopg

from src.api.config import api_database_url

READINESS_TIMEOUT_SECONDS = 2


def database_status() -> str:
    """Return 'ok', 'not_configured', or 'unavailable'. Never raises, never logs the URL."""
    url = api_database_url()
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
