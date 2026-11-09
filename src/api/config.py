import os
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")


def api_database_url() -> str | None:
    """Return the read-only database URL, or None when it is not configured."""
    return os.getenv("API_DATABASE_URL")
