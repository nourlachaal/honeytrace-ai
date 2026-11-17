"""Runner : lit security_events, applique règles + corrélation, écrit en base.

    python -m src.pipeline                          # tout traiter
    python -m src.pipeline --since 2026-11-19T00:00:00Z
    python -m src.pipeline --dry-run                # n'écrit rien

--since : prend les sessions qui ont au moins un événement depuis cette date,
puis charge TOUS les événements de ces sessions (seuils et timelines complets).
Idempotent : une 2e exécution ne modifie rien (détections en DO NOTHING,
incidents mis à jour seulement s'ils reçoivent de nouvelles détections).
Variable d'environnement : DATABASE_URL.
"""

import argparse
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import psycopg
from dotenv import load_dotenv
from psycopg.rows import dict_row

from src.correlation.correlator import IncidentCorrelator
from src.detection.engine import DetectionEngine
from src.storage.detections_writer import write_results

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Colonnes strictement nécessaires (ni message ni raw_event).
EVENT_COLUMNS = (
    "event_id, source, event_type, session_id, event_timestamp, src_ip, "
    "protocol, username, command, http_method, route, status_code, metadata"
)


def parse_since(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("--since must include a timezone, e.g. 2026-11-19T00:00:00Z")
    return parsed.astimezone(timezone.utc)


def build_events_query(since: Optional[datetime]) -> tuple:
    base = f"SELECT {EVENT_COLUMNS} FROM security_events"
    order = " ORDER BY event_timestamp, event_id"
    if since is None:
        return base + order, {}
    where = (
        " WHERE event_timestamp >= %(since)s OR (session_id IS NOT NULL AND "
        "(source, session_id) IN (SELECT source, session_id FROM security_events "
        "WHERE session_id IS NOT NULL AND event_timestamp >= %(since)s))"
    )
    return base + where + order, {"since": since}


def fetch_events(connection, since: Optional[datetime]) -> list:
    query, params = build_events_query(since)
    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(query, params)
        return list(cursor.fetchall())


def run_pipeline(events: list, now: Optional[datetime] = None) -> tuple:
    """Règles puis corrélation. Aucune écriture : fonction pure, testable."""
    now = now or datetime.now(timezone.utc)
    detections = DetectionEngine().analyze(events, now=now)
    incidents = IncidentCorrelator().correlate(detections, events, now=now)
    return detections, incidents


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run detection and correlation.")
    parser.add_argument("--since", help="ISO 8601 UTC, e.g. 2026-11-19T00:00:00Z")
    parser.add_argument("--dry-run", action="store_true", help="do not write to the database")
    args = parser.parse_args(argv)

    load_dotenv(PROJECT_ROOT / ".env")
    url = os.getenv("DATABASE_URL")
    if not url:
        print("DATABASE_URL is not configured")
        return 2
    try:
        since = parse_since(args.since) if args.since else None
    except ValueError as exc:
        print(f"Invalid --since: {exc}")
        return 2

    with psycopg.connect(url) as connection:
        events = fetch_events(connection, since)
        detections, incidents = run_pipeline(events)
        print(f"events read: {len(events)}")
        print(f"detections: {len(detections)} | incidents: {len(incidents)}")
        print("incidents by severity:", dict(sorted(Counter(i.severity for i in incidents).items())))
        if args.dry_run:
            print("dry-run: nothing written")
            return 0
        print("written:", write_results(connection, detections, incidents))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())