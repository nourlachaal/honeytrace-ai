"""Build the session label CSV from the replay manifest and PostgreSQL.

For each COMPLETED manifest run, find the Cowrie session whose first event
falls within a few seconds of the run's START (runs are at least 10 s apart,
so these windows cannot overlap) and that contains at least one
cowrie.command.input event. Runs that match zero or several sessions are
skipped with a warning, never guessed. Existing rows in the output file are kept.

Example:
    python scripts/build_labels.py
"""
import argparse
import csv
import os
from datetime import datetime, timedelta
from pathlib import Path

import psycopg
from dotenv import load_dotenv

FIELDS = ["source", "session_id", "label", "scenario_id", "test_run_id"]

QUERY = """
SELECT session_id
FROM security_events
WHERE source = 'cowrie' AND session_id IS NOT NULL
GROUP BY session_id
HAVING MIN(event_timestamp) BETWEEN %s AND %s
   AND COUNT(*) FILTER (WHERE event_type = 'cowrie.command.input') > 0
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", type=Path,
                        default=Path("data/manifests/replay_manifest.csv"))
    parser.add_argument("--output", type=Path,
                        default=Path("data/labels/session_labels.csv"))
    args = parser.parse_args()

    load_dotenv()
    rows: dict[str, dict] = {}
    if args.output.exists():
        with args.output.open(newline="", encoding="utf-8") as file:
            for row in csv.DictReader(file):
                rows[row["session_id"]] = row

    added = skipped = 0
    claimed: set[str] = set()
    with psycopg.connect(os.environ["DATABASE_URL"]) as connection, \
            args.manifest.open(newline="", encoding="utf-8") as manifest:
        for run in csv.DictReader(manifest):
            if run["status"] != "completed":
                skipped += 1
                continue
            started = datetime.fromisoformat(run["started_utc"])
            start = started - timedelta(seconds=1)
            end = started + timedelta(seconds=5)
            with connection.cursor() as cursor:
                cursor.execute(QUERY, (start, end))
                sessions = [r[0] for r in cursor.fetchall()]
            if len(sessions) != 1:
                print(f"WARNING {run['scenario_id']} {run['started_utc']}: "
                      f"{len(sessions)} matching sessions, skipped")
                skipped += 1
                continue
            if sessions[0] in claimed:
                print(f"WARNING {run['scenario_id']} {run['started_utc']}: "
                      f"session {sessions[0]} already used by another run, skipped")
                skipped += 1
                continue
            claimed.add(sessions[0])
            rows[sessions[0]] = {
                "source": "cowrie", "session_id": sessions[0],
                "label": run["label"], "scenario_id": run["scenario_id"],
                "test_run_id": run["test_run_id"],
            }
            added += 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows.values())
    print(f"runs matched: {added}, skipped: {skipped}, total labeled sessions: {len(rows)}")


if __name__ == "__main__":
    main()