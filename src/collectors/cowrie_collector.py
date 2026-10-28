
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.normalization.normalize import normalize_event
from src.storage.postgres import insert_events

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOG_FILE = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "cowrie"
    / "cowrie-var"
    / "log"
    / "cowrie"
    / "cowrie.json"
)
QUARANTINE_FILE = PROJECT_ROOT / "data" / "quarantine" / "cowrie_errors.jsonl"


def write_quarantine(line_number: int, line: str, reason: str) -> None:
    """Record safe diagnostic metadata without copying the raw log line."""
    QUARANTINE_FILE.parent.mkdir(parents=True, exist_ok=True)

    record = {
        "line_number": line_number,
        "reason": reason,
        "line_sha256": hashlib.sha256(line.encode("utf-8")).hexdigest(),
        "quarantined_at": datetime.now(timezone.utc).isoformat(),
    }

    with QUARANTINE_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record) + "\n")


def read_cowrie_events(log_file: Path) -> tuple[list[dict[str, Any]], int]:
    """Read Cowrie JSONL, normalize valid records, and quarantine invalid ones."""
    events: list[dict[str, Any]] = []
    quarantined = 0

    with log_file.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                raw_event = json.loads(line)
            except json.JSONDecodeError:
                write_quarantine(line_number, line, "Invalid JSON")
                quarantined += 1
                continue

            try:
                event = normalize_event(raw_event, source="cowrie")
            except (ValueError, TypeError, AttributeError):
                # Do not write the raw event or exception details to quarantine.
                write_quarantine(line_number, line, "Event normalization failed")
                quarantined += 1
                continue

            events.append(event)

    return events, quarantined


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Normalize local Cowrie JSONL events and import them into PostgreSQL."
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=DEFAULT_LOG_FILE,
        help="Path to the Cowrie JSONL log file.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and normalize events without inserting into PostgreSQL.",
    )
    args = parser.parse_args()

    if not args.log_file.is_file():
        raise SystemExit(
            "Cowrie log file not found. Check the --log-file path and try again."
        )

    events, quarantined = read_cowrie_events(args.log_file)

    if args.dry_run:
        print(f"Valid events normalized: {len(events)}")
        print(f"Records quarantined: {quarantined}")
        print("Dry run only; nothing was inserted into PostgreSQL.")
        return

    inserted, duplicates = insert_events(events)
    print(f"New events inserted: {inserted}")
    print(f"Duplicate events skipped: {duplicates}")
    print(f"Records quarantined: {quarantined}")


if __name__ == "__main__":
    main()
