
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.normalization.normalize import normalize_event
from src.storage.postgres import insert_events

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOG_FILE = PROJECT_ROOT / "data" / "raw" / "juice-shop" / "access.jsonl"
QUARANTINE_FILE = (
    PROJECT_ROOT / "data" / "quarantine" / "juice_shop_errors.jsonl"
)


def write_quarantine(line_number: int, line: str, reason: str) -> None:
    """Store diagnostic metadata without copying potentially sensitive log data."""
    QUARANTINE_FILE.parent.mkdir(parents=True, exist_ok=True)

    record = {
        "line_number": line_number,
        "reason": reason,
        "line_sha256": hashlib.sha256(line.encode("utf-8")).hexdigest(),
        "quarantined_at": datetime.now(timezone.utc).isoformat(),
    }

    with QUARANTINE_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record) + "\n")


def read_juice_shop_events(
    log_file: Path,
    scenario_id: str | None = None, test_run_id: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Parse and normalize Nginx JSONL access events."""
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
                event = normalize_event(raw_event, source="juice_shop", scenario_id=scenario_id, test_run_id=test_run_id)
            except (ValueError, TypeError, AttributeError):
                write_quarantine(
                    line_number, line, "Event normalization failed"
                )
                quarantined += 1
                continue

            events.append(event)

    return events, quarantined


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Import normalized Juice Shop HTTP access events."
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=DEFAULT_LOG_FILE,
        help="Path to the Nginx JSONL access log.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Normalize events without inserting them into PostgreSQL.",
    )
    parser.add_argument("--scenario-id", default=None)
    parser.add_argument("--test-run-id", default=None)
    args = parser.parse_args()

    if not args.log_file.is_file():
        raise SystemExit(
            "Juice Shop access log not found. Check the --log-file path."
        )

    events, quarantined = read_juice_shop_events(args.log_file, args.scenario_id, args.test_run_id)

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
