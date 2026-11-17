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
COMPRESSED_SUFFIXES = {".gz", ".bz2", ".xz", ".zip"}


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


def read_cowrie_events(
    log_file: Path,
    scenario_id: str | None = None,
    test_run_id: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Read Cowrie JSONL, normalize valid records, and quarantine invalid ones.

    scenario_id and test_run_id are attached to every event of the file, so
    pass them only for a log that contains a single, verified test run.
    """
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
                event = normalize_event(
                    raw_event,
                    source="cowrie",
                    scenario_id=scenario_id,
                    test_run_id=test_run_id,
                )
            except (ValueError, TypeError, AttributeError):
                # Do not write the raw event or exception details to quarantine.
                write_quarantine(line_number, line, "Event normalization failed")
                quarantined += 1
                continue

            events.append(event)

    return events, quarantined


def find_log_files(log_file: Path, include_rotated: bool = True) -> list[Path]:
    """Return rotated logs (oldest first, by date suffix) then the current log.

    Compressed rotations (.gz and similar) are skipped: they are not JSONL text.
    """
    files: list[Path] = []
    if include_rotated:
        files = sorted(
            path
            for path in log_file.parent.glob(f"{log_file.name}.*")
            if path.is_file() and path.suffix not in COMPRESSED_SUFFIXES
        )
    files.append(log_file)
    return files


def read_cowrie_logs(
    log_file: Path,
    scenario_id: str | None = None,
    test_run_id: str | None = None,
    include_rotated: bool = True,
) -> tuple[list[dict[str, Any]], int]:
    """Read the current Cowrie log and, by default, its rotated siblings."""
    events: list[dict[str, Any]] = []
    quarantined = 0
    for path in find_log_files(log_file, include_rotated):
        file_events, file_quarantined = read_cowrie_events(
            path, scenario_id, test_run_id
        )
        events.extend(file_events)
        quarantined += file_quarantined
    return events, quarantined


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Normalize local Cowrie JSONL events and import them into PostgreSQL."
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=DEFAULT_LOG_FILE,
        help="Path to the Cowrie JSONL log file (rotated cowrie.json.* files "
        "next to it are read too).",
    )
    parser.add_argument(
        "--no-rotated",
        action="store_true",
        help="Read only --log-file, not its rotated siblings.",
    )
    parser.add_argument(
        "--scenario-id",
        default=None,
        help="Verified scenario id to attach to every event of this log.",
    )
    parser.add_argument(
        "--test-run-id",
        default=None,
        help="Verified test run id to attach to every event of this log.",
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

    files = find_log_files(args.log_file, include_rotated=not args.no_rotated)
    if (args.scenario_id or args.test_run_id) and len(files) > 1:
        raise SystemExit(
            "Refusing to tag events from several log files with one test run. "
            "Use --no-rotated with a log file that contains only that run."
        )

    events, quarantined = read_cowrie_logs(
        args.log_file,
        scenario_id=args.scenario_id,
        test_run_id=args.test_run_id,
        include_rotated=not args.no_rotated,
    )

    if args.dry_run:
        print(f"Log files read: {len(files)}")
        print(f"Valid events normalized: {len(events)}")
        print(f"Records quarantined: {quarantined}")
        print("Dry run only; nothing was inserted into PostgreSQL.")
        return

    inserted, duplicates = insert_events(events)
    print(f"Log files read: {len(files)}")
    print(f"New events inserted: {inserted}")
    print(f"Duplicate events skipped: {duplicates}")
    print(f"Records quarantined: {quarantined}")


if __name__ == "__main__":
    main()