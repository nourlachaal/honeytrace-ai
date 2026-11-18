"""Charge les labels de sessions (CSV de Person 1) : {(source, session_id): 0|1}."""

import csv
from pathlib import Path

REQUIRED_COLUMNS = ("source", "session_id", "label")


def load_labels(path) -> dict:
    labels = {}
    with Path(path).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = [c for c in REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"Missing column(s): {', '.join(missing)}")
        for line, row in enumerate(reader, start=2):
            source = (row["source"] or "").strip()
            session_id = (row["session_id"] or "").strip()
            if not source or not session_id:
                raise ValueError(f"Line {line}: empty source or session_id")
            if row["label"] not in ("0", "1"):
                raise ValueError(f"Line {line}: label must be 0 or 1")
            key = (source, session_id)
            if key in labels:
                raise ValueError(f"Line {line}: duplicate session")
            labels[key] = int(row["label"])
    if not labels:
        raise ValueError("No labels found")
    return labels