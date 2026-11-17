"""Évalue règles et Isolation Forest sur les sessions labellisées de la base.

    python -m src.ml.evaluate_real [--labels data/labels/session_labels.csv]

Non supervisé : les labels ne servent qu'à évaluer. Les données sont SCRIPTÉES
(laboratoire) : les métriques sont optimistes. Le modèle est entraîné et évalué
sur les mêmes sessions (22), faute de plus : résultat instable, à ne pas généraliser.
"""

import argparse
import os
from pathlib import Path

import psycopg
from dotenv import load_dotenv

from src.ml.compare_methods import compare_methods, format_table
from src.ml.load_labels import load_labels
from src.pipeline import fetch_events

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def evaluate_labelled(events, labels, contamination=0.1, random_state=42) -> dict:
    """Retourne {"results": ..., "missing": [...], "evaluated": n}."""
    events = list(events)
    present = {(e.get("source"), e.get("session_id")) for e in events}
    kept = {k: v for k, v in labels.items() if k in present}
    missing = sorted(set(labels) - set(kept))
    scoped = [e for e in events if (e.get("source"), e.get("session_id")) in kept]
    if not kept:
        raise ValueError("None of the labelled sessions has events")
    results = compare_methods(scoped, scoped, kept, contamination, random_state)
    return {"results": results, "missing": missing, "evaluated": len(kept)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate on labelled sessions.")
    parser.add_argument("--labels", default="data/labels/session_labels.csv")
    parser.add_argument("--contamination", type=float, default=0.1)
    args = parser.parse_args(argv)

    load_dotenv(PROJECT_ROOT / ".env")
    url = os.getenv("DATABASE_URL")
    if not url:
        print("DATABASE_URL is not configured")
        return 2
    labels = load_labels(args.labels)
    with psycopg.connect(url) as connection:
        events = fetch_events(connection, None)
    out = evaluate_labelled(events, labels, args.contamination)

    print("ATTENTION : données scriptées de laboratoire, métriques optimistes.")
    print(f"sessions labellisées : {len(labels)} | évaluées : {out['evaluated']} "
          f"| sans événements : {len(out['missing'])}")
    print(format_table(out["results"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())