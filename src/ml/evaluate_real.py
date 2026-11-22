"""Évaluation par rôles et Isolation Forest sur les sessions labellisées de la base.

    python -m src.ml.evaluate_real [--labels data/labels/session_labels.csv]
    python -m src.ml.evaluate_real --train-fraction 0.7

Non supervisé : les labels ne servent qu'à évaluer. Les données sont SCRIPTÉES
(laboratoire) : les métriques sont optimistes. Le modèle est entraîné et évalué
sur des sessions disjointes (train/test) pour éviter la fuite de données.
Variable d'environnement : DATABASE_URL.
"""

import argparse
import os
import random
from pathlib import Path

import psycopg
from dotenv import load_dotenv

from src.ml.compare_methods import compare_methods, format_table
from src.ml.load_labels import load_labels
from src.pipeline import fetch_events

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MIN_SESSIONS_IF = 20


def _split_sessions(kept: dict, train_fraction: float, seed: int = 42) -> tuple:
    """Split session keys into train/test, stratified by label when possible."""
    rng = random.Random(seed)
    by_label = {}
    for key, label in kept.items():
        by_label.setdefault(label, []).append(key)

    train_keys = set()
    test_keys = set()
    for label, keys in by_label.items():
        keys = sorted(keys)
        rng.shuffle(keys)
        n = len(keys)
        n_train = int(round(n * train_fraction))
        if n_train < 1 and n > 1:
            n_train = 1
        if n_train > n - 1 and n > 1:
            n_train = n - 1
        train_keys.update(keys[:n_train])
        test_keys.update(keys[n_train:])

    return train_keys, test_keys


def evaluate_labelled(events, labels, contamination=0.1, random_state=42,
                      train_fraction=1.0, min_sessions_if=MIN_SESSIONS_IF) -> dict:
    """Retourne {"results": ..., "missing": [...], "evaluated": n,
    "train_sessions": n, "test_sessions": n, "train_attacks": n,
    "test_attacks": n, "if_skipped_reason": str|None}."""
    events = list(events)
    present = {(e.get("source"), e.get("session_id")) for e in events}
    kept = {k: v for k, v in labels.items() if k in present}
    missing = sorted(set(labels) - set(kept))
    if not kept:
        raise ValueError("None of the labelled sessions has events")

    # Backward-compatible: train_fraction=1.0 means train==test (original behaviour).
    if train_fraction >= 1.0:
        train_keys = set(kept)
        test_keys = set(kept)
    else:
        train_keys, test_keys = _split_sessions(kept, train_fraction, random_state)

    train_events = [e for e in events if (e.get("source"), e.get("session_id")) in train_keys]
    test_events = [e for e in events if (e.get("source"), e.get("session_id")) in test_keys]
    train_labels = {k: v for k, v in kept.items() if k in train_keys}
    test_labels = {k: v for k, v in kept.items() if k in test_keys}

    if not test_events:
        raise ValueError("Test split is empty; lower train_fraction")

    # Isolation Forest needs enough training sessions. If not, skip it (rules still run).
    if_skipped = None
    train_features_count = len({(e.get("source"), e.get("session_id")) for e in train_events
                               if e.get("session_id")})
    if train_features_count < min_sessions_if:
        if_skipped = (f"Isolation Forest skipped: training set has {train_features_count} "
                      f"sessions (< {min_sessions_if} minimum). Rules still evaluated.")

    if train_features_count < min_sessions_if:
        if_skipped = (f"Isolation Forest skipped: training set has {train_features_count} "
                      f"sessions (< {min_sessions_if} minimum). Rules still evaluated.")
        from src.ml.compare_methods import rules_flagged_sessions
        from src.ml.metrics import evaluate_sessions
        flagged = rules_flagged_sessions(test_events)
        results = {"rules": evaluate_sessions(test_labels, flagged)}
    else:
        results = compare_methods(train_events, test_events, test_labels, contamination, random_state)

    return {
        "results": results,
        "missing": missing,
        "evaluated": len(kept),
        "train_sessions": len(train_keys),
        "test_sessions": len(test_keys),
        "train_attacks": sum(train_labels.values()),
        "test_attacks": sum(test_labels.values()),
        "if_skipped_reason": if_skipped,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate on labelled sessions.")
    parser.add_argument("--labels", default="data/labels/session_labels.csv")
    parser.add_argument("--contamination", type=float, default=0.1)
    parser.add_argument("--train-fraction", type=float, default=0.7,
                        help="Fraction of sessions used for training (default 0.7). "
                             "Use 1.0 for the legacy train==test behaviour.")
    parser.add_argument("--min-sessions-if", type=int, default=MIN_SESSIONS_IF,
                        help="Minimum training sessions required for Isolation Forest.")
    args = parser.parse_args(argv)

    load_dotenv(PROJECT_ROOT / ".env")
    url = os.getenv("DATABASE_URL")
    if not url:
        print("DATABASE_URL is not configured")
        return 2
    labels = load_labels(args.labels)
    with psycopg.connect(url) as connection:
        events = fetch_events(connection, None)
    out = evaluate_labelled(events, labels, args.contamination,
                            train_fraction=args.train_fraction,
                            min_sessions_if=args.min_sessions_if)

    print("ATTENTION : données scriptées de laboratoire, métriques optimistes.")
    print(f"sessions labellisées : {len(labels)} | évaluées : {out['evaluated']} "
          f"| sans événements : {len(out['missing'])}")
    print(f"train : {out['train_sessions']} sessions ({out['train_attacks']} attaques) | "
          f"test : {out['test_sessions']} sessions ({out['test_attacks']} attaques)")
    if out["if_skipped_reason"]:
        print("NOTE :", out["if_skipped_reason"])
    print(format_table(out["results"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())