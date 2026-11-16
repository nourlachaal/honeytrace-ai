"""Compare la détection par règles et Isolation Forest, session par session.

Lancer : python -m src.ml.compare_methods
Les données par défaut sont SYNTHÉTIQUES : les chiffres ne mesurent aucune
performance réelle. Le même code servira sur les vrais labels de Person 1.
"""

import argparse
from typing import Iterable, Optional

from src.correlation.correlator import IncidentCorrelator
from src.detection.engine import DetectionEngine
from src.ml.features import build_session_features
from src.ml.isolation_forest import SessionAnomalyDetector
from src.ml.metrics import Metrics, evaluate_sessions
from src.ml.synthetic import generate_dataset

SYNTHETIC_WARNING = (
    "ATTENTION : données SYNTHÉTIQUES. Ces chiffres testent le code, "
    "ils ne mesurent aucune performance réelle."
)


def rules_flagged_sessions(events: Iterable, min_severity: str = "medium") -> set:
    """Sessions qui produisent au moins un incident de sévérité >= min_severity."""
    events = list(events)
    detections = DetectionEngine().analyze(events)
    incidents = IncidentCorrelator(min_severity).correlate(detections, events)
    return {(incident.source, incident.session_id) for incident in incidents}


def ml_flagged_sessions(
    train_events: Iterable,
    test_events: Iterable,
    contamination: float = 0.1,
    random_state: int = 42,
) -> set:
    """Entraîne sur train_events (sans labels), signale les sessions atypiques de test_events."""
    train = build_session_features(train_events)
    test = build_session_features(test_events)
    detector = SessionAnomalyDetector(
        contamination=contamination, random_state=random_state
    ).fit(train)
    return {(s.source, s.session_id) for s in detector.score(test) if s.is_anomaly}


def compare_methods(
    train_events: Iterable,
    test_events: Iterable,
    test_labels: dict,
    contamination: float = 0.1,
    random_state: int = 42,
) -> dict:
    """Retourne {"rules": Metrics, "isolation_forest": Metrics} sur le même jeu de test."""
    test_events = list(test_events)
    return {
        "rules": evaluate_sessions(test_labels, rules_flagged_sessions(test_events)),
        "isolation_forest": evaluate_sessions(
            test_labels,
            ml_flagged_sessions(train_events, test_events, contamination, random_state),
        ),
    }


def _fmt(value: Optional[float]) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def format_table(results: dict) -> str:
    header = f"{'method':<18}{'TP':>5}{'FP':>5}{'FN':>5}{'TN':>5}" \
             f"{'precision':>11}{'recall':>9}{'f1':>8}{'fpr':>8}"
    lines = [header, "-" * len(header)]
    for name, m in results.items():
        lines.append(
            f"{name:<18}{m.tp:>5}{m.fp:>5}{m.fn:>5}{m.tn:>5}"
            f"{_fmt(m.precision):>11}{_fmt(m.recall):>9}{_fmt(m.f1):>8}{_fmt(m.fpr):>8}"
        )
    lines.append("n/a = métrique indéfinie (dénominateur nul)")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Compare rules and Isolation Forest.")
    parser.add_argument("--sessions", type=int, default=300)
    parser.add_argument("--attack-ratio", type=float, default=0.15)
    parser.add_argument("--train-seed", type=int, default=1)
    parser.add_argument("--test-seed", type=int, default=2)
    parser.add_argument("--contamination", type=float, default=0.1)
    args = parser.parse_args(argv)

    train = generate_dataset(args.sessions, args.attack_ratio, args.train_seed)
    test = generate_dataset(args.sessions, args.attack_ratio, args.test_seed)
    results = compare_methods(
        train.events, test.events, test.labels, contamination=args.contamination
    )

    print(SYNTHETIC_WARNING)
    print(f"Unité d'évaluation : session | sessions de test : {len(test.labels)} "
          f"| attaques : {sum(test.labels.values())}")
    print(format_table(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())