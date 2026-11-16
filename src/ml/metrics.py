"""Métriques d'évaluation : Precision, Recall, F1, False Positive Rate.

Une métrique dont le dénominateur vaut 0 est INDÉFINIE et vaut None
(jamais 0 par défaut, ce qui masquerait le problème dans un rapport).
"""

from dataclasses import dataclass
from numbers import Real
from typing import Iterable, Optional


@dataclass(frozen=True)
class Metrics:
    tp: int
    fp: int
    fn: int
    tn: int
    precision: Optional[float]   # TP / (TP + FP)
    recall: Optional[float]      # TP / (TP + FN)
    f1: Optional[float]          # 2TP / (2TP + FP + FN)
    fpr: Optional[float]         # FP / (FP + TN)


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    return None if denominator == 0 else numerator / denominator


def _to_binary(values: Iterable, name: str) -> list:
    result = []
    for value in values:
        if not isinstance(value, Real) or value not in (0, 1):
            raise ValueError(f"{name} must contain only 0/1 or booleans")
        result.append(int(value))
    return result


def confusion_counts(y_true: Iterable, y_pred: Iterable) -> dict:
    truth = _to_binary(y_true, "y_true")
    pred = _to_binary(y_pred, "y_pred")
    if len(truth) != len(pred):
        raise ValueError("y_true and y_pred must have the same length")
    if not truth:
        raise ValueError("Inputs must not be empty")
    return {
        "tp": sum(1 for t, p in zip(truth, pred) if t == 1 and p == 1),
        "fp": sum(1 for t, p in zip(truth, pred) if t == 0 and p == 1),
        "fn": sum(1 for t, p in zip(truth, pred) if t == 1 and p == 0),
        "tn": sum(1 for t, p in zip(truth, pred) if t == 0 and p == 0),
    }


def evaluate(y_true: Iterable, y_pred: Iterable) -> Metrics:
    c = confusion_counts(y_true, y_pred)
    tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
    return Metrics(
        tp=tp, fp=fp, fn=fn, tn=tn,
        precision=_ratio(tp, tp + fp),
        recall=_ratio(tp, tp + fn),
        f1=_ratio(2 * tp, 2 * tp + fp + fn),
        fpr=_ratio(fp, fp + tn),
    )


def evaluate_sessions(labels: dict, flagged: Iterable) -> Metrics:
    """labels : {(source, session_id): 0 ou 1}. flagged : sessions signalées.

    Toute session signalée absente des labels est refusée, au lieu d'être
    ignorée en silence (cela fausserait Precision).
    """
    flagged = set(flagged)
    unknown = flagged - set(labels)
    if unknown:
        raise ValueError(f"{len(unknown)} flagged session(s) have no label")
    keys = sorted(labels)
    return evaluate(
        [labels[k] for k in keys],
        [1 if k in flagged else 0 for k in keys],
    )