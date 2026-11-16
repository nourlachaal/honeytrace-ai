import random

import pytest

pytest.importorskip("sklearn")

from sklearn.metrics import f1_score, precision_score, recall_score

from src.detection.engine import DetectionEngine
from src.ml.metrics import confusion_counts, evaluate, evaluate_sessions
from src.ml.synthetic import generate_dataset

# 3 positifs réels, 7 négatifs réels.
# prédits : 2 vrais positifs, 1 faux positif, 1 faux négatif, 6 vrais négatifs.
TRUTH = [1, 1, 1, 0, 0, 0, 0, 0, 0, 0]
PRED = [1, 1, 0, 1, 0, 0, 0, 0, 0, 0]


def test_confusion_counts_by_hand():
    assert confusion_counts(TRUTH, PRED) == {"tp": 2, "fp": 1, "fn": 1, "tn": 6}


def test_metrics_by_hand():
    m = evaluate(TRUTH, PRED)
    assert m.precision == pytest.approx(2 / 3)   # 2 / (2 + 1)
    assert m.recall == pytest.approx(2 / 3)      # 2 / (2 + 1)
    assert m.f1 == pytest.approx(2 / 3)          # 4 / (4 + 1 + 1)
    assert m.fpr == pytest.approx(1 / 7)         # 1 / (1 + 6)


def test_perfect_prediction():
    m = evaluate([1, 1, 0, 0], [1, 1, 0, 0])
    assert (m.precision, m.recall, m.f1, m.fpr) == (1.0, 1.0, 1.0, 0.0)


def test_no_positive_prediction_makes_precision_undefined():
    m = evaluate([1, 0, 0], [0, 0, 0])
    assert m.precision is None
    assert m.recall == 0.0
    assert m.f1 == 0.0
    assert m.fpr == 0.0


def test_no_positive_in_truth_makes_recall_undefined():
    m = evaluate([0] * 5, [1, 0, 0, 0, 0])
    assert m.recall is None
    assert m.precision == 0.0
    assert m.f1 == 0.0
    assert m.fpr == pytest.approx(0.2)


def test_no_negative_in_truth_makes_fpr_undefined():
    m = evaluate([1, 1], [1, 0])
    assert m.fpr is None
    assert m.precision == 1.0
    assert m.recall == 0.5
    assert m.f1 == pytest.approx(2 / 3)          # 2 / (2 + 0 + 1)


def test_bool_and_int_inputs_are_equivalent():
    assert evaluate([True, False, True], [True, True, False]) == evaluate(
        [1, 0, 1], [1, 1, 0]
    )


def test_length_mismatch_is_rejected():
    with pytest.raises(ValueError):
        evaluate([1, 0], [1])


def test_empty_input_is_rejected():
    with pytest.raises(ValueError):
        evaluate([], [])


@pytest.mark.parametrize("bad", [2, -1, "a", None, 0.5])
def test_invalid_values_are_rejected(bad):
    with pytest.raises(ValueError):
        evaluate([1, 0], [1, bad])


def test_matches_scikit_learn_on_random_data():
    rng = random.Random(0)
    truth = [rng.randint(0, 1) for _ in range(300)]
    pred = [rng.randint(0, 1) for _ in range(300)]
    m = evaluate(truth, pred)
    assert m.precision == pytest.approx(precision_score(truth, pred))
    assert m.recall == pytest.approx(recall_score(truth, pred))
    assert m.f1 == pytest.approx(f1_score(truth, pred))


def test_evaluate_sessions_by_hand():
    labels = {("cowrie", "a"): 1, ("cowrie", "b"): 1,
              ("cowrie", "c"): 0, ("cowrie", "d"): 0}
    m = evaluate_sessions(labels, {("cowrie", "a"), ("cowrie", "c")})
    assert (m.tp, m.fp, m.fn, m.tn) == (1, 1, 1, 1)
    assert (m.precision, m.recall, m.f1, m.fpr) == (0.5, 0.5, 0.5, 0.5)


def test_unknown_flagged_session_is_rejected():
    with pytest.raises(ValueError):
        evaluate_sessions({("cowrie", "a"): 1}, {("cowrie", "ghost")})


def test_session_order_does_not_matter():
    labels = {("cowrie", "a"): 1, ("cowrie", "b"): 0, ("cowrie", "c"): 0}
    reordered = dict(reversed(list(labels.items())))
    flagged = [("cowrie", "a"), ("cowrie", "b")]
    assert evaluate_sessions(labels, flagged) == evaluate_sessions(reordered, flagged)


def test_brute_force_rule_on_synthetic_data():
    # Données SYNTHÉTIQUES : ce test vérifie le code, il ne mesure aucune performance réelle.
    data = generate_dataset(200, 0.15, seed=5)
    detections = DetectionEngine().analyze(data.events)
    flagged = {
        ("cowrie", d.evidence["session_id"])
        for d in detections if d.rule_id == "COWRIE_BRUTE_FORCE_SESSION"
    }
    m = evaluate_sessions(data.labels, flagged)
    assert m.precision == 1.0   # la règle ne se déclenche que sur des attaques
    assert m.fpr == 0.0
    assert m.recall < 1.0       # elle rate les attaques discrètes (2 à 4 échecs)