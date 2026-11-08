import pytest

from src.ml.compare_methods import (
    SYNTHETIC_WARNING,
    compare_methods,
    format_table,
    main,
    rules_flagged_sessions,
)
from src.ml.metrics import Metrics
from src.ml.synthetic import generate_dataset


def run(n=300, seed_train=1, seed_test=2):
    train = generate_dataset(n, 0.15, seed_train)
    test = generate_dataset(n, 0.15, seed_test)
    return test, compare_methods(train.events, test.events, test.labels)


def test_both_methods_are_reported():
    _, results = run()
    assert set(results) == {"rules", "isolation_forest"}
    assert all(isinstance(m, Metrics) for m in results.values())


def test_counts_cover_every_test_session():
    test, results = run()
    for m in results.values():
        assert m.tp + m.fp + m.fn + m.tn == len(test.labels)
        assert m.tp + m.fn == sum(test.labels.values())


def test_comparison_is_deterministic():
    assert run()[1] == run()[1]


def test_rules_only_flag_known_sessions():
    test, _ = run()
    assert rules_flagged_sessions(test.events) <= set(test.labels)


def test_ml_needs_enough_training_sessions():
    small = generate_dataset(10, 0.2, 1)
    test = generate_dataset(50, 0.15, 2)
    with pytest.raises(ValueError):
        compare_methods(small.events, test.events, test.labels)


def test_table_lists_methods_and_marks_undefined_as_na():
    undefined = Metrics(0, 0, 1, 5, None, 0.0, 0.0, 0.0)
    table = format_table({"rules": undefined})
    assert "rules" in table
    assert "n/a" in table


def test_table_from_real_run_contains_both_methods():
    _, results = run()
    table = format_table(results)
    assert "rules" in table and "isolation_forest" in table


def test_main_prints_synthetic_warning(capsys):
    assert main(["--sessions", "60"]) == 0
    out = capsys.readouterr().out
    assert SYNTHETIC_WARNING in out
    assert "isolation_forest" in out