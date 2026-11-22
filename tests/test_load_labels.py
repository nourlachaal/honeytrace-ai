import pytest

pytest.importorskip("sklearn")

from src.ml.evaluate_real import evaluate_labelled
from src.ml.load_labels import load_labels
from src.ml.synthetic import generate_dataset


def write(tmp_path, text):
    path = tmp_path / "labels.csv"
    path.write_text(text, encoding="utf-8")
    return path


def test_loads_valid_csv(tmp_path):
    path = write(tmp_path, "source,session_id,label\ncowrie,a,0\ncowrie,b,1\n")
    assert load_labels(path) == {("cowrie", "a"): 0, ("cowrie", "b"): 1}


@pytest.mark.parametrize("body", [
    "source,session_id,label\ncowrie,a,2\n",
    "source,session_id,label\ncowrie,a,0\ncowrie,a,1\n",
    "source,session_id,label\ncowrie,,0\n",
    "source,session_id\ncowrie,a\n",
    "source,session_id,label\n",
])
def test_invalid_csv_is_rejected(tmp_path, body):
    with pytest.raises(ValueError):
        load_labels(write(tmp_path, body))


def test_real_repo_file_has_22_labels_balanced():
    labels = load_labels("data/labels/session_labels.csv")
    assert len(labels) == 23
    assert sum(labels.values()) == 12


def test_evaluate_reports_sessions_without_events():
    data = generate_dataset(60, 0.2, seed=3)
    labels = dict(data.labels)
    labels[("cowrie", "ghost")] = 1
    out = evaluate_labelled(data.events, labels)
    assert out["missing"] == [("cowrie", "ghost")]
    assert out["evaluated"] == 60


def test_evaluate_fails_when_no_session_has_events():
    with pytest.raises(ValueError):
        evaluate_labelled([], {("cowrie", "x"): 1})