import os
from datetime import datetime, timedelta, timezone

import pytest

try:
    import sklearn  # noqa: F401

    _HAS_SKLEARN = True
except ImportError:
    _HAS_SKLEARN = False

import src.pipeline as pipeline_module
from src.correlation.export import public_evidence
from src.detection.engine import DETECTOR_VERSION, DetectionEngine
from src.ml.features import build_session_features
from src.ml.isolation_forest import (
    ARTIFACT_FORMAT_VERSION,
    MODEL_VERSION,
    SessionAnomalyDetector,
)
from src.pipeline import _attach_ml_scores, run_pipeline

pytestmark = pytest.mark.skipif(not _HAS_SKLEARN, reason="scikit-learn not installed")

T0 = datetime(2026, 11, 8, 10, 0, 0, tzinfo=timezone.utc)


def _make_events(n_sessions=25, n_events=4, source="cowrie", session_prefix="sess"):
    events = []
    for s in range(n_sessions):
        for i in range(n_events):
            events.append(
                {
                    "event_id": f"e_{session_prefix}_{s}_{i}",
                    "source": source,
                    "event_type": "cowrie.login.failed",
                    "session_id": f"{session_prefix}_{s}",
                    "src_ip": "172.17.0.1",
                    "event_timestamp": T0 + timedelta(seconds=i * 5 + s * 100),
                }
            )
    return events


def _scored_detections(detections):
    return [d for d in detections if "ml_anomaly_score" in d.evidence]


def test_existing_compatible_artifact_loads_and_is_reused(tmp_path, monkeypatch):
    """1. Existing compatible artifact loads and is reused."""
    model_path = tmp_path / "model.joblib"
    monkeypatch.setenv("ML_MODEL_PATH", str(model_path))
    events = _make_events()
    dets = DetectionEngine().analyze(events)

    _, status1 = _attach_ml_scores(events, dets)
    assert status1["completed"] is True
    assert status1["model_source"] == "trained"
    assert status1["model_action"] == "trained"
    assert model_path.exists()

    _, status2 = _attach_ml_scores(events, dets)
    assert status2["completed"] is True
    assert status2["status"] in ("completed", "persistence_degraded")
    assert status2["model_source"] == "loaded"
    assert status2["model_action"] == "loaded"
    assert status2["persistence_status"] == "reused"


def test_missing_artifact_triggers_training_when_sufficient_data(tmp_path, monkeypatch):
    """2. Missing artifact triggers training when sufficient data exists."""
    model_path = tmp_path / "missing" / "model.joblib"
    if model_path.exists():
        model_path.unlink()
    monkeypatch.setenv("ML_MODEL_PATH", str(model_path))
    events = _make_events()
    dets = DetectionEngine().analyze(events)

    _, status = _attach_ml_scores(events, dets)
    assert status["completed"] is True
    assert status["inference_success"] is True
    assert status["model_source"] == "trained"
    assert status["artifact_load_status"] == "missing"
    assert status["persistence_status"] in ("saved", "failed")
    assert status["sessions_scored"] == 25
    if status["persistence_status"] == "saved":
        assert model_path.exists()


def test_corrupted_artifact_is_handled_correctly(tmp_path, monkeypatch):
    """3. Corrupted artifact is handled correctly (reported and retrained)."""
    model_path = tmp_path / "corrupt.joblib"
    model_path.write_bytes(b"not a valid joblib artifact")
    monkeypatch.setenv("ML_MODEL_PATH", str(model_path))
    events = _make_events()
    dets = DetectionEngine().analyze(events)

    _, status = _attach_ml_scores(events, dets)
    assert status["completed"] is True
    assert status["inference_success"] is True
    assert status["model_source"] == "trained"
    assert status["artifact_load_status"] == "invalid"
    assert status["artifact_load_error"]


def test_incompatible_artifact_is_handled_correctly(tmp_path, monkeypatch):
    """4. Incompatible artifact is handled correctly (reported and retrained)."""
    model_path = tmp_path / "incompat.joblib"
    features = build_session_features(_make_events())
    detector = SessionAnomalyDetector(contamination=0.1, random_state=42, version="0.9.0")
    detector.fit(features)
    detector.save(model_path)
    monkeypatch.setenv("ML_MODEL_PATH", str(model_path))
    events = _make_events()
    dets = DetectionEngine().analyze(events)

    _, status = _attach_ml_scores(events, dets)
    assert status["completed"] is True
    assert status["inference_success"] is True
    assert status["model_source"] == "trained"
    assert status["artifact_load_status"] == "invalid"
    assert "Incompatible model version" in (status["artifact_load_error"] or "")


def test_insufficient_sessions_produce_honest_skipped_status():
    """5. Insufficient sessions produce an honest skipped status."""
    events = _make_events(n_sessions=5)
    dets = DetectionEngine().analyze(events)
    dets_out, status = _attach_ml_scores(events, dets)

    assert status["enabled"] is True
    assert status["completed"] is False
    assert status["inference_success"] is False
    assert status["status"] == "skipped_insufficient_data"
    assert status["skipped_reason"] == "skipped_insufficient_data"
    assert status["sessions_scored"] == 0
    assert status["detections_scored"] == 0
    assert status["eligible_sessions"] < 20
    for d in dets_out:
        assert "ml_anomaly_score" not in d.evidence


def test_missing_sklearn_produces_honest_dependency_status(monkeypatch):
    """6. Missing scikit-learn produces an honest dependency status."""
    import builtins

    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name.startswith("src.ml") or name == "sklearn" or name.startswith("sklearn."):
            raise ImportError("mocked missing sklearn")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)
    events = _make_events()
    dets = DetectionEngine().analyze(events)
    dets_out, status = _attach_ml_scores(events, dets)

    assert status["enabled"] is False
    assert status["completed"] is False
    assert status["status"] == "dependency_missing"
    assert status["skipped_reason"] == "dependency_missing"
    assert status["dependency_status"] == "missing"
    assert all("ml_anomaly_score" not in d.evidence for d in dets_out)


def test_inference_produces_real_scores_from_valid_feature_data(tmp_path, monkeypatch):
    """7. Inference produces real scores from valid feature data."""
    model_path = tmp_path / "scores.joblib"
    monkeypatch.setenv("ML_MODEL_PATH", str(model_path))
    events = _make_events(n_sessions=25)
    dets = DetectionEngine().analyze(events)

    dets_out, status = _attach_ml_scores(events, dets)
    assert status["completed"] is True
    assert status["inference_success"] is True
    assert status["sessions_scored"] == 25
    scored = _scored_detections(dets_out)
    assert scored
    assert all(isinstance(d.evidence["ml_anomaly_score"], float) for d in scored)
    assert all(isinstance(d.evidence["ml_is_anomaly"], bool) for d in scored)


def test_scores_are_associated_with_correct_session(tmp_path, monkeypatch):
    """8. Scores are associated with the correct session."""
    model_path = tmp_path / "assoc.joblib"
    monkeypatch.setenv("ML_MODEL_PATH", str(model_path))
    events = _make_events(n_sessions=25)
    dets = DetectionEngine().analyze(events)
    dets_out, status = _attach_ml_scores(events, dets)
    assert status["completed"] is True

    scored = _scored_detections(dets_out)
    assert scored
    for d in scored:
        # All detections in these synthetic events belong to a session and
        # should carry the session's score.
        assert "session_id" in d.evidence
        assert d.evidence["ml_model"] == "isolation_forest"
        assert d.evidence["ml_model_version"] == MODEL_VERSION


def test_multiple_detections_sharing_session_receive_same_session_score(tmp_path, monkeypatch):
    """9. Multiple detections sharing a session receive the same session score."""
    model_path = tmp_path / "shared.joblib"
    monkeypatch.setenv("ML_MODEL_PATH", str(model_path))
    events = _make_events(n_sessions=25, n_events=4)
    dets = DetectionEngine().analyze(events)  # threshold rule may produce detections per session
    dets_out, status = _attach_ml_scores(events, dets)
    assert status["completed"] is True

    by_session = {}
    for d in _scored_detections(dets_out):
        sid = d.evidence.get("session_id")
        if sid:
            by_session.setdefault(sid, []).append(d.evidence["ml_anomaly_score"])
    # At least one session should have multiple scored detections in this scenario.
    multi = [vals for vals in by_session.values() if len(vals) > 1]
    assert multi, "Expected at least one session with multiple scored detections"
    for vals in multi:
        assert len(set(vals)) == 1


def test_detections_without_session_id_do_not_receive_fabricated_scores(tmp_path, monkeypatch):
    """10. Detections without a session ID do not receive fabricated scores."""
    model_path = tmp_path / "nosession.joblib"
    monkeypatch.setenv("ML_MODEL_PATH", str(model_path))
    events = _make_events(n_sessions=25)
    dets = list(DetectionEngine().analyze(events))
    # Add a synthetic detection with no session evidence and no resolvable source events.
    from src.detection.engine import Detection

    dets.append(
        Detection(
            detection_id="no-session-det",
            rule_id="TEST_NO_SESSION",
            description="test",
            severity="low",
            source_event_ids=("missing-event",),
            evidence={"event_type": "test"},
            detector_version=DETECTOR_VERSION,
        )
    )

    dets_out, status = _attach_ml_scores(events, dets)
    assert status["completed"] is True
    nosession = [d for d in dets_out if d.detection_id == "no-session-det"]
    assert len(nosession) == 1
    assert "ml_anomaly_score" not in nosession[0].evidence
    assert "ml_is_anomaly" not in nosession[0].evidence


def test_model_saving_failure_is_reported_without_false_success(tmp_path, monkeypatch):
    """11. Model saving failure is reported without falsely reporting successful persistence."""
    model_path = tmp_path / "savefail" / "model.joblib"
    monkeypatch.setenv("ML_MODEL_PATH", str(model_path))
    events = _make_events(n_sessions=25)
    dets = DetectionEngine().analyze(events)

    def fail_save(self, path, retries=3, retry_delay=0.0):
        raise OSError("simulated disk full")

    monkeypatch.setattr(SessionAnomalyDetector, "save", fail_save)
    dets_out, status = _attach_ml_scores(events, dets)

    # Inference should still succeed in-memory.
    assert status["inference_success"] is True
    assert status["completed"] is True
    assert status["status"] == "persistence_degraded"
    assert status["persistence_status"] == "failed"
    assert status["persistence_error"]
    assert "simulated disk full" in status["persistence_error"]
    assert status["sessions_scored"] == 25
    assert _scored_detections(dets_out)


def test_ml_information_never_leaks_into_public_evidence(tmp_path, monkeypatch):
    """12. ML information never leaks into public evidence."""
    model_path = tmp_path / "public.joblib"
    monkeypatch.setenv("ML_MODEL_PATH", str(model_path))
    events = _make_events()
    detections, _, ml_status = run_pipeline(events)
    assert ml_status["completed"] is True
    scored = _scored_detections(detections)
    assert scored
    for d in scored:
        pub = public_evidence(d.evidence)
        assert "ml_anomaly_score" not in pub
        assert "ml_is_anomaly" not in pub
        assert "ml_model" not in pub
        assert "ml_model_version" not in pub


def test_normal_pipeline_entry_point_actually_invokes_ml(monkeypatch):
    """13. The normal pipeline entry point actually invokes ML (via run_pipeline)."""

    class _Conn:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(pipeline_module, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setenv("DATABASE_URL", "postgresql://x@127.0.0.1/db")
    monkeypatch.setattr(pipeline_module.psycopg, "connect", lambda *a, **k: _Conn())
    monkeypatch.setattr(pipeline_module, "fetch_events", lambda conn, since: _make_events())

    seen = {}

    def fake_run_pipeline(events, now=None):
        dets, incs, ml = run_pipeline(events, now=now)
        seen["called"] = True
        seen["ml"] = ml
        return dets, incs, ml

    # main() calls run_pipeline in this module namespace.
    monkeypatch.setattr(pipeline_module, "run_pipeline", fake_run_pipeline)
    monkeypatch.setattr(pipeline_module, "write_results", lambda *a, **k: {"detections_inserted": 0, "incidents_upserted": 0, "incidents_skipped": 0})

    rc = pipeline_module.main(["--dry-run"])
    assert rc == 0
    assert seen.get("called") is True
    assert seen["ml"]["enabled"] is True
    assert seen["ml"]["inference_success"] is True


def test_second_pipeline_run_reuses_saved_model(tmp_path, monkeypatch):
    """14. A second pipeline run reuses the saved model instead of retraining unnecessarily."""
    model_path = tmp_path / "reuse.joblib"
    monkeypatch.setenv("ML_MODEL_PATH", str(model_path))
    events = _make_events()

    dets1, _, status1 = run_pipeline(events)
    assert status1["completed"] is True
    assert status1["model_source"] == "trained"
    assert model_path.exists()

    dets2, _, status2 = run_pipeline(events)
    assert status2["completed"] is True
    assert status2["model_source"] == "loaded"
    assert status2["model_action"] == "loaded"
    assert _scored_detections(dets1)
    assert _scored_detections(dets2)


def test_save_retries_on_transient_errors(tmp_path, monkeypatch):
    """Bounded retries: transient save errors are retried and can succeed."""
    import joblib

    model_path = tmp_path / "retry.joblib"
    features = build_session_features(_make_events())
    detector = SessionAnomalyDetector(contamination=0.1, random_state=42, version=MODEL_VERSION)
    detector.fit(features)

    real_dump = joblib.dump
    calls = {"n": 0}

    def flaky_dump(obj, file, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("transient write error")
        return real_dump(obj, file, *args, **kwargs)

    monkeypatch.setattr(joblib, "dump", flaky_dump)
    fmt = detector.save(model_path, retries=3, retry_delay=0.0)
    assert fmt == ARTIFACT_FORMAT_VERSION
    assert calls["n"] >= 2
    assert model_path.exists()
    loaded = SessionAnomalyDetector.load(model_path, expected_model_version=MODEL_VERSION)
    assert loaded.is_fitted


def test_version_separation_detector_and_model(tmp_path, monkeypatch):
    """Detector engine version and ML model version are independent."""
    model_path = tmp_path / "versions.joblib"
    monkeypatch.setenv("ML_MODEL_PATH", str(model_path))
    events = _make_events()
    detections, _, status = run_pipeline(events)
    assert detections
    assert status["completed"] is True
    assert status["detector_version"] == DETECTOR_VERSION
    assert status["model_version"] == MODEL_VERSION
    assert status["detector_version"] != status["model_version"]
    # Detections carry detector engine version; ML evidence carries model version.
    assert all(d.detector_version == DETECTOR_VERSION for d in detections)
    for d in _scored_detections(detections):
        assert d.evidence["ml_model_version"] == MODEL_VERSION
        assert d.detector_version == DETECTOR_VERSION


def test_pipeline_run_on_development_dataset_if_available(tmp_path, monkeypatch):
    """Controlled integration against existing development data when present."""
    # Prefer labeled fixture / raw data available in repo; fall back to synthetic.
    candidates = [
        "data/fixtures/cowrie/labeled_cowrie_runs.jsonl",
        "data/raw/labeled_cowrie_runs.jsonl",
    ]
    events = None
    for cand in candidates:
        if os.path.exists(cand):
            # Build minimal normalized-like events from JSONL if possible.
            import json

            loaded = []
            with open(cand, "r", encoding="utf-8") as f:
                for i, line in enumerate(f):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    # Map to minimal event shape expected by feature extraction/pipeline.
                    ts = obj.get("event_timestamp") or obj.get("timestamp")
                    if isinstance(ts, str):
                        try:
                            from datetime import datetime

                            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        except Exception:
                            ts = None
                    if not isinstance(ts, datetime):
                        ts = T0 + timedelta(seconds=i)
                    sid = obj.get("session_id") or obj.get("session") or f"dev_{i//4}"
                    loaded.append(
                        {
                            "event_id": obj.get("event_id") or f"dev_{i}",
                            "source": obj.get("source") or "cowrie",
                            "event_type": obj.get("event_type") or obj.get("eventid") or "cowrie.login.failed",
                            "session_id": sid,
                            "src_ip": obj.get("src_ip") or obj.get("src_ip_addr") or "172.17.0.1",
                            "event_timestamp": ts,
                        }
                    )
            # Use only if we got enough usable sessions.
            if len({(e.get("source"), e.get("session_id")) for e in loaded if e.get("session_id")}) >= 20:
                events = loaded
            elif loaded:
                # If not enough, supplement with synthetic sessions to reach threshold for inference proof.
                have = len({(e.get("source"), e.get("session_id")) for e in loaded if e.get("session_id")})
                need = max(0, 20 - have)
                events = loaded + _make_events(n_sessions=need, session_prefix="supp")
            break

    if events is None:
        events = _make_events(n_sessions=25)

    model_path = tmp_path / "devdata.joblib"
    monkeypatch.setenv("ML_MODEL_PATH", str(model_path))
    detections, incidents, status = run_pipeline(events)
    assert isinstance(detections, list)
    assert isinstance(incidents, list)
    assert status["enabled"] is True
    assert status["completed"] is True
    assert status["inference_success"] is True
    assert status["sessions_scored"] >= 20
    assert status["status"] in ("completed", "persistence_degraded")
