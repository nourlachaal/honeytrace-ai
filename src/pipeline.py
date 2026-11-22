"""Runner : lit security_events, applique règles + corrélation, écrit en base.

    python -m src.pipeline                          # tout traiter
    python -m src.pipeline --since 2026-11-19T00:00:00Z
    python -m src.pipeline --dry-run                # n'écrit rien

--since : prend les sessions qui ont au moins un événement depuis cette date,
puis charge TOUS les événements de ces sessions (seuils et timelines complets).
Idempotent : une 2e exécution ne modifie rien (détections en DO NOTHING,
incidents mis à jour seulement s'ils reçoivent de nouvelles détections).
Variable d'environnement : DATABASE_URL.
"""

import argparse
import dataclasses
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import psycopg
from dotenv import load_dotenv
from psycopg.rows import dict_row

from src.correlation.correlator import IncidentCorrelator
from src.detection.engine import DetectionEngine, DETECTOR_VERSION
from src.storage.detections_writer import write_results

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Colonnes strictement nécessaires (ni message ni raw_event).
EVENT_COLUMNS = (
    "event_id, source, event_type, session_id, event_timestamp, src_ip, "
    "protocol, username, command, http_method, route, status_code, metadata"
)


def parse_since(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("--since must include a timezone, e.g. 2026-11-19T00:00:00Z")
    return parsed.astimezone(timezone.utc)


def build_events_query(since: Optional[datetime]) -> tuple:
    base = f"SELECT {EVENT_COLUMNS} FROM security_events"
    order = " ORDER BY event_timestamp, event_id"
    if since is None:
        return base + order, {}
    where = (
        " WHERE event_timestamp >= %(since)s OR (session_id IS NOT NULL AND "
        "(source, session_id) IN (SELECT source, session_id FROM security_events "
        "WHERE session_id IS NOT NULL AND event_timestamp >= %(since)s))"
    )
    return base + where + order, {"since": since}


def fetch_events(connection, since: Optional[datetime]) -> list:
    query, params = build_events_query(since)
    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(query, params)
        return list(cursor.fetchall())



def _attach_ml_scores(events: list, detections: list) -> tuple:
    """Advisory ML score per session, stored in evidence (internal only).

    Lifecycle:
      1. Initialize config/dependencies/path and report execution mode.
      2. Extract valid session features from pipeline events.
      3. Load a compatible artifact or train when needed (no unnecessary retraining).
      4. Run inference and attach one session score per eligible session.
      5. Persist the model safely (bounded retries + load verification) when trained.
         Persistence failures are reported and never silently ignored; inference can
         continue in-memory when safe (persistence_degraded).
      6. Keep ML fields in evidence_internal only (never evidence_public/API).

    Returns (detections, status). Status is truthful on every run.
    """
    import os
    from pathlib import Path

    model_path_env = os.getenv("ML_MODEL_PATH")
    if model_path_env:
        model_path = Path(model_path_env)
        if not model_path.is_absolute():
            model_path = (PROJECT_ROOT / model_path).resolve()
    else:
        model_path = (PROJECT_ROOT / "data/models/isolation_forest.joblib").resolve()

    ml_enabled = os.getenv("ML_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}

    status = {
        "enabled": False,
        "running": False,
        "completed": False,
        "status": "disabled" if not ml_enabled else "initialized",
        "skipped_reason": "disabled" if not ml_enabled else None,
        "dependency_status": "unknown",
        "events_received": len(events) if isinstance(events, list) else 0,
        "unique_sessions": 0,
        "eligible_sessions": 0,
        "sessions_evaluated": 0,
        "sessions_scored": 0,
        "detections_scored": 0,
        "anomalous_sessions": 0,
        "anomalies_found": 0,  # session-level anomalies (kept for compatibility)
        "model_name": "isolation_forest",
        "model_version": None,
        "detector_version": DETECTOR_VERSION,
        "artifact_format_version": None,
        "model_source": None,  # loaded | trained | skipped
        "model_action": "skipped",
        "artifact_path": str(model_path),
        "artifact_load_status": None,
        "artifact_load_error": None,
        "persistence_status": "not_applicable",
        "persistence_error": None,
        "inference_success": False,
        "skipped_reason_detail": None,
    }

    if not ml_enabled:
        status["dependency_status"] = "not_checked"
        print(f"ML status: disabled (events={status['events_received']}, artifact={model_path})")
        return detections, status

    # Dependency check
    try:
        from src.ml.features import build_session_features
        from src.ml.isolation_forest import (
            ARTIFACT_FORMAT_VERSION,
            MIN_SESSIONS,
            MODEL_VERSION,
            SessionAnomalyDetector,
        )
    except ImportError as exc:
        status["dependency_status"] = "missing"
        status["status"] = "dependency_missing"
        status["skipped_reason"] = "dependency_missing"
        status["skipped_reason_detail"] = str(exc)
        status["model_action"] = "skipped"
        print(f"ML status: dependency_missing (scikit-learn not installed, events={status['events_received']})")
        return detections, status

    status["enabled"] = True
    status["dependency_status"] = "available"
    status["model_version"] = MODEL_VERSION
    status["artifact_format_version"] = ARTIFACT_FORMAT_VERSION

    # Unique sessions present in raw events (best-effort).
    unique_sessions = set()
    for e in events or []:
        if not isinstance(e, dict):
            continue
        sid = e.get("session_id")
        src = e.get("source") or "unknown"
        if isinstance(sid, str) and sid:
            unique_sessions.add((src, sid))
    status["unique_sessions"] = len(unique_sessions)

    # Feature extraction
    try:
        features = build_session_features(events)
    except Exception as exc:
        status["status"] = "inference_failed"
        status["skipped_reason"] = "feature_extraction_failed"
        status["skipped_reason_detail"] = str(exc)
        status["model_action"] = "skipped"
        print(f"ML status: inference_failed/feature_extraction_failed ({exc})")
        return detections, status

    status["eligible_sessions"] = len(features)
    status["sessions_evaluated"] = len(features)
    if len(features) < MIN_SESSIONS:
        status["status"] = "skipped_insufficient_data"
        status["skipped_reason"] = "skipped_insufficient_data"
        status["skipped_reason_detail"] = f"{len(features)} eligible sessions < {MIN_SESSIONS}"
        status["model_action"] = "skipped"
        print(
            f"ML status: skipped_insufficient_data "
            f"(events={status['events_received']}, unique_sessions={status['unique_sessions']}, "
            f"eligible_sessions={len(features)} < {MIN_SESSIONS})"
        )
        return detections, status

    status["running"] = True
    detector = None
    try:
        # Step 3: load or train
        try:
            detector = SessionAnomalyDetector.load(model_path, expected_model_version=MODEL_VERSION)
            status["artifact_load_status"] = "loaded"
            status["model_source"] = "loaded"
            status["model_action"] = "loaded"
            print(f"ML status: artifact loaded (path={model_path}, model_version={detector.model_version})")
        except FileNotFoundError as exc:
            status["artifact_load_status"] = "missing"
            status["artifact_load_error"] = str(exc)
            print(f"ML status: artifact missing, will train (path={model_path})")
        except ValueError as exc:
            # Incompatible/corrupt artifact: report reason before retraining.
            status["artifact_load_status"] = "invalid"
            status["artifact_load_error"] = str(exc)
            print(f"ML status: artifact invalid/incompatible, will retrain (reason={exc})")
        except Exception as exc:
            status["artifact_load_status"] = "load_error"
            status["artifact_load_error"] = str(exc)
            print(f"ML status: artifact load failed, will retrain (reason={exc})")

        if detector is None:
            detector = SessionAnomalyDetector(
                contamination=0.1, random_state=42, version=MODEL_VERSION
            )
            print(f"ML status: training model (eligible_sessions={len(features)}, version={MODEL_VERSION})")
            detector.fit(features)
            status["model_source"] = "trained"
            status["model_action"] = "trained"
            try:
                fmt = detector.save(model_path)
                status["persistence_status"] = "saved"
                status["artifact_format_version"] = fmt
                print(f"ML status: model persisted (path={model_path}, format={fmt})")
            except Exception as exc:
                # Persistence failure must not be silently ignored, but inference can continue.
                status["persistence_status"] = "failed"
                status["persistence_error"] = str(exc)
                print(f"ML status: WARNING - persistence failed, continuing in-memory ({exc})")
        else:
            status["persistence_status"] = "reused"

        # Step 4: inference
        scores = {(sc.source, sc.session_id): sc for sc in detector.score(features)}
        status["inference_success"] = True
        status["model_version"] = getattr(detector, "model_version", detector.version)
    except Exception as exc:
        status["running"] = False
        status["completed"] = False
        status["inference_success"] = False
        status["status"] = "inference_failed"
        status["skipped_reason"] = "inference_failed"
        status["skipped_reason_detail"] = str(exc)
        status["model_action"] = status.get("model_action") or "skipped"
        print(f"ML status: inference_failed ({exc})")
        return detections, status

    status["sessions_scored"] = len(scores)
    status["anomalous_sessions"] = sum(1 for sc in scores.values() if sc.is_anomaly)
    status["anomalies_found"] = status["anomalous_sessions"]

    # Step 6: associate session scores with detections (never fabricate scores).
    event_index = {
        e.get("event_id"): e for e in events
        if isinstance(e, dict) and e.get("event_id")
    }

    def session_key(detection):
        sid = detection.evidence.get("session_id")
        src = None
        if not sid:
            for eid in detection.source_event_ids:
                ev = event_index.get(eid)
                if isinstance(ev, dict):
                    sid = ev.get("session_id") or sid
                    src = ev.get("source") or src
                    if sid:
                        break
        if not sid:
            return None
        if src is None:
            for eid in detection.source_event_ids:
                ev = event_index.get(eid)
                if isinstance(ev, dict) and ev.get("source"):
                    src = ev["source"]
                    break
        if src is None:
            src = "unknown"
        return src, sid

    result = []
    detections_scored = 0
    for detection in detections:
        key = session_key(detection)
        score = scores.get(key) if key is not None else None
        if score is None:
            result.append(detection)
            continue
        new_evidence = dict(detection.evidence)
        new_evidence["ml_anomaly_score"] = score.anomaly_score
        new_evidence["ml_is_anomaly"] = score.is_anomaly
        new_evidence["ml_model"] = "isolation_forest"
        new_evidence["ml_model_version"] = status["model_version"]
        result.append(dataclasses.replace(detection, evidence=new_evidence))
        detections_scored += 1

    status["detections_scored"] = detections_scored
    status["running"] = False
    status["completed"] = True
    if status.get("persistence_status") == "failed":
        status["status"] = "persistence_degraded"
        status["skipped_reason"] = None
    else:
        status["status"] = "completed"
        status["skipped_reason"] = None

    print(
        "ML status: "
        f"{status['status']} "
        f"(events={status['events_received']}, unique_sessions={status['unique_sessions']}, "
        f"eligible_sessions={status['eligible_sessions']}, model_action={status['model_action']}, "
        f"model_version={status['model_version']}, artifact={status['artifact_path']}, "
        f"sessions_scored={status['sessions_scored']}, detections_scored={status['detections_scored']}, "
        f"anomalous_sessions={status['anomalous_sessions']}, "
        f"persistence={status['persistence_status']}, persistence_error={status['persistence_error']})"
    )

    # Write metrics to JSON file for API consumption (aggregate only, no sensitive data)
    try:
        import json
        from datetime import datetime, timezone

        metrics_path = Path(PROJECT_ROOT) / "data" / "ml_metrics.json"

        # Advisory, per-anomaly detail derived from the same inference run.
        # Features are numeric aggregates only (no command, username or text).
        feature_by_key = {
            (f.source, f.session_id): dict(f.values) for f in features
        }
        anomaly_threshold = getattr(detector, "decision_threshold", None)
        ranked_scores = sorted(sc.anomaly_score for sc in scores.values())

        def _criticality(score: float) -> str:
            """Band the score by its percentile among the scored sessions."""
            if not ranked_scores:
                return "low"
            rank = sum(1 for value in ranked_scores if value <= score) / len(ranked_scores)
            if rank >= 0.99:
                return "critical"
            if rank >= 0.95:
                return "high"
            if rank >= 0.85:
                return "medium"
            return "low"

        def _category(source: str, values: dict) -> str:
            """Describe which behaviour dominated the anomalous session."""
            if source == "juice_shop":
                return "web_request"
            commands = int(values.get("command_count") or 0)
            failed = int(values.get("login_failed_count") or 0)
            if commands and commands >= failed:
                return "command_execution"
            if failed:
                return "failed_login_burst"
            return "session_behaviour"

        anomaly_sessions = []
        for sc in scores.values():
            if not sc.is_anomaly:
                continue
            values = feature_by_key.get((sc.source, sc.session_id), {})
            anomaly_sessions.append(
                {
                    "source": sc.source,
                    "session_id": sc.session_id,
                    "score": float(sc.anomaly_score),
                    "threshold": (
                        float(anomaly_threshold)
                        if anomaly_threshold is not None
                        else None
                    ),
                    "criticality": _criticality(sc.anomaly_score),
                    "category": _category(sc.source, values),
                    "features": values,
                    "is_anomaly": bool(sc.is_anomaly),
                }
            )

        metrics_data = {
            "inference_executed": status["inference_success"] is not None and status["inference_success"] is True,
            "inference_success": status["inference_success"],
            "model_loaded": status["artifact_load_status"] == "loaded",
            # True when the in-memory detector is fitted, whether this run
            # trained it or loaded a previously trained artifact from disk.
            "model_trained": bool(getattr(detector, "is_fitted", False)),
            "sessions_evaluated": status["eligible_sessions"],
            "sessions_scored": status["sessions_scored"],
            "anomalies_found": status["anomalies_found"],
            "detections_scored": status.get("detections_scored", 0),
            "model_version": status.get("model_version") or MODEL_VERSION,
            "model_source": status.get("model_source", "unknown"),
            "persistence_status": status.get("persistence_status", "not_applicable"),
            "last_inference_at": datetime.now(timezone.utc).isoformat(),
            "inference_error": status.get("skipped_reason_detail") or status.get("artifact_load_error"),
            # Advisory ML anomaly detail (session-level, from the actual run).
            # Session ids are already public through /incidents and /events.
            "anomaly_type": (
                "isolation_forest"
                if status.get("model_source") in ("loaded", "trained")
                else None
            ),
            "anomaly_threshold": (
                float(anomaly_threshold) if anomaly_threshold is not None else None
            ),
            "anomaly_sessions": anomaly_sessions,
        }
        # Write atomically: write to temp file then rename
        tmp_path = metrics_path.with_suffix(metrics_path.suffix + ".tmp")
        metrics_path.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp_path, "w") as f:
            json.dump(metrics_data, f)
        tmp_path.replace(metrics_path)
    except Exception as e:
        # Never let metrics file write failure prevent in-memory inference results.
        print(f"ML metrics: WARNING - failed to write metrics file: {e}")

    return result, status
def run_pipeline(events: list, now: Optional[datetime] = None) -> tuple:
    now = now or datetime.now(timezone.utc)
    detections = DetectionEngine().analyze(events, now=now)
    detections, ml_status = _attach_ml_scores(events, detections)
    incidents = IncidentCorrelator().correlate(detections, events, now=now)
    return detections, incidents, ml_status

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run detection and correlation.")
    parser.add_argument("--since", help="ISO 8601 UTC, e.g. 2026-11-19T00:00:00Z")
    parser.add_argument("--dry-run", action="store_true", help="do not write to the database")
    args = parser.parse_args(argv)

    load_dotenv(PROJECT_ROOT / ".env")
    url = os.getenv("DATABASE_URL")
    if not url:
        print("DATABASE_URL is not configured")
        return 2
    try:
        since = parse_since(args.since) if args.since else None
    except ValueError as exc:
        print(f"Invalid --since: {exc}")
        return 2

    with psycopg.connect(url) as connection:
        events = fetch_events(connection, since)
        detections, incidents, ml_status = run_pipeline(events)
        status_label = ml_status.get("status") or (ml_status.get("skipped_reason") or "completed")
        print(
            "ML status: "
            f"status={status_label}, enabled={ml_status.get('enabled')}, "
            f"dependency={ml_status.get('dependency_status')}, "
            f"events_received={ml_status.get('events_received')}, "
            f"unique_sessions={ml_status.get('unique_sessions')}, "
            f"eligible_sessions={ml_status.get('eligible_sessions') or ml_status.get('sessions_evaluated')}, "
            f"model_action={ml_status.get('model_action') or ml_status.get('model_source')}, "
            f"model_version={ml_status.get('model_version')}, "
            f"detector_version={ml_status.get('detector_version')}, "
            f"artifact={ml_status.get('artifact_path')}, "
            f"inference_success={ml_status.get('inference_success')}, "
            f"sessions_scored={ml_status.get('sessions_scored')}, "
            f"detections_scored={ml_status.get('detections_scored')}, "
            f"anomalous_sessions={ml_status.get('anomalous_sessions', ml_status.get('anomalies_found'))}, "
            f"persistence={ml_status.get('persistence_status')}, "
            f"persistence_error={ml_status.get('persistence_error')}, "
            f"reason={ml_status.get('skipped_reason_detail') or ml_status.get('skipped_reason')}"
        )
        print(f"events read: {len(events)}")
        print(f"detections: {len(detections)} | incidents: {len(incidents)}")
        print("incidents by severity:", dict(sorted(Counter(i.severity for i in incidents).items())))
        if args.dry_run:
            print("dry-run: nothing written")
            return 0
        print("written:", write_results(connection, detections, incidents))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())