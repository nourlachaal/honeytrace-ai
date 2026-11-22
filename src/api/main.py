from datetime import datetime
from typing import Annotated, Any, Literal
from pathlib import Path

from dotenv import load_dotenv

from fastapi import FastAPI, HTTPException, Path as FastAPIPath, Query, Request, Response, status
from fastapi.responses import JSONResponse
from src.api.database import database_status
from src.api.events import (
    CursorError,
    DatabaseNotConfigured,
    DatabaseUnavailable,
    EVENT_ID_REGEX,
    decode_cursor,
    encode_cursor,
    fetch_event,
    fetch_events,
)
from src.api.incidents import (
    INCIDENT_ID_REGEX,
    IncidentsUnavailable,
    fetch_incident,
    fetch_incidents,
)
from src.api.models import EventPage, EventSummary, IncidentPage, IncidentSummary
from src.detection.engine import DETECTOR_VERSION
from src.ml.isolation_forest import MODEL_VERSION, ARTIFACT_FORMAT_VERSION

load_dotenv(Path(__file__).resolve().parents[2])

app = FastAPI(
    title="HoneyTrace AI API",
    description="Read-only API for normalized security events.",
    version="0.1.0",
)


@app.exception_handler(IncidentsUnavailable)
async def incidents_unavailable_handler(
    request: Request, exc: IncidentsUnavailable
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": f"incidents_{exc.reason}"},
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/db")
def health_db(response: Response) -> dict[str, str]:
    result = database_status()
    if result != "ok":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": result}


@app.get("/ml/status")
async def ml_status() -> dict[str, Any]:
    """Advisory ML isolation forest status.

    Returns operational metrics. The model is integrated into the
    live pipeline (_attach_ml_scores in src/pipeline.py) and runs
    automatically on every pipeline execution.

    An anomaly is not a confirmed attack; ML remains advisory.
    Some metrics may be None when unverifiable without pipeline execution
    evidence or database permissions. The dashboard displays "Non disponible"
    for any None API value.
    """
    import os
    from pathlib import Path

    from psycopg import errors as pg_errors

    # Check ML_ENABLED - default to enabled if not set
    ml_enabled_str = os.getenv("ML_ENABLED", "1").strip().lower()
    ml_enabled = ml_enabled_str not in {"0", "false", "no", "off"}

    # Initialize result with safe defaults (never None – dashboard uses _flag/_label)
    result: dict[str, Any] = {
        "enabled": bool(ml_enabled),
        "model_loaded": False,
        "model_trained": False,
        "model_version": str(MODEL_VERSION) if MODEL_VERSION else "Unknown",
        "detector_version": str(DETECTOR_VERSION) if DETECTOR_VERSION else "Unknown",
        "artifact_format_version": str(ARTIFACT_FORMAT_VERSION) if str(ARTIFACT_FORMAT_VERSION).isdigit() else "1",
        "sessions_evaluated": 0,
        "sessions_scored": 0,
        "detections_scored": 0,
        "anomalies_found": 0,
        "inference_success": False,
        "inference_executed": False,
        "persistence_status": "not_applicable",
        "model_source": "unknown",
        "status": "disabled" if not ml_enabled else "completed",
        "events_total": 0,
        "sessions_total": 0,
        # Advisory ML anomaly detail, filled from the pipeline bridge when available.
        "anomaly_type": None,
        "anomaly_threshold": None,
        "anomaly_sessions": [],
    }

    if not ml_enabled:
        return result

    # ML enabled - check artifact and database state
    model_path = os.getenv("ML_MODEL_PATH", "data/models/isolation_forest.joblib")
    p = Path(model_path)

    artifact_exists = p.is_file() if p else False

    # Database metrics - read-only via existing permissions
    db_url = os.getenv("API_DATABASE_URL") or os.getenv("DATABASE_URL")
    if db_url:
        try:
            import psycopg
            conn = psycopg.connect(db_url, connect_timeout=2, application_name='ml-status-readonly')
            with conn.cursor() as cur:
                # Total events collected
                try:
                    cur.execute('SELECT COUNT(*) FROM security_events')
                    result["events_total"] = cur.fetchone()[0]
                except Exception:
                    pass
                # Distinct sessions with events
                try:
                    cur.execute('SELECT COUNT(DISTINCT session_id) FROM security_events WHERE session_id IS NOT NULL')
                    result["sessions_total"] = cur.fetchone()[0]
                except Exception:
                    pass
            conn.close()
        except Exception:
            pass

    if artifact_exists:
        result["model_loaded"] = True
        # model_trained reflects actual fitted state.
        # Since the API endpoint cannot verify training state without running
        # the pipeline, we set None to avoid claiming unverified state.
        # The pipeline confirms is_fitted=True when artifact loads successfully.
        result["model_trained"] = None
        # Do NOT set inference_success = True based solely on artifact existence.
        # Inference success requires actual inference execution evidence.
        result["inference_executed"] = None
        result["inference_success"] = None
        # Read aggregate metrics from pipeline execution file bridge,
        # if available — no new DB privileges or schema changes required.
        bridge_metrics = None
        try:
            import json
            from pathlib import Path
            from src.pipeline import PROJECT_ROOT
            metrics_path = Path(PROJECT_ROOT) / "data" / "ml_metrics.json"
            if metrics_path.is_file():
                with open(metrics_path, "r") as f:
                    metrics_data = json.load(f)
                # Keep only safe, aggregate keys; ignore any internal evidence.
                safe_keys = {
                    "inference_executed",
                    "inference_success",
                    "sessions_evaluated",
                    "sessions_scored",
                    "anomalies_found",
                    "detections_scored",
                    "model_version",
                    "model_source",
                    "persistence_status",
                    "last_inference_at",
                    "inference_error",
                    "model_trained",
                    "anomaly_type",
                    "anomaly_threshold",
                    "anomaly_sessions",
                }
                filtered = {k: v for k, v in metrics_data.items() if k in safe_keys}
                bridge_metrics = filtered if filtered else None
        except Exception:
            # Never expose file-read errors through the API.
            bridge_metrics = None

        if bridge_metrics is not None:
            result["inference_executed"] = bridge_metrics.get("inference_executed")
            result["inference_success"] = bridge_metrics.get("inference_success")
            result["sessions_evaluated"] = bridge_metrics.get("sessions_evaluated")
            result["sessions_scored"] = bridge_metrics.get("sessions_scored")
            result["anomalies_found"] = bridge_metrics.get("anomalies_found")
            result["detections_scored"] = bridge_metrics.get("detections_scored")
            result["model_source"] = bridge_metrics.get("model_source") or "loaded"
            result["persistence_status"] = bridge_metrics.get("persistence_status")
            result["last_inference_at"] = bridge_metrics.get("last_inference_at")
            result["inference_error"] = bridge_metrics.get("inference_error")
            # Actual fitted state recorded by the pipeline that ran inference.
            result["model_trained"] = bridge_metrics.get("model_trained")
            # Advisory anomaly detail (session-level) from that same run.
            result["anomaly_type"] = bridge_metrics.get("anomaly_type")
            result["anomaly_threshold"] = bridge_metrics.get("anomaly_threshold")
            result["anomaly_sessions"] = bridge_metrics.get("anomaly_sessions") or []
        else:
            # No bridge file — keep the default None values set above.
            pass
        # Reflect actual pipeline state from database,
        # prioritizing bridge values when available.
        if result["sessions_total"] > 0:
            if result["sessions_evaluated"] is None:
                result["sessions_evaluated"] = result["sessions_total"]
            # sessions_scored: bridge value if available; otherwise None.
            # Do NOT compute from events_total.
            if result["sessions_scored"] is None:
                pass  # Keep None; will be set below
        if result["events_total"] > 0:
            # events_total is the total event count from the database.
            # detections_scored comes only from the pipeline bridge; never
            # equate it with events_total.
            if result.get("detections_scored") is None:
                result["detections_scored"] = None
        # Model source: bridge value if available.
        if bridge_metrics is not None and bridge_metrics.get("model_source"):
            result["model_source"] = bridge_metrics["model_source"]
    else:
        # No artifact: ML would train on next run if sufficient data exists
        result["persistence_status"] = "not_trained"
        result["status"] = "completed"

    return result


@app.get("/events", response_model=EventPage)
def list_events(
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    source: Annotated[Literal["cowrie", "juice_shop"] | None, Query()] = None,
    event_type: Annotated[str | None, Query(max_length=100)] = None,
    src_ip: Annotated[str | None, Query(max_length=64)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> EventPage:
    for value in (since, until):
        if value is not None and value.tzinfo is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="timestamp_must_include_timezone",
            )

    decoded_cursor = None
    if cursor is not None:
        try:
            decoded_cursor = decode_cursor(cursor)
        except CursorError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid_cursor",
            ) from None

    try:
        rows = fetch_events(
            limit=limit,
            cursor=decoded_cursor,
            source=source,
            event_type=event_type,
            src_ip=src_ip,
            since=since,
            until=until,
        )
    except DatabaseNotConfigured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="database_not_configured",
        ) from None
    except DatabaseUnavailable:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="database_unavailable",
        ) from None

    items = rows[:limit]
    next_cursor = None
    if len(rows) > limit and items:
        last = items[-1]
        next_cursor = encode_cursor(last["event_timestamp"], last["event_id"])

    return EventPage(items=items, next_cursor=next_cursor)


@app.get("/events/{event_id}", response_model=EventSummary)
def get_event(
    event_id: Annotated[str, FastAPIPath(pattern=EVENT_ID_REGEX)],
) -> EventSummary:
    try:
        row = fetch_event(event_id)
    except DatabaseNotConfigured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="database_not_configured",
        ) from None
    except DatabaseUnavailable:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="database_unavailable",
        ) from None

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="event_not_found",
        )

    return EventSummary.model_validate(row)


@app.get("/incidents", response_model=IncidentPage)
def list_incidents(
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    source: Annotated[str | None, Query(max_length=64)] = None,
    incident_status: Annotated[
        Literal["open", "under_review", "resolved", "false_positive"] | None,
        Query(alias="status"),
    ] = None,
    severity: Annotated[
        Literal["low", "medium", "high", "critical"] | None, Query()
    ] = None,
) -> IncidentPage:
    decoded_cursor = None
    if cursor is not None:
        try:
            decoded_cursor = decode_cursor(cursor)
        except CursorError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid_cursor",
            ) from None

    rows = fetch_incidents(
        limit=limit,
        cursor=decoded_cursor,
        source=source,
        incident_status=incident_status,
        severity=severity,
    )

    items = rows[:limit]
    next_cursor = None
    if len(rows) > limit and items:
        last = items[-1]
        next_cursor = encode_cursor(last["updated_at"], last["incident_id"])

    return IncidentPage(items=items, next_cursor=next_cursor)


@app.get("/incidents/{incident_id}", response_model=IncidentSummary)
def get_incident(
    incident_id: Annotated[str, FastAPIPath(pattern=INCIDENT_ID_REGEX)],
) -> IncidentSummary:
    row = fetch_incident(incident_id)

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="incident_not_found",
        )

    return IncidentSummary.model_validate(row)