"""Incidents: SOC incident investigation centre."""

from __future__ import annotations

import html

import streamlit as st

from src.dashboard import theme
from src.dashboard.api_client import (
    INCIDENT_STATUSES,
    SEVERITIES,
    ApiError,
    fetch_incident,
    fetch_incidents,
    fetch_ml_status,
)
from src.dashboard.components import (
    badges,
    empty_state,
    kpi_row,
    kv_grid,
    panel,
    parse_timestamp,
    show_api_error,
    short_timestamp,
    source_dot,
)

# Every 503 the incident endpoint can answer, mapped to an actionable state.
# (title, body, icon, one-line hint) — titles and bodies are unchanged.
INCIDENT_REASONS = {
    "incidents_table_missing": (
        "Waiting for the database migration",
        "The detections and incidents tables do not exist yet (sql/003). "
        "This tab starts working as soon as the migration is applied.",
        "database",
        "next: apply sql/003",
    ),
    "incidents_not_granted": (
        "The API role cannot read incidents",
        "honeytrace_api has no column-level SELECT grant on incidents yet (sql/004).",
        "lock",
        "next: apply sql/004",
    ),
    "incidents_not_configured": (
        "The incident API is not configured",
        "The API has no database URL, so incidents cannot be read.",
        "plug",
        "next: set DATABASE_URL for the API",
    ),
    "incidents_unavailable": (
        "The incident tables are not readable",
        "The tables exist but the query failed. Check the API logs for the SQL error.",
        "alert",
        "next: check the API logs",
    ),
}

DETAIL_FIELDS = (
    "incident_id",
    "source",
    "session_id",
    "severity",
    "status",
    "has_new_evidence",
    "created_at",
    "updated_at",
)


def reset(keep_detail: bool = False) -> None:
    """Drop cached incident pages so the next render refetches from the API."""
    for key in ("incident_pages", "incident_cursor", "incident_filters", "incident_detail"):
        if keep_detail and key == "incident_detail":
            continue
        st.session_state.pop(key, None)


def _ml_context() -> tuple[dict[tuple, dict], dict]:
    """Return {(source, session_id): anomaly} plus the full /ml/status payload.

    The ML model is advisory and session-level. ``/ml/status`` publishes only
    the sessions the last pipeline run flagged, so an incident is marked as an
    anomaly only when its own (source, session_id) appears in that list.
    """
    try:
        status = fetch_ml_status()
    except Exception:
        return {}, {}

    index: dict[tuple, dict] = {}
    for item in status.get("anomaly_sessions") or []:
        if not isinstance(item, dict):
            continue
        key = (item.get("source"), item.get("session_id"))
        index[key] = item
    return index, status


def _anomaly_for(incident: dict, anomalies: dict[tuple, dict]) -> dict | None:
    return anomalies.get((incident.get("source"), incident.get("session_id")))


def _criticality_chip(level: str | None) -> str:
    """Render the advisory ML criticality as a colored chip."""
    value = str(level or "low").lower()
    return f'<span class="ht-chip ml-crit-{html.escape(value)}">{html.escape(value)}</span>'


def _adjusted_severity(item: dict, anomalies: dict[tuple, dict]) -> str:
    severity = str(item.get("severity") or "low")
    anomaly = _anomaly_for(item, anomalies)
    if anomaly is not None:
        crit = str(anomaly.get("criticality") or "").lower()
        if crit in ("critical", "high"):
            _rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            if _rank.get(crit, 0) > _rank.get(severity, 0):
                severity = crit
    return severity


def _metrics(items: list, anomalies: dict[tuple, dict] | None = None) -> None:
    anomalies = anomalies or {}
    open_count = sum(1 for item in items if item.get("status") == "open")
    new_count = sum(1 for item in items if item.get("has_new_evidence"))
    urgent = sum(
        1 for item in items
        if _adjusted_severity(item, anomalies) in ("high", "critical")
    )
    ml_count = sum(1 for item in items if _anomaly_for(item, anomalies) is not None)

    kpi_row(
        [
            {
                "key": "inc-total",
                "label": "Incidents",
                "value": len(items),
                "icon": "shield",
                "help": "Incidents on this page",
            },
            {
                "key": "inc-open",
                "label": "Open",
                "value": open_count,
                "icon": "folder",
                "help": "status = open",
            },
            {
                "key": "inc-new",
                "label": "New evidence",
                "value": new_count,
                "icon": "plus-circle",
                "help": "Not yet acknowledged by an analyst",
            },
            {
                "key": "inc-urgent",
                "label": "High or critical",
                "value": urgent,
                "icon": "alert",
                "help": "Severity high or critical",
            },
            {
                "key": "inc-ml",
                "label": "ML anomalies",
                "value": ml_count,
                "icon": "activity",
                "help": "Sessions flagged by the advisory ML model",
            },
        ]
    )


def _table(
    items: list,
    anomalies: dict[tuple, dict] | None = None,
    ml_status: dict | None = None,
) -> None:
    anomalies = anomalies or {}
    ml_status = ml_status or {}
    anomaly_type = str(ml_status.get("anomaly_type") or "isolation_forest")
    rows = []
    for incident in items:
        title = str(incident.get("title") or "-")
        summary = str(incident.get("summary") or "")
        incident_id = str(incident.get("incident_id") or "")
        short_id = incident_id[:12] if incident_id else "-"
        severity = str(incident.get("severity") or "low")
        # Advisory ML criticality escalates the displayed severity: when the
        # model flags the session as critical/high, the table shows that level
        # instead of the rule-based one (severity only ever rises).
        anomaly = _anomaly_for(incident, anomalies)
        if anomaly is not None:
            crit = str(anomaly.get("criticality") or "").lower()
            if crit in ("critical", "high"):
                _rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
                if _rank.get(crit, 0) > _rank.get(severity, 0):
                    severity = crit
        classes = f"sev-{html.escape(severity)}"
        if incident.get("has_new_evidence"):
            classes += " is-new"
        if anomaly is not None:
            category = str(anomaly.get("category") or "session_behaviour")
            criticality = str(anomaly.get("criticality") or "low")
            ml_cell = (
                '<span class="ht-chip ml-anomaly" title="Advisory ML result">'
                f"anomaly · {html.escape(category)}</span> "
                f"{_criticality_chip(criticality)}"
                f'<div class="ht-inc-sub">{html.escape(anomaly_type)}</div>'
            )
            badge_incident = dict(incident)
            badge_incident["severity"] = severity
        else:
            ml_cell = '<span class="ht-chip">normal</span>'
            badge_incident = incident
        rows.append(
            f'<tr class="{classes}">'
            f'<td><div class="ht-inc-title">{html.escape(title)}</div>'
            f'<div class="ht-inc-sub" title="{html.escape(summary)}">'
            f'<span class="ht-inc-mono">{html.escape(short_id)}</span> · '
            f"{html.escape(summary)}</div></td>"
            f"<td>{badges(badge_incident)}</td>"
            f'<td class="ht-inc-mono">{html.escape(str(incident.get("source") or "-"))}</td>'
            f'<td class="ht-inc-mono">{html.escape(str(incident.get("session_id") or "-"))}</td>'
            f"<td>{ml_cell}</td>"
            f'<td class="ht-inc-mono">{html.escape(short_timestamp(incident.get("updated_at")))}</td>'
            "</tr>"
        )

    st.markdown(
        '<div class="ht-table-scroll"><table class="ht-inc-table"><thead><tr>'
        "<th>Incident</th><th>Severity &amp; status</th><th>Source</th>"
        "<th>Session</th><th>ML</th><th>Updated (UTC)</th>"
        f'</tr></thead><tbody>{"".join(rows)}</tbody></table></div>',
        unsafe_allow_html=True,
    )


def _timeline(entries: list) -> None:
    if not entries:
        st.caption("No timeline entries.")
        return

    rows = []
    for entry in entries:
        moment = parse_timestamp(entry.get("timestamp"))
        stamp = moment.strftime("%d %b %H:%M:%S") if moment else "-"
        detections = len(entry.get("detection_ids") or [])
        rows.append(
            '<div class="ht-vtl-row">'
            f'<span class="ht-vtl-time">{html.escape(stamp)}</span>'
            f'<span class="ht-vtl-type">{html.escape(str(entry.get("event_type") or "-"))}</span>'
            '<span class="ht-vtl-source">'
            f'{source_dot(entry.get("source"), size=7)}'
            f'{html.escape(str(entry.get("source") or "-"))}</span>'
            '<span class="ht-vtl-count">'
            f'<span class="ht-chip">{detections} detection(s)</span></span>'
            "</div>"
        )
    st.markdown(f'<div class="ht-vtl">{"".join(rows)}</div>', unsafe_allow_html=True)


def _num(value, digits: int = 4) -> str | None:
    """Format a numeric value without inventing one when it is missing."""
    if value is None:
        return None
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return str(value)


def _detail(
    incident: dict,
    anomalies: dict[tuple, dict] | None = None,
    ml_status: dict | None = None,
) -> None:
    ml_status = ml_status or {}
    anomaly_type = str(ml_status.get("anomaly_type") or "isolation_forest")
    st.markdown("#### Incident detail")
    st.markdown(
        kv_grid([(field, incident.get(field)) for field in DETAIL_FIELDS]),
        unsafe_allow_html=True,
    )

    anomaly = _anomaly_for(incident, anomalies or {})
    score = anomaly.get("score") if isinstance(anomaly, dict) else None
    threshold = anomaly.get("threshold") if isinstance(anomaly, dict) else None
    features = (anomaly.get("features") or {}) if isinstance(anomaly, dict) else {}

    st.write("")
    st.markdown("**ML anomaly (advisory)**")
    st.markdown(
        kv_grid(
            [
                ("ml_is_anomaly", "Yes" if anomaly is not None else "No"),
                ("anomaly_type", anomaly_type if anomaly is not None else "-"),
                (
                    "anomaly_category",
                    str(anomaly.get("category") or "-")
                    if anomaly is not None
                    else "-",
                ),
                (
                    "criticality",
                    str(anomaly.get("criticality") or "-")
                    if anomaly is not None
                    else "-",
                ),
                ("anomaly_score", _num(score)),
                ("decision_threshold", _num(threshold)),
            ]
        ),
        unsafe_allow_html=True,
    )

    if anomaly is not None and features:
        st.write("")
        st.markdown("**Session features used by the model**")
        st.markdown(
            kv_grid(
                [
                    ("event_count", features.get("event_count")),
                    ("login_failed_count", features.get("login_failed_count")),
                    ("login_success_count", features.get("login_success_count")),
                    ("command_count", features.get("command_count")),
                    ("distinct_event_types", features.get("distinct_event_types")),
                    ("distinct_usernames", features.get("distinct_usernames")),
                    ("duration_seconds", _num(features.get("duration_seconds"), 2)),
                    ("events_per_second", _num(features.get("events_per_second"), 4)),
                    ("failed_login_ratio", _num(features.get("failed_login_ratio"), 4)),
                ]
            ),
            unsafe_allow_html=True,
        )

    st.write("")
    st.markdown("**ML run details**")
    st.markdown(
        kv_grid(
            [
                ("model_version", ml_status.get("model_version")),
                ("detector_version", ml_status.get("detector_version")),
                ("artifact_format_version", ml_status.get("artifact_format_version")),
                ("model_source", ml_status.get("model_source")),
                ("model_loaded", ml_status.get("model_loaded")),
                ("model_trained", ml_status.get("model_trained")),
                ("sessions_scored", ml_status.get("sessions_scored")),
                ("anomalies_found", ml_status.get("anomalies_found")),
                ("persistence_status", ml_status.get("persistence_status")),
                ("last_inference_at", ml_status.get("last_inference_at")),
                ("inference_success", ml_status.get("inference_success")),
            ]
        ),
        unsafe_allow_html=True,
    )
    st.caption(
        "Session-level Isolation Forest result from the last pipeline run. "
        "The category describes the dominant behaviour, the criticality is a "
        "percentile band of the anomaly score, and an anomaly is not a "
        "confirmed attack: it is advisory."
    )

    st.write("")
    st.markdown("**Summary**")
    st.write(str(incident.get("summary") or "-"))
    st.caption(
        f"{len(incident.get('detection_ids') or [])} detection(s), "
        f"{len(incident.get('event_ids') or [])} event(s), "
        f"{len(incident.get('missing_event_ids') or [])} missing event(s). "
        "Timeline entries contain only public fields."
    )

    st.write("")
    with panel(
        "incident-timeline",
        "Timeline",
        "Chronological, ordered as written by the correlator",
        icon="clock",
    ):
        _timeline(incident.get("timeline") or [])


def render() -> None:
    col1, col2, col3 = st.columns(3, gap="small")
    source_choice = col1.selectbox("Source", ("all", *theme.SOURCE_LABELS), key="incident_source")
    status_choice = col2.selectbox(
        "Status",
        ("all", *INCIDENT_STATUSES),
        format_func=lambda value: "all" if value == "all" else value.replace("_", " "),
        key="incident_status",
    )
    severity_choice = col3.selectbox(
        "Severity", ("all", *SEVERITIES), key="incident_severity"
    )

    filters = {
        "source": None if source_choice == "all" else source_choice,
        "status": None if status_choice == "all" else status_choice,
        "severity": None if severity_choice == "all" else severity_choice,
    }

    if st.session_state.get("incident_filters") != filters:
        st.session_state.incident_filters = filters
        st.session_state.incident_pages = []
        st.session_state.incident_cursor = None

    pages = st.session_state.setdefault("incident_pages", [])
    if not pages:
        try:
            page = fetch_incidents(limit=50, **filters)
        except ApiError as exc:
            code = str(exc)
            reason = INCIDENT_REASONS.get(
                code,
                (
                    "The incident API is not available",
                    f"The API returned {exc.status_code or 'no status'}: {code}",
                    "alert",
                    "next: check the API logs",
                ),
            )
            empty_state(*reason)
            if code:
                st.caption(f"API reason: {code}")
            return
        pages = [page.get("items") or []]
        st.session_state.incident_pages = pages
        st.session_state.incident_cursor = page.get("next_cursor")

    items = [item for page in pages for item in page]
    if not items:
        empty_state(
            "No incidents yet",
            "No detection rule has produced an incident. Incidents appear once "
            "the engine writes a session with detections and the correlator groups "
            "it by (source, session_id).",
            icon="hexagon",
            hint="next: run the pipeline after detections arrive",
        )
        return

    # New evidence first; the sort is stable inside each group.
    items = sorted(items, key=lambda item: 0 if item.get("has_new_evidence") else 1)

    anomalies, ml_status = _ml_context()

    _metrics(items, anomalies)
    st.write("")
    _table(items, anomalies, ml_status)
    st.caption(
        f"{len(items)} incident(s) loaded · "
        f"{len(anomalies)} session(s) flagged by the advisory ML model."
    )

    cursor = st.session_state.get("incident_cursor")
    if cursor:
        st.caption("More incidents match. Load more to see them.")
        if st.button("Load more incidents", key="incidents_more"):
            try:
                page = fetch_incidents(limit=50, cursor=cursor, **filters)
            except ApiError as exc:
                show_api_error(exc)
                return
            st.session_state.incident_pages.append(page.get("items") or [])
            st.session_state.incident_cursor = page.get("next_cursor")
            st.rerun()

    st.write("")
    options = [incident.get("incident_id") for incident in items]
    labels = {
        incident.get("incident_id"): (
            f"{incident.get('title') or 'incident'} — {incident.get('session_id') or '-'}"
        )
        for incident in items
    }
    current = st.session_state.get("incident_detail")
    if current not in ("-", *options):
        st.session_state.incident_detail = "-"
    chosen = st.selectbox(
        "Inspect an incident",
        ["-", *options],
        format_func=lambda value: "-" if value == "-" else labels.get(value, value),
        key="incident_detail",
    )
    if chosen == "-":
        return

    try:
        detail = fetch_incident(chosen)
    except ApiError as exc:
        show_api_error(exc)
        return

    st.divider()
    _detail(detail, anomalies, ml_status)
