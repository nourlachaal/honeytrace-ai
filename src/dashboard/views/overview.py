"""Overview: SOC monitoring summary, timeline and activity feed."""

from __future__ import annotations

import html
from datetime import datetime, timedelta, timezone
from typing import Any

import altair as alt
import streamlit as st

from src.dashboard import theme
from src.dashboard.api_client import ApiError, fetch_ml_status
from src.dashboard.components import (
    empty_state,
    kpi_row,
    parse_timestamp,
    status_chip,
)


def _bar_records(counts: dict, shorten: bool = False, limit: int = None) -> list:
    """Convert count dict to bar chart record format.

    Each entry is a dict with 'label' and 'value' keys suitable for
    _bar_list rendering.
    """
    items = list(counts.items())
    if shorten:
        src_labels = theme.SOURCE_LABELS
        mapped = []
        for key, val in items:
            for source in src_labels:
                prefix = f"{source}."
                if key.startswith(prefix):
                    key = key[len(prefix):]
                    break
            mapped.append((key, val))
        items = mapped
    if limit:
        items = items[:limit]
    return [{"label": k, "value": v} for k, v in items]


def _bar_list(records: list) -> None:
    """Display a list of bar chart records as Altair chart.

    Renders a simple horizontal bar chart from the given records.
    Each record should have 'label' and 'value' keys.
    """
    if not records:
        st.caption("No data to display.")
        return
    labels = [r["label"] for r in records]
    values = [r["value"] for r in records]
    chart = alt.Chart(
        alt.Data(values=[{"label": l, "value": v} for l, v in zip(labels, values)])
    ).mark_bar().encode(
        x=alt.X("value:Q", title="Count"),
        y=alt.Y("label:N", title="", sort="-x"),
    )
    st.altair_chart(chart, use_container_width=True)


def _delta(rows: list) -> str | None:
    """Compute a simple delta indicator from rows.

    Returns a string like "+5" or "-3" or None if not computable.
    """
    timestamps = []
    for row in rows:
        ts = row.get("event_timestamp")
        if ts:
            try:
                from src.dashboard.components import parse_timestamp as _parse
                moment = _parse(ts)
                if moment is not None:
                    timestamps.append(moment)
            except Exception:
                pass
    if len(timestamps) >= 2:
        delta = timestamps[-1] - timestamps[0]
        total_seconds = delta.total_seconds()
        if total_seconds != 0:
            count = len(rows)
            per_sec = count / abs(int(total_seconds)) if total_seconds else 0
            return f"{count} events/{abs(int(total_seconds))}s"
    return None


def _donut_chart(rows: list) -> tuple:
    """Create a donut chart from event source counts.

    Returns (chart_altair, total_count) tuple.
    """
    from collections import Counter
    counts = Counter()
    for row in rows:
        src = row.get("source")
        if src:
            counts[src] += 1
    total = sum(counts.values())
    if total == 0:
        return None, 0
    # Build Altair donut
    data = [{"source": s, "count": n} for s, n in counts.items()]
    chart = (
        alt.Chart(alt.Data(values=data))
        .mark_arc(outerRadius=80, innerRadius=55)
        .encode(
            theta=alt.Theta(field="count", type="quantitative"),
            color=alt.Color(field="source", type="nominal", legend=alt.Legend(title="Source")),
        )
    )
    return chart, total


def _latest_events(rows: list) -> None:
    """Display the latest events from the row set."""
    if not rows:
        st.caption("No events to display.")
        return
    # Show up to 10 latest events
    display_rows = rows[-10:] if len(rows) > 10 else rows
    for row in reversed(display_rows):
        ts = row.get("event_timestamp", "unknown")
        src = row.get("source", "unknown")
        evt_type = row.get("event_type", "unknown")
        st.caption(f"{ts} | {src} | {evt_type}")


def _spark(rows: list) -> str | None:
    """Create a sparkline representation from rows.

    Returns a sparkline string or None if not computable.
    """
    # Simple placeholder returning None; actual sparkline would need
    # time series data which may not be available.
    return None


def _timeline_chart(rows: list) -> tuple:
    """Create a timeline chart from events.

    Returns (altair_chart, note) tuple.
    """
    from datetime import timezone as tz

    timestamps = []
    sources = []
    for row in rows:
        ts = row.get("event_timestamp")
        if ts:
            try:
                from src.dashboard.components import parse_timestamp as _parse
                moment = _parse(ts)
                if moment is not None:
                    timestamps.append(moment)
                    sources.append(row.get("source", "unknown"))
            except Exception:
                pass

    if len(timestamps) < 2:
        return None, "No parseable timestamps for timeline."

    # Create simple timeline chart
    data = [
        {"time": moment.isoformat(), "source": source}
        for moment, source in zip(timestamps, sources)
    ]
    chart = (
        alt.Chart(alt.Data(values=data))
        .mark_line()
        .encode(
            x=alt.X("time:T", title="Time (UTC)"),
            y=alt.Y("count():Q", title="Events"),
            color=alt.Color(field="source", type="nominal", legend=alt.Legend(title="Source")),
        )
    )
    note = f"{len(timestamps)} events plotted"
    return chart, note


def _flag(value: Any) -> str:
    """Render a JSON boolean as Yes/No without inventing a value."""
    if value is None:
        return "Unknown"
    return "Yes" if value else "No"


def _label(value: Any) -> str:
    """Render an enum-like string as a readable label."""
    if value is None:
        return "Unknown"
    return str(value).replace("_", " ").title()


def _content(filters: dict, interval_seconds: int) -> None:
    """Render the ML monitoring section from the ``/ml/status`` API.

    The heading is always rendered. When the API cannot be reached the
    section stays visible and shows an explicit error, so a failure is
    never silent and never hides the section.
    """
    st.markdown("#### Machine Learning — Anomaly Detection Monitoring")

    try:
        ml_status = fetch_ml_status()
    except ApiError as exc:
        st.error(f"ML status unavailable — {exc}")
        st.caption(
            "The dashboard could not read /ml/status. The ML section remains "
            "visible so this failure is not silent; other dashboard sections "
            "continue to work."
        )
        return
    except Exception as exc:  # defensive: never let the section vanish
        st.error(f"ML status unavailable — unexpected error: {exc}")
        return

    # The 14 fields returned by /ml/status. Values are read verbatim; no
    # metric is calculated or hardcoded in the dashboard.
    row1 = st.columns(4, gap="small")
    row1[0].metric("ML Enabled", _flag(ml_status.get("enabled")))
    row1[1].metric("Model Loaded", _flag(ml_status.get("model_loaded")))
    row1[2].metric("Model Trained", _flag(ml_status.get("model_trained")))
    row1[3].metric("Model Version", str(ml_status.get("model_version", "Unknown")))

    row2 = st.columns(4, gap="small")
    row2[0].metric(
        "Detector Version", str(ml_status.get("detector_version", "Unknown"))
    )
    row2[1].metric(
        "Artifact Format Version",
        str(ml_status.get("artifact_format_version", "Unknown")),
    )
    row2[2].metric(
        "Sessions Evaluated",
        str(ml_status.get("sessions_evaluated")) if ml_status.get("sessions_evaluated") is not None else "Non disponible",
    )
    row2[3].metric(
        "Sessions Scored",
        str(ml_status.get("sessions_scored")) if ml_status.get("sessions_scored") is not None else "Non disponible",
    )

    row3 = st.columns(4, gap="small")
    row3[0].metric(
        "Detections Scored",
        str(ml_status.get("detections_scored")) if ml_status.get("detections_scored") is not None else "Non disponible",
    )
    row3[1].metric(
        "Anomalies Found",
        str(ml_status.get("anomalies_found")) if ml_status.get("anomalies_found") is not None else "Non disponible",
    )
    row3[2].metric(
        "Inference Success", _flag(ml_status.get("inference_success"))
    )
    row3[3].metric(
        "Persistence Status", _label(ml_status.get("persistence_status"))
    )

    row4 = st.columns(4, gap="small")
    row4[0].metric("Model Source", _label(ml_status.get("model_source")))
    row4[1].metric("Overall ML Status", _label(ml_status.get("status")))

    st.caption(
        "Source: /ml/status · refreshed "
        f"{datetime.now(timezone.utc).strftime('%H:%M:%S')} UTC"
    )


def render(
    rows: list,
    filters: dict,
    interval_seconds: int,
    error: Exception | None = None,
) -> None:
    """Render the Overview page.

    The ML monitoring section is rendered first, on every page load and on
    every fragment refresh, independently of the events API. The event
    summaries follow. ``rows`` and ``error`` come from the app shell so the
    page never performs a second, divergent fetch.
    """
    _content(filters, interval_seconds)

    if error is not None:
        from src.dashboard.components import show_api_error

        show_api_error(error)
        if st.button("Retry", key="overview_retry"):
            st.session_state.loaded = False
            st.rerun()
        return

    _render_overview_content(rows)


def _render_overview_content(rows: list) -> None:
    """Render the non-ML portion of the overview page."""
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Event Sources")
        counts = _counts(rows, "source")
        if counts:
            _bar_list(_bar_records(counts, shorten=True))
        else:
            st.caption("No event data available.")

    with col2:
        st.markdown("### Event Types")
        counts = _counts(rows, "event_type")
        if counts:
            _bar_list(_bar_records(counts, shorten=True))
        else:
            st.caption("No event type data available.")

    # Timeline and latest events
    st.markdown("### Recent Events")
    _latest_events(rows)

    # Severity distribution
    st.markdown("### Severity Distribution")
    counts = _counts(rows, "severity")
    if counts:
        _bar_list(_bar_records(counts, shorten=True))
    else:
        st.caption("No severity data available.")


def _counts(rows: list, key: str) -> dict:
    counts: dict = {}
    for row in rows:
        value = row.get(key)
        if value:
            counts[value] = counts.get(value, 0) + 1
    return counts


def _short_type(name: str) -> str:
    """Drop the redundant source prefix: 'cowrie.login.failed' -> 'login.failed'."""
    for source in theme.SOURCE_LABELS:
        prefix = f"{source}."
        if name.startswith(prefix):
            return name[len(prefix):]
    return name