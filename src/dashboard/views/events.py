"""Events: table, quick filter and single-event investigation."""

from __future__ import annotations

import streamlit as st

from src.dashboard.api_client import ApiError, fetch_event
from src.dashboard.components import (
    empty_state,
    kv_grid,
    parse_timestamp,
    show_api_error,
    source_legend,
)

APPROVED_FIELDS = (
    "event_id",
    "source",
    "event_timestamp",
    "collected_at",
    "event_type",
    "session_id",
    "scenario_id",
    "test_run_id",
    "src_ip",
    "protocol",
    "http_method",
    "route",
    "status_code",
)

DISPLAY_COLUMNS = (
    "event_timestamp",
    "source",
    "event_type",
    "src_ip",
    "route",
    "status_code",
)

COLUMN_LABELS = {
    "event_timestamp": "Timestamp (UTC)",
    "source": "Source",
    "event_type": "Event type",
    "src_ip": "Source IP",
    "route": "Route",
    "status_code": "Status",
}

FILTER_CHIPS = (
    ("filter_source", "Source", "all"),
    ("filter_event_type", "Event type", ""),
    ("filter_src_ip", "Source IP", ""),
)


def _filtered(rows: list, query: str) -> list:
    """Client-side filter over the rows already loaded from the API."""
    text = query.strip().lower()
    if not text:
        return rows
    keys = ("event_type", "route", "src_ip", "source", "session_id")
    return [
        row
        for row in rows
        if any(text in str(row.get(key) or "").lower() for key in keys)
    ]


def _active_chips() -> list[tuple[str, str]]:
    chips = []
    for key, label, default in FILTER_CHIPS:
        value = st.session_state.get(key)
        if value and value != default:
            chips.append((key, f"{label}: {value}"))
    if st.session_state.get("filter_time"):
        chips.append(("filter_time", "Time range (UTC)"))
    query = st.session_state.get("event_search") or ""
    if query.strip():
        chips.append(("event_search", f"Search: {query.strip()}"))
    return chips


def _render_chips() -> None:
    chips = _active_chips()
    if not chips:
        return
    columns = st.columns(len(chips), gap="small")
    for column, (key, text) in zip(columns, chips):
        with column:
            if st.button(f"{text}  ✕", key=f"chip-{key}"):
                st.session_state["_clear_filter"] = key
                st.rerun()


def _render_detail(event_id: str) -> None:
    detail = st.session_state.get("detail")
    if detail is None or detail.get("event_id") != event_id:
        try:
            detail = fetch_event(event_id)
        except ApiError as exc:
            show_api_error(exc)
            return
        st.session_state.detail = detail

    # Project onto the approved contract: never render an unexpected field.
    projected = {field: detail.get(field) for field in APPROVED_FIELDS}

    st.markdown("#### Event detail")
    st.caption(
        f"Exactly {len(APPROVED_FIELDS)} approved fields. "
        "raw_event, metadata, command, message and username are never exposed."
    )
    st.markdown(
        kv_grid([(field, projected[field]) for field in APPROVED_FIELDS]),
        unsafe_allow_html=True,
    )

    with st.expander("Raw JSON (same 13 fields)"):
        st.json(projected)


def render(rows: list, next_cursor: str | None, on_load_more) -> None:
    if not rows:
        empty_state(
            "No events collected yet",
            "Run a collector to populate the database, then press Refresh data.",
            icon="database",
            hint="next: start a collector, then refresh",
        )
        return

    head_left, head_right = st.columns([3, 2], gap="small")
    with head_left:
        source_legend()
    with head_right:
        query = st.text_input(
            "Quick filter (current page only)",
            placeholder="event type, route, IP or session",
            label_visibility="collapsed",
            key="event_search",
        )

    _render_chips()

    visible = _filtered(rows, query)
    if query.strip():
        st.caption(
            f"Filtering {len(visible)} of {len(rows)} loaded event(s). "
            "This search runs on the current page only; use the sidebar filters "
            "to query the API."
        )

    st.write("")
    selection = st.dataframe(
        [
            {
                COLUMN_LABELS[column]: (
                    parse_timestamp(row.get(column)).strftime("%Y-%m-%d %H:%M:%S")
                    if column == "event_timestamp" and parse_timestamp(row.get(column))
                    else row.get(column)
                )
                for column in DISPLAY_COLUMNS
            }
            for row in visible
        ],
        hide_index=True,
        width="stretch",
        on_select="rerun",
        selection_mode="single-row",
        key="events_table",
        column_config={
            "Timestamp (UTC)": st.column_config.TextColumn(width="medium"),
            "Source": st.column_config.TextColumn(width="small"),
            "Event type": st.column_config.TextColumn(width="large"),
            "Source IP": st.column_config.TextColumn(width="small"),
            "Route": st.column_config.TextColumn(width="medium"),
            "Status": st.column_config.NumberColumn(width="small", format="%d"),
        },
    )

    st.caption(f"{len(visible)} event(s) loaded. Select a row to see all 13 fields.")

    if next_cursor:
        if st.button("Load more", key="events_more"):
            on_load_more()
            st.rerun()
    else:
        st.caption("End of results.")

    selected_rows = getattr(getattr(selection, "selection", None), "rows", [])
    if selected_rows:
        index = selected_rows[0]
        if 0 <= index < len(visible):
            st.divider()
            _render_detail(visible[index]["event_id"])
