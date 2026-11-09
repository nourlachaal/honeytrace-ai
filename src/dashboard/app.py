"""HoneyTrace AI — read-only event dashboard.

Run from the repository root:

    python -m streamlit run src/dashboard/app.py

The dashboard reads only through the HTTP API (default http://127.0.0.1:8000).
It never connects to PostgreSQL, so the API's field allowlist and the
column-level grants on `honeytrace_api` stay the single access path.
"""

import sys
from datetime import date, datetime, time as dtime, timedelta, timezone
from pathlib import Path

import streamlit as st

# `streamlit run` puts this file's directory on sys.path, not the repo root.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.dashboard.api_client import (  # noqa: E402
    SOURCES,
    ApiError,
    api_base_url,
    fetch_event,
    fetch_events,
)

DISPLAY_COLUMNS = (
    "event_timestamp",
    "source",
    "event_type",
    "src_ip",
    "route",
    "status_code",
)

APPROVED_FIELD_COUNT = 13


def _sidebar_filters() -> dict:
    """Render the sidebar and return the filter dict passed to fetch_events."""
    st.sidebar.header("Filters")

    source_choice = st.sidebar.selectbox("Source", ("all", *SOURCES))
    event_type = st.sidebar.text_input("Event type", placeholder="cowrie.login.failed")
    src_ip = st.sidebar.text_input("Source IP", placeholder="10.0.0.9")
    limit = st.sidebar.slider("Page size", min_value=10, max_value=200, value=50, step=10)

    since = until = None
    if st.sidebar.checkbox("Filter by time range (UTC)"):
        since_col, until_col = st.sidebar.columns(2)
        today = datetime.now(timezone.utc).date()
        since_date = since_col.date_input("Since date", value=today - timedelta(days=7))
        since_time = since_col.time_input("Since time", value=dtime(0, 0))
        until_date = until_col.date_input("Until date", value=today + timedelta(days=1))
        until_time = until_col.time_input("Until time", value=dtime(0, 0))

        since = datetime.combine(since_date, since_time, tzinfo=timezone.utc).isoformat()
        until = datetime.combine(until_date, until_time, tzinfo=timezone.utc).isoformat()

    if st.sidebar.button("Refresh"):
        st.session_state.loaded = False
        st.session_state.pages = []
        st.session_state.next_cursor = None
        st.session_state.detail = None

    st.sidebar.divider()
    st.sidebar.caption(f"API: {api_base_url()}")
    st.sidebar.caption("Read-only. 13 approved fields only.")

    return {
        "limit": limit,
        "source": None if source_choice == "all" else source_choice,
        "event_type": event_type or None,
        "src_ip": src_ip or None,
        "since": since,
        "until": until,
    }


def _reset_state() -> None:
    st.session_state.setdefault("loaded", False)
    st.session_state.setdefault("pages", [])
    st.session_state.setdefault("next_cursor", None)
    st.session_state.setdefault("detail", None)
    st.session_state.setdefault("filters", None)
    st.session_state.setdefault("error", None)


def _show_api_error(exc: ApiError) -> None:
    if exc.status_code is None:
        st.error(
            f"Cannot reach the API at {api_base_url()}. "
            "Start it with: python -m uvicorn src.api.main:app --port 8000"
        )
    else:
        st.error(f"API returned {exc.status_code}: {exc}")


def _load_first_page(filters: dict) -> None:
    try:
        page = fetch_events(**filters)
    except ApiError as exc:
        st.session_state.error = exc
    else:
        st.session_state.error = None
        st.session_state.pages = [page["items"]]
        st.session_state.next_cursor = page.get("next_cursor")
    st.session_state.loaded = True


def _load_next_page() -> None:
    try:
        page = fetch_events(**st.session_state.filters, cursor=st.session_state.next_cursor)
    except ApiError as exc:
        _show_api_error(exc)
        return

    st.session_state.pages.append(page["items"])
    st.session_state.next_cursor = page.get("next_cursor")


def _render_detail(event_id: str) -> None:
    detail = st.session_state.detail
    if detail is None or detail.get("event_id") != event_id:
        try:
            detail = fetch_event(event_id)
        except ApiError as exc:
            _show_api_error(exc)
            return
        st.session_state.detail = detail

    st.subheader("Event detail")
    st.caption(
        f"Exactly {APPROVED_FIELD_COUNT} approved fields. "
        "raw_event, metadata, command, message and username are never exposed."
    )
    st.json(detail)


def main() -> None:
    st.set_page_config(page_title="HoneyTrace AI", page_icon="🍯", layout="wide")
    _reset_state()

    st.title("HoneyTrace AI — Events")
    st.caption("Read-only view of normalized Cowrie and Juice Shop events.")

    filters = _sidebar_filters()

    if st.session_state.filters != filters:
        st.session_state.filters = filters
        st.session_state.pages = []
        st.session_state.next_cursor = None
        st.session_state.detail = None
        st.session_state.loaded = False

    if not st.session_state.loaded:
        _load_first_page(filters)

    if st.session_state.error is not None:
        _show_api_error(st.session_state.error)
        if st.button("Retry"):
            st.session_state.loaded = False
            st.rerun()
        st.stop()

    rows = [row for page in st.session_state.pages for row in page]

    if not rows:
        st.info(
            "No events collected yet. This is expected when data/raw/ is empty: "
            "run a collector, then press Refresh."
        )
        st.stop()

    selection = st.dataframe(
        [{column: row.get(column) for column in DISPLAY_COLUMNS} for row in rows],
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
    )

    st.caption(f"{len(rows)} event(s) loaded.")

    if st.session_state.next_cursor:
        if st.button("Load more"):
            _load_next_page()
            st.rerun()
    else:
        st.caption("End of results.")

    selected_rows = getattr(getattr(selection, "selection", None), "rows", [])
    if selected_rows:
        index = selected_rows[0]
        if 0 <= index < len(rows):
            st.divider()
            _render_detail(rows[index]["event_id"])


if __name__ == "__main__":
    main()
