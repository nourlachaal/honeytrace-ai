"""HoneyTrace AI - read-only SOC dashboard.

Run from the repository root:

    python -m streamlit run src/dashboard/app.py

This module is the application shell: page configuration, session state, the
sidebar (navigation + global filters + auto-refresh) and page routing. The
three sections live in ``views/`` and the design system in ``theme.py`` /
``components.py``.

The dashboard reads only through the HTTP API (default http://127.0.0.1:8000).
It never connects to PostgreSQL, so the API field allowlist and the
column-level grants on `honeytrace_api` remain the single access path.
"""

from __future__ import annotations

import html
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import streamlit as st

# `streamlit run` puts this file's directory on sys.path, not the repo root.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.dashboard import components, theme  # noqa: E402
from src.dashboard.api_client import (  # noqa: E402
    SOURCES,
    ApiError,
    api_base_url,
    fetch_events,
)
from src.dashboard.views import events as events_view  # noqa: E402
from src.dashboard.views import incidents as incidents_view  # noqa: E402
from src.dashboard.views import overview as overview_view  # noqa: E402

APPROVED_FIELD_COUNT = 13

PAGE_META = {
    "Overview": (
        "Security overview",
        "Cowrie and Juice Shop telemetry, aggregated from the loaded page set.",
    ),
    "Events": (
        "Event explorer",
        "Every row comes from /events. Select an event to inspect its 13 approved fields.",
    ),
    "Incidents": (
        "Incident investigation",
        "Correlated Cowrie sessions. Incidents group detections by (source, session_id).",
    ),
}

REFRESH_INTERVALS = {"Off": 0, "15s": 15, "30s": 30}

FILTER_DEFAULTS = {
    "filter_source": "all",
    "filter_event_type": "",
    "filter_src_ip": "",
}


# --------------------------------------------------------------------------
# session state
# --------------------------------------------------------------------------
def _reset_state() -> None:
    st.session_state.setdefault("loaded", False)
    st.session_state.setdefault("pages", [])
    st.session_state.setdefault("next_cursor", None)
    st.session_state.setdefault("detail", None)
    st.session_state.setdefault("filters", None)
    st.session_state.setdefault("error", None)
    st.session_state.setdefault("last_refresh", None)
    st.session_state.setdefault("nav", theme.NAV_ITEMS[0])
    st.session_state.setdefault("auto_refresh", "Off")
    # ML status defaults
    st.session_state.setdefault("ml_enabled", True)
    st.session_state.setdefault("ml_model_version", "1.2.0")
    st.session_state.setdefault("ml_detector_version", "1.1.0")


def _apply_pending_clear() -> None:
    """Apply a filter-chip clear before the sidebar widgets are instantiated."""
    key = st.session_state.pop("_clear_filter", None)
    if key in FILTER_DEFAULTS:
        st.session_state[key] = FILTER_DEFAULTS[key]
    elif key == "filter_time":
        st.session_state["filter_time"] = False
    elif key == "event_search":
        st.session_state["event_search"] = ""


# --------------------------------------------------------------------------
# sidebar
# --------------------------------------------------------------------------
def _sidebar_brand() -> None:
    st.sidebar.markdown(
        '<div class="ht-side-brand">'
        '<div class="ht-side-mark">'
        '<svg width="19" height="19" viewBox="0 0 24 24" fill="none" aria-hidden="true">'
        '<path d="M12 2.6l8.2 4.7v9.4L12 21.4 3.8 16.7V7.3L12 2.6z" '
        'fill="#EA580C" fill-opacity="0.14" stroke="#EA580C" stroke-width="1.5" '
        'stroke-linejoin="round"/>'
        '<circle cx="12" cy="12" r="2.4" fill="#EA580C"/>'
        "</svg>"
        "</div>"
        '<div><div class="ht-side-name">HoneyTrace AI</div>'
        '<div class="ht-side-sub">SOC console</div></div>'
        "</div>",
        unsafe_allow_html=True,
    )


def _refresh_age_caption() -> None:
    """Live "Updated Xs ago" label for the sidebar."""
    st.sidebar.caption(
        f"Updated {components.updated_ago(st.session_state.get('last_refresh'))}"
    )


def _sidebar() -> tuple[dict, int]:
    """Render the sidebar and return the event filters plus refresh interval."""
    _sidebar_brand()

    st.sidebar.markdown(
        '<div class="ht-navlabel">Navigation</div>', unsafe_allow_html=True
    )
    st.sidebar.radio(
        "Navigation",
        theme.NAV_ITEMS,
        key="nav",
        label_visibility="collapsed",
    )

    st.sidebar.divider()
    st.sidebar.markdown('<div class="ht-navlabel">Filters</div>', unsafe_allow_html=True)

    source_choice = st.sidebar.selectbox(
        "Source", ("all", *SOURCES), key="filter_source"
    )
    event_type = st.sidebar.text_input(
        "Event type", placeholder="cowrie.login.failed", key="filter_event_type"
    )
    src_ip = st.sidebar.text_input(
        "Source IP", placeholder="10.0.0.9", key="filter_src_ip"
    )
    limit = st.sidebar.slider(
        "Page size", min_value=10, max_value=200, value=50, step=10, key="filter_limit"
    )

    since = until = None
    if st.sidebar.checkbox("Filter by time range (UTC)", key="filter_time"):
        since_col, until_col = st.sidebar.columns(2)
        today = datetime.now(timezone.utc).date()
        since_date = since_col.date_input(
            "Since date", value=today - timedelta(days=7), key="filter_since_date"
        )
        since_time = since_col.time_input(
            "Since time",
            value=datetime.min.time(),
            label_visibility="collapsed",
            key="filter_since_time",
        )
        until_date = until_col.date_input(
            "Until date", value=today + timedelta(days=1), key="filter_until_date"
        )
        until_time = until_col.time_input(
            "Until time",
            value=datetime.min.time(),
            label_visibility="collapsed",
            key="filter_until_time",
        )

        since = datetime.combine(since_date, since_time, tzinfo=timezone.utc).isoformat()
        until = datetime.combine(until_date, until_time, tzinfo=timezone.utc).isoformat()

    st.sidebar.divider()
    st.sidebar.markdown('<div class="ht-navlabel">Live</div>', unsafe_allow_html=True)
    auto_refresh = st.sidebar.selectbox(
        "Auto-refresh",
        tuple(REFRESH_INTERVALS),
        key="auto_refresh",
        help="Re-read the first page from the API on a timer.",
    )
    interval_seconds = REFRESH_INTERVALS.get(auto_refresh, 0)
    if interval_seconds:
        # The age label lives outside the content fragment, so it needs its own
        # timer to stay honest while auto-refresh reloads the page set.
        st.fragment(_refresh_age_caption, run_every="5s")()
    else:
        _refresh_age_caption()

    if st.sidebar.button("Refresh data", type="primary", width="stretch"):
        st.session_state.loaded = False
        st.session_state.pages = []
        st.session_state.next_cursor = None
        st.session_state.detail = None
        st.session_state.error = None
        incidents_view.reset()

    st.sidebar.divider()
    st.sidebar.markdown(
        '<div class="ht-policy">'
        '<div class="ht-policy-head">'
        f'{theme.icon_svg("lock", size=13, color="#FDBA74")} Read-only'
        "</div>"
        "<div>Endpoint</div>"
        f"<code>{html.escape(api_base_url())}</code>"
        "<div style=\"margin-top:.55rem\">"
        f"{APPROVED_FIELD_COUNT} approved fields. No raw_event, metadata, command, "
        "message or username.</div>"
        "<div style=\"margin-top:.4rem\">Sources: Cowrie &middot; Juice Shop</div>"
        "</div>",
        unsafe_allow_html=True,
    )

    return {
        "limit": limit,
        "source": None if source_choice == "all" else source_choice,
        "event_type": event_type or None,
        "src_ip": src_ip or None,
        "since": since,
        "until": until,
    }, interval_seconds


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------
def _load_first_page(filters: dict) -> None:
    slot = st.empty()
    slot.markdown(components.skeleton(), unsafe_allow_html=True)
    try:
        page = fetch_events(**filters)
    except ApiError as exc:
        st.session_state.error = exc
        st.session_state.pages = []
        st.session_state.next_cursor = None
    else:
        st.session_state.error = None
        st.session_state.pages = [page["items"]]
        st.session_state.next_cursor = page.get("next_cursor")
    finally:
        slot.empty()
    st.session_state.last_refresh = datetime.now(timezone.utc)
    st.session_state.loaded = True


def _load_next_page() -> None:
    try:
        page = fetch_events(
            **st.session_state.filters, cursor=st.session_state.next_cursor
        )
    except ApiError as exc:
        components.show_api_error(exc)
        return

    st.session_state.pages.append(page["items"])
    st.session_state.next_cursor = page.get("next_cursor")
    st.session_state.last_refresh = datetime.now(timezone.utc)


def _maybe_auto_refresh(filters: dict, interval_seconds: int) -> None:
    if not interval_seconds:
        return
    last = st.session_state.get("last_refresh")
    if last is None:
        _load_first_page(filters)
        return
    age = (datetime.now(timezone.utc) - last).total_seconds()
    # Fragment timers tick at the interval, so the age can be a fraction of a
    # second short; without the tolerance a 15s timer would only refresh on
    # every second tick.
    if age >= interval_seconds - 1:
        _load_first_page(filters)
        incidents_view.reset(keep_detail=True)


# --------------------------------------------------------------------------
# shell
# --------------------------------------------------------------------------
def _page_heading(nav: str) -> None:
    title, subtitle = PAGE_META.get(nav, (nav, ""))
    st.markdown(
        f'<div class="ht-page"><div class="ht-page-title">{html.escape(title)}</div>'
        f'<div class="ht-page-sub">{html.escape(subtitle)}</div></div>',
        unsafe_allow_html=True,
    )


def _latest_event_timestamp(rows: list) -> str | None:
    moments = [
        moment
        for moment in (
            components.parse_timestamp(row.get("event_timestamp")) for row in rows
        )
        if moment is not None
    ]
    if not moments:
        return None
    return max(moments).strftime("%Y-%m-%d %H:%M:%S")


def _content(filters: dict, interval_seconds: int) -> None:
    if not st.session_state.loaded:
        _load_first_page(filters)
    elif interval_seconds:
        _maybe_auto_refresh(filters, interval_seconds)

    rows = [row for page in st.session_state.pages for row in page]
    components.page_header(
        connected=st.session_state.error is None,
        last_event=_latest_event_timestamp(rows),
    )

    nav = st.session_state.get("nav", theme.NAV_ITEMS[0])
    _page_heading(nav)

    if nav == "Overview":
        # The Overview owns its own error handling so the ML section still
        # renders when the events endpoint is down.
        overview_view.render(
            rows, filters, interval_seconds, error=st.session_state.error
        )
    elif st.session_state.error is not None:
        components.show_api_error(st.session_state.error)
        if st.button("Retry"):
            st.session_state.loaded = False
            st.rerun()
    elif nav == "Events":
        events_view.render(rows, st.session_state.next_cursor, _load_next_page)
    else:
        incidents_view.render()


def main() -> None:
    st.set_page_config(
        page_title="HoneyTrace AI",
        page_icon="🍯",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    theme.register_altair_theme()
    components.inject_css()
    _reset_state()
    _apply_pending_clear()
    if st.session_state.get("last_refresh") is None:
        # The sidebar renders before the first fetch; without this the age
        # label would read "not refreshed" until the next interaction.
        st.session_state.last_refresh = datetime.now(timezone.utc)

    filters, interval_seconds = _sidebar()

    if st.session_state.filters != filters:
        st.session_state.filters = filters
        st.session_state.pages = []
        st.session_state.next_cursor = None
        st.session_state.detail = None
        st.session_state.loaded = False

    if interval_seconds:
        st.fragment(_content, run_every=f"{interval_seconds}s")(filters, interval_seconds)
    else:
        _content(filters, interval_seconds)


if __name__ == "__main__":
    main()