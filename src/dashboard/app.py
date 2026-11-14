"""HoneyTrace AI - read-only event console.

Run from the repository root:

    python -m streamlit run src/dashboard/app.py

The dashboard reads only through the HTTP API (default http://127.0.0.1:8000).
It never connects to PostgreSQL, so the API field allowlist and the
column-level grants on `honeytrace_api` remain the single access path.
"""

import html
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

COLUMN_LABELS = {
    "event_timestamp": "Timestamp (UTC)",
    "source": "Source",
    "event_type": "Event type",
    "src_ip": "Source IP",
    "route": "Route",
    "status_code": "Status",
}

APPROVED_FIELD_COUNT = 13

CSS = """
<style>
  .block-container { padding-top: 2.2rem; padding-bottom: 3rem; max-width: 1500px; }

  .ht-header {
    display: flex; align-items: center; justify-content: space-between; gap: 1rem;
    padding: 1.15rem 1.45rem; border-radius: 16px; margin-bottom: 1.15rem;
    background: linear-gradient(135deg, rgba(249,115,22,0.14), rgba(30,41,59,0.55));
    border: 1px solid rgba(249,115,22,0.26);
  }
  .ht-title { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em; }
  .ht-sub { font-size: 0.85rem; opacity: 0.70; margin-top: 0.2rem; }
  .ht-pill {
    font-size: 0.76rem; font-weight: 600; padding: 0.32rem 0.72rem;
    border-radius: 999px; white-space: nowrap;
  }
  .ht-pill.ok  { background: rgba(34,197,94,0.15);  color: #4ade80; border: 1px solid rgba(34,197,94,0.35); }
  .ht-pill.bad { background: rgba(239,68,68,0.15);  color: #f87171; border: 1px solid rgba(239,68,68,0.35); }

  div[data-testid="stMetric"] {
    background: rgba(20,26,36,0.75);
    border: 1px solid rgba(148,163,184,0.15);
    border-radius: 14px; padding: 0.85rem 1rem;
  }
  div[data-testid="stMetricLabel"] { opacity: 0.65; }
  div[data-testid="stMetricValue"] { font-size: 1.45rem; }

  .ht-card {
    background: rgba(20,26,36,0.75);
    border: 1px solid rgba(148,163,184,0.15);
    border-radius: 14px; padding: 1rem 1.15rem; margin-top: 0.4rem;
  }
  .ht-card-title {
    font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.08em;
    opacity: 0.55; margin-bottom: 0.75rem;
  }

  .ht-bar-row { display: flex; align-items: center; gap: 0.7rem; margin: 0.38rem 0; font-size: 0.86rem; }
  .ht-bar-label {
    width: 190px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; opacity: 0.85;
  }
  .ht-bar-track { flex: 1; height: 7px; border-radius: 999px; background: rgba(148,163,184,0.14); }
  .ht-bar-fill  { display: block; height: 7px; border-radius: 999px;
                  background: linear-gradient(90deg, #f97316, #fb923c); }
  .ht-bar-value { width: 34px; text-align: right; opacity: 0.65; }

  .ht-kv { display: grid; grid-template-columns: 210px 1fr; gap: 0.4rem 1.1rem; font-size: 0.88rem; }
  .ht-kv dt { opacity: 0.55; }
  .ht-kv dd { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
  .ht-null { opacity: 0.3; font-style: italic; }

  .ht-empty {
    padding: 2.6rem 1.4rem; text-align: center; border-radius: 16px;
    border: 1px dashed rgba(148,163,184,0.30); background: rgba(20,26,36,0.4);
  }
  .ht-empty-title { font-size: 1rem; font-weight: 600; margin-bottom: 0.35rem; }
  .ht-empty-body { font-size: 0.88rem; opacity: 0.65; }
</style>
"""


def _inject_css() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def _header(connected: bool) -> None:
    pill = (
        '<span class="ht-pill ok">&#9679; API connected</span>'
        if connected
        else '<span class="ht-pill bad">&#9679; API unreachable</span>'
    )
    st.markdown(
        '<div class="ht-header"><div>'
        '<div class="ht-title">HoneyTrace AI</div>'
        '<div class="ht-sub">Read-only console for normalized Cowrie and Juice Shop events</div>'
        "</div>"
        f"{pill}"
        "</div>",
        unsafe_allow_html=True,
    )


def _sidebar_filters() -> dict:
    """Render the sidebar and return the filter dict passed to fetch_events."""
    st.sidebar.markdown(
        '<div style="font-size:0.75rem;letter-spacing:0.12em;opacity:0.5;'
        'text-transform:uppercase;margin-bottom:0.4rem;">HoneyTrace</div>',
        unsafe_allow_html=True,
    )
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

    if st.sidebar.button("Refresh", use_container_width=True):
        st.session_state.loaded = False
        st.session_state.pages = []
        st.session_state.next_cursor = None
        st.session_state.detail = None

    st.sidebar.divider()
    st.sidebar.caption(f"API: {api_base_url()}")
    st.sidebar.caption(f"Read-only. {APPROVED_FIELD_COUNT} approved fields only.")

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
        st.error(f"Cannot reach the API at {api_base_url()}. Check that the API is running and reachable.")
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


def _short_timestamp(value) -> str:
    if not value:
        return "-"
    return str(value).replace("T", " ")[:19]


def _metrics(rows: list) -> None:
    sources = {row.get("source") for row in rows if row.get("source")}
    ips = {row.get("src_ip") for row in rows if row.get("src_ip")}
    latest = max((_short_timestamp(row.get("event_timestamp")) for row in rows), default="-")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Events loaded", len(rows))
    col2.metric("Sources", len(sources))
    col3.metric("Unique source IPs", len(ips))
    col4.metric("Latest event (UTC)", latest)


def _counts(rows: list, key: str) -> dict:
    counts: dict = {}
    for row in rows:
        value = row.get(key)
        if value:
            counts[value] = counts.get(value, 0) + 1
    return counts


def _bar_list(title: str, counts: dict) -> None:
    if not counts:
        body = '<div class="ht-bar-row" style="opacity:0.4">no data</div>'
    else:
        peak = max(counts.values())
        body = "".join(
            '<div class="ht-bar-row">'
            f'<span class="ht-bar-label">{html.escape(str(name))}</span>'
            f'<span class="ht-bar-track"><span class="ht-bar-fill" '
            f'style="width:{max(4, int(value * 100 / peak))}%"></span></span>'
            f'<span class="ht-bar-value">{value}</span>'
            "</div>"
            for name, value in sorted(counts.items(), key=lambda item: -item[1])[:6]
        )
    st.markdown(
        f'<div class="ht-card"><div class="ht-card-title">{html.escape(title)}</div>{body}</div>',
        unsafe_allow_html=True,
    )


def _render_detail(event_id: str) -> None:
    detail = st.session_state.detail
    if detail is None or detail.get("event_id") != event_id:
        try:
            detail = fetch_event(event_id)
        except ApiError as exc:
            _show_api_error(exc)
            return
        st.session_state.detail = detail

    st.markdown("### Event detail")
    st.caption(
        f"Exactly {APPROVED_FIELD_COUNT} approved fields. "
        "raw_event, metadata, command, message and username are never exposed."
    )

    items = []
    for name, value in detail.items():
        shown = (
            f'<span class="ht-null">null</span>'
            if value is None or value == ""
            else html.escape(str(value))
        )
        items.append(f"<dt>{html.escape(str(name))}</dt><dd>{shown}</dd>")

    st.markdown(
        f'<div class="ht-card"><dl class="ht-kv">{"".join(items)}</dl></div>',
        unsafe_allow_html=True,
    )

    with st.expander("Raw JSON (same 13 fields)"):
        st.json(detail)


def _empty_state() -> None:
    st.markdown(
        '<div class="ht-empty">'
        '<div class="ht-empty-title">No events collected yet</div>'
        '<div class="ht-empty-body">Run a collector to populate the database, '
        "then press Refresh in the sidebar.</div>"
        "</div>",
        unsafe_allow_html=True,
    )


def main() -> None:
    st.set_page_config(page_title="HoneyTrace AI", page_icon="🍯", layout="wide")
    _inject_css()
    _reset_state()

    filters = _sidebar_filters()

    if st.session_state.filters != filters:
        st.session_state.filters = filters
        st.session_state.pages = []
        st.session_state.next_cursor = None
        st.session_state.detail = None
        st.session_state.loaded = False

    if not st.session_state.loaded:
        _load_first_page(filters)

    connected = st.session_state.error is None
    _header(connected)

    if st.session_state.error is not None:
        _show_api_error(st.session_state.error)
        if st.button("Retry"):
            st.session_state.loaded = False
            st.rerun()
        return

    rows = [row for page in st.session_state.pages for row in page]

    tab_overview, tab_events, tab_incidents = st.tabs(["Overview", "Events", "Incidents"])

    with tab_overview:
        _metrics(rows)
        st.write("")
        left, right = st.columns(2)
        with left:
            _bar_list("Events by type", _counts(rows, "event_type"))
        with right:
            _bar_list("Events by source", _counts(rows, "source"))

    with tab_events:
        if not rows:
            _empty_state()
        else:
            selection = st.dataframe(
                [
                    {COLUMN_LABELS[column]: row.get(column) for column in DISPLAY_COLUMNS}
                    for row in rows
                ],
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

    with tab_incidents:
        st.markdown(
            '<div class="ht-empty">'
            '<div class="ht-empty-title">Incidents are not available yet</div>'
            '<div class="ht-empty-body">The incident API depends on the persistence '
            "layer and the evidence policy. See docs/integration-contract-review.md.</div>"
            "</div>",
            unsafe_allow_html=True,
        )


if __name__ == "__main__":
    main()
