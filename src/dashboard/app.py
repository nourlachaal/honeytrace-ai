"""HoneyTrace AI - read-only event console.

Run from the repository root:

    python -m streamlit run src/dashboard/app.py

The dashboard reads only through the HTTP API (default http://127.0.0.1:8000).
It never connects to PostgreSQL, so the API field allowlist and the
column-level grants on `honeytrace_api` remain the single access path.

Everything on screen is derived from the 13 approved fields. No new field is
requested from the API and no value is rendered without html.escape().
"""

import html
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import altair as alt
import streamlit as st

# `streamlit run` puts this file's directory on sys.path, not the repo root.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.dashboard.api_client import (  # noqa: E402
    INCIDENT_STATUSES,
    SEVERITIES,
    SOURCES,
    ApiError,
    api_base_url,
    fetch_event,
    fetch_events,
    fetch_incident,
    fetch_incidents,
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

# Every 503 the incident endpoint can answer, mapped to a state the analyst can
# act on. The key is the API's `detail` string, which the client keeps as the
# ApiError message.
INCIDENT_REASONS = {
    "incidents_table_missing": (
        "Waiting for the database migration",
        "The detections and incidents tables do not exist yet (sql/003). "
        "This tab starts working as soon as the migration is applied.",
    ),
    "incidents_not_granted": (
        "The API role cannot read incidents",
        "honeytrace_api has no column-level SELECT grant on incidents yet (sql/004).",
    ),
    "incidents_not_configured": (
        "The incident API is not configured",
        "The API has no database URL, so incidents cannot be read.",
    ),
    "incidents_unavailable": (
        "The incident tables are not readable",
        "The tables exist but the query failed. Check the API logs for the SQL error.",
    ),
}

# Fixed palette so a source keeps its colour across every chart on the page.
SOURCE_COLORS = {
    "cowrie": "#ea580c",
    "juice_shop": "#0284c7",
}
FALLBACK_COLORS = ("#7c3aed", "#0d9488", "#db2777", "#64748b")

INK = "#0f172a"
MUTED = "#64748b"
GRID = "#eef2f7"
BORDER = "#e2e8f0"

CSS = """
<style>
  :root {
    --ht-border: #e2e8f0;
    --ht-ink: #0f172a;
    --ht-muted: #64748b;
    --ht-accent: #ea580c;
    --ht-accent-soft: #fff3e9;
    --ht-shadow: 0 1px 2px rgba(15, 23, 42, 0.05);
    --ht-shadow-hover: 0 10px 26px rgba(15, 23, 42, 0.09);
  }

  /* ---------- page shell ---------- */
  [data-testid="stAppViewContainer"] { background: #f6f8fb; }
  [data-testid="stHeader"] { background: transparent; }
  [data-testid="stToolbar"], [data-testid="stDecoration"] { display: none; }
  #MainMenu, footer { visibility: hidden; }

  .block-container {
    padding-top: 1.15rem; padding-bottom: 3rem; max-width: 1500px;
  }

  /* ---------- header ---------- */
  .ht-header {
    display: flex; align-items: center; justify-content: space-between;
    flex-wrap: wrap; gap: 0.9rem;
    background: #ffffff; border: 1px solid var(--ht-border);
    border-radius: 14px; padding: 0.85rem 1.15rem; margin-bottom: 1rem;
    box-shadow: var(--ht-shadow);
  }
  .ht-brand { display: flex; align-items: center; gap: 0.75rem; }
  .ht-mark {
    width: 38px; height: 38px; border-radius: 11px; flex: 0 0 auto;
    display: grid; place-items: center;
    background: var(--ht-accent-soft); border: 1px solid #fed7aa;
  }
  .ht-title {
    font-size: 1.22rem; font-weight: 700; letter-spacing: -0.02em;
    color: var(--ht-ink); line-height: 1.2;
  }
  .ht-sub { font-size: 0.8rem; color: var(--ht-muted); margin-top: 0.1rem; }
  .ht-status { display: flex; align-items: center; gap: 0.7rem; flex-wrap: wrap; }
  .ht-meta { font-size: 0.78rem; color: var(--ht-muted); }

  .ht-pill {
    display: inline-flex; align-items: center; gap: 0.42rem;
    font-size: 0.75rem; font-weight: 600; padding: 0.3rem 0.7rem;
    border-radius: 999px; white-space: nowrap;
  }
  .ht-pill.ok  { background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; }
  .ht-pill.bad { background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }
  .ht-dot { width: 7px; height: 7px; border-radius: 50%; background: #10b981; }
  .ht-pill.ok .ht-dot { animation: ht-pulse 2.2s ease-out infinite; }
  .ht-pill.bad .ht-dot { background: #ef4444; animation: none; }
  @keyframes ht-pulse {
    0%   { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.5); }
    70%  { box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
    100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
  }

  /* ---------- KPI cards ---------- */
  div[data-testid="stMetric"] {
    background: #ffffff; border: 1px solid var(--ht-border);
    border-radius: 14px; padding: 0.8rem 0.95rem;
    box-shadow: var(--ht-shadow);
    transition: transform .16s ease, box-shadow .16s ease, border-color .16s ease;
  }
  div[data-testid="stMetric"]:hover {
    transform: translateY(-2px);
    box-shadow: var(--ht-shadow-hover);
    border-color: #cbd5e1;
  }
  div[data-testid="stMetricLabel"] p {
    font-size: 0.76rem !important; font-weight: 600;
    color: var(--ht-muted) !important; letter-spacing: 0.01em;
  }
  div[data-testid="stMetricValue"] {
    font-size: 1.55rem; color: var(--ht-ink); line-height: 1.25;
  }

  /* ---------- panels (st.container(border=False, key=...)) ---------- */
  [class*="st-key-panel-"] {
    background: #ffffff; border: 1px solid var(--ht-border);
    border-radius: 14px; padding: 0.95rem 1.1rem;
    box-shadow: var(--ht-shadow);
    transition: box-shadow .16s ease, border-color .16s ease;
  }
  [class*="st-key-panel-"]:hover {
    box-shadow: var(--ht-shadow-hover); border-color: #cbd5e1;
  }
  .ht-panel-head { margin-bottom: 0.55rem; }
  .ht-panel-title {
    font-size: 0.9rem; font-weight: 700; color: var(--ht-ink);
  }
  .ht-panel-sub { font-size: 0.75rem; color: var(--ht-muted); margin-top: 0.1rem; }

  /* ---------- tabs ---------- */
  button[data-baseweb="tab"] {
    font-weight: 600; color: var(--ht-muted); transition: color .15s ease;
  }
  button[data-baseweb="tab"]:hover { color: var(--ht-accent); }
  button[data-baseweb="tab"][aria-selected="true"] { color: var(--ht-accent); }
  div[data-baseweb="tab-highlight"] { background-color: var(--ht-accent); }

  /* ---------- buttons ---------- */
  .stButton > button {
    border-radius: 9px; font-weight: 600; border: 1px solid var(--ht-border);
    transition: all .15s ease;
  }
  .stButton > button:hover {
    border-color: var(--ht-accent); color: var(--ht-accent);
    background: var(--ht-accent-soft); transform: translateY(-1px);
  }
  .stButton > button[kind="primary"] { background: var(--ht-accent); border-color: var(--ht-accent); }
  .stButton > button[kind="primary"]:hover { background: #c2410c; border-color: #c2410c; color: #fff; }

  /* ---------- dataframe ---------- */
  div[data-testid="stDataFrame"] {
    border: 1px solid var(--ht-border); border-radius: 12px;
    overflow: hidden; box-shadow: var(--ht-shadow);
  }
  div[data-testid="stDataFrame"]:hover { box-shadow: var(--ht-shadow-hover); }

  /* ---------- incidents ---------- */
  .ht-inc-table {
    width: 100%; border-collapse: separate; border-spacing: 0;
    background: #ffffff; border: 1px solid var(--ht-border);
    border-radius: 14px; overflow: hidden; box-shadow: var(--ht-shadow);
    transition: box-shadow .16s ease, border-color .16s ease;
  }
  .ht-inc-table:hover { box-shadow: var(--ht-shadow-hover); border-color: #cbd5e1; }
  .ht-inc-table th {
    font-size: 0.7rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.06em; color: var(--ht-muted); text-align: left;
    padding: 0.55rem 0.85rem; background: #f8fafc;
    border-bottom: 1px solid var(--ht-border);
  }
  .ht-inc-table td {
    padding: 0.6rem 0.85rem; border-top: 1px solid #f1f5f9;
    font-size: 0.8rem; color: var(--ht-ink); vertical-align: middle;
  }
  .ht-inc-table tbody tr { transition: background .14s ease; }
  .ht-inc-table tbody tr:hover { background: #fff7ed; }
  .ht-inc-title { font-weight: 600; }
  .ht-inc-sub {
    font-size: 0.72rem; color: var(--ht-muted); margin-top: 0.12rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    max-width: 38ch;
  }
  .ht-inc-mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    color: #475569; font-size: 0.76rem;
  }
  .ht-badge {
    display: inline-flex; align-items: center; gap: 0.28rem;
    font-size: 0.68rem; font-weight: 700; padding: 0.16rem 0.5rem;
    border-radius: 999px; text-transform: capitalize; white-space: nowrap;
    border: 1px solid transparent;
  }
  .ht-badge.sev-low      { background: #f1f5f9; color: #475569; border-color: #e2e8f0; }
  .ht-badge.sev-medium   { background: #eff6ff; color: #1d4ed8; border-color: #bfdbfe; }
  .ht-badge.sev-high     { background: #fff7ed; color: #c2410c; border-color: #fed7aa; }
  .ht-badge.sev-critical { background: #fef2f2; color: #b91c1c; border-color: #fecaca; }
  .ht-badge.st-open           { background: #fffbeb; color: #b45309; border-color: #fde68a; }
  .ht-badge.st-under_review   { background: #eff6ff; color: #1d4ed8; border-color: #bfdbfe; }
  .ht-badge.st-resolved       { background: #ecfdf5; color: #047857; border-color: #a7f3d0; }
  .ht-badge.st-false_positive { background: #f8fafc; color: #64748b; border-color: #e2e8f0; }
  .ht-badge.new {
    background: var(--ht-accent-soft); color: #c2410c;
    border-color: #fed7aa; margin-left: 0.35rem;
  }
  .ht-badge.new .ht-dot {
    width: 6px; height: 6px; border-radius: 50%; background: #ea580c;
    animation: ht-pulse 2.2s ease-out infinite;
  }

  /* ---------- incident timeline ---------- */
  .ht-tl { display: flex; flex-direction: column; }
  .ht-tl-row {
    display: grid; grid-template-columns: 128px minmax(0, 1fr) 96px 90px;
    align-items: center; gap: 0.7rem;
    padding: 0.42rem 0.4rem; border-top: 1px solid #f1f5f9;
    font-size: 0.78rem; transition: background .14s ease;
  }
  .ht-tl-row:first-child { border-top: none; }
  .ht-tl-row:hover { background: #fff7ed; }
  .ht-tl-time { color: var(--ht-muted); font-variant-numeric: tabular-nums; }
  .ht-tl-type {
    color: var(--ht-ink); font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .ht-tl-source { color: #475569; font-size: 0.74rem; }
  .ht-tl-count {
    color: #475569; font-size: 0.74rem; text-align: right;
    font-variant-numeric: tabular-nums;
  }

  /* ---------- detail ---------- */
  .ht-detail {
    background: #ffffff; border: 1px solid var(--ht-border); border-radius: 14px;
    padding: 0.55rem 1.15rem; box-shadow: var(--ht-shadow);
  }
  .ht-kv { display: grid; grid-template-columns: minmax(120px, 190px) 1fr; gap: 0 1.1rem; }
  .ht-kv .ht-row { display: contents; }
  .ht-kv dt {
    font-size: 0.78rem; font-weight: 600; color: var(--ht-muted);
    padding: 0.42rem 0; border-top: 1px solid var(--ht-grid, #eef2f7);
  }
  .ht-kv dd {
    margin: 0; padding: 0.42rem 0; font-size: 0.82rem; color: var(--ht-ink);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    word-break: break-all; border-top: 1px solid #eef2f7;
    transition: color .12s ease;
  }
  .ht-kv .ht-row:hover dd { color: var(--ht-accent); }
  .ht-kv .ht-row:hover dt { color: var(--ht-ink); }
  .ht-null { color: #cbd5e1; font-style: italic; }

  /* ---------- bar lists ---------- */
  .ht-list { display: flex; flex-direction: column; gap: 0.55rem; }
  .ht-list-row {
    padding: 0.3rem 0.4rem; border-radius: 8px;
    transition: background .14s ease;
  }
  .ht-list-row:hover { background: #fff7ed; }
  .ht-list-head {
    display: flex; align-items: baseline; justify-content: space-between;
    gap: 0.6rem; margin-bottom: 0.3rem;
  }
  .ht-list-name {
    font-size: 0.78rem; color: #334155; overflow: hidden;
    text-overflow: ellipsis; white-space: nowrap;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  .ht-list-count {
    font-size: 0.78rem; font-weight: 700; color: var(--ht-muted);
    font-variant-numeric: tabular-nums;
  }
  .ht-list-track { height: 7px; border-radius: 999px; background: #f1f5f9; overflow: hidden; }
  .ht-list-fill { height: 7px; border-radius: 999px; transition: width .35s ease; }
  .ht-list-row:hover .ht-list-fill { filter: brightness(1.12) saturate(1.05); }

  /* ---------- latest events ---------- */
  .ht-latest { display: flex; flex-direction: column; }
  .ht-latest-row {
    display: grid;
    grid-template-columns: 10px 92px minmax(0, 1.2fr) 112px minmax(0, 1fr) 42px;
    align-items: center; gap: 0.7rem;
    padding: 0.45rem 0.4rem; border-radius: 8px;
    border-top: 1px solid #f1f5f9;
    font-size: 0.78rem; transition: background .14s ease;
  }
  .ht-latest-row:first-child { border-top: none; }
  .ht-latest-row:hover { background: #fff7ed; }
  .ht-src-dot { width: 8px; height: 8px; border-radius: 50%; }
  .ht-latest-time { color: var(--ht-muted); font-variant-numeric: tabular-nums; }
  .ht-latest-type {
    color: var(--ht-ink); font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .ht-latest-ip, .ht-latest-route {
    color: #475569; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .ht-latest-route { color: #64748b; }
  .ht-latest-status {
    text-align: right; font-weight: 700; color: var(--ht-muted);
    font-variant-numeric: tabular-nums;
  }
  .ht-latest-status.ok { color: #047857; }
  .ht-latest-status.warn { color: #b45309; }
  .ht-latest-status.bad { color: #b91c1c; }

  /* Vega paints the page colour behind the plot; panels are white */
  .stVegaLiteChart svg { background-color: #ffffff !important; }

  /* ---------- empty state ---------- */
  .ht-empty {
    padding: 2.2rem 1.4rem; text-align: center; border-radius: 14px;
    border: 1px dashed #cbd5e1; background: #ffffff;
  }
  .ht-empty-title { font-size: 0.98rem; font-weight: 700; color: var(--ht-ink); margin-bottom: 0.3rem; }
  .ht-empty-body { font-size: 0.85rem; color: var(--ht-muted); }

  /* ---------- sidebar ---------- */
  section[data-testid="stSidebar"] {
    background: #ffffff; border-right: 1px solid var(--ht-border);
  }
  section[data-testid="stSidebar"] .ht-brandline {
    font-size: 0.68rem; letter-spacing: 0.16em; text-transform: uppercase;
    color: #94a3b8; font-weight: 700;
  }
  section[data-testid="stSidebar"] h2 {
    font-size: 1.05rem; color: var(--ht-ink); margin: 0.1rem 0 0.9rem;
  }
  section[data-testid="stSidebar"] .ht-policy {
    font-size: 0.73rem; color: var(--ht-muted); line-height: 1.5;
    background: #f8fafc; border: 1px solid #eef2f7;
    border-radius: 10px; padding: 0.6rem 0.7rem;
  }
  section[data-testid="stSidebar"] .ht-policy strong { color: var(--ht-ink); }
  section[data-testid="stSidebar"] code { font-size: 0.72rem; }
</style>
"""


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def _inject_css() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def _panel(title: str, subtitle: str = "") -> None:
    """Panel heading. The card itself is the st.container with `key=...`."""
    st.markdown(
        f'<div class="ht-panel-head"><div class="ht-panel-title">{html.escape(title)}</div>'
        + (f'<div class="ht-panel-sub">{html.escape(subtitle)}</div>' if subtitle else "")
        + "</div>",
        unsafe_allow_html=True,
    )


def _parse_timestamp(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _short_timestamp(value) -> str:
    parsed = _parse_timestamp(value)
    return parsed.strftime("%Y-%m-%d %H:%M:%S") if parsed else "-"


def _source_color(name: str) -> str:
    if name in SOURCE_COLORS:
        return SOURCE_COLORS[name]
    known = [source for source in SOURCES if source in SOURCE_COLORS]
    extra = [source for source in SOURCES if source not in SOURCE_COLORS]
    for index, source in enumerate(extra):
        if source == name:
            return FALLBACK_COLORS[index % len(FALLBACK_COLORS)]
    return FALLBACK_COLORS[len(known) % len(FALLBACK_COLORS)]


def _counts(rows: list, key: str) -> dict:
    counts: dict = {}
    for row in rows:
        value = row.get(key)
        if value:
            counts[value] = counts.get(value, 0) + 1
    return counts


def _bucket(points: list, span: timedelta) -> tuple:
    """Choose a bucket size from the data span and truncate each timestamp."""
    if span <= timedelta(hours=3):
        step, label = "minute", "%H:%M"
        truncate = lambda moment: moment.replace(second=0, microsecond=0)  # noqa: E731
    elif span <= timedelta(days=3):
        step, label = "hour", "%d %b %H:%M"
        truncate = lambda moment: moment.replace(minute=0, second=0, microsecond=0)  # noqa: E731
    else:
        step, label = "day", "%d %b"
        truncate = lambda moment: moment.replace(hour=0, minute=0, second=0, microsecond=0)  # noqa: E731

    buckets: dict = {}
    for moment, source in points:
        key = (truncate(moment), source)
        buckets[key] = buckets.get(key, 0) + 1

    records = [
        {
            "label": moment.strftime(label),
            "time": moment.isoformat(),
            "source": source,
            "count": count,
        }
        for (moment, source), count in sorted(buckets.items())
    ]
    return records, step


# --------------------------------------------------------------------------
# charts
# --------------------------------------------------------------------------
def _style_chart(chart):
    return (
        chart.configure_view(strokeOpacity=0)
        .configure_axis(
            labelColor=MUTED,
            labelFontSize=11,
            titleColor=MUTED,
            titleFontSize=11,
            gridColor=GRID,
            domainColor=BORDER,
            tickColor=BORDER,
        )
        .configure_legend(labelColor=MUTED, titleColor=MUTED, labelFontSize=11, symbolSize=90)
    )


def _data(records: list):
    """Altair 6 wants an explicit inline-data object, not a bare list."""
    return alt.Data(values=records)


def _timeline_chart(rows: list):
    points = []
    for row in rows:
        moment = _parse_timestamp(row.get("event_timestamp"))
        if moment is not None:
            points.append((moment, row.get("source") or "unknown"))
    if not points:
        return None, None

    moments = [moment for moment, _ in points]
    records, step = _bucket(points, max(moments) - min(moments))

    sources = sorted({record["source"] for record in records})
    color_range = [_source_color(source) for source in sources]
    peak = max(record["count"] for record in records)
    # Chronological order, de-duplicated: two sources can share a bucket label.
    labels = list(dict.fromkeys(record["label"] for record in records))

    chart = (
        alt.Chart(_data(records))
        .mark_bar(cornerRadiusTopLeft=3, cornerRadiusTopRight=3)
        .encode(
            x=alt.X(
                "label:N",
                sort=labels,
                title=None,
                scale=alt.Scale(paddingInner=0.55, paddingOuter=0.15),
                axis=alt.Axis(labelAngle=0, labelFontSize=10, tickSize=0, grid=False),
            ),
            y=alt.Y(
                "count:Q",
                title=None,
                scale=alt.Scale(domain=[0, peak * 1.2]),
                axis=alt.Axis(
                    format="d", tickMinStep=1, grid=True, tickSize=0, domainOpacity=0
                ),
            ),
            color=alt.Color(
                "source:N",
                title=None,
                scale=alt.Scale(domain=sources, range=color_range),
                legend=alt.Legend(orient="top", direction="horizontal", offset=4),
            ),
            tooltip=[
                alt.Tooltip("time:T", title="Bucket", format="%Y-%m-%d %H:%M"),
                alt.Tooltip("source:N", title="Source"),
                alt.Tooltip("count:Q", title="Events"),
            ],
        )
        .properties(height=150)
    )
    return _style_chart(chart), f"1 bar = 1 {step}"


def _short_type(name: str) -> str:
    """Drop the redundant source prefix: 'cowrie.login.failed' -> 'login.failed'."""
    for source in SOURCES:
        prefix = f"{source}."
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def _bar_records(counts: dict, limit: int = 6, shorten: bool = False) -> list:
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    return [
        {
            "name": name,
            "label": _short_type(name) if shorten else name,
            "count": count,
        }
        for name, count in ordered
    ]


def _bar_list(records: list, colored: bool = False) -> None:
    """Horizontal bar list. Full-width tracks, so nothing can collapse or clip."""
    if not records:
        st.caption("No data yet.")
        return

    peak = max(record["count"] for record in records)
    rows = []
    for record in records:
        width = max(4, round(record["count"] * 100 / peak, 1))
        color = _source_color(record["name"]) if colored else "#ea580c"
        rows.append(
            f'<div class="ht-list-row" title="{html.escape(record["name"])}'
            f' &mdash; {record["count"]} event(s)">'
            '<div class="ht-list-head">'
            f'<span class="ht-list-name">{html.escape(record["label"])}</span>'
            f'<span class="ht-list-count">{record["count"]}</span>'
            "</div>"
            '<div class="ht-list-track">'
            f'<div class="ht-list-fill" style="width:{width}%;background:{color}"></div>'
            "</div>"
            "</div>"
        )
    st.markdown(f'<div class="ht-list">{"".join(rows)}</div>', unsafe_allow_html=True)


def _latest_events(rows: list, limit: int = 5) -> None:
    ordered = sorted(
        rows,
        key=lambda row: _parse_timestamp(row.get("event_timestamp"))
        or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )[:limit]

    if not ordered:
        st.caption("No events yet.")
        return

    items = []
    for row in ordered:
        moment = _parse_timestamp(row.get("event_timestamp"))
        stamp = moment.strftime("%d %b %H:%M:%S") if moment else "-"
        status = row.get("status_code")
        status_class = ""
        if isinstance(status, int):
            status_class = (
                "ok" if status < 400 else ("warn" if status < 500 else "bad")
            )
        items.append(
            '<div class="ht-latest-row">'
            f'<span class="ht-src-dot" style="background:{_source_color(row.get("source") or "")}"></span>'
            f'<span class="ht-latest-time">{html.escape(stamp)}</span>'
            f'<span class="ht-latest-type">{html.escape(str(row.get("event_type") or "-"))}</span>'
            f'<span class="ht-latest-ip">{html.escape(str(row.get("src_ip") or "-"))}</span>'
            f'<span class="ht-latest-route">{html.escape(str(row.get("route") or "-"))}</span>'
            f'<span class="ht-latest-status {status_class}">'
            f'{"" if status is None else html.escape(str(status))}'
            "</span>"
            "</div>"
        )
    st.markdown(f'<div class="ht-latest">{"".join(items)}</div>', unsafe_allow_html=True)


def _bar_records(counts: dict, limit: int = 7, shorten: bool = False) -> list:
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    return [
        {
            "name": name,
            "label": _short_type(name) if shorten else name,
            "count": count,
        }
        for name, count in ordered
    ]


# --------------------------------------------------------------------------
# sidebar / state
# --------------------------------------------------------------------------
def _sidebar_filters() -> dict:
    """Render the sidebar and return the filter dict passed to fetch_events."""
    st.sidebar.markdown('<div class="ht-brandline">HoneyTrace</div>', unsafe_allow_html=True)
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
        since_time = since_col.time_input(
            "Since time", value=datetime.min.time(), label_visibility="collapsed"
        )
        until_date = until_col.date_input("Until date", value=today + timedelta(days=1))
        until_time = until_col.time_input(
            "Until time", value=datetime.min.time(), label_visibility="collapsed"
        )

        since = datetime.combine(since_date, since_time, tzinfo=timezone.utc).isoformat()
        until = datetime.combine(until_date, until_time, tzinfo=timezone.utc).isoformat()

    if st.sidebar.button("Refresh data", type="primary", width="stretch"):
        st.session_state.loaded = False
        st.session_state.pages = []
        st.session_state.next_cursor = None
        st.session_state.detail = None

    st.sidebar.divider()
    st.sidebar.markdown(
        f'<div class="ht-policy"><strong>Endpoint</strong><br>'
        f"<code>{html.escape(api_base_url())}</code><br><br>"
        f"<strong>Read-only</strong><br>{APPROVED_FIELD_COUNT} approved fields. "
        "No raw_event, metadata, command, message or username.</div>",
        unsafe_allow_html=True,
    )

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
            "Check that the API is running and reachable from here."
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


# --------------------------------------------------------------------------
# page sections
# --------------------------------------------------------------------------
def _header(connected: bool, rows: list) -> None:
    pill = (
        '<span class="ht-pill ok"><span class="ht-dot"></span>API connected</span>'
        if connected
        else '<span class="ht-pill bad"><span class="ht-dot"></span>API unreachable</span>'
    )
    latest = max((_short_timestamp(row.get("event_timestamp")) for row in rows), default="-")
    meta = (
        f'<span class="ht-meta">Last event {html.escape(latest)} UTC</span>'
        if rows
        else '<span class="ht-meta">No events loaded</span>'
    )

    st.markdown(
        '<div class="ht-header">'
        '<div class="ht-brand">'
        '<div class="ht-mark">'
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">'
        '<path d="M12 2.6l8.2 4.7v9.4L12 21.4 3.8 16.7V7.3L12 2.6z" '
        'fill="#ea580c" fill-opacity="0.12" stroke="#ea580c" stroke-width="1.5" '
        'stroke-linejoin="round"/>'
        '<circle cx="12" cy="12" r="2.4" fill="#ea580c"/>'
        "</svg>"
        "</div>"
        "<div>"
        '<div class="ht-title">HoneyTrace AI</div>'
        '<div class="ht-sub">Read-only console &middot; Cowrie and Juice Shop events</div>'
        "</div>"
        "</div>"
        f'<div class="ht-status">{pill}{meta}</div>'
        "</div>",
        unsafe_allow_html=True,
    )


def _metrics(rows: list) -> None:
    sessions = {row.get("session_id") for row in rows if row.get("session_id")}
    ips = {row.get("src_ip") for row in rows if row.get("src_ip")}
    types = {row.get("event_type") for row in rows if row.get("event_type")}

    col1, col2, col3, col4 = st.columns(4, gap="small")
    col1.metric("Events", len(rows), help="Events in the current page set")
    col2.metric("Sessions", len(sessions), help="Distinct session_id values")
    col3.metric("Source IPs", len(ips), help="Distinct client addresses. Not an identity.")
    col4.metric("Event types", len(types), help="Distinct event_type values")


def _render_detail(event_id: str) -> None:
    detail = st.session_state.detail
    if detail is None or detail.get("event_id") != event_id:
        try:
            detail = fetch_event(event_id)
        except ApiError as exc:
            _show_api_error(exc)
            return
        st.session_state.detail = detail

    st.markdown("#### Event detail")
    st.caption(
        f"Exactly {APPROVED_FIELD_COUNT} approved fields. "
        "raw_event, metadata, command, message and username are never exposed."
    )

    items = []
    for name, value in detail.items():
        shown = (
            '<span class="ht-null">null</span>'
            if value is None or value == ""
            else html.escape(str(value))
        )
        items.append(
            f'<div class="ht-row"><dt>{html.escape(str(name))}</dt><dd>{shown}</dd></div>'
        )

    st.markdown(
        f'<div class="ht-detail"><dl class="ht-kv">{"".join(items)}</dl></div>',
        unsafe_allow_html=True,
    )

    with st.expander("Raw JSON (same 13 fields)"):
        st.json(detail)


def _empty_state(title: str, body: str) -> None:
    st.markdown(
        f'<div class="ht-empty"><div class="ht-empty-title">{html.escape(title)}</div>'
        f'<div class="ht-empty-body">{html.escape(body)}</div></div>',
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------------
# incidents
# --------------------------------------------------------------------------
def _incident_badges(incident: dict) -> str:
    severity = str(incident.get("severity") or "")
    status_value = str(incident.get("status") or "")
    badges = [
        f'<span class="ht-badge sev-{html.escape(severity)}">'
        f"{html.escape(severity)}</span>",
        f'<span class="ht-badge st-{html.escape(status_value)}">'
        f'{html.escape(status_value.replace("_", " "))}</span>',
    ]
    if incident.get("has_new_evidence"):
        badges.append(
            '<span class="ht-badge new"><span class="ht-dot"></span>new evidence</span>'
        )
    return "".join(badges)


def _incident_metrics(items: list) -> None:
    open_count = sum(1 for item in items if item.get("status") == "open")
    new_count = sum(1 for item in items if item.get("has_new_evidence"))
    urgent = sum(1 for item in items if item.get("severity") in ("high", "critical"))

    col1, col2, col3, col4 = st.columns(4, gap="small")
    col1.metric("Incidents", len(items), help="Incidents on this page")
    col2.metric("Open", open_count, help="status = open")
    col3.metric(
        "New evidence", new_count, help="Not yet acknowledged by an analyst"
    )
    col4.metric("High or critical", urgent, help="Severity high or critical")


def _incidents_table(items: list) -> None:
    rows = []
    for incident in items:
        title = str(incident.get("title") or "-")
        summary = str(incident.get("summary") or "")
        rows.append(
            "<tr>"
            f'<td><div class="ht-inc-title">{html.escape(title)}</div>'
            f'<div class="ht-inc-sub" title="{html.escape(summary)}">'
            f"{html.escape(summary)}</div></td>"
            f"<td>{_incident_badges(incident)}</td>"
            f'<td class="ht-inc-mono">{html.escape(str(incident.get("source") or "-"))}</td>'
            f'<td class="ht-inc-mono">{html.escape(str(incident.get("session_id") or "-"))}</td>'
            f'<td class="ht-inc-mono">{html.escape(_short_timestamp(incident.get("updated_at")))}</td>'
            "</tr>"
        )

    st.markdown(
        '<table class="ht-inc-table"><thead><tr>'
        "<th>Incident</th><th>Severity &amp; status</th><th>Source</th>"
        "<th>Session</th><th>Updated (UTC)</th>"
        f'</tr></thead><tbody>{"".join(rows)}</tbody></table>',
        unsafe_allow_html=True,
    )


def _incident_timeline(entries: list) -> None:
    if not entries:
        st.caption("No timeline entries.")
        return

    rows = []
    for entry in entries:
        moment = _parse_timestamp(entry.get("timestamp"))
        stamp = moment.strftime("%d %b %H:%M:%S") if moment else "-"
        detections = len(entry.get("detection_ids") or [])
        rows.append(
            '<div class="ht-tl-row">'
            f'<span class="ht-tl-time">{html.escape(stamp)}</span>'
            f'<span class="ht-tl-type">{html.escape(str(entry.get("event_type") or "-"))}</span>'
            f'<span class="ht-tl-source">{html.escape(str(entry.get("source") or "-"))}</span>'
            f'<span class="ht-tl-count">{detections} detection(s)</span>'
            "</div>"
        )
    st.markdown(f'<div class="ht-tl">{"".join(rows)}</div>', unsafe_allow_html=True)


def _incident_detail(incident: dict) -> None:
    st.markdown("#### Incident detail")

    items = []
    for name in (
        "incident_id",
        "source",
        "session_id",
        "severity",
        "status",
        "has_new_evidence",
        "created_at",
        "updated_at",
    ):
        value = incident.get(name)
        shown = (
            '<span class="ht-null">null</span>'
            if value is None or value == ""
            else html.escape(str(value))
        )
        items.append(
            f'<div class="ht-row"><dt>{html.escape(name)}</dt><dd>{shown}</dd></div>'
        )
    st.markdown(
        f'<div class="ht-detail"><dl class="ht-kv">{"".join(items)}</dl></div>',
        unsafe_allow_html=True,
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
    with st.container(key="panel-incident-timeline"):
        _panel("Timeline", "Ordered as written by the correlator")
        _incident_timeline(incident.get("timeline") or [])


def _incidents_tab() -> None:
    col1, col2, col3 = st.columns(3, gap="small")
    source_choice = col1.selectbox("Source", ("all", *SOURCES), key="incident_source")
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

    try:
        page = fetch_incidents(limit=50, **filters)
    except ApiError as exc:
        code = str(exc)
        title, body = INCIDENT_REASONS.get(
            code,
            (
                "The incident API is not available",
                f"The API returned {exc.status_code or 'no status'}: {code}",
            ),
        )
        _empty_state(title, body)
        if code:
            st.caption(f"API reason: {code}")
        return

    items = page.get("items") or []
    if not items:
        _empty_state(
            "No incidents yet",
            "No detection rule has produced an incident. Incidents appear once "
            "the engine writes a session with detections and the correlator groups "
            "it by (source, session_id).",
        )
        return

    _incident_metrics(items)
    st.write("")
    _incidents_table(items)
    st.caption(f"{len(items)} incident(s) loaded.")
    if page.get("next_cursor"):
        st.caption("More incidents match. Narrow the filters to see them.")

    st.write("")
    options = [incident.get("incident_id") for incident in items]
    labels = {
        incident.get("incident_id"): (
            f"{incident.get('title') or 'incident'} — {incident.get('session_id') or '-'}"
        )
        for incident in items
    }
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
        _show_api_error(exc)
        return

    st.divider()
    _incident_detail(detail)


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
    rows = [row for page in st.session_state.pages for row in page]
    _header(connected, rows)

    if st.session_state.error is not None:
        _show_api_error(st.session_state.error)
        if st.button("Retry"):
            st.session_state.loaded = False
            st.rerun()
        return

    tab_overview, tab_events, tab_incidents = st.tabs(["Overview", "Events", "Incidents"])

    with tab_overview:
        _metrics(rows)

        if not rows:
            st.write("")
            _empty_state(
                "No events collected yet",
                "Run a collector to populate the database, then press Refresh data.",
            )
        else:
            st.write("")
            with st.container(key="panel-timeline"):
                chart, note = _timeline_chart(rows)
                _panel("Events over time", f"Stacked by source, UTC. {note}." if note else "")
                if chart is not None:
                    st.altair_chart(chart, width="stretch", theme=None)
                else:
                    st.caption("No parseable timestamps in this page.")

            st.write("")
            left, right = st.columns(2, gap="medium")
            with left:
                with st.container(key="panel-types"):
                    _panel("Top event types", "Source prefix omitted; hover for the full name")
                    _bar_list(_bar_records(_counts(rows, "event_type"), shorten=True))
            with right:
                with st.container(key="panel-sources"):
                    _panel("Events by source", "Colour matches the timeline")
                    _bar_list(_bar_records(_counts(rows, "source")), colored=True)
                st.write("")
                with st.container(key="panel-ips"):
                    _panel("Top source IPs", "Distinct clients, not identities")
                    _bar_list(_bar_records(_counts(rows, "src_ip"), limit=4))

            st.write("")
            with st.container(key="panel-latest"):
                _panel("Latest events", "Newest first, from the loaded page")
                _latest_events(rows)

    with tab_events:
        if not rows:
            _empty_state(
                "No events collected yet",
                "Run a collector to populate the database, then press Refresh data.",
            )
        else:
            selection = st.dataframe(
                [
                    {
                        COLUMN_LABELS[column]: (
                            _short_timestamp(row.get(column))
                            if column == "event_timestamp"
                            else ("" if row.get(column) is None else row.get(column))
                        )
                        for column in DISPLAY_COLUMNS
                    }
                    for row in rows
                ],
                hide_index=True,
                width="stretch",
                on_select="rerun",
                selection_mode="single-row",
                column_config={
                    "Timestamp (UTC)": st.column_config.TextColumn(width="medium"),
                    "Event type": st.column_config.TextColumn(width="large"),
                    "Route": st.column_config.TextColumn(width="medium"),
                    "Status": st.column_config.TextColumn(width="small"),
                },
            )

            st.caption(f"{len(rows)} event(s) loaded. Select a row to see all 13 fields.")

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
        _incidents_tab()


if __name__ == "__main__":
    main()
