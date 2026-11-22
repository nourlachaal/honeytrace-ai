"""Reusable dashboard components: header, KPI cards, panels, badges, states."""

from __future__ import annotations

import html
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator

import streamlit as st

from src.dashboard import theme
from src.dashboard.api_client import ApiError, api_base_url


# --------------------------------------------------------------------------
# time helpers
# --------------------------------------------------------------------------
def parse_timestamp(value) -> datetime | None:
    """Parse an ISO-8601 timestamp into an aware UTC datetime, or ``None``."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def short_timestamp(value) -> str:
    parsed = parse_timestamp(value)
    return parsed.strftime("%Y-%m-%d %H:%M:%S") if parsed else "-"


def clock(value: datetime | None) -> str:
    if value is None:
        return "-"
    return value.astimezone(timezone.utc).strftime("%H:%M:%S")


def updated_ago(value: datetime | None) -> str:
    """Human age of the last refresh, e.g. ``12s ago``."""
    if value is None:
        return "not refreshed"
    seconds = int(max(0, (datetime.now(timezone.utc) - value).total_seconds()))
    if seconds < 2:
        return "just now"
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    return f"{seconds // 3600}h ago"


# --------------------------------------------------------------------------
# shell
# --------------------------------------------------------------------------
def inject_css() -> None:
    st.markdown(theme.CSS, unsafe_allow_html=True)


def page_header(
    connected: bool,
    last_event: str | None,
) -> None:
    """Sticky application header, identical on every section."""
    pill = (
        '<span class="ht-pill ok"><span class="ht-dot"></span>API connected</span>'
        if connected
        else '<span class="ht-pill bad"><span class="ht-dot"></span>API unreachable</span>'
    )
    last_event_text = (
        f"Last event <strong>{html.escape(last_event)}</strong> UTC"
        if last_event
        else "No events loaded"
    )

    st.markdown(
        '<div class="ht-header">'
        '<div class="ht-brand">'
        '<div class="ht-mark">'
        '<svg width="21" height="21" viewBox="0 0 24 24" fill="none" aria-hidden="true">'
        '<path d="M12 2.6l8.2 4.7v9.4L12 21.4 3.8 16.7V7.3L12 2.6z" '
        'fill="#EA580C" fill-opacity="0.14" stroke="#EA580C" stroke-width="1.5" '
        'stroke-linejoin="round"/>'
        '<circle cx="12" cy="12" r="2.4" fill="#EA580C"/>'
        "</svg>"
        "</div>"
        "<div>"
        '<div class="ht-title">HoneyTrace AI</div>'
        '<div class="ht-sub">Security Monitoring &amp; Incident Investigation</div>'
        "</div>"
        "</div>"
        f'<div class="ht-status">{pill}'
        f'<span class="ht-meta">{last_event_text}</span>'
        "</div>"
        "</div>",
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------------
# KPI cards
# --------------------------------------------------------------------------
def _kpi_icon_rule(key: str, icon_name: str) -> str:
    uri = theme.icon_data_uri(icon_name, color=theme.FAINT, size=18)
    return (
        "<style>"
        f'[class*="st-key-kpi-{key}"] [data-testid="stMetricLabel"] p::before {{'
        'content: ""; display: inline-block; width: 16px; height: 16px;'
        "margin-right: 7px; vertical-align: -3px;"
        f'background: url("{uri}") no-repeat center / contain; opacity: .9;'
        "}"
        "</style>"
    )


def sparkline(
    values: list[int],
    color: str = theme.ACCENT,
    width: int = 86,
    height: int = 22,
) -> str:
    """Tiny inline SVG sparkline. No external assets."""
    series = [int(value) for value in values] or [0]
    peak = max(series) or 1
    count = len(series)
    points = []
    for index, value in enumerate(series):
        ratio = index / (count - 1) if count > 1 else 0.5
        x = 2 + (width - 4) * ratio
        y = height - 2 - (height - 4) * (value / peak)
        points.append((round(x, 1), round(y, 1)))
    line = " ".join(f"{x},{y}" for x, y in points)
    area = f"2,{height - 1} " + line + f" {width - 2},{height - 1}"
    return (
        f'<svg class="ht-spark" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" aria-hidden="true">'
        f'<polygon points="{area}" fill="{color}" fill-opacity="0.12"/>'
        f'<polyline points="{line}" fill="none" stroke="{color}" '
        'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>'
        "</svg>"
    )


def _delta_html(delta: int | None) -> str:
    if delta is None:
        return ""
    if delta > 0:
        return f'<span class="ht-delta up">&#9650; {delta}</span>'
    if delta < 0:
        return f'<span class="ht-delta down">&#9660; {abs(delta)}</span>'
    return '<span class="ht-delta flat">&#8226; 0</span>'


def kpi_card(
    key: str,
    label: str,
    value,
    icon_name: str,
    help_text: str | None = None,
    spark: list[int] | None = None,
    delta: int | None = None,
) -> None:
    """One KPI card: native metric plus sparkline / delta in the same card."""
    with st.container(key=f"kpi-{key}"):
        st.metric(label, value, help=help_text)
        if spark is not None or delta is not None:
            foot = ""
            if spark is not None:
                foot += sparkline(spark)
            if delta is not None:
                foot += _delta_html(delta) + '<span class="ht-delta-label">vs prev.</span>'
            st.markdown(f'<div class="ht-kpi-foot">{foot}</div>', unsafe_allow_html=True)
    st.markdown(_kpi_icon_rule(key, icon_name), unsafe_allow_html=True)


def kpi_row(cards: list[dict]) -> None:
    with st.container(key="kpirow"):
        columns = st.columns(len(cards), gap="small")
        for column, card in zip(columns, cards):
            with column:
                kpi_card(
                    card["key"],
                    card["label"],
                    card["value"],
                    card.get("icon", "activity"),
                    card.get("help"),
                    card.get("spark"),
                    card.get("delta"),
                )


# --------------------------------------------------------------------------
# panels
# --------------------------------------------------------------------------
@contextmanager
def panel(
    key: str,
    title: str,
    subtitle: str = "",
    icon: str | None = None,
) -> Iterator[None]:
    """Card with a heading. The key must be unique on the page."""
    with st.container(key=f"panel-{key}"):
        mark = theme.icon_svg(icon, color=theme.FAINT) if icon else ""
        st.markdown(
            f'<div class="ht-panel-head"><div class="ht-panel-title">{mark}'
            f"{html.escape(title)}</div>"
            + (f'<div class="ht-panel-sub">{html.escape(subtitle)}</div>' if subtitle else "")
            + "</div>",
            unsafe_allow_html=True,
        )
        yield


def empty_state(
    title: str,
    body: str,
    icon: str = "hexagon",
    hint: str | None = None,
) -> None:
    hint_html = f'<div class="ht-empty-hint">{html.escape(hint)}</div>' if hint else ""
    st.markdown(
        f'<div class="ht-empty"><div class="ht-empty-icon">{theme.icon_svg(icon, size=24, color="#FDBA74")}</div>'
        f'<div class="ht-empty-title">{html.escape(title)}</div>'
        f'<div class="ht-empty-body">{html.escape(body)}</div>{hint_html}</div>',
        unsafe_allow_html=True,
    )


def skeleton() -> str:
    """Shimmer placeholder shown while the first page is fetched."""
    return (
        '<div class="ht-skeleton">'
        '<div class="ht-skel-line w40"></div>'
        '<div class="ht-skel-line w90"></div>'
        '<div class="ht-skel-line w70"></div>'
        '<div class="ht-skel-line w90"></div>'
        "</div>"
    )


def show_api_error(exc: ApiError) -> None:
    if exc.status_code is None:
        st.error(
            f"Cannot reach the API at {api_base_url()}. "
            "Check that the API is running and reachable from here."
        )
    else:
        st.error(f"API returned {exc.status_code}: {exc}")


# --------------------------------------------------------------------------
# badges and small pieces
# --------------------------------------------------------------------------
def severity_badge(severity: str | None) -> str:
    value = html.escape(str(severity or ""))
    return f'<span class="ht-badge sev-{value}">{value}</span>'


def status_badge(status: str | None) -> str:
    value = html.escape(str(status or ""))
    label = html.escape(str(status or "").replace("_", " "))
    return f'<span class="ht-badge st-{value}">{label}</span>'


def new_evidence_badge() -> str:
    return '<span class="ht-badge new"><span class="ht-dot"></span>new evidence</span>'


def badges(incident: dict) -> str:
    parts = [severity_badge(incident.get("severity")), status_badge(incident.get("status"))]
    if incident.get("has_new_evidence"):
        parts.append(new_evidence_badge())
    return "".join(parts)


def source_dot(source: str | None, size: int = 8) -> str:
    return (
        f'<span class="ht-src-dot" style="display:inline-block;width:{size}px;'
        f"height:{size}px;border-radius:50%;background:{theme.source_color(source)}\"></span>"
    )


def source_legend() -> None:
    chips = []
    for source, label in theme.SOURCE_LABELS.items():
        chips.append(
            '<span class="ht-legend-chip">'
            f'<span class="ht-legend-swatch" style="background:{theme.SOURCE_COLORS[source]}"></span>'
            f"{html.escape(label)}</span>"
        )
    st.markdown(f'<div class="ht-legend">{"".join(chips)}</div>', unsafe_allow_html=True)


def status_chip(status) -> str:
    if status is None:
        return '<span class="ht-status-chip none">-</span>'
    try:
        code = int(status)
    except (TypeError, ValueError):
        return f'<span class="ht-status-chip none">{html.escape(str(status))}</span>'
    css = "ok" if code < 400 else ("warn" if code < 500 else "bad")
    return f'<span class="ht-status-chip {css}">{code}</span>'


def kv_value(value) -> str:
    """Render a value for a key/value grid, marking empty values."""
    if value is None or value == "":
        return '<span class="ht-null">null</span>'
    return f'<span class="ht-id">{html.escape(str(value))}</span>'


def kv_grid(items: list[tuple[str, object]]) -> str:
    rows = "".join(
        f'<div class="ht-row"><dt>{html.escape(str(name))}</dt>'
        f"<dd>{kv_value(value)}</dd></div>"
        for name, value in items
    )
    return f'<div class="ht-detail"><dl class="ht-kv">{rows}</dl></div>'
