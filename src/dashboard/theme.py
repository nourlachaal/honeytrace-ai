"""Design tokens, global CSS and icon helpers for the HoneyTrace dashboard.

Dark, dense SOC console: quiet blue-slate surfaces with a single orange accent.
Every colour, radius and shadow used by the views comes from here.
"""

from __future__ import annotations

import urllib.parse

# --------------------------------------------------------------------------
# tokens
# --------------------------------------------------------------------------
BG = "#0A0F1C"
SURFACE = "#101828"
SURFACE_2 = "#152036"
BORDER = "#1D2A44"
GRID = "#16213A"

TEXT = "#E8EEFB"
MUTED = "#8A99B8"
FAINT = "#5B6A8A"

ACCENT = "#EA580C"
ACCENT_SOFT = "rgba(234, 88, 12, 0.12)"
ACCENT_GLOW = "rgba(234, 88, 12, 0.28)"

COWRIE = "#F97316"
JUICE = "#22D3EE"
GREEN = "#22C55E"
AMBER = "#F59E0B"
RED = "#EF4444"
BLUE = "#3B82F6"
SLATE = "#64748B"

SOURCE_COLORS = {"cowrie": COWRIE, "juice_shop": JUICE}
SOURCE_LABELS = {"cowrie": "Cowrie", "juice_shop": "Juice Shop"}
FALLBACK_COLORS = ("#A78BFA", "#2DD4BF", "#F472B6", "#94A3B8")

SEVERITY_COLORS = {
    "low": SLATE,
    "medium": BLUE,
    "high": AMBER,
    "critical": RED,
}
STATUS_COLORS = {
    "open": AMBER,
    "under_review": BLUE,
    "resolved": GREEN,
    "false_positive": SLATE,
}

NAV_ITEMS = ("Overview", "Events", "Incidents")

# --------------------------------------------------------------------------
# icons (inline SVG, no external assets)
# --------------------------------------------------------------------------
_ICON_PATHS = {
    "activity": '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    "terminal": (
        '<polyline points="4 17 10 11 4 5"/>'
        '<line x1="12" y1="19" x2="20" y2="19"/>'
    ),
    "globe": (
        '<circle cx="12" cy="12" r="10"/>'
        '<line x1="2" y1="12" x2="22" y2="12"/>'
        '<path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 '
        '15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>'
    ),
    "tags": (
        '<path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10'
        'l8.59 8.59a2 2 0 0 1 0 2.82z"/>'
        '<line x1="7" y1="7" x2="7.01" y2="7"/>'
    ),
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "shield-alert": (
        '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
        '<line x1="12" y1="8" x2="12" y2="12"/>'
        '<line x1="12" y1="16" x2="12.01" y2="16"/>'
    ),
    "alert": (
        '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 '
        '1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>'
        '<line x1="12" y1="9" x2="12" y2="13"/>'
        '<line x1="12" y1="17" x2="12.01" y2="17"/>'
    ),
    "folder": (
        '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 '
        '2-2h5l2 3h9a2 2 0 0 1 2 2z"/>'
    ),
    "plus-circle": (
        '<circle cx="12" cy="12" r="10"/>'
        '<line x1="12" y1="8" x2="12" y2="16"/>'
        '<line x1="8" y1="12" x2="16" y2="12"/>'
    ),
    "clock": (
        '<circle cx="12" cy="12" r="10"/>'
        '<polyline points="12 6 12 12 16 14"/>'
    ),
    "search": (
        '<circle cx="11" cy="11" r="8"/>'
        '<line x1="21" y1="21" x2="16.65" y2="16.65"/>'
    ),
    "layers": (
        '<polygon points="12 2 2 7 12 12 22 7 12 2"/>'
        '<polyline points="2 17 12 22 22 17"/>'
        '<polyline points="2 12 12 17 22 12"/>'
    ),
    "lock": (
        '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>'
        '<path d="M7 11V7a5 5 0 0 1 10 0v4"/>'
    ),
    "database": (
        '<ellipse cx="12" cy="5" rx="9" ry="3"/>'
        '<path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>'
        '<path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>'
    ),
    "plug": (
        '<path d="M12 22v-5"/>'
        '<path d="M9 8V2"/>'
        '<path d="M15 8V2"/>'
        '<path d="M18 8v3a6 6 0 0 1-12 0V8z"/>'
    ),
    "hexagon": (
        '<path d="M12 2.6l8.2 4.7v9.4L12 21.4 3.8 16.7V7.3L12 2.6z"/>'
        '<circle cx="12" cy="12" r="2.4"/>'
    ),
    "refresh": (
        '<polyline points="23 4 23 10 17 10"/>'
        '<polyline points="1 20 1 14 7 14"/>'
        '<path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10"/>'
        '<path d="M20.49 15a9 9 0 0 1-14.85 3.36L1 14"/>'
    ),
    "filter": '<polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/>',
}


def icon_svg(
    name: str,
    size: int = 18,
    color: str = "currentColor",
    stroke_width: float = 1.8,
) -> str:
    """Return one inline SVG icon. Unknown names fall back to ``activity``."""
    body = _ICON_PATHS.get(name, _ICON_PATHS["activity"])
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
        f'stroke="{color}" stroke-width="{stroke_width}" stroke-linecap="round" '
        f'stroke-linejoin="round" aria-hidden="true">{body}</svg>'
    )


def icon_data_uri(name: str, color: str = MUTED, size: int = 18) -> str:
    """Encode an icon as a CSS ``background-image`` data URI."""
    svg = icon_svg(name, size=size, color=color)
    return "data:image/svg+xml," + urllib.parse.quote(svg, safe="")


def source_color(name: str | None) -> str:
    """Stable colour for a telemetry source, with a deterministic fallback."""
    if name in SOURCE_COLORS:
        return SOURCE_COLORS[name]
    extra = [source for source in SOURCE_COLORS if source != name]
    return FALLBACK_COLORS[len(extra) % len(FALLBACK_COLORS)]


def source_label(name: str | None) -> str:
    """Human label for a source (``juice_shop`` -> ``Juice Shop``)."""
    if not name:
        return "Unknown"
    return SOURCE_LABELS.get(name, str(name))


def severity_color(severity: str | None) -> str:
    return SEVERITY_COLORS.get(str(severity or ""), SLATE)


def status_color(status: str | None) -> str:
    return STATUS_COLORS.get(str(status or ""), SLATE)


# --------------------------------------------------------------------------
# Altair theme (registered once by the app shell)
# --------------------------------------------------------------------------
def altair_theme() -> dict:
    return {
        "config": {
            "background": "transparent",
            "view": {"stroke": None, "continuousWidth": 400, "continuousHeight": 200},
            "axis": {
                "domain": False,
                "grid": True,
                "gridColor": GRID,
                "gridOpacity": 1,
                "labelColor": MUTED,
                "labelFontSize": 11,
                "titleColor": MUTED,
                "titleFontSize": 11,
                "tickColor": BORDER,
                "tickSize": 0,
            },
            "legend": {
                "labelColor": MUTED,
                "titleColor": MUTED,
                "labelFontSize": 11,
                "symbolSize": 90,
                "orient": "top",
                "direction": "horizontal",
            },
            "range": {"category": [COWRIE, JUICE]},
            "arc": {"stroke": SURFACE, "strokeWidth": 2},
            "area": {"opacity": 0.85},
            "text": {"color": TEXT},
        }
    }


def register_altair_theme() -> None:
    """Register and enable the dark chart theme (idempotent)."""
    import altair as alt

    if "honeytrace_dark" not in alt.theme.names():
        alt.theme.register("honeytrace_dark", enable=True)(altair_theme)
    else:
        alt.theme.enable("honeytrace_dark")


# --------------------------------------------------------------------------
# global stylesheet
# --------------------------------------------------------------------------
CSS = """
<style>
  :root {
    --bg: #0A0F1C;
    --surface: #101828;
    --surface-2: #152036;
    --border: #1D2A44;
    --grid: #16213A;
    --text: #E8EEFB;
    --muted: #8A99B8;
    --faint: #5B6A8A;
    --accent: #EA580C;
    --accent-glow: rgba(234, 88, 12, .28);
    --cowrie: #F97316;
    --juice: #22D3EE;
    --low: #64748B;
    --medium: #3B82F6;
    --high: #F59E0B;
    --critical: #EF4444;
    --open: #F59E0B;
    --under_review: #3B82F6;
    --resolved: #22C55E;
    --false_positive: #64748B;
    --radius: 14px;
    --radius-chip: 8px;
    --shadow: 0 1px 0 rgba(255,255,255,.03) inset, 0 8px 24px rgba(0,0,0,.35);
    --shadow-hover: 0 1px 0 rgba(255,255,255,.05) inset, 0 16px 38px rgba(0,0,0,.5);
    --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }

  /* ---------- page shell ---------- */
  [data-testid="stAppViewContainer"] {
    background:
      radial-gradient(900px 420px at 8% -8%, rgba(234, 88, 12, .08), transparent 60%),
      var(--bg);
    color: var(--text);
  }
  [data-testid="stHeader"] {
    visibility: hidden; background: transparent;
    height: 0; min-height: 0; padding: 0;
  }
  /* The sidebar re-open control lives inside Streamlit's header: keep it
     reachable even though the rest of the header is hidden. */
  [data-testid="stHeader"] [data-testid="stExpandSidebarButton"] {
    visibility: visible; position: fixed; top: 0.7rem; left: 0.7rem;
    z-index: 1000; display: flex; align-items: center; justify-content: center;
    width: 34px; height: 34px; border-radius: 9px;
    background: var(--surface); border: 1px solid var(--border);
    color: var(--text); box-shadow: var(--shadow);
  }
  [data-testid="stHeader"] [data-testid="stExpandSidebarButton"]:hover {
    border-color: rgba(234, 88, 12, .55); background: rgba(234, 88, 12, .1);
  }
  [data-testid="stDecoration"], [data-testid="stStatusWidget"],
  [data-testid="stToolbarActions"], [data-testid="stAppDeployButton"],
  #MainMenu, footer { display: none; }
  .block-container {
    padding-top: 1rem; padding-bottom: 3rem; max-width: 1500px;
    font-family: var(--sans);
  }
  body, p, span, div, label { color: var(--text); }
  a { color: var(--accent); }

  /* ---------- sticky header ---------- */
  .ht-header {
    position: sticky; top: 0.55rem; z-index: 60;
    display: flex; align-items: center; justify-content: space-between;
    flex-wrap: wrap; gap: 0.9rem;
    background: rgba(16, 24, 40, .78);
    backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px);
    border: 1px solid var(--border); border-radius: var(--radius);
    padding: 0.7rem 1.1rem; margin-bottom: 1rem;
    box-shadow: var(--shadow);
  }
  .ht-brand { display: flex; align-items: center; gap: 0.75rem; }
  .ht-mark {
    width: 38px; height: 38px; border-radius: 11px; flex: 0 0 auto;
    display: grid; place-items: center;
    background: rgba(234, 88, 12, .1);
    border: 1px solid rgba(234, 88, 12, .35);
    box-shadow: 0 0 18px rgba(234, 88, 12, .18);
  }
  .ht-title {
    font-size: 1.16rem; font-weight: 700; letter-spacing: -0.02em;
    color: var(--text); line-height: 1.2;
  }
  .ht-sub { font-size: 0.76rem; color: var(--muted); margin-top: 0.1rem; }
  .ht-status { display: flex; align-items: center; gap: 0.55rem; flex-wrap: wrap; }
  .ht-meta { font-size: 0.74rem; color: var(--muted); white-space: nowrap; }
  .ht-meta strong {
    color: var(--text); font-weight: 600; font-family: var(--mono);
    font-variant-numeric: tabular-nums;
  }

  .ht-pill {
    display: inline-flex; align-items: center; gap: 0.42rem;
    font-size: 0.72rem; font-weight: 700; padding: 0.28rem 0.68rem;
    border-radius: 999px; white-space: nowrap; border: 1px solid transparent;
  }
  .ht-pill.ok  { background: rgba(34,197,94,.1); color: #4ADE80; border-color: rgba(34,197,94,.32); }
  .ht-pill.bad { background: rgba(239,68,68,.1); color: #F87171; border-color: rgba(239,68,68,.32); }
  .ht-dot { width: 7px; height: 7px; border-radius: 50%; background: #22C55E; }
  .ht-pill.ok .ht-dot { animation: ht-pulse 2.4s ease-out infinite; }
  .ht-pill.bad .ht-dot { background: #EF4444; animation: none; }
  @keyframes ht-pulse {
    0%   { box-shadow: 0 0 0 0 rgba(34, 197, 94, .5); }
    70%  { box-shadow: 0 0 0 7px rgba(34, 197, 94, 0); }
    100% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0); }
  }

  /* ---------- page heading ---------- */
  .ht-page { margin: 0.15rem 0 0.9rem; }
  .ht-page-title {
    font-size: 1.45rem; font-weight: 700; color: var(--text);
    letter-spacing: -0.025em; line-height: 1.2;
  }
  .ht-page-sub { font-size: 0.79rem; color: var(--muted); margin-top: 0.15rem; }

  /* ---------- KPI cards ---------- */
  [class*="st-key-kpi-"] {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 0.85rem 1rem 0.7rem;
    box-shadow: var(--shadow);
    transition: transform .16s ease, box-shadow .16s ease, border-color .16s ease;
  }
  [class*="st-key-kpi-"]:hover {
    transform: translateY(-2px); box-shadow: var(--shadow-hover);
    border-color: rgba(234, 88, 12, .4);
  }
  div[data-testid="stMetric"] { background: transparent; border: none; padding: 0; box-shadow: none; }
  div[data-testid="stMetricLabel"] p {
    font-size: 0.68rem !important; font-weight: 700;
    color: var(--muted) !important; letter-spacing: 0.09em;
    text-transform: uppercase; white-space: normal !important;
    overflow: visible !important; text-overflow: clip !important;
    line-height: 1.3;
  }
  [data-testid="stMetricLabel"] { min-height: 1.9rem; align-items: flex-start; }
  [data-testid="stMetricLabel"] .stMarkdownEllipsis,
  [data-testid="stMetricLabel"] [data-testid="stMarkdownContainer"] {
    overflow: visible !important; white-space: normal !important;
    text-overflow: clip !important;
  }
  [data-testid="stMetricLabel"] > div { min-width: 0; }
  div[data-testid="stMetricValue"] {
    font-size: 2.05rem; font-weight: 700; color: var(--text);
    line-height: 1.15; font-variant-numeric: tabular-nums;
    letter-spacing: -0.02em;
  }
  div[data-testid="stMetricDelta"] { font-size: 0.72rem; }
  .ht-kpi-foot {
    display: flex; align-items: center; gap: 0.45rem;
    margin-top: 0.15rem; min-height: 22px;
  }
  .ht-spark { display: block; opacity: 0.95; }
  .ht-delta { font-size: 0.7rem; font-weight: 700; font-variant-numeric: tabular-nums; }
  .ht-delta.up { color: #4ADE80; }
  .ht-delta.down { color: #F87171; }
  .ht-delta.flat { color: var(--faint); }
  .ht-delta-label { font-size: 0.66rem; color: var(--faint); }

  /* ---------- panels ---------- */
  [class*="st-key-panel-"] {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 0.9rem 1.05rem;
    box-shadow: var(--shadow);
    transition: transform .16s ease, box-shadow .16s ease, border-color .16s ease;
  }
  [class*="st-key-panel-"]:hover {
    transform: translateY(-2px); box-shadow: var(--shadow-hover);
    border-color: rgba(234, 88, 12, .4);
  }
  .ht-panel-head { margin-bottom: 0.6rem; }
  .ht-panel-title {
    font-size: 0.86rem; font-weight: 700; color: var(--text);
    display: flex; align-items: center; gap: 0.45rem;
  }
  .ht-panel-title svg { color: var(--faint); }
  .ht-panel-sub { font-size: 0.72rem; color: var(--muted); margin-top: 0.12rem; }

  /* ---------- buttons ---------- */
  .stButton > button {
    border-radius: 9px; font-weight: 600; border: 1px solid var(--border);
    background: var(--surface-2); color: var(--text);
    transition: all .16s ease;
  }
  .stButton > button:hover {
    border-color: rgba(234, 88, 12, .55); color: var(--text);
    background: rgba(234, 88, 12, .1); transform: translateY(-1px);
  }
  .stButton > button[kind="primary"] {
    background: var(--accent); border-color: var(--accent); color: #FFF;
    box-shadow: 0 0 0 0 var(--accent-glow);
  }
  .stButton > button[kind="primary"]:hover {
    background: #F97316; border-color: #F97316; color: #FFF;
    box-shadow: 0 0 0 4px var(--accent-glow);
  }
  .stDownloadButton > button { border-radius: 9px; }

  /* ---------- sidebar ---------- */
  section[data-testid="stSidebar"] {
    background: var(--surface); border-right: 1px solid var(--border);
  }
  section[data-testid="stSidebar"] [data-testid="stSidebarContent"] {
    padding-top: 0.4rem;
  }
  .ht-side-brand {
    display: flex; align-items: center; gap: 0.6rem; margin: 0.15rem 0 1.1rem;
  }
  .ht-side-mark {
    width: 34px; height: 34px; border-radius: 10px; flex: 0 0 auto;
    display: grid; place-items: center;
    background: rgba(234, 88, 12, .1); border: 1px solid rgba(234, 88, 12, .35);
  }
  .ht-side-name {
    font-size: 0.93rem; font-weight: 700; color: var(--text);
    letter-spacing: -0.01em; line-height: 1.2;
  }
  .ht-side-sub { font-size: 0.68rem; color: var(--faint); }
  .ht-navlabel {
    font-size: 0.66rem; font-weight: 700; letter-spacing: 0.14em;
    text-transform: uppercase; color: var(--faint);
    margin: 0.2rem 0 0.5rem;
  }

  section[data-testid="stSidebar"] [data-testid="stRadioGroup"] {
    display: flex; flex-direction: column; gap: 3px;
  }
  section[data-testid="stSidebar"] [data-testid="stRadioGroup"] > div { width: 100%; }
  section[data-testid="stSidebar"] [data-testid="stRadioOption"] {
    display: flex; align-items: center; width: 100%;
    padding: 0.48rem 0.6rem; border-radius: 9px;
    border-left: 2px solid transparent;
    transition: background .14s ease, border-color .14s ease;
    cursor: pointer;
  }
  section[data-testid="stSidebar"] [data-testid="stRadioOption"]:hover {
    background: rgba(255, 255, 255, .035);
  }
  section[data-testid="stSidebar"] [data-testid="stRadioOption"][data-selected="true"] {
    background: rgba(234, 88, 12, .12);
    border-left-color: var(--accent);
    box-shadow: inset 0 0 18px rgba(234, 88, 12, .06);
  }
  section[data-testid="stSidebar"] [data-testid="stRadioOption"] p {
    color: var(--muted); font-size: 0.84rem; font-weight: 600; margin: 0;
  }
  section[data-testid="stSidebar"] [data-testid="stRadioOption"][data-selected="true"] p {
    color: #FDBA74; font-weight: 700;
  }
  section[data-testid="stSidebar"] [data-testid="stRadioOption"] > div > div:first-child {
    display: none;
  }

  section[data-testid="stSidebar"] .ht-policy {
    font-size: 0.71rem; color: var(--muted); line-height: 1.55;
    background: rgba(21, 32, 54, .5);
    border: 1px dashed rgba(138, 153, 184, .35);
    border-radius: 10px; padding: 0.65rem 0.75rem;
  }
  section[data-testid="stSidebar"] .ht-policy .ht-policy-head {
    display: flex; align-items: center; gap: 0.4rem;
    color: var(--text); font-weight: 700; margin-bottom: 0.35rem;
    font-size: 0.7rem; letter-spacing: 0.08em; text-transform: uppercase;
  }
  section[data-testid="stSidebar"] .ht-policy code {
    font-family: var(--mono); font-size: 0.69rem; color: #FDBA74;
    word-break: break-all;
  }
  section[data-testid="stSidebar"] code { font-family: var(--mono); }

  /* ---------- inputs ---------- */
  div[data-baseweb="select"] > div,
  div[data-baseweb="input"] > div,
  .stTextInput input, .stNumberInput input, .stTextArea textarea {
    background: var(--surface-2) !important;
    border-color: var(--border) !important;
    color: var(--text) !important;
    border-radius: 9px !important;
  }
  div[data-baseweb="select"] > div:focus-within,
  div[data-baseweb="input"] > div:focus-within,
  .stTextInput input:focus, .stTextArea textarea:focus {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 3px var(--accent-glow) !important;
  }
  div[data-baseweb="popover"] [role="listbox"] {
    background: var(--surface-2) !important;
    border: 1px solid var(--border) !important;
  }
  div[data-baseweb="popover"] [role="option"]:hover {
    background: rgba(234, 88, 12, .12) !important;
  }
  [data-testid="stSlider"] [role="slider"] {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 3px var(--accent-glow);
  }
  [data-testid="stCheckbox"] label span { color: var(--muted); }

  /* ---------- tabs (kept for any future tabbed surface) ---------- */
  .stTabs [data-baseweb="tab-list"] {
    gap: 1.4rem; border-bottom: 1px solid var(--border); background: transparent;
  }
  .stTabs [data-baseweb="tab"] {
    background: transparent; color: var(--muted); font-weight: 600;
    padding: 0.45rem 0.1rem; border: none;
  }
  .stTabs [data-baseweb="tab"]:hover { color: var(--text); }
  .stTabs [aria-selected="true"] {
    color: var(--text) !important;
    box-shadow: inset 0 -2px 0 var(--accent);
    text-shadow: 0 0 16px var(--accent-glow);
  }
  .stTabs [data-baseweb="tab-highlight"], .stTabs [data-baseweb="tab-border"] {
    display: none;
  }

  /* ---------- legend ---------- */
  .ht-legend { display: flex; align-items: center; gap: 0.9rem; flex-wrap: wrap; }
  .ht-legend-chip {
    display: inline-flex; align-items: center; gap: 0.4rem;
    font-size: 0.72rem; color: var(--muted); font-weight: 600;
  }
  .ht-legend-swatch { width: 9px; height: 9px; border-radius: 3px; }

  /* ---------- active filter chips ---------- */
  [class*="st-key-chip-"] button {
    min-height: 1.75rem; padding: 0.16rem 0.55rem;
    border-radius: 999px; font-size: 0.69rem; font-weight: 600;
    color: #FDBA74; background: rgba(234, 88, 12, .1);
    border-color: rgba(234, 88, 12, .35);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  [class*="st-key-chip-"] button:hover {
    background: rgba(234, 88, 12, .18);
    border-color: rgba(234, 88, 12, .55);
    transform: none;
  }

  /* ---------- dataframe ---------- */
  div[data-testid="stDataFrame"] {
    border: 1px solid var(--border); border-radius: 12px;
    overflow: hidden; box-shadow: var(--shadow);
    transition: border-color .16s ease, box-shadow .16s ease;
  }
  div[data-testid="stDataFrame"]:hover {
    border-color: rgba(234, 88, 12, .4); box-shadow: var(--shadow-hover);
  }
  div[data-testid="stDataFrameResizable"] { border-radius: 12px; }

  /* ---------- incident table ---------- */
  .ht-table-scroll { overflow-x: auto; border-radius: var(--radius); }
  .ht-inc-table {
    width: 100%; border-collapse: separate; border-spacing: 0;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); overflow: hidden; box-shadow: var(--shadow);
    transition: box-shadow .16s ease, border-color .16s ease;
  }
  .ht-inc-table:hover { box-shadow: var(--shadow-hover); border-color: rgba(234, 88, 12, .35); }
  .ht-inc-table th {
    font-size: 0.66rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.08em; color: var(--faint); text-align: left;
    padding: 0.55rem 0.85rem; background: rgba(21, 32, 54, .65);
    border-bottom: 1px solid var(--border); white-space: nowrap;
  }
  .ht-inc-table td {
    padding: 0.6rem 0.85rem; border-top: 1px solid var(--grid);
    font-size: 0.79rem; color: var(--text); vertical-align: middle;
  }
  .ht-inc-table tbody tr { transition: background .14s ease; }
  .ht-inc-table tbody tr:hover { background: rgba(234, 88, 12, .06); }
  .ht-inc-table tbody tr.is-new { background: rgba(234, 88, 12, .035); }
  .ht-inc-table tbody tr td:first-child { box-shadow: inset 3px 0 0 var(--low); }
  .ht-inc-table tbody tr.sev-low td:first-child      { box-shadow: inset 3px 0 0 var(--low); }
  .ht-inc-table tbody tr.sev-medium td:first-child   { box-shadow: inset 3px 0 0 var(--medium); }
  .ht-inc-table tbody tr.sev-high td:first-child     { box-shadow: inset 3px 0 0 var(--high); }
  .ht-inc-table tbody tr.sev-critical td:first-child {
    box-shadow: inset 3px 0 0 var(--critical), inset 12px 0 18px rgba(239, 68, 68, .12);
  }
  .ht-inc-title { font-weight: 600; color: var(--text); }
  .ht-inc-sub {
    font-size: 0.7rem; color: var(--muted); margin-top: 0.14rem;
    font-family: var(--mono);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    max-width: 46ch;
  }
  .ht-inc-mono { font-family: var(--mono); color: var(--muted); font-size: 0.74rem; }

  /* ---------- badges ---------- */
  .ht-badge {
    display: inline-flex; align-items: center; gap: 0.3rem;
    font-size: 0.66rem; font-weight: 700; padding: 0.16rem 0.52rem;
    border-radius: 999px; text-transform: capitalize; white-space: nowrap;
    border: 1px solid transparent; margin-right: 0.25rem;
  }
  .ht-badge.sev-low      { background: rgba(100,116,139,.14); color: #94A3B8; border-color: rgba(100,116,139,.4); }
  .ht-badge.sev-medium   { background: rgba(59,130,246,.14); color: #93C5FD; border-color: rgba(59,130,246,.4); }
  .ht-badge.sev-high     { background: rgba(245,158,11,.14); color: #FCD34D; border-color: rgba(245,158,11,.4); }
  .ht-badge.sev-critical {
    background: rgba(239,68,68,.16); color: #FCA5A5; border-color: rgba(239,68,68,.45);
    box-shadow: 0 0 12px rgba(239, 68, 68, .22);
  }
  .ht-badge.st-open           { background: rgba(245,158,11,.13); color: #FCD34D; border-color: rgba(245,158,11,.38); }
  .ht-badge.st-under_review   { background: rgba(59,130,246,.13); color: #93C5FD; border-color: rgba(59,130,246,.38); }
  .ht-badge.st-resolved       { background: rgba(34,197,94,.13); color: #86EFAC; border-color: rgba(34,197,94,.38); }
  .ht-badge.st-false_positive { background: rgba(100,116,139,.14); color: #94A3B8; border-color: rgba(100,116,139,.4); }
  .ht-badge.new {
    background: rgba(234,88,12,.14); color: #FDBA74;
    border-color: rgba(234,88,12,.42);
  }
  .ht-badge.new .ht-dot {
    width: 6px; height: 6px; border-radius: 50%; background: var(--accent);
    animation: ht-pulse-orange 1.8s ease-out infinite;
  }
  @keyframes ht-pulse-orange {
    0%   { box-shadow: 0 0 0 0 rgba(234, 88, 12, .55); }
    70%  { box-shadow: 0 0 0 6px rgba(234, 88, 12, 0); }
    100% { box-shadow: 0 0 0 0 rgba(234, 88, 12, 0); }
  }
  .ht-chip {
    display: inline-flex; align-items: center; gap: 0.25rem;
    font-size: 0.66rem; font-weight: 600; color: var(--muted);
    background: var(--surface-2); border: 1px solid var(--border);
    border-radius: var(--radius-chip); padding: 0.1rem 0.45rem;
    font-family: var(--mono); white-space: nowrap;
  }
  .ht-chip.ml-anomaly {
    color: #fbbf24;
    background: rgba(251, 191, 36, .12);
    border-color: rgba(251, 191, 36, .45);
  }
  .ht-chip.ml-crit-low {
    color: #93c5fd; background: rgba(147, 197, 253, .12);
    border-color: rgba(147, 197, 253, .4);
  }
  .ht-chip.ml-crit-medium {
    color: #38bdf8; background: rgba(56, 189, 248, .12);
    border-color: rgba(56, 189, 248, .45);
  }
  .ht-chip.ml-crit-high {
    color: #fb923c; background: rgba(251, 146, 60, .14);
    border-color: rgba(251, 146, 60, .5);
  }
  .ht-chip.ml-crit-critical {
    color: #f87171; background: rgba(248, 113, 113, .14);
    border-color: rgba(248, 113, 113, .55);
  }

  /* ---------- vertical timeline ---------- */
  .ht-vtl { position: relative; margin-left: 4px; padding-left: 20px; }
  .ht-vtl::before {
    content: ""; position: absolute; left: 5px; top: 6px; bottom: 6px;
    width: 1px; background: linear-gradient(var(--border), rgba(29,42,68,.25));
  }
  .ht-vtl-row {
    position: relative; display: grid;
    grid-template-columns: 118px minmax(0, 1fr) 96px 118px;
    align-items: center; gap: 0.6rem;
    padding: 0.42rem 0.35rem; border-radius: 7px;
    font-size: 0.76rem; transition: background .14s ease;
  }
  .ht-vtl-row:hover { background: rgba(234, 88, 12, .06); }
  .ht-vtl-row::before {
    content: ""; position: absolute; left: -19px; top: 50%;
    width: 9px; height: 9px; border-radius: 50%;
    background: var(--surface); border: 2px solid var(--accent);
    transform: translateY(-50%);
    box-shadow: 0 0 10px rgba(234, 88, 12, .35);
  }
  .ht-vtl-time {
    color: var(--muted); font-family: var(--mono);
    font-variant-numeric: tabular-nums; font-size: 0.7rem;
  }
  .ht-vtl-type {
    color: var(--text); font-family: var(--mono);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .ht-vtl-source {
    display: inline-flex; align-items: center; gap: 0.35rem;
    color: var(--muted); font-size: 0.72rem;
  }
  .ht-vtl-count { text-align: right; }

  /* ---------- detail ---------- */
  .ht-detail {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 0.55rem 1.1rem;
    box-shadow: var(--shadow);
  }
  .ht-kv { display: grid; grid-template-columns: minmax(130px, 200px) 1fr; gap: 0 1.1rem; }
  .ht-kv .ht-row { display: contents; }
  .ht-kv dt {
    font-size: 0.74rem; font-weight: 600; color: var(--muted);
    padding: 0.45rem 0; border-top: 1px solid var(--grid);
  }
  .ht-kv dd {
    margin: 0; padding: 0.45rem 0; font-size: 0.79rem; color: var(--text);
    font-family: var(--mono); word-break: break-all;
    border-top: 1px solid var(--grid); transition: color .12s ease;
  }
  .ht-kv .ht-row:hover dd { color: #FDBA74; background: rgba(234, 88, 12, .05); }
  .ht-kv .ht-row:hover dt { color: var(--text); }
  .ht-null { color: var(--faint); font-style: italic; }
  .ht-id { user-select: all; }

  /* ---------- bar lists ---------- */
  .ht-list { display: flex; flex-direction: column; gap: 0.6rem; }
  .ht-list-row { padding: 0.28rem 0.35rem; border-radius: 8px; transition: background .14s ease; }
  .ht-list-row:hover { background: rgba(234, 88, 12, .06); }
  .ht-list-head {
    display: flex; align-items: baseline; justify-content: space-between;
    gap: 0.6rem; margin-bottom: 0.32rem;
  }
  .ht-list-name {
    font-size: 0.75rem; color: var(--text); overflow: hidden;
    text-overflow: ellipsis; white-space: nowrap; font-family: var(--mono);
  }
  .ht-list-count {
    font-size: 0.74rem; font-weight: 700; color: var(--muted);
    font-variant-numeric: tabular-nums;
  }
  .ht-list-track { height: 6px; border-radius: 999px; background: var(--grid); overflow: hidden; }
  .ht-list-fill { height: 6px; border-radius: 999px; transition: width .35s ease; }
  .ht-list-row:hover .ht-list-fill { filter: brightness(1.15); }

  /* ---------- latest activity feed ---------- */
  .ht-feed { display: flex; flex-direction: column; gap: 2px; }
  .ht-feed-row {
    display: grid;
    grid-template-columns: 3px 88px minmax(0, 1.1fr) 108px minmax(0, 1fr) 52px;
    align-items: center; gap: 0.65rem;
    padding: 0.38rem 0.45rem 0.38rem 0;
    border-radius: 7px; border-top: 1px solid var(--grid);
    font-size: 0.76rem; transition: background .14s ease;
  }
  .ht-feed-row:first-child { border-top: none; animation: ht-fade .4s ease; }
  .ht-feed-row:hover { background: rgba(234, 88, 12, .06); }
  .ht-feed-stripe { width: 3px; height: 22px; border-radius: 2px; }
  .ht-feed-time {
    color: var(--muted); font-family: var(--mono);
    font-variant-numeric: tabular-nums; font-size: 0.7rem;
  }
  .ht-feed-type {
    color: var(--text); font-family: var(--mono);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .ht-feed-ip, .ht-feed-route {
    color: var(--muted); font-family: var(--mono);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .ht-feed-route { color: var(--faint); }
  .ht-feed-status { text-align: right; }
  .ht-status-chip {
    display: inline-flex; align-items: center; justify-content: center;
    min-width: 40px; padding: 0.08rem 0.35rem; border-radius: 6px;
    font-family: var(--mono); font-size: 0.68rem; font-weight: 700;
    border: 1px solid transparent;
  }
  .ht-status-chip.ok   { color: #86EFAC; background: rgba(34,197,94,.1); border-color: rgba(34,197,94,.3); }
  .ht-status-chip.warn { color: #FCD34D; background: rgba(245,158,11,.1); border-color: rgba(245,158,11,.3); }
  .ht-status-chip.bad  { color: #FCA5A5; background: rgba(239,68,68,.1); border-color: rgba(239,68,68,.3); }
  .ht-status-chip.none { color: var(--faint); background: transparent; border-color: transparent; }
  @keyframes ht-fade { from { opacity: 0; transform: translateY(-3px); } to { opacity: 1; transform: none; } }

  /* ---------- donut centre ---------- */
  [class*="st-key-donut-stage"] { position: relative; }
  .ht-donut-center {
    position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
    text-align: center; pointer-events: none; z-index: 2;
  }
  .ht-donut-total {
    font-size: 1.9rem; font-weight: 700; color: var(--text);
    line-height: 1; font-variant-numeric: tabular-nums;
  }
  .ht-donut-label {
    font-size: 0.62rem; color: var(--faint); text-transform: uppercase;
    letter-spacing: 0.12em; margin-top: 0.2rem;
  }

  /* ---------- empty state ---------- */
  .ht-empty {
    padding: 2.4rem 1.4rem; text-align: center; border-radius: var(--radius);
    border: 1px dashed rgba(138, 153, 184, .35);
    background: rgba(16, 24, 40, .7);
  }
  .ht-empty-icon {
    width: 46px; height: 46px; margin: 0 auto 0.8rem;
    display: grid; place-items: center; border-radius: 12px;
    background: rgba(234, 88, 12, .08);
    border: 1px solid rgba(234, 88, 12, .25);
    color: #FDBA74;
  }
  .ht-empty-title { font-size: 0.96rem; font-weight: 700; color: var(--text); margin-bottom: 0.35rem; }
  .ht-empty-body { font-size: 0.82rem; color: var(--muted); max-width: 62ch; margin: 0 auto; line-height: 1.55; }
  .ht-empty-hint { font-size: 0.74rem; color: var(--faint); margin-top: 0.6rem; font-family: var(--mono); }

  /* ---------- skeleton ---------- */
  .ht-skeleton {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 1rem 1.1rem; box-shadow: var(--shadow);
  }
  .ht-skel-line {
    height: 11px; border-radius: 6px; margin: 0.55rem 0;
    background: linear-gradient(90deg, #152036 25%, #1d2a44 37%, #152036 63%);
    background-size: 400% 100%;
    animation: ht-shimmer 1.4s ease infinite;
  }
  .ht-skel-line.w40 { width: 40%; }
  .ht-skel-line.w70 { width: 70%; }
  .ht-skel-line.w90 { width: 90%; }
  @keyframes ht-shimmer { 0% { background-position: 100% 50%; } 100% { background-position: 0 50%; } }

  /* Vega paints the page colour behind the plot; panels are dark */
  .stVegaLiteChart svg { background-color: transparent !important; }
  .stVegaLiteChart { background: transparent; }

  /* ---------- responsive ---------- */
  @media (max-width: 1100px) {
    .block-container { padding-left: 1rem; padding-right: 1rem; }
    .ht-feed-row { grid-template-columns: 3px 78px minmax(0, 1fr) 52px; }
    .ht-feed-ip, .ht-feed-route { display: none; }
    .ht-vtl-row { grid-template-columns: 104px minmax(0, 1fr) 90px; }
    .ht-vtl-count { display: none; }
  }
  @media (max-width: 900px) {
    [class*="st-key-kpirow"] [data-testid="stHorizontalBlock"] { flex-wrap: wrap; }
    [class*="st-key-kpirow"] [data-testid="stColumn"] {
      flex: 1 1 calc(50% - 0.5rem); min-width: calc(50% - 0.5rem);
    }
    .ht-header { flex-direction: column; align-items: flex-start; }
    .ht-kv { grid-template-columns: 1fr; }
  }

  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
      animation: none !important; transition: none !important;
    }
  }
</style>
"""


# --------------------------------------------------------------------------
# sidebar navigation icons
# --------------------------------------------------------------------------
_NAV_ICONS = {
    "Overview": "activity",
    "Events": "terminal",
    "Incidents": "shield-alert",
}


def _nav_icon_css() -> str:
    """One inline icon per radio option, orange while the option is selected."""
    rules = []
    for index, item in enumerate(NAV_ITEMS, start=1):
        icon = _NAV_ICONS.get(item, "activity")
        base = icon_data_uri(icon, color=FAINT, size=16)
        active = icon_data_uri(icon, color="#FDBA74", size=16)
        root = (
            'section[data-testid="stSidebar"] [data-testid="stRadioGroup"] '
            f'> div:nth-child({index}) [data-testid="stRadioOption"]'
        )
        shared = (
            'content: ""; display: inline-block; width: 15px; height: 15px;'
            " margin-right: 8px; vertical-align: -3px;"
            " background-repeat: no-repeat; background-position: center;"
            " background-size: contain;"
        )
        rules.append(f"{root} p::before {{ {shared} background-image: url(\"{base}\"); }}")
        rules.append(
            f'{root}[data-selected="true"] p::before {{'
            f' background-image: url("{active}"); }}'
        )
    return "<style>" + "".join(rules) + "</style>"


CSS += _nav_icon_css()
