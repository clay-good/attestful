"""
Main dashboard application using Dash/Plotly.

Implements Section 14 of the Attestful specification:
- Monochrome design with minimal accent colors
- Large hero compliance percentage
- Framework selector with category breakdowns
- Platform status grid
- Light/dark mode toggle
- Static HTML export for air-gapped viewing
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import dash
    from dash import dcc, html, callback, Input, Output, State
    import plotly.graph_objects as go
    import plotly.express as px

    DASH_AVAILABLE = True
except ImportError:
    DASH_AVAILABLE = False
    dash = None  # type: ignore[assignment]
    dcc = None  # type: ignore[assignment]
    html = None  # type: ignore[assignment]
    callback = None  # type: ignore[assignment]
    Input = None  # type: ignore[assignment]
    Output = None  # type: ignore[assignment]
    State = None  # type: ignore[assignment]
    go = None  # type: ignore[assignment]
    px = None  # type: ignore[assignment]

from attestful import __version__
from attestful.core.logging import get_logger

logger = get_logger(__name__)


# =============================================================================
# Color Palette (Section 14.2.1)
# =============================================================================

COLORS = {
    "light": {
        "background": "#FFFFFF",
        "card_bg": "#F5F5F5",
        "border": "#E5E5E5",
        "text_primary": "#0A0A0A",
        "text_secondary": "#6B7280",
    },
    "dark": {
        "background": "#0A0A0A",
        "card_bg": "#1A1A1A",
        "border": "#2A2A2A",
        "text_primary": "#FAFAFA",
        "text_secondary": "#6B7280",
    },
    "accent": "#3B82F6",  # Blue for interactive elements
    "status": {
        "pass": "#10B981",  # Green
        "fail": "#EF4444",  # Red
        "warning": "#F59E0B",  # Amber
    },
}

# Typography (Section 14.2.2)
FONTS = {
    "primary": '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    "monospace": 'ui-monospace, "SF Mono", Monaco, "Courier New", monospace',
}

FONT_SIZES = {
    "hero": "72px",
    "hero_mobile": "48px",
    "heading": "24px",
    "section": "18px",
    "body": "14px",
    "small": "12px",
}


# =============================================================================
# Sample Data (for demonstration - replace with database queries)
# =============================================================================

def get_sample_compliance_data() -> dict[str, Any]:
    """Get sample compliance data for dashboard display."""
    return {
        "frameworks": {
            "soc2": {
                "name": "SOC 2 Type II",
                "compliance_pct": 87,
                "trend": 3,
                "last_assessed": "2024-01-15T10:30:00Z",
                "categories": {
                    "Security": 92,
                    "Availability": 85,
                    "Processing Integrity": 88,
                    "Confidentiality": 80,
                    "Privacy": 78,
                },
                "total_controls": 64,
                "controls_with_evidence": 56,
                "controls_missing": 8,
            },
            "nist-csf": {
                "name": "NIST CSF 2.0",
                "compliance_pct": 72,
                "trend": 5,
                "last_assessed": "2024-01-14T14:00:00Z",
                "categories": {
                    "Govern": 68,
                    "Identify": 75,
                    "Protect": 80,
                    "Detect": 70,
                    "Respond": 65,
                    "Recover": 72,
                },
                "total_controls": 106,
                "controls_with_evidence": 76,
                "controls_missing": 30,
            },
            "nist-800-53": {
                "name": "NIST 800-53 Rev 5",
                "compliance_pct": 65,
                "trend": -2,
                "last_assessed": "2024-01-13T09:00:00Z",
                "categories": {
                    "Access Control": 70,
                    "Audit & Accountability": 68,
                    "Security Assessment": 60,
                    "Configuration Mgmt": 72,
                    "Identification & Auth": 58,
                },
                "total_controls": 324,
                "controls_with_evidence": 211,
                "controls_missing": 113,
            },
            "iso-27001": {
                "name": "ISO 27001:2022",
                "compliance_pct": 78,
                "trend": 4,
                "last_assessed": "2024-01-12T16:00:00Z",
                "categories": {
                    "Organizational": 82,
                    "People": 75,
                    "Physical": 80,
                    "Technological": 76,
                },
                "total_controls": 93,
                "controls_with_evidence": 73,
                "controls_missing": 20,
            },
            "hitrust": {
                "name": "HITRUST CSF",
                "compliance_pct": 58,
                "trend": 8,
                "last_assessed": "2024-01-10T11:00:00Z",
                "categories": {
                    "Information Protection": 55,
                    "Endpoint Protection": 62,
                    "Network Protection": 58,
                    "Access Control": 54,
                    "Audit Logging": 60,
                },
                "total_controls": 156,
                "controls_with_evidence": 90,
                "controls_missing": 66,
            },
        },
        "platforms": {
            "aws": {"name": "AWS", "status": "connected", "last_collected": "2024-01-15T08:00:00Z"},
            "okta": {"name": "Okta", "status": "connected", "last_collected": "2024-01-15T07:30:00Z"},
            "github": {"name": "GitHub", "status": "connected", "last_collected": "2024-01-15T06:00:00Z"},
            "slack": {"name": "Slack", "status": "error", "last_collected": "2024-01-14T12:00:00Z"},
            "jira": {"name": "Jira", "status": "connected", "last_collected": "2024-01-15T05:00:00Z"},
            "datadog": {"name": "Datadog", "status": "not_configured", "last_collected": None},
            "azure": {"name": "Azure", "status": "connected", "last_collected": "2024-01-15T04:00:00Z"},
            "gcp": {"name": "GCP", "status": "not_configured", "last_collected": None},
        },
        "evidence_stats": {
            "total": 15420,
            "today": 234,
            "this_week": 1567,
            "this_month": 4892,
        },
    }


# =============================================================================
# CSS Styles
# =============================================================================

def get_css_styles() -> str:
    """Generate CSS styles for the dashboard."""
    return """
    :root {
        /* Light mode (default) */
        --bg-primary: #FFFFFF;
        --bg-card: #F5F5F5;
        --border-color: #E5E5E5;
        --text-primary: #0A0A0A;
        --text-secondary: #6B7280;
        --accent: #3B82F6;
        --status-pass: #10B981;
        --status-fail: #EF4444;
        --status-warning: #F59E0B;
    }

    [data-theme="dark"] {
        --bg-primary: #0A0A0A;
        --bg-card: #1A1A1A;
        --border-color: #2A2A2A;
        --text-primary: #FAFAFA;
        --text-secondary: #6B7280;
    }

    * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
    }

    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background-color: var(--bg-primary);
        color: var(--text-primary);
        transition: background-color 0.2s ease, color 0.2s ease;
        line-height: 1.5;
    }

    .dashboard-container {
        max-width: 1280px;
        margin: 0 auto;
        padding: 32px 24px;
    }

    /* Header */
    .header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 32px;
        padding-bottom: 16px;
        border-bottom: 1px solid var(--border-color);
    }

    .header h1 {
        font-size: 24px;
        font-weight: 600;
        color: var(--text-primary);
    }

    .theme-toggle {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 8px 16px;
        cursor: pointer;
        color: var(--text-primary);
        font-size: 14px;
        transition: all 0.2s ease;
    }

    .theme-toggle:hover {
        border-color: var(--accent);
    }

    /* Hero Section */
    .hero-section {
        text-align: center;
        padding: 48px 0;
        margin-bottom: 32px;
    }

    .hero-percentage {
        font-size: 72px;
        font-weight: 700;
        color: var(--text-primary);
        line-height: 1;
    }

    .hero-framework {
        font-size: 18px;
        color: var(--text-secondary);
        margin-top: 8px;
    }

    .hero-trend {
        font-size: 14px;
        margin-top: 12px;
    }

    .trend-up {
        color: var(--status-pass);
    }

    .trend-down {
        color: var(--status-fail);
    }

    .last-assessed {
        font-size: 12px;
        color: var(--text-secondary);
        margin-top: 8px;
    }

    /* Framework Selector */
    .framework-tabs {
        display: flex;
        gap: 8px;
        margin-bottom: 32px;
        flex-wrap: wrap;
        justify-content: center;
    }

    .framework-tab {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 12px 20px;
        cursor: pointer;
        transition: all 0.2s ease;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    .framework-tab:hover {
        border-color: var(--accent);
    }

    .framework-tab.active {
        border-color: var(--accent);
        background: var(--accent);
        color: white;
    }

    .framework-tab .mini-pct {
        font-size: 12px;
        padding: 2px 6px;
        border-radius: 4px;
        background: rgba(0, 0, 0, 0.1);
    }

    .framework-tab.active .mini-pct {
        background: rgba(255, 255, 255, 0.2);
    }

    /* Cards */
    .card {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 24px;
        margin-bottom: 24px;
    }

    .card-title {
        font-size: 18px;
        font-weight: 600;
        color: var(--text-primary);
        margin-bottom: 16px;
    }

    /* Stats Grid */
    .stats-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 24px;
        margin-bottom: 32px;
    }

    @media (max-width: 1024px) {
        .stats-grid {
            grid-template-columns: repeat(2, 1fr);
        }
    }

    @media (max-width: 640px) {
        .stats-grid {
            grid-template-columns: 1fr;
        }
        .hero-percentage {
            font-size: 48px;
        }
    }

    .stat-card {
        text-align: center;
    }

    .stat-value {
        font-size: 32px;
        font-weight: 700;
        color: var(--text-primary);
    }

    .stat-label {
        font-size: 14px;
        color: var(--text-secondary);
        margin-top: 4px;
    }

    /* Category Breakdown */
    .category-list {
        display: flex;
        flex-direction: column;
        gap: 16px;
    }

    .category-item {
        display: flex;
        align-items: center;
        gap: 16px;
    }

    .category-name {
        width: 180px;
        font-size: 14px;
        color: var(--text-primary);
    }

    .category-bar-container {
        flex: 1;
        height: 24px;
        background: var(--border-color);
        border-radius: 4px;
        overflow: hidden;
    }

    .category-bar {
        height: 100%;
        border-radius: 4px;
        transition: width 0.3s ease;
    }

    .category-bar.pass {
        background: var(--status-pass);
    }

    .category-bar.warning {
        background: var(--status-warning);
    }

    .category-bar.fail {
        background: var(--status-fail);
    }

    .category-pct {
        width: 50px;
        text-align: right;
        font-size: 14px;
        font-weight: 600;
        color: var(--text-primary);
    }

    /* Platform Grid */
    .platform-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 16px;
    }

    @media (max-width: 1024px) {
        .platform-grid {
            grid-template-columns: repeat(2, 1fr);
        }
    }

    @media (max-width: 640px) {
        .platform-grid {
            grid-template-columns: 1fr;
        }
    }

    .platform-card {
        background: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 16px;
        display: flex;
        align-items: center;
        gap: 12px;
    }

    .platform-status {
        width: 12px;
        height: 12px;
        border-radius: 50%;
    }

    .platform-status.connected {
        background: var(--status-pass);
    }

    .platform-status.error {
        background: var(--status-fail);
    }

    .platform-status.not_configured {
        background: var(--text-secondary);
    }

    .platform-info {
        flex: 1;
    }

    .platform-name {
        font-size: 14px;
        font-weight: 500;
        color: var(--text-primary);
    }

    .platform-last {
        font-size: 12px;
        color: var(--text-secondary);
    }

    /* Two Column Layout */
    .two-column {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 24px;
    }

    @media (max-width: 1024px) {
        .two-column {
            grid-template-columns: 1fr;
        }
    }

    /* Footer */
    .footer {
        text-align: center;
        padding: 32px 0;
        color: var(--text-secondary);
        font-size: 12px;
        border-top: 1px solid var(--border-color);
        margin-top: 48px;
    }

    /* Circular Progress */
    .circular-progress {
        width: 200px;
        height: 200px;
        margin: 0 auto 16px;
    }
    """


# =============================================================================
# Component Builders
# =============================================================================

def build_header(theme: str = "light") -> Any:
    """Build the header with title and theme toggle."""
    if not DASH_AVAILABLE:
        return None

    return html.Div(
        className="header",
        children=[
            html.H1("Attestful"),
            html.Button(
                id="theme-toggle",
                className="theme-toggle",
                children="🌙 Dark Mode" if theme == "light" else "☀️ Light Mode",
            ),
        ],
    )


def build_hero_section(
    compliance_pct: int,
    framework_name: str,
    trend: int,
    last_assessed: str,
) -> Any:
    """Build the hero section with large compliance percentage."""
    if not DASH_AVAILABLE:
        return None

    trend_class = "trend-up" if trend >= 0 else "trend-down"
    trend_arrow = "↑" if trend >= 0 else "↓"
    trend_text = f"{trend_arrow} {abs(trend)}% from last assessment"

    # Parse last assessed date
    try:
        assessed_dt = datetime.fromisoformat(last_assessed.replace("Z", "+00:00"))
        assessed_str = assessed_dt.strftime("%B %d, %Y at %I:%M %p")
    except (ValueError, AttributeError):
        assessed_str = last_assessed

    # Create circular progress chart
    fig = go.Figure(go.Pie(
        values=[compliance_pct, 100 - compliance_pct],
        hole=0.75,
        marker_colors=[COLORS["status"]["pass"] if compliance_pct >= 80
                       else COLORS["status"]["warning"] if compliance_pct >= 50
                       else COLORS["status"]["fail"],
                       COLORS["light"]["border"]],
        textinfo="none",
        hoverinfo="skip",
    ))
    fig.update_layout(
        showlegend=False,
        margin=dict(l=0, r=0, t=0, b=0),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        width=200,
        height=200,
        annotations=[dict(
            text=f"{compliance_pct}%",
            x=0.5, y=0.5,
            font_size=40,
            font_weight=700,
            showarrow=False,
        )],
    )

    return html.Div(
        className="hero-section",
        children=[
            dcc.Graph(
                figure=fig,
                config={"displayModeBar": False},
                className="circular-progress",
            ),
            html.Div(framework_name, className="hero-framework"),
            html.Div(trend_text, className=f"hero-trend {trend_class}"),
            html.Div(f"Last assessed: {assessed_str}", className="last-assessed"),
        ],
    )


def build_framework_tabs(frameworks: dict[str, Any], active: str) -> Any:
    """Build the framework selector tabs."""
    if not DASH_AVAILABLE:
        return None

    tabs = []
    for fw_id, fw_data in frameworks.items():
        is_active = fw_id == active
        tabs.append(
            html.Div(
                id={"type": "framework-tab", "index": fw_id},
                className=f"framework-tab {'active' if is_active else ''}",
                children=[
                    html.Span(fw_data["name"]),
                    html.Span(f"{fw_data['compliance_pct']}%", className="mini-pct"),
                ],
                n_clicks=0,
            )
        )

    return html.Div(className="framework-tabs", children=tabs)


def build_stats_cards(framework_data: dict[str, Any]) -> Any:
    """Build the quick stats cards."""
    if not DASH_AVAILABLE:
        return None

    return html.Div(
        className="stats-grid",
        children=[
            html.Div(
                className="card stat-card",
                children=[
                    html.Div(str(framework_data["total_controls"]), className="stat-value"),
                    html.Div("Total Controls", className="stat-label"),
                ],
            ),
            html.Div(
                className="card stat-card",
                children=[
                    html.Div(str(framework_data["controls_with_evidence"]), className="stat-value"),
                    html.Div("With Evidence", className="stat-label"),
                ],
            ),
            html.Div(
                className="card stat-card",
                children=[
                    html.Div(str(framework_data["controls_missing"]), className="stat-value"),
                    html.Div("Missing Evidence", className="stat-label"),
                ],
            ),
            html.Div(
                className="card stat-card",
                children=[
                    html.Div(
                        f"{framework_data['controls_with_evidence'] / framework_data['total_controls'] * 100:.0f}%",
                        className="stat-value",
                    ),
                    html.Div("Evidence Coverage", className="stat-label"),
                ],
            ),
        ],
    )


def build_category_breakdown(categories: dict[str, int]) -> Any:
    """Build the category breakdown with progress bars."""
    if not DASH_AVAILABLE:
        return None

    items = []
    for name, pct in categories.items():
        bar_class = "pass" if pct >= 80 else "warning" if pct >= 50 else "fail"
        items.append(
            html.Div(
                className="category-item",
                children=[
                    html.Span(name, className="category-name"),
                    html.Div(
                        className="category-bar-container",
                        children=[
                            html.Div(
                                className=f"category-bar {bar_class}",
                                style={"width": f"{pct}%"},
                            ),
                        ],
                    ),
                    html.Span(f"{pct}%", className="category-pct"),
                ],
            )
        )

    return html.Div(
        className="card",
        children=[
            html.Div("Category Breakdown", className="card-title"),
            html.Div(className="category-list", children=items),
        ],
    )


def build_platform_grid(platforms: dict[str, Any]) -> Any:
    """Build the platform status grid."""
    if not DASH_AVAILABLE:
        return None

    cards = []
    for platform_id, platform_data in platforms.items():
        status = platform_data["status"]
        last = platform_data.get("last_collected")

        if last:
            try:
                last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                last_str = last_dt.strftime("%b %d, %I:%M %p")
            except (ValueError, AttributeError):
                last_str = "Unknown"
        else:
            last_str = "Not collected"

        cards.append(
            html.Div(
                className="platform-card",
                children=[
                    html.Div(className=f"platform-status {status}"),
                    html.Div(
                        className="platform-info",
                        children=[
                            html.Div(platform_data["name"], className="platform-name"),
                            html.Div(last_str, className="platform-last"),
                        ],
                    ),
                ],
            )
        )

    return html.Div(
        className="card",
        children=[
            html.Div("Evidence Collection Status", className="card-title"),
            html.Div(className="platform-grid", children=cards),
        ],
    )


def build_evidence_stats(stats: dict[str, int]) -> Any:
    """Build the evidence statistics card."""
    if not DASH_AVAILABLE:
        return None

    return html.Div(
        className="card",
        children=[
            html.Div("Evidence Summary", className="card-title"),
            html.Div(
                className="stats-grid",
                style={"marginBottom": "0"},
                children=[
                    html.Div(
                        className="stat-card",
                        children=[
                            html.Div(f"{stats['total']:,}", className="stat-value"),
                            html.Div("Total Items", className="stat-label"),
                        ],
                    ),
                    html.Div(
                        className="stat-card",
                        children=[
                            html.Div(str(stats["today"]), className="stat-value"),
                            html.Div("Today", className="stat-label"),
                        ],
                    ),
                    html.Div(
                        className="stat-card",
                        children=[
                            html.Div(f"{stats['this_week']:,}", className="stat-value"),
                            html.Div("This Week", className="stat-label"),
                        ],
                    ),
                    html.Div(
                        className="stat-card",
                        children=[
                            html.Div(f"{stats['this_month']:,}", className="stat-value"),
                            html.Div("This Month", className="stat-label"),
                        ],
                    ),
                ],
            ),
        ],
    )


def build_footer() -> Any:
    """Build the footer."""
    if not DASH_AVAILABLE:
        return None

    return html.Div(
        className="footer",
        children=[
            html.P(f"Attestful v{__version__} • OSCAL-first Compliance Platform"),
            html.P("Open source evidence collection and visualization"),
        ],
    )


# =============================================================================
# Main Dashboard App
# =============================================================================

def create_dashboard_app(
    host: str = "127.0.0.1",
    port: int = 8050,
) -> Any | None:
    """
    Create and configure the Dash dashboard application.

    Implements Section 14 of the Attestful specification with:
    - Monochrome design with minimal accent colors
    - Large hero compliance percentage (72px)
    - Framework selector with mini percentage badges
    - Category breakdown with progress bars
    - Platform status grid
    - Light/dark mode toggle

    Args:
        host: Host to bind to
        port: Port to run on

    Returns:
        Dash app instance or None if Dash is not available
    """
    if not DASH_AVAILABLE:
        logger.error("Dash is not installed. Install with: pip install 'attestful[enterprise]'")
        return None

    # Get sample data
    data = get_sample_compliance_data()
    default_framework = "soc2"

    # Create Dash app
    app = dash.Dash(
        __name__,
        title="Attestful Dashboard",
        update_title="Loading...",
        suppress_callback_exceptions=True,
    )

    # Build initial layout
    fw_data = data["frameworks"][default_framework]

    app.layout = html.Div(
        id="app-container",
        className="dashboard-container",
        children=[
            # Store for theme and framework state
            dcc.Store(id="theme-store", data="light"),
            dcc.Store(id="framework-store", data=default_framework),

            # Header
            build_header(),

            # Hero section
            html.Div(
                id="hero-container",
                children=build_hero_section(
                    compliance_pct=fw_data["compliance_pct"],
                    framework_name=fw_data["name"],
                    trend=fw_data["trend"],
                    last_assessed=fw_data["last_assessed"],
                ),
            ),

            # Framework tabs
            html.Div(
                id="framework-tabs-container",
                children=build_framework_tabs(data["frameworks"], default_framework),
            ),

            # Stats cards
            html.Div(
                id="stats-container",
                children=build_stats_cards(fw_data),
            ),

            # Two column layout
            html.Div(
                className="two-column",
                children=[
                    # Category breakdown
                    html.Div(
                        id="category-container",
                        children=build_category_breakdown(fw_data["categories"]),
                    ),
                    # Evidence stats
                    build_evidence_stats(data["evidence_stats"]),
                ],
            ),

            # Platform grid
            build_platform_grid(data["platforms"]),

            # Footer
            build_footer(),
        ],
    )

    # Custom CSS
    app.index_string = f"""
    <!DOCTYPE html>
    <html>
        <head>
            {{%metas%}}
            <title>{{%title%}}</title>
            {{%favicon%}}
            {{%css%}}
            <style>
                {get_css_styles()}
            </style>
        </head>
        <body>
            {{%app_entry%}}
            <footer>
                {{%config%}}
                {{%scripts%}}
                {{%renderer%}}
            </footer>
            <script>
                // Theme toggle functionality
                document.addEventListener('DOMContentLoaded', function() {{
                    // Check for saved theme preference
                    const savedTheme = localStorage.getItem('attestful-theme');
                    if (savedTheme) {{
                        document.documentElement.setAttribute('data-theme', savedTheme);
                    }} else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {{
                        document.documentElement.setAttribute('data-theme', 'dark');
                    }}
                }});
            </script>
        </body>
    </html>
    """

    logger.info(
        "Dashboard application created",
        version=__version__,
    )

    return app


def run_dashboard(
    host: str = "127.0.0.1",
    port: int = 8050,
    debug: bool = False,
) -> None:
    """
    Run the dashboard server.

    Args:
        host: Host to bind to
        port: Port to run on
        debug: Enable debug mode
    """
    app = create_dashboard_app(host=host, port=port)
    if app is None:
        return

    logger.info(f"Starting dashboard on http://{host}:{port}")
    app.run_server(host=host, port=port, debug=debug)


# =============================================================================
# Static Export for Air-Gapped Viewing (Section 14.7.4)
# =============================================================================

def export_static_dashboard(
    output_path: str | Path,
    include_data: bool = True,
) -> Path:
    """
    Export the dashboard as a static HTML file for air-gapped viewing.

    This creates a single self-contained HTML file that can be opened
    in any browser without a server, suitable for offline deployments.

    Args:
        output_path: Path to save the HTML file
        include_data: Whether to include current data snapshot

    Returns:
        Path to the generated HTML file
    """
    output_path = Path(output_path)

    # Get data
    data = get_sample_compliance_data()
    default_framework = "soc2"
    fw_data = data["frameworks"][default_framework]

    # Generate HTML
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attestful Compliance Dashboard</title>
    <style>
        {get_css_styles()}
    </style>
</head>
<body>
    <div class="dashboard-container">
        <!-- Header -->
        <div class="header">
            <h1>Attestful</h1>
            <button class="theme-toggle" onclick="toggleTheme()">🌙 Dark Mode</button>
        </div>

        <!-- Hero Section -->
        <div class="hero-section">
            <div style="font-size: 72px; font-weight: 700; color: var(--text-primary);">
                {fw_data['compliance_pct']}%
            </div>
            <div class="hero-framework">{fw_data['name']}</div>
            <div class="hero-trend {'trend-up' if fw_data['trend'] >= 0 else 'trend-down'}">
                {'↑' if fw_data['trend'] >= 0 else '↓'} {abs(fw_data['trend'])}% from last assessment
            </div>
            <div class="last-assessed">Last assessed: {fw_data['last_assessed']}</div>
        </div>

        <!-- Framework Tabs -->
        <div class="framework-tabs">
            {''.join(f'''
            <div class="framework-tab {'active' if fw_id == default_framework else ''}"
                 onclick="selectFramework('{fw_id}')">
                <span>{fw['name']}</span>
                <span class="mini-pct">{fw['compliance_pct']}%</span>
            </div>
            ''' for fw_id, fw in data['frameworks'].items())}
        </div>

        <!-- Stats Grid -->
        <div class="stats-grid">
            <div class="card stat-card">
                <div class="stat-value">{fw_data['total_controls']}</div>
                <div class="stat-label">Total Controls</div>
            </div>
            <div class="card stat-card">
                <div class="stat-value">{fw_data['controls_with_evidence']}</div>
                <div class="stat-label">With Evidence</div>
            </div>
            <div class="card stat-card">
                <div class="stat-value">{fw_data['controls_missing']}</div>
                <div class="stat-label">Missing Evidence</div>
            </div>
            <div class="card stat-card">
                <div class="stat-value">{fw_data['controls_with_evidence'] / fw_data['total_controls'] * 100:.0f}%</div>
                <div class="stat-label">Evidence Coverage</div>
            </div>
        </div>

        <!-- Two Column Layout -->
        <div class="two-column">
            <!-- Category Breakdown -->
            <div class="card">
                <div class="card-title">Category Breakdown</div>
                <div class="category-list">
                    {''.join(f'''
                    <div class="category-item">
                        <span class="category-name">{cat}</span>
                        <div class="category-bar-container">
                            <div class="category-bar {'pass' if pct >= 80 else 'warning' if pct >= 50 else 'fail'}"
                                 style="width: {pct}%"></div>
                        </div>
                        <span class="category-pct">{pct}%</span>
                    </div>
                    ''' for cat, pct in fw_data['categories'].items())}
                </div>
            </div>

            <!-- Evidence Stats -->
            <div class="card">
                <div class="card-title">Evidence Summary</div>
                <div class="stats-grid" style="margin-bottom: 0">
                    <div class="stat-card">
                        <div class="stat-value">{data['evidence_stats']['total']:,}</div>
                        <div class="stat-label">Total Items</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{data['evidence_stats']['today']}</div>
                        <div class="stat-label">Today</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{data['evidence_stats']['this_week']:,}</div>
                        <div class="stat-label">This Week</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{data['evidence_stats']['this_month']:,}</div>
                        <div class="stat-label">This Month</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Platform Grid -->
        <div class="card">
            <div class="card-title">Evidence Collection Status</div>
            <div class="platform-grid">
                {''.join(f'''
                <div class="platform-card">
                    <div class="platform-status {p['status']}"></div>
                    <div class="platform-info">
                        <div class="platform-name">{p['name']}</div>
                        <div class="platform-last">{p.get('last_collected', 'Not collected') or 'Not collected'}</div>
                    </div>
                </div>
                ''' for p in data['platforms'].values())}
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>Attestful v{__version__} • OSCAL-first Compliance Platform</p>
            <p>Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
    </div>

    <script>
        // Theme toggle
        function toggleTheme() {{
            const html = document.documentElement;
            const current = html.getAttribute('data-theme') || 'light';
            const next = current === 'light' ? 'dark' : 'light';
            html.setAttribute('data-theme', next);
            localStorage.setItem('attestful-theme', next);

            const btn = document.querySelector('.theme-toggle');
            btn.textContent = next === 'light' ? '🌙 Dark Mode' : '☀️ Light Mode';
        }}

        // Check saved theme on load
        document.addEventListener('DOMContentLoaded', function() {{
            const saved = localStorage.getItem('attestful-theme');
            if (saved) {{
                document.documentElement.setAttribute('data-theme', saved);
                const btn = document.querySelector('.theme-toggle');
                btn.textContent = saved === 'light' ? '🌙 Dark Mode' : '☀️ Light Mode';
            }} else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {{
                document.documentElement.setAttribute('data-theme', 'dark');
                document.querySelector('.theme-toggle').textContent = '☀️ Light Mode';
            }}
        }});

        // Framework selection (static - shows alert)
        function selectFramework(id) {{
            alert('Framework switching requires the live dashboard. This is a static export.');
        }}
    </script>
</body>
</html>
"""

    output_path.write_text(html_content)
    logger.info(f"Static dashboard exported to {output_path}")

    return output_path
