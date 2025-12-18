"""
Main dashboard application using Dash/Plotly.

Migrated from Compliy (Step 4.2.12 of instructions.txt).
"""

from typing import Any

try:
    import dash
    from dash import dcc, html

    DASH_AVAILABLE = True
except ImportError:
    DASH_AVAILABLE = False
    dash = None  # type: ignore[assignment]
    dcc = None  # type: ignore[assignment]
    html = None  # type: ignore[assignment]

from attestful import __version__
from attestful.core.logging import get_logger

logger = get_logger(__name__)


def create_dashboard_app(
    host: str = "127.0.0.1",
    port: int = 8050,
) -> Any | None:
    """
    Create and configure the Dash dashboard application.

    Args:
        host: Host to bind to
        port: Port to run on

    Returns:
        Dash app instance or None if Dash is not available
    """
    if not DASH_AVAILABLE:
        logger.error("Dash is not installed. Install with: pip install 'attestful[enterprise]'")
        return None

    # Create Dash app
    app = dash.Dash(
        __name__,
        title="Attestful Dashboard",
        update_title="Loading...",
        suppress_callback_exceptions=True,
    )

    # Define layout
    app.layout = html.Div(
        [
            # Header
            html.Div(
                [
                    html.H1(
                        "Attestful Dashboard",
                        style={
                            "textAlign": "center",
                            "color": "#2c3e50",
                            "marginBottom": "10px",
                        },
                    ),
                    html.P(
                        "OSCAL-first compliance monitoring and analytics",
                        style={
                            "textAlign": "center",
                            "color": "#7f8c8d",
                            "marginBottom": "30px",
                        },
                    ),
                ]
            ),
            # Auto-refresh interval (every 30 seconds)
            dcc.Interval(
                id="interval-component",
                interval=30 * 1000,  # in milliseconds
                n_intervals=0,
            ),
            # Summary Cards
            html.Div(
                [
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.H3("Total Scans", style={"color": "#3498db"}),
                                    html.H2(
                                        id="total-scans",
                                        children="0",
                                        style={"fontSize": "48px"},
                                    ),
                                ],
                                className="card",
                            ),
                        ],
                        style={
                            "width": "23%",
                            "display": "inline-block",
                            "margin": "1%",
                        },
                    ),
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.H3("Compliance Score", style={"color": "#2ecc71"}),
                                    html.H2(
                                        id="compliance-score",
                                        children="0%",
                                        style={"fontSize": "48px"},
                                    ),
                                ],
                                className="card",
                            ),
                        ],
                        style={
                            "width": "23%",
                            "display": "inline-block",
                            "margin": "1%",
                        },
                    ),
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.H3("Failed Checks", style={"color": "#e74c3c"}),
                                    html.H2(
                                        id="failed-checks",
                                        children="0",
                                        style={"fontSize": "48px"},
                                    ),
                                ],
                                className="card",
                            ),
                        ],
                        style={
                            "width": "23%",
                            "display": "inline-block",
                            "margin": "1%",
                        },
                    ),
                    html.Div(
                        [
                            html.Div(
                                [
                                    html.H3("Frameworks", style={"color": "#9b59b6"}),
                                    html.H2(
                                        id="frameworks-count",
                                        children="6",
                                        style={"fontSize": "48px"},
                                    ),
                                ],
                                className="card",
                            ),
                        ],
                        style={
                            "width": "23%",
                            "display": "inline-block",
                            "margin": "1%",
                        },
                    ),
                ],
                style={"marginBottom": "30px"},
            ),
            # Charts Row
            html.Div(
                [
                    html.Div(
                        [
                            dcc.Graph(id="compliance-trend-chart"),
                        ],
                        style={"width": "48%", "display": "inline-block", "margin": "1%"},
                    ),
                    html.Div(
                        [
                            dcc.Graph(id="framework-breakdown-chart"),
                        ],
                        style={"width": "48%", "display": "inline-block", "margin": "1%"},
                    ),
                ],
                style={"marginBottom": "30px"},
            ),
            # Framework status
            html.Div(
                [
                    html.H2("Supported Frameworks", style={"color": "#2c3e50"}),
                    html.Ul(
                        [
                            html.Li("NIST CSF 2.0 - Cybersecurity Framework"),
                            html.Li("NIST 800-53 Rev 5 / FedRAMP"),
                            html.Li("SOC 2 Type II - Trust Services Criteria"),
                            html.Li("ISO 27001:2022"),
                            html.Li("HITRUST CSF"),
                        ]
                    ),
                ],
                style={"marginTop": "30px"},
            ),
            # Footer
            html.Div(
                [
                    html.P(
                        f"Attestful v{__version__} - OSCAL-first Compliance Platform",
                        style={"textAlign": "center", "color": "#7f8c8d"},
                    ),
                ],
                style={"marginTop": "50px"},
            ),
        ],
        style={
            "padding": "20px",
            "fontFamily": "Arial, sans-serif",
            "backgroundColor": "#ecf0f1",
        },
    )

    # Add custom CSS
    app.index_string = """
    <!DOCTYPE html>
    <html>
        <head>
            {%metas%}
            <title>{%title%}</title>
            {%favicon%}
            {%css%}
            <style>
                .card {
                    background-color: white;
                    padding: 20px;
                    border-radius: 10px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                    text-align: center;
                }
                .card h3 {
                    margin-bottom: 10px;
                }
                ul {
                    list-style-type: none;
                    padding: 0;
                }
                li {
                    padding: 10px;
                    margin: 5px 0;
                    background-color: white;
                    border-radius: 5px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
                }
            </style>
        </head>
        <body>
            {%app_entry%}
            <footer>
                {%config%}
                {%scripts%}
                {%renderer%}
            </footer>
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
