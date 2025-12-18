"""
Dashboard for Attestful (enterprise feature).

Provides Dash/Plotly-based interactive dashboard for
compliance visualization and monitoring.

Install with: pip install 'attestful[enterprise]'
"""

from attestful.dashboard.app import create_dashboard_app, run_dashboard

__all__ = [
    "create_dashboard_app",
    "run_dashboard",
]
