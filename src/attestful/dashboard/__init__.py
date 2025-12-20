"""
Dashboard for Attestful (enterprise feature).

Provides Dash/Plotly-based interactive dashboard for
compliance visualization and monitoring.

Implements Section 14 of the Attestful specification:
- Monochrome design with minimal accent colors
- Large hero compliance percentage (72px font)
- Framework selector with mini percentage badges
- Category breakdown with horizontal progress bars
- Platform status grid with connection indicators
- Light/dark mode toggle with localStorage persistence
- Static HTML export for air-gapped viewing

Install with: pip install 'attestful[enterprise]'
"""

from attestful.dashboard.app import (
    create_dashboard_app,
    run_dashboard,
    export_static_dashboard,
)

__all__ = [
    "create_dashboard_app",
    "run_dashboard",
    "export_static_dashboard",
]
