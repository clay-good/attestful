"""
REST API for Attestful (enterprise feature).

Provides FastAPI-based REST API for programmatic access
to scanning, collection, and reporting functionality.

Install with: pip install 'attestful[enterprise]'
"""

from attestful.api.app import create_api_app, run_api_server

__all__ = [
    "create_api_app",
    "run_api_server",
]
