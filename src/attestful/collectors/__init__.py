"""
Collectors for resources and evidence.

This module provides the unified collector architecture that supports both:
- Resource collection for compliance checking (Compliy pattern)
- Evidence collection for proof gathering (Nisify pattern)
"""

from attestful.collectors.base import (
    BaseCollector,
    CollectorMode,
    CollectorRegistry,
    collector_registry,
)

__all__ = [
    "BaseCollector",
    "CollectorMode",
    "CollectorRegistry",
    "collector_registry",
]
