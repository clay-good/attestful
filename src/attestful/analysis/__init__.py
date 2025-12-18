"""
Analysis module for Attestful.

Provides maturity scoring, gap analysis, trend tracking,
cross-framework mapping, and compliance posture assessment.
"""

from attestful.analysis.maturity import (
    MaturityLevel,
    MaturityCalculator,
    MaturityScore,
    CategoryScore,
    FrameworkMaturity,
)
from attestful.analysis.gaps import GapAnalyzer, ComplianceGap
from attestful.analysis.crosswalk import (
    Framework,
    MappingStrength,
    ControlMapping,
    CrosswalkResult,
    FrameworkCrosswalk,
    get_crosswalk,
    find_equivalent_controls,
    get_control_coverage_map,
)
from attestful.analysis.trend_tracker import (
    TrendAnalysis,
    TrendDirection,
    TrendItem,
    TrendPoint,
    TrendTracker,
    TrendTrackerConfig,
)

__all__ = [
    # Maturity
    "MaturityLevel",
    "MaturityCalculator",
    "MaturityScore",
    "CategoryScore",
    "FrameworkMaturity",
    # Gap Analysis
    "GapAnalyzer",
    "ComplianceGap",
    # Cross-Framework Mapping
    "Framework",
    "MappingStrength",
    "ControlMapping",
    "CrosswalkResult",
    "FrameworkCrosswalk",
    "get_crosswalk",
    "find_equivalent_controls",
    "get_control_coverage_map",
    # Trend Tracking
    "TrendAnalysis",
    "TrendDirection",
    "TrendItem",
    "TrendPoint",
    "TrendTracker",
    "TrendTrackerConfig",
]
