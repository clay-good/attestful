"""
Cross-Framework Mapping Implementation.

Provides bidirectional control mappings between all supported compliance
frameworks, enabling unified compliance analysis and gap identification.

Supported Framework Pairs:
--------------------------
- NIST CSF 2.0 <-> NIST 800-53
- NIST 800-53 <-> SOC 2
- NIST 800-53 <-> ISO 27001
- NIST 800-53 <-> HITRUST
- SOC 2 <-> ISO 27001
- NIST CSF 2.0 <-> SOC 2
- NIST CSF 2.0 <-> ISO 27001
- NIST CSF 2.0 <-> HITRUST
- SOC 2 <-> HITRUST
- ISO 27001 <-> HITRUST

Key Components:
---------------
- Bidirectional mapping registry
- Control equivalency scoring (0-1.0)
- Gap analysis tools
- Unified compliance dashboards
- Cross-framework coverage analysis

Mapping Strength Levels:
------------------------
- 1.0 (Strong): Direct equivalence, same control intent and implementation
- 0.8 (Good): Substantially similar, minor differences in scope
- 0.6 (Moderate): Related controls, some gaps in coverage
- 0.4 (Partial): Loosely related, significant supplementation needed
- 0.2 (Weak): Tangentially related, minimal overlap
- 0.0 (None): No meaningful mapping exists
"""

from attestful.frameworks.mapping.registry import (
    FrameworkID,
    MappingDirection,
    ControlMapping,
    FrameworkPairMapping,
    MappingRegistry,
    get_mapping_registry,
    get_mapping,
    get_mappings_for_control,
    get_all_mappings_between,
    get_strongest_mapping,
    get_mapping_strength,
)
from attestful.frameworks.mapping.equivalency import (
    EquivalencyScore,
    EquivalencyFactors,
    calculate_equivalency_score,
    get_semantic_similarity,
    get_implementation_overlap,
    get_industry_standard_weight,
    score_mapping_quality,
)
from attestful.frameworks.mapping.gap_analysis import (
    GapType,
    ControlGap,
    FrameworkGapAnalysis,
    analyze_gaps,
    get_unmapped_controls,
    get_partial_mappings,
    get_framework_specific_controls,
    generate_gap_report,
)
from attestful.frameworks.mapping.unified_dashboard import (
    ComplianceStatus,
    FrameworkComplianceState,
    UnifiedComplianceView,
    generate_unified_view,
    get_shared_control_coverage,
    get_framework_specific_gaps,
    get_effort_prioritization,
    export_dashboard_data,
)

__all__ = [
    # Registry types
    "FrameworkID",
    "MappingDirection",
    "ControlMapping",
    "FrameworkPairMapping",
    "MappingRegistry",
    # Registry functions
    "get_mapping_registry",
    "get_mapping",
    "get_mappings_for_control",
    "get_all_mappings_between",
    "get_strongest_mapping",
    "get_mapping_strength",
    # Equivalency types
    "EquivalencyScore",
    "EquivalencyFactors",
    # Equivalency functions
    "calculate_equivalency_score",
    "get_semantic_similarity",
    "get_implementation_overlap",
    "get_industry_standard_weight",
    "score_mapping_quality",
    # Gap analysis types
    "GapType",
    "ControlGap",
    "FrameworkGapAnalysis",
    # Gap analysis functions
    "analyze_gaps",
    "get_unmapped_controls",
    "get_partial_mappings",
    "get_framework_specific_controls",
    "generate_gap_report",
    # Dashboard types
    "ComplianceStatus",
    "FrameworkComplianceState",
    "UnifiedComplianceView",
    # Dashboard functions
    "generate_unified_view",
    "get_shared_control_coverage",
    "get_framework_specific_gaps",
    "get_effort_prioritization",
    "export_dashboard_data",
]
