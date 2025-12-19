"""
Cross-Framework Gap Analysis Module.

Provides tools for identifying control gaps when mapping between
compliance frameworks.

Gap Types:
----------
1. Unmapped Controls: Controls in one framework with no mapping to another
2. Partial Mappings: Mappings that only partially cover the control
3. Framework-Specific: Requirements unique to one framework

Use Cases:
----------
- Multi-framework compliance programs
- Framework migration planning
- Control consolidation efforts
- Audit preparation across multiple standards
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from attestful.core.logging import get_logger
from attestful.frameworks.mapping.registry import (
    FrameworkID,
    ControlMapping,
    get_mapping_registry,
    get_mappings_for_control,
    get_all_mappings_between,
    FRAMEWORK_NAMES,
)
from attestful.frameworks.mapping.equivalency import (
    calculate_equivalency_score,
    EquivalencyScore,
)

logger = get_logger("frameworks.mapping.gap_analysis")


# =============================================================================
# Enums and Constants
# =============================================================================


class GapType(str, Enum):
    """Type of gap between frameworks."""

    UNMAPPED = "unmapped"  # No mapping exists at all
    PARTIAL = "partial"  # Mapping exists but is weak (< 0.5 strength)
    FRAMEWORK_SPECIFIC = "framework_specific"  # Unique to one framework
    COVERAGE_GAP = "coverage_gap"  # Target framework lacks equivalent control


class GapSeverity(str, Enum):
    """Severity of the gap for compliance."""

    CRITICAL = "critical"  # Must be addressed for compliance
    HIGH = "high"  # Significant gap requiring attention
    MEDIUM = "medium"  # Notable gap, should be addressed
    LOW = "low"  # Minor gap, optional to address


# Gap severity thresholds
SEVERITY_THRESHOLDS = {
    GapSeverity.CRITICAL: 0.0,  # No mapping at all
    GapSeverity.HIGH: 0.3,  # Very weak mapping
    GapSeverity.MEDIUM: 0.5,  # Partial mapping
    GapSeverity.LOW: 0.7,  # Decent mapping with some gaps
}


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class ControlGap:
    """
    Represents a gap between framework controls.

    Attributes:
        source_framework: Framework where the control exists.
        source_control: Control ID in source framework.
        source_title: Control title.
        target_framework: Framework being mapped to.
        gap_type: Type of gap.
        severity: Gap severity.
        mapping_strength: Strength of best available mapping (0 if unmapped).
        mapped_controls: Controls this maps to (if any).
        notes: Gap description and remediation guidance.
        remediation_effort: Estimated effort to close gap.
    """

    source_framework: FrameworkID
    source_control: str
    source_title: str
    target_framework: FrameworkID
    gap_type: GapType
    severity: GapSeverity
    mapping_strength: float = 0.0
    mapped_controls: list[str] = field(default_factory=list)
    notes: str = ""
    remediation_effort: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source_framework": self.source_framework.value,
            "source_control": self.source_control,
            "source_title": self.source_title,
            "target_framework": self.target_framework.value,
            "gap_type": self.gap_type.value,
            "severity": self.severity.value,
            "mapping_strength": round(self.mapping_strength, 3),
            "mapped_controls": self.mapped_controls,
            "notes": self.notes,
            "remediation_effort": self.remediation_effort,
        }


@dataclass
class FrameworkGapAnalysis:
    """
    Complete gap analysis between two frameworks.

    Attributes:
        source_framework: Source framework ID.
        target_framework: Target framework ID.
        analysis_date: When the analysis was performed.
        total_source_controls: Total controls in source framework.
        total_mapped: Controls with mappings.
        total_unmapped: Controls without any mapping.
        total_partial: Controls with partial/weak mappings.
        gaps: List of identified gaps.
        coverage_percentage: Percentage of controls with adequate mapping.
        statistics: Additional statistics.
    """

    source_framework: FrameworkID
    target_framework: FrameworkID
    analysis_date: datetime
    total_source_controls: int
    total_mapped: int
    total_unmapped: int
    total_partial: int
    gaps: list[ControlGap]
    coverage_percentage: float
    statistics: dict[str, Any] = field(default_factory=dict)

    def get_gaps_by_severity(self, severity: GapSeverity) -> list[ControlGap]:
        """Get gaps filtered by severity."""
        return [g for g in self.gaps if g.severity == severity]

    def get_gaps_by_type(self, gap_type: GapType) -> list[ControlGap]:
        """Get gaps filtered by type."""
        return [g for g in self.gaps if g.gap_type == gap_type]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source_framework": self.source_framework.value,
            "source_framework_name": FRAMEWORK_NAMES.get(self.source_framework, ""),
            "target_framework": self.target_framework.value,
            "target_framework_name": FRAMEWORK_NAMES.get(self.target_framework, ""),
            "analysis_date": self.analysis_date.isoformat(),
            "summary": {
                "total_source_controls": self.total_source_controls,
                "total_mapped": self.total_mapped,
                "total_unmapped": self.total_unmapped,
                "total_partial": self.total_partial,
                "coverage_percentage": round(self.coverage_percentage, 1),
            },
            "gaps": [g.to_dict() for g in self.gaps],
            "statistics": self.statistics,
        }


@dataclass
class MultiFrameworkGapReport:
    """
    Gap report across multiple frameworks.

    Attributes:
        target_framework: Primary framework being targeted.
        source_frameworks: Frameworks being analyzed against target.
        analysis_date: When the analysis was performed.
        framework_analyses: Individual analyses by source framework.
        consolidated_gaps: Gaps aggregated across all sources.
        overall_coverage: Overall coverage percentage.
    """

    target_framework: FrameworkID
    source_frameworks: list[FrameworkID]
    analysis_date: datetime
    framework_analyses: dict[FrameworkID, FrameworkGapAnalysis]
    consolidated_gaps: list[ControlGap]
    overall_coverage: float

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "target_framework": self.target_framework.value,
            "source_frameworks": [f.value for f in self.source_frameworks],
            "analysis_date": self.analysis_date.isoformat(),
            "framework_analyses": {
                f.value: a.to_dict() for f, a in self.framework_analyses.items()
            },
            "consolidated_gap_count": len(self.consolidated_gaps),
            "overall_coverage": round(self.overall_coverage, 1),
        }


# =============================================================================
# Gap Analysis Functions
# =============================================================================


def analyze_gaps(
    source_framework: FrameworkID,
    target_framework: FrameworkID,
    source_controls: list[str] | None = None,
) -> FrameworkGapAnalysis:
    """
    Analyze gaps between two frameworks.

    Args:
        source_framework: Source framework ID.
        target_framework: Target framework ID.
        source_controls: Optional list of source controls (defaults to all).

    Returns:
        Complete gap analysis.
    """
    registry = get_mapping_registry()

    # Get all mappings between frameworks
    all_mappings = get_all_mappings_between(source_framework, target_framework)

    # Index mappings by source control
    mappings_by_source: dict[str, list[ControlMapping]] = {}
    for mapping in all_mappings:
        if mapping.source_control not in mappings_by_source:
            mappings_by_source[mapping.source_control] = []
        mappings_by_source[mapping.source_control].append(mapping)

    # Use provided controls or extract from mappings
    if source_controls is None:
        source_controls = list(mappings_by_source.keys())

    gaps: list[ControlGap] = []
    total_mapped = 0
    total_partial = 0
    total_unmapped = 0

    for control_id in source_controls:
        control_mappings = mappings_by_source.get(control_id, [])

        if not control_mappings:
            # No mapping exists
            gap = ControlGap(
                source_framework=source_framework,
                source_control=control_id,
                source_title=_get_control_title(control_id),
                target_framework=target_framework,
                gap_type=GapType.UNMAPPED,
                severity=GapSeverity.CRITICAL,
                mapping_strength=0.0,
                notes=f"No mapping found from {source_framework.value} {control_id} to {target_framework.value}",
                remediation_effort="high",
            )
            gaps.append(gap)
            total_unmapped += 1
        else:
            # Find strongest mapping
            best_mapping = max(control_mappings, key=lambda m: m.strength)
            mapped_controls = [m.target_control for m in control_mappings]

            if best_mapping.strength < 0.5:
                # Partial/weak mapping
                severity = _determine_severity(best_mapping.strength)
                gap = ControlGap(
                    source_framework=source_framework,
                    source_control=control_id,
                    source_title=_get_control_title(control_id),
                    target_framework=target_framework,
                    gap_type=GapType.PARTIAL,
                    severity=severity,
                    mapping_strength=best_mapping.strength,
                    mapped_controls=mapped_controls,
                    notes=f"Weak mapping (strength: {best_mapping.strength:.2f}) - supplemental controls may be needed",
                    remediation_effort="medium",
                )
                gaps.append(gap)
                total_partial += 1
            else:
                # Adequate mapping
                total_mapped += 1

    # Calculate coverage
    total = len(source_controls) if source_controls else 1
    coverage_pct = ((total_mapped + total_partial * 0.5) / total * 100) if total > 0 else 0

    # Build statistics
    severity_counts = {s.value: 0 for s in GapSeverity}
    for gap in gaps:
        severity_counts[gap.severity.value] += 1

    type_counts = {t.value: 0 for t in GapType}
    for gap in gaps:
        type_counts[gap.gap_type.value] += 1

    statistics = {
        "by_severity": severity_counts,
        "by_type": type_counts,
        "high_priority_gaps": len([g for g in gaps if g.severity in [GapSeverity.CRITICAL, GapSeverity.HIGH]]),
        "avg_mapping_strength": (
            sum(g.mapping_strength for g in gaps) / len(gaps) if gaps else 1.0
        ),
    }

    return FrameworkGapAnalysis(
        source_framework=source_framework,
        target_framework=target_framework,
        analysis_date=datetime.now(UTC),
        total_source_controls=len(source_controls),
        total_mapped=total_mapped,
        total_unmapped=total_unmapped,
        total_partial=total_partial,
        gaps=gaps,
        coverage_percentage=coverage_pct,
        statistics=statistics,
    )


def get_unmapped_controls(
    source_framework: FrameworkID,
    target_framework: FrameworkID,
    source_controls: list[str],
) -> list[str]:
    """
    Get controls with no mapping to target framework.

    Args:
        source_framework: Source framework ID.
        target_framework: Target framework ID.
        source_controls: List of source control IDs.

    Returns:
        List of unmapped control IDs.
    """
    unmapped = []

    for control_id in source_controls:
        mappings = get_mappings_for_control(source_framework, control_id)
        if target_framework not in mappings:
            unmapped.append(control_id)

    return unmapped


def get_partial_mappings(
    source_framework: FrameworkID,
    target_framework: FrameworkID,
    source_controls: list[str],
    threshold: float = 0.6,
) -> list[tuple[str, float]]:
    """
    Get controls with partial/weak mappings.

    Args:
        source_framework: Source framework ID.
        target_framework: Target framework ID.
        source_controls: List of source control IDs.
        threshold: Strength threshold for "partial" (default 0.6).

    Returns:
        List of (control_id, best_strength) tuples for partial mappings.
    """
    partial = []

    all_mappings = get_all_mappings_between(source_framework, target_framework)

    # Index by source
    mappings_by_source: dict[str, list[ControlMapping]] = {}
    for mapping in all_mappings:
        if mapping.source_control not in mappings_by_source:
            mappings_by_source[mapping.source_control] = []
        mappings_by_source[mapping.source_control].append(mapping)

    for control_id in source_controls:
        control_mappings = mappings_by_source.get(control_id, [])
        if control_mappings:
            best_strength = max(m.strength for m in control_mappings)
            if best_strength < threshold:
                partial.append((control_id, best_strength))

    return partial


def get_framework_specific_controls(
    framework: FrameworkID,
    controls: list[str],
    compare_to: list[FrameworkID],
) -> list[str]:
    """
    Get controls unique to one framework (no mapping to any comparison framework).

    Args:
        framework: Framework to analyze.
        controls: Controls in the framework.
        compare_to: Frameworks to compare against.

    Returns:
        List of framework-specific control IDs.
    """
    specific = []

    for control_id in controls:
        all_mappings = get_mappings_for_control(framework, control_id)

        # Check if any comparison framework has a mapping
        has_mapping = False
        for target in compare_to:
            if target in all_mappings and all_mappings[target]:
                has_mapping = True
                break

        if not has_mapping:
            specific.append(control_id)

    return specific


def generate_gap_report(
    source_framework: FrameworkID,
    target_framework: FrameworkID,
    source_controls: list[str] | None = None,
    include_details: bool = True,
) -> dict[str, Any]:
    """
    Generate a comprehensive gap report.

    Args:
        source_framework: Source framework ID.
        target_framework: Target framework ID.
        source_controls: Optional list of source controls.
        include_details: Whether to include detailed gap information.

    Returns:
        Gap report dictionary.
    """
    analysis = analyze_gaps(source_framework, target_framework, source_controls)

    report = {
        "report_metadata": {
            "title": f"Gap Analysis: {FRAMEWORK_NAMES.get(source_framework, source_framework.value)} to {FRAMEWORK_NAMES.get(target_framework, target_framework.value)}",
            "generated_at": datetime.now(UTC).isoformat(),
            "source_framework": source_framework.value,
            "target_framework": target_framework.value,
        },
        "executive_summary": {
            "total_controls_analyzed": analysis.total_source_controls,
            "controls_with_mapping": analysis.total_mapped,
            "controls_with_partial_mapping": analysis.total_partial,
            "controls_without_mapping": analysis.total_unmapped,
            "coverage_percentage": round(analysis.coverage_percentage, 1),
            "critical_gaps": len(analysis.get_gaps_by_severity(GapSeverity.CRITICAL)),
            "high_priority_gaps": len(analysis.get_gaps_by_severity(GapSeverity.HIGH)),
        },
        "recommendations": _generate_recommendations(analysis),
    }

    if include_details:
        report["gap_details"] = {
            "critical": [g.to_dict() for g in analysis.get_gaps_by_severity(GapSeverity.CRITICAL)],
            "high": [g.to_dict() for g in analysis.get_gaps_by_severity(GapSeverity.HIGH)],
            "medium": [g.to_dict() for g in analysis.get_gaps_by_severity(GapSeverity.MEDIUM)],
            "low": [g.to_dict() for g in analysis.get_gaps_by_severity(GapSeverity.LOW)],
        }

    report["statistics"] = analysis.statistics

    return report


def analyze_multi_framework_gaps(
    target_framework: FrameworkID,
    source_frameworks: list[FrameworkID],
) -> MultiFrameworkGapReport:
    """
    Analyze gaps from multiple source frameworks to a target.

    Args:
        target_framework: Target framework to map to.
        source_frameworks: Source frameworks to analyze.

    Returns:
        Multi-framework gap report.
    """
    analyses: dict[FrameworkID, FrameworkGapAnalysis] = {}
    all_gaps: list[ControlGap] = []

    for source in source_frameworks:
        if source != target_framework:
            analysis = analyze_gaps(source, target_framework)
            analyses[source] = analysis
            all_gaps.extend(analysis.gaps)

    # Calculate overall coverage (average of individual coverages)
    if analyses:
        overall_coverage = sum(a.coverage_percentage for a in analyses.values()) / len(analyses)
    else:
        overall_coverage = 0.0

    return MultiFrameworkGapReport(
        target_framework=target_framework,
        source_frameworks=source_frameworks,
        analysis_date=datetime.now(UTC),
        framework_analyses=analyses,
        consolidated_gaps=all_gaps,
        overall_coverage=overall_coverage,
    )


# =============================================================================
# Helper Functions
# =============================================================================


def _get_control_title(control_id: str) -> str:
    """Get control title from metadata."""
    from attestful.frameworks.mapping.equivalency import CONTROL_METADATA
    meta = CONTROL_METADATA.get(control_id, {})
    return meta.get("title", f"Control {control_id}")


def _determine_severity(strength: float) -> GapSeverity:
    """Determine gap severity based on mapping strength."""
    if strength == 0:
        return GapSeverity.CRITICAL
    elif strength < 0.3:
        return GapSeverity.HIGH
    elif strength < 0.5:
        return GapSeverity.MEDIUM
    else:
        return GapSeverity.LOW


def _generate_recommendations(analysis: FrameworkGapAnalysis) -> list[str]:
    """Generate recommendations based on gap analysis."""
    recommendations = []

    critical_count = len(analysis.get_gaps_by_severity(GapSeverity.CRITICAL))
    high_count = len(analysis.get_gaps_by_severity(GapSeverity.HIGH))

    if critical_count > 0:
        recommendations.append(
            f"Address {critical_count} critical gap(s) with no framework mapping. "
            "These controls require dedicated implementation in the target framework."
        )

    if high_count > 0:
        recommendations.append(
            f"Review {high_count} high-priority gap(s) with weak mappings. "
            "Consider supplemental controls to ensure adequate coverage."
        )

    if analysis.total_partial > analysis.total_mapped:
        recommendations.append(
            "More controls have partial mappings than full mappings. "
            "Consider a comprehensive gap remediation program."
        )

    if analysis.coverage_percentage < 70:
        recommendations.append(
            f"Coverage is {analysis.coverage_percentage:.1f}%, below recommended 70% threshold. "
            "Prioritize high-value controls for additional mapping work."
        )
    elif analysis.coverage_percentage >= 90:
        recommendations.append(
            f"Strong coverage at {analysis.coverage_percentage:.1f}%. "
            "Focus on closing remaining gaps for comprehensive compliance."
        )

    return recommendations


__all__ = [
    # Enums
    "GapType",
    "GapSeverity",
    # Constants
    "SEVERITY_THRESHOLDS",
    # Data classes
    "ControlGap",
    "FrameworkGapAnalysis",
    "MultiFrameworkGapReport",
    # Functions
    "analyze_gaps",
    "get_unmapped_controls",
    "get_partial_mappings",
    "get_framework_specific_controls",
    "generate_gap_report",
    "analyze_multi_framework_gaps",
]
