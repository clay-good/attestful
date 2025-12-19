"""
Unified Compliance Dashboard Module.

Provides tools for generating unified compliance views across
multiple frameworks simultaneously.

Dashboard Features:
-------------------
1. Compliance status across all frameworks
2. Shared control implementation coverage
3. Framework-specific gap indicators
4. Effort prioritization recommendations

Use Cases:
----------
- Executive reporting across multiple compliance programs
- Identifying controls that satisfy multiple frameworks
- Prioritizing remediation efforts for maximum impact
- Continuous compliance monitoring
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from attestful.core.logging import get_logger
from attestful.frameworks.mapping.registry import (
    FrameworkID,
    FRAMEWORK_NAMES,
    get_mapping_registry,
    get_mappings_for_control,
    get_all_mappings_between,
)
from attestful.frameworks.mapping.gap_analysis import (
    FrameworkGapAnalysis,
    analyze_gaps,
    GapSeverity,
)

logger = get_logger("frameworks.mapping.unified_dashboard")


# =============================================================================
# Enums and Constants
# =============================================================================


class ComplianceStatus(str, Enum):
    """Compliance status for a control or framework."""

    COMPLIANT = "compliant"  # Fully implemented/satisfied
    PARTIAL = "partial"  # Partially implemented
    NON_COMPLIANT = "non_compliant"  # Not implemented
    NOT_ASSESSED = "not_assessed"  # Not yet evaluated
    NOT_APPLICABLE = "not_applicable"  # Control doesn't apply


class PriorityLevel(str, Enum):
    """Priority level for remediation efforts."""

    CRITICAL = "critical"  # Address immediately
    HIGH = "high"  # Address soon
    MEDIUM = "medium"  # Address in normal course
    LOW = "low"  # Address when convenient


# Colors for dashboard display (hex codes)
STATUS_COLORS = {
    ComplianceStatus.COMPLIANT: "#28a745",  # Green
    ComplianceStatus.PARTIAL: "#ffc107",  # Yellow
    ComplianceStatus.NON_COMPLIANT: "#dc3545",  # Red
    ComplianceStatus.NOT_ASSESSED: "#6c757d",  # Gray
    ComplianceStatus.NOT_APPLICABLE: "#17a2b8",  # Cyan
}

PRIORITY_COLORS = {
    PriorityLevel.CRITICAL: "#dc3545",  # Red
    PriorityLevel.HIGH: "#fd7e14",  # Orange
    PriorityLevel.MEDIUM: "#ffc107",  # Yellow
    PriorityLevel.LOW: "#28a745",  # Green
}


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class ControlComplianceState:
    """
    Compliance state for a single control.

    Attributes:
        control_id: Control identifier.
        framework: Framework the control belongs to.
        status: Current compliance status.
        evidence_count: Number of evidence items.
        last_assessed: Last assessment date.
        assessor_notes: Notes from assessor.
    """

    control_id: str
    framework: FrameworkID
    status: ComplianceStatus = ComplianceStatus.NOT_ASSESSED
    evidence_count: int = 0
    last_assessed: datetime | None = None
    assessor_notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "control_id": self.control_id,
            "framework": self.framework.value,
            "status": self.status.value,
            "status_color": STATUS_COLORS.get(self.status, "#6c757d"),
            "evidence_count": self.evidence_count,
            "last_assessed": self.last_assessed.isoformat() if self.last_assessed else None,
            "assessor_notes": self.assessor_notes,
        }


@dataclass
class FrameworkComplianceState:
    """
    Overall compliance state for a framework.

    Attributes:
        framework: Framework ID.
        framework_name: Display name.
        total_controls: Total controls in framework.
        compliant_count: Number of compliant controls.
        partial_count: Number of partially compliant controls.
        non_compliant_count: Number of non-compliant controls.
        not_assessed_count: Number of unassessed controls.
        compliance_percentage: Overall compliance percentage.
        control_states: Individual control states.
        last_updated: Last update time.
    """

    framework: FrameworkID
    framework_name: str
    total_controls: int = 0
    compliant_count: int = 0
    partial_count: int = 0
    non_compliant_count: int = 0
    not_assessed_count: int = 0
    compliance_percentage: float = 0.0
    control_states: dict[str, ControlComplianceState] = field(default_factory=dict)
    last_updated: datetime | None = None

    def calculate_percentage(self) -> float:
        """Calculate compliance percentage."""
        assessed = self.compliant_count + self.partial_count + self.non_compliant_count
        if assessed == 0:
            return 0.0
        # Compliant = 100%, Partial = 50%, Non-compliant = 0%
        score = (self.compliant_count * 100 + self.partial_count * 50) / assessed
        self.compliance_percentage = score
        return score

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framework": self.framework.value,
            "framework_name": self.framework_name,
            "total_controls": self.total_controls,
            "compliant_count": self.compliant_count,
            "partial_count": self.partial_count,
            "non_compliant_count": self.non_compliant_count,
            "not_assessed_count": self.not_assessed_count,
            "compliance_percentage": round(self.compliance_percentage, 1),
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
        }


@dataclass
class SharedControlCoverage:
    """
    Control that satisfies requirements across multiple frameworks.

    Attributes:
        primary_control_id: Primary control identifier.
        primary_framework: Framework of the primary control.
        covered_frameworks: Frameworks this control helps satisfy.
        coverage_strength: Mapping strength to each framework.
        total_frameworks_covered: Number of frameworks covered.
        is_high_value: Whether this is a high-value shared control.
    """

    primary_control_id: str
    primary_framework: FrameworkID
    covered_frameworks: list[FrameworkID] = field(default_factory=list)
    coverage_strength: dict[str, float] = field(default_factory=dict)
    total_frameworks_covered: int = 0
    is_high_value: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "primary_control_id": self.primary_control_id,
            "primary_framework": self.primary_framework.value,
            "covered_frameworks": [f.value for f in self.covered_frameworks],
            "coverage_strength": {k: round(v, 2) for k, v in self.coverage_strength.items()},
            "total_frameworks_covered": self.total_frameworks_covered,
            "is_high_value": self.is_high_value,
        }


@dataclass
class EffortPrioritization:
    """
    Prioritized remediation effort recommendation.

    Attributes:
        control_id: Control to remediate.
        framework: Primary framework.
        priority: Priority level.
        impact_score: Expected impact score (0-100).
        frameworks_affected: Frameworks that benefit from remediation.
        gap_severity: Severity of current gap.
        estimated_effort: Estimated effort to remediate.
        rationale: Reason for prioritization.
    """

    control_id: str
    framework: FrameworkID
    priority: PriorityLevel
    impact_score: float = 0.0
    frameworks_affected: list[FrameworkID] = field(default_factory=list)
    gap_severity: GapSeverity = GapSeverity.MEDIUM
    estimated_effort: str = "medium"
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "control_id": self.control_id,
            "framework": self.framework.value,
            "priority": self.priority.value,
            "priority_color": PRIORITY_COLORS.get(self.priority, "#ffc107"),
            "impact_score": round(self.impact_score, 1),
            "frameworks_affected": [f.value for f in self.frameworks_affected],
            "gap_severity": self.gap_severity.value,
            "estimated_effort": self.estimated_effort,
            "rationale": self.rationale,
        }


@dataclass
class UnifiedComplianceView:
    """
    Unified view of compliance across all frameworks.

    Attributes:
        view_id: Unique view identifier.
        generated_at: When the view was generated.
        frameworks: List of frameworks included.
        framework_states: Compliance state per framework.
        overall_compliance: Overall compliance percentage.
        shared_controls: Controls covering multiple frameworks.
        framework_gaps: Gaps by framework pair.
        prioritized_efforts: Prioritized remediation list.
        statistics: Summary statistics.
    """

    view_id: str
    generated_at: datetime
    frameworks: list[FrameworkID]
    framework_states: dict[FrameworkID, FrameworkComplianceState]
    overall_compliance: float
    shared_controls: list[SharedControlCoverage]
    framework_gaps: dict[str, FrameworkGapAnalysis]
    prioritized_efforts: list[EffortPrioritization]
    statistics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "view_id": self.view_id,
            "generated_at": self.generated_at.isoformat(),
            "frameworks": [f.value for f in self.frameworks],
            "framework_states": {
                f.value: state.to_dict() for f, state in self.framework_states.items()
            },
            "overall_compliance": round(self.overall_compliance, 1),
            "shared_controls_count": len(self.shared_controls),
            "top_shared_controls": [c.to_dict() for c in self.shared_controls[:10]],
            "prioritized_efforts": [e.to_dict() for e in self.prioritized_efforts[:20]],
            "statistics": self.statistics,
        }


# =============================================================================
# Dashboard Generation Functions
# =============================================================================


def generate_unified_view(
    frameworks: list[FrameworkID],
    control_states: dict[str, ControlComplianceState] | None = None,
) -> UnifiedComplianceView:
    """
    Generate a unified compliance view across frameworks.

    Args:
        frameworks: List of frameworks to include.
        control_states: Optional pre-populated control states.

    Returns:
        Complete unified compliance view.
    """
    import uuid

    view_id = f"UCV-{uuid.uuid4().hex[:8].upper()}"
    generated_at = datetime.now(UTC)

    # Initialize framework states
    framework_states: dict[FrameworkID, FrameworkComplianceState] = {}
    for framework in frameworks:
        state = FrameworkComplianceState(
            framework=framework,
            framework_name=FRAMEWORK_NAMES.get(framework, framework.value),
            last_updated=generated_at,
        )
        framework_states[framework] = state

    # Populate from control states if provided
    if control_states:
        for control_id, ctrl_state in control_states.items():
            framework = ctrl_state.framework
            if framework in framework_states:
                framework_states[framework].control_states[control_id] = ctrl_state
                framework_states[framework].total_controls += 1

                if ctrl_state.status == ComplianceStatus.COMPLIANT:
                    framework_states[framework].compliant_count += 1
                elif ctrl_state.status == ComplianceStatus.PARTIAL:
                    framework_states[framework].partial_count += 1
                elif ctrl_state.status == ComplianceStatus.NON_COMPLIANT:
                    framework_states[framework].non_compliant_count += 1
                else:
                    framework_states[framework].not_assessed_count += 1

        # Calculate percentages
        for state in framework_states.values():
            state.calculate_percentage()

    # Calculate overall compliance
    if framework_states:
        overall = sum(s.compliance_percentage for s in framework_states.values()) / len(framework_states)
    else:
        overall = 0.0

    # Get shared controls
    shared_controls = get_shared_control_coverage(frameworks)

    # Analyze gaps between framework pairs
    framework_gaps: dict[str, FrameworkGapAnalysis] = {}
    for i, source in enumerate(frameworks):
        for target in frameworks[i + 1:]:
            pair_key = f"{source.value}:{target.value}"
            # Get sample controls for analysis
            mappings = get_all_mappings_between(source, target)
            if mappings:
                source_controls = list(set(m.source_control for m in mappings))
                analysis = analyze_gaps(source, target, source_controls)
                framework_gaps[pair_key] = analysis

    # Generate prioritized efforts
    prioritized_efforts = get_effort_prioritization(frameworks, framework_gaps)

    # Build statistics
    statistics = {
        "total_frameworks": len(frameworks),
        "total_shared_controls": len(shared_controls),
        "high_value_shared_controls": len([c for c in shared_controls if c.is_high_value]),
        "framework_coverage_summary": {
            f.value: {
                "compliance_pct": round(framework_states[f].compliance_percentage, 1),
                "total_controls": framework_states[f].total_controls,
            }
            for f in frameworks
        },
        "gap_analysis_pairs": len(framework_gaps),
        "prioritized_efforts_count": len(prioritized_efforts),
    }

    return UnifiedComplianceView(
        view_id=view_id,
        generated_at=generated_at,
        frameworks=frameworks,
        framework_states=framework_states,
        overall_compliance=overall,
        shared_controls=shared_controls,
        framework_gaps=framework_gaps,
        prioritized_efforts=prioritized_efforts,
        statistics=statistics,
    )


def get_shared_control_coverage(
    frameworks: list[FrameworkID],
    min_frameworks: int = 2,
) -> list[SharedControlCoverage]:
    """
    Get controls that provide coverage across multiple frameworks.

    Args:
        frameworks: Frameworks to analyze.
        min_frameworks: Minimum number of frameworks for "shared" status.

    Returns:
        List of shared control coverage items, sorted by coverage.
    """
    registry = get_mapping_registry()
    shared_controls: list[SharedControlCoverage] = []

    # Track controls we've already analyzed
    seen_controls: set[tuple[FrameworkID, str]] = set()

    for source_framework in frameworks:
        # Get all mappings from this framework
        pair_mappings = [
            registry.get_pair_mapping(source_framework, target)
            for target in frameworks
            if target != source_framework
        ]

        # Collect unique source controls
        source_controls: set[str] = set()
        for pair in pair_mappings:
            if pair:
                for mapping in pair.mappings:
                    source_controls.add(mapping.source_control)

        # Analyze each source control
        for control_id in source_controls:
            key = (source_framework, control_id)
            if key in seen_controls:
                continue
            seen_controls.add(key)

            # Get mappings to all other frameworks
            all_mappings = get_mappings_for_control(source_framework, control_id)

            covered = []
            strengths = {}
            for target_framework, mappings in all_mappings.items():
                if target_framework in frameworks and mappings:
                    best_strength = max(m.strength for m in mappings)
                    if best_strength >= 0.5:  # Meaningful mapping
                        covered.append(target_framework)
                        strengths[target_framework.value] = best_strength

            # Check if shared across enough frameworks
            total_covered = len(covered) + 1  # +1 for source framework
            if total_covered >= min_frameworks:
                is_high_value = total_covered >= 3 or (
                    total_covered >= 2 and all(s >= 0.8 for s in strengths.values())
                )

                shared = SharedControlCoverage(
                    primary_control_id=control_id,
                    primary_framework=source_framework,
                    covered_frameworks=covered,
                    coverage_strength=strengths,
                    total_frameworks_covered=total_covered,
                    is_high_value=is_high_value,
                )
                shared_controls.append(shared)

    # Sort by total coverage (descending), then by average strength
    shared_controls.sort(
        key=lambda c: (c.total_frameworks_covered, sum(c.coverage_strength.values()) / max(1, len(c.coverage_strength))),
        reverse=True,
    )

    return shared_controls


def get_framework_specific_gaps(
    view: UnifiedComplianceView,
) -> dict[FrameworkID, list[str]]:
    """
    Get gaps specific to each framework (not covered by others).

    Args:
        view: Unified compliance view.

    Returns:
        Dictionary mapping frameworks to their specific gap control IDs.
    """
    specific_gaps: dict[FrameworkID, list[str]] = {}

    for framework in view.frameworks:
        gaps = []
        state = view.framework_states.get(framework)
        if state:
            # Controls that are non-compliant and not shared
            shared_control_ids = {c.primary_control_id for c in view.shared_controls}
            for control_id, ctrl_state in state.control_states.items():
                if ctrl_state.status == ComplianceStatus.NON_COMPLIANT:
                    if control_id not in shared_control_ids:
                        gaps.append(control_id)
        specific_gaps[framework] = gaps

    return specific_gaps


def get_effort_prioritization(
    frameworks: list[FrameworkID],
    gap_analyses: dict[str, FrameworkGapAnalysis],
) -> list[EffortPrioritization]:
    """
    Generate prioritized remediation efforts based on impact.

    Args:
        frameworks: Frameworks being managed.
        gap_analyses: Gap analyses between framework pairs.

    Returns:
        Sorted list of prioritized efforts.
    """
    efforts: list[EffortPrioritization] = []
    seen_controls: set[str] = set()

    # Collect all gaps
    all_gaps = []
    for analysis in gap_analyses.values():
        for gap in analysis.gaps:
            all_gaps.append((analysis, gap))

    # Score and prioritize
    for analysis, gap in all_gaps:
        if gap.source_control in seen_controls:
            continue
        seen_controls.add(gap.source_control)

        # Calculate impact score based on:
        # - Number of frameworks affected
        # - Severity of gaps
        # - Mapping coverage
        affected_frameworks = [analysis.source_framework]
        impact_score = 0.0

        # Check other framework mappings
        mappings = get_mappings_for_control(analysis.source_framework, gap.source_control)
        for target in frameworks:
            if target in mappings:
                affected_frameworks.append(target)

        # Impact based on frameworks affected
        impact_score += len(affected_frameworks) * 25

        # Impact based on severity
        severity_multipliers = {
            GapSeverity.CRITICAL: 40,
            GapSeverity.HIGH: 30,
            GapSeverity.MEDIUM: 20,
            GapSeverity.LOW: 10,
        }
        impact_score += severity_multipliers.get(gap.severity, 15)

        # Determine priority
        if gap.severity == GapSeverity.CRITICAL or impact_score >= 80:
            priority = PriorityLevel.CRITICAL
        elif gap.severity == GapSeverity.HIGH or impact_score >= 60:
            priority = PriorityLevel.HIGH
        elif impact_score >= 40:
            priority = PriorityLevel.MEDIUM
        else:
            priority = PriorityLevel.LOW

        # Build rationale
        rationale_parts = []
        if len(affected_frameworks) > 1:
            rationale_parts.append(f"Affects {len(affected_frameworks)} frameworks")
        if gap.severity in [GapSeverity.CRITICAL, GapSeverity.HIGH]:
            rationale_parts.append(f"{gap.severity.value.title()} severity gap")
        if not rationale_parts:
            rationale_parts.append("Standard remediation priority")

        effort = EffortPrioritization(
            control_id=gap.source_control,
            framework=analysis.source_framework,
            priority=priority,
            impact_score=min(100, impact_score),
            frameworks_affected=affected_frameworks,
            gap_severity=gap.severity,
            estimated_effort=gap.remediation_effort,
            rationale="; ".join(rationale_parts),
        )
        efforts.append(effort)

    # Sort by priority then impact score
    priority_order = {
        PriorityLevel.CRITICAL: 0,
        PriorityLevel.HIGH: 1,
        PriorityLevel.MEDIUM: 2,
        PriorityLevel.LOW: 3,
    }
    efforts.sort(key=lambda e: (priority_order[e.priority], -e.impact_score))

    return efforts


def export_dashboard_data(
    view: UnifiedComplianceView,
    format: str = "json",
) -> dict[str, Any] | str:
    """
    Export dashboard data in various formats.

    Args:
        view: Unified compliance view to export.
        format: Export format ("json", "summary").

    Returns:
        Exported data (dict for json, string for summary).
    """
    if format == "json":
        return view.to_dict()

    elif format == "summary":
        lines = [
            "=" * 60,
            "UNIFIED COMPLIANCE DASHBOARD",
            f"Generated: {view.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
            f"View ID: {view.view_id}",
            "=" * 60,
            "",
            "OVERALL COMPLIANCE",
            "-" * 40,
            f"Overall Score: {view.overall_compliance:.1f}%",
            f"Frameworks Monitored: {len(view.frameworks)}",
            "",
            "FRAMEWORK STATUS",
            "-" * 40,
        ]

        for framework in view.frameworks:
            state = view.framework_states.get(framework)
            if state:
                lines.append(
                    f"  {state.framework_name}: {state.compliance_percentage:.1f}% "
                    f"({state.compliant_count}/{state.total_controls} controls)"
                )

        lines.extend([
            "",
            "SHARED CONTROLS",
            "-" * 40,
            f"Total shared controls: {len(view.shared_controls)}",
            f"High-value shared: {len([c for c in view.shared_controls if c.is_high_value])}",
            "",
            "TOP PRIORITY REMEDIATION",
            "-" * 40,
        ])

        for effort in view.prioritized_efforts[:5]:
            lines.append(
                f"  [{effort.priority.value.upper()}] {effort.control_id} "
                f"(Impact: {effort.impact_score:.0f})"
            )

        lines.append("=" * 60)

        return "\n".join(lines)

    else:
        raise ValueError(f"Unknown format: {format}")


__all__ = [
    # Enums
    "ComplianceStatus",
    "PriorityLevel",
    # Constants
    "STATUS_COLORS",
    "PRIORITY_COLORS",
    # Data classes
    "ControlComplianceState",
    "FrameworkComplianceState",
    "SharedControlCoverage",
    "EffortPrioritization",
    "UnifiedComplianceView",
    # Functions
    "generate_unified_view",
    "get_shared_control_coverage",
    "get_framework_specific_gaps",
    "get_effort_prioritization",
    "export_dashboard_data",
]
