"""
HITRUST CSF Maturity Scoring Calculator.

This module calculates maturity levels (1-5) for HITRUST CSF controls,
categories, and overall compliance based on evidence and check results.

HITRUST Maturity Levels:
------------------------
Unlike other frameworks that use 0-4 scales, HITRUST uses a 1-5 scale where
each level represents a different aspect of control implementation:

    - Level 1 (Policy): Policy exists and is documented
    - Level 2 (Procedure): Procedure exists and is implemented
    - Level 3 (Implemented): Control is fully implemented
    - Level 4 (Measured): Control is measured and monitored
    - Level 5 (Managed): Control is managed and optimized

HITRUST Certification Thresholds:
---------------------------------
    - r2 Validated Assessment: Minimum Level 3 for all required controls
    - i1 Validated Assessment: Level 2 sufficient for many controls
    - e1 Basic Assessment: Level 1 documentation focus

Scoring Methodology:
--------------------
Each level requires specific evidence types:
    1. Policy: Policy document review
    2. Procedure: Process documentation + implementation evidence
    3. Implemented: Technical configuration evidence + automated checks
    4. Measured: Metrics, KPIs, audit logs
    5. Managed: Continuous improvement evidence, trend analysis

Roll-up Scoring:
----------------
    1. Control scores are individual assessments (Level 1-5)
    2. Category scores are averages of control scores
    3. Overall score is weighted average across categories
    4. Certification eligibility based on minimum level requirements
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from attestful.core.logging import get_logger
from attestful.frameworks.hitrust.controls import (
    HITRUST_CONTROLS,
    CATEGORY_NAMES,
    MATURITY_POLICY,
    MATURITY_PROCEDURE,
    MATURITY_IMPLEMENTED,
    MATURITY_MEASURED,
    MATURITY_MANAGED,
    MATURITY_LEVEL_NAMES,
    get_control,
    get_controls_by_category,
    get_all_categories,
)

logger = get_logger("frameworks.hitrust.maturity")


# =============================================================================
# Enums and Constants
# =============================================================================


class HITRUSTCertificationType(str, Enum):
    """HITRUST certification/assessment types."""

    E1_BASIC = "e1"  # Basic, Current-State Assessment
    I1_VALIDATED = "i1"  # Implemented, 1-year Validated Assessment
    R2_VALIDATED = "r2"  # Risk-based, 2-year Validated Assessment


class MaturityEntityType(str, Enum):
    """Type of entity being scored."""

    CONTROL = "control"
    CATEGORY = "category"
    OVERALL = "overall"


# Certification minimum level requirements
CERTIFICATION_REQUIREMENTS = {
    HITRUSTCertificationType.E1_BASIC: {
        "min_level": 1,
        "description": "Policy documentation focus",
        "validity_years": 1,
    },
    HITRUSTCertificationType.I1_VALIDATED: {
        "min_level": 2,
        "description": "Implementation focus with some measurement",
        "validity_years": 1,
    },
    HITRUSTCertificationType.R2_VALIDATED: {
        "min_level": 3,
        "description": "Full implementation with measurement",
        "validity_years": 2,
    },
}

# Evidence types required for each maturity level
LEVEL_EVIDENCE_REQUIREMENTS = {
    MATURITY_POLICY: ["policy_document", "policy_approval"],
    MATURITY_PROCEDURE: ["procedure_document", "training_records", "process_evidence"],
    MATURITY_IMPLEMENTED: ["configuration_evidence", "automated_check_results", "implementation_evidence"],
    MATURITY_MEASURED: ["metrics", "kpis", "audit_logs", "monitoring_data"],
    MATURITY_MANAGED: ["improvement_plans", "trend_analysis", "optimization_evidence"],
}


# =============================================================================
# Configuration
# =============================================================================


@dataclass
class HITRUSTMaturityConfig:
    """
    Configuration for HITRUST maturity scoring.

    Attributes:
        policy_threshold: Score threshold for Level 1 (Policy).
        procedure_threshold: Score threshold for Level 2 (Procedure).
        implemented_threshold: Score threshold for Level 3 (Implemented).
        measured_threshold: Score threshold for Level 4 (Measured).
        managed_threshold: Score threshold for Level 5 (Managed).
        automation_bonus: Bonus for automated evidence collection.
        freshness_threshold_days: Days before evidence is considered stale.
        stale_evidence_penalty: Penalty multiplier for stale evidence.
        category_weights: Custom weights for categories (default: equal).
    """

    # Level thresholds (score >= threshold = level achieved)
    policy_threshold: float = 80.0
    procedure_threshold: float = 80.0
    implemented_threshold: float = 80.0
    measured_threshold: float = 80.0
    managed_threshold: float = 80.0

    # Modifiers
    automation_bonus: float = 5.0
    freshness_threshold_days: int = 90
    stale_evidence_penalty: float = 0.8

    # Category weights (default: equal weight)
    category_weights: dict[str, float] = field(default_factory=dict)

    def get_category_weight(self, category_code: str) -> float:
        """Get weight for a category (default 1.0)."""
        return self.category_weights.get(category_code, 1.0)


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class HITRUSTControlScore:
    """
    Maturity score for a single HITRUST control.

    Attributes:
        control_id: HITRUST control ID.
        control_title: Control title.
        category: Control category code.
        policy_score: Score for Level 1 (0-100).
        procedure_score: Score for Level 2 (0-100).
        implemented_score: Score for Level 3 (0-100).
        measured_score: Score for Level 4 (0-100).
        managed_score: Score for Level 5 (0-100).
        overall_level: Calculated maturity level (1-5, or 0 if no level achieved).
        evidence_count: Number of evidence items.
        last_evidence_date: Most recent evidence date.
        automated_checks_passed: Number of automated checks passed.
        automated_checks_total: Total automated checks applicable.
        explanation: Human-readable explanation.
        evidence_gaps: Missing evidence types.
    """

    control_id: str
    control_title: str
    category: str
    policy_score: float = 0.0
    procedure_score: float = 0.0
    implemented_score: float = 0.0
    measured_score: float = 0.0
    managed_score: float = 0.0
    overall_level: int = 0
    evidence_count: int = 0
    last_evidence_date: datetime | None = None
    automated_checks_passed: int = 0
    automated_checks_total: int = 0
    explanation: str = ""
    evidence_gaps: list[str] = field(default_factory=list)

    @property
    def automation_rate(self) -> float:
        """Calculate automation pass rate."""
        if self.automated_checks_total == 0:
            return 0.0
        return (self.automated_checks_passed / self.automated_checks_total) * 100

    @property
    def level_name(self) -> str:
        """Get the name of the current maturity level."""
        if self.overall_level == 0:
            return "Not Achieved"
        return MATURITY_LEVEL_NAMES.get(self.overall_level, f"Level {self.overall_level}")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "control_id": self.control_id,
            "control_title": self.control_title,
            "category": self.category,
            "scores": {
                "policy": round(self.policy_score, 1),
                "procedure": round(self.procedure_score, 1),
                "implemented": round(self.implemented_score, 1),
                "measured": round(self.measured_score, 1),
                "managed": round(self.managed_score, 1),
            },
            "overall_level": self.overall_level,
            "level_name": self.level_name,
            "evidence_count": self.evidence_count,
            "last_evidence_date": (
                self.last_evidence_date.isoformat()
                if self.last_evidence_date else None
            ),
            "automation_rate": round(self.automation_rate, 1),
            "automated_checks": {
                "passed": self.automated_checks_passed,
                "total": self.automated_checks_total,
            },
            "explanation": self.explanation,
            "evidence_gaps": self.evidence_gaps,
        }


@dataclass
class HITRUSTCategoryScore:
    """
    Maturity score for a HITRUST category.

    Attributes:
        category_code: Category code (e.g., "01").
        category_name: Category display name.
        avg_level: Average maturity level across controls.
        min_level: Minimum level in category.
        max_level: Maximum level in category.
        control_count: Number of controls in category.
        level_distribution: Count of controls at each level.
        controls_at_level: Controls achieving specific levels.
        contributing_scores: Individual control scores.
    """

    category_code: str
    category_name: str
    avg_level: float = 0.0
    min_level: int = 0
    max_level: int = 0
    control_count: int = 0
    level_distribution: dict[int, int] = field(default_factory=dict)
    controls_at_level: dict[int, list[str]] = field(default_factory=dict)
    contributing_scores: list[HITRUSTControlScore] = field(default_factory=list)

    @property
    def effective_level(self) -> int:
        """Effective category level (floor of average)."""
        return int(self.avg_level)

    @property
    def level_name(self) -> str:
        """Get the name of the effective maturity level."""
        if self.effective_level == 0:
            return "Not Achieved"
        return MATURITY_LEVEL_NAMES.get(self.effective_level, f"Level {self.effective_level}")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "category_code": self.category_code,
            "category_name": self.category_name,
            "avg_level": round(self.avg_level, 2),
            "effective_level": self.effective_level,
            "level_name": self.level_name,
            "min_level": self.min_level,
            "max_level": self.max_level,
            "control_count": self.control_count,
            "level_distribution": self.level_distribution,
        }


@dataclass
class HITRUSTMaturityBreakdown:
    """
    Complete HITRUST maturity breakdown for an organization.

    Attributes:
        timestamp: When the breakdown was calculated.
        overall_level: Overall maturity level.
        overall_avg: Average maturity score.
        by_category: Scores by category.
        by_control: Scores by control.
        certification_eligibility: Certification types the org is eligible for.
        statistics: Summary statistics.
    """

    timestamp: datetime
    overall_level: int
    overall_avg: float
    by_category: dict[str, HITRUSTCategoryScore]
    by_control: dict[str, HITRUSTControlScore]
    certification_eligibility: dict[str, bool]
    statistics: dict[str, Any]

    @property
    def overall_level_name(self) -> str:
        """Get the name of the overall maturity level."""
        if self.overall_level == 0:
            return "Not Achieved"
        return MATURITY_LEVEL_NAMES.get(self.overall_level, f"Level {self.overall_level}")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "overall": {
                "level": self.overall_level,
                "level_name": self.overall_level_name,
                "average": round(self.overall_avg, 2),
            },
            "by_category": {k: v.to_dict() for k, v in self.by_category.items()},
            "certification_eligibility": self.certification_eligibility,
            "statistics": self.statistics,
        }


@dataclass
class CertificationGapAnalysis:
    """
    Gap analysis for HITRUST certification eligibility.

    Attributes:
        certification_type: Target certification type.
        is_eligible: Whether organization is currently eligible.
        required_level: Minimum level required.
        controls_below_threshold: Controls not meeting minimum level.
        gap_count: Number of controls with gaps.
        remediation_priority: Prioritized list of controls to remediate.
        estimated_effort: Estimated effort to achieve certification.
    """

    certification_type: HITRUSTCertificationType
    is_eligible: bool
    required_level: int
    controls_below_threshold: list[dict[str, Any]]
    gap_count: int
    remediation_priority: list[str]
    estimated_effort: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "certification_type": self.certification_type.value,
            "is_eligible": self.is_eligible,
            "required_level": self.required_level,
            "controls_below_threshold": self.controls_below_threshold,
            "gap_count": self.gap_count,
            "remediation_priority": self.remediation_priority,
            "estimated_effort": self.estimated_effort,
        }


# =============================================================================
# Input Data Classes
# =============================================================================


@dataclass
class ControlEvidenceInput:
    """
    Evidence input for a HITRUST control maturity calculation.

    Attributes:
        control_id: HITRUST control ID.
        evidence_items: List of evidence items with metadata.
        automated_check_results: Results from automated checks.
    """

    control_id: str
    evidence_items: list[dict[str, Any]] = field(default_factory=list)
    automated_check_results: list[dict[str, Any]] = field(default_factory=list)

    @property
    def evidence_types(self) -> set[str]:
        """Get unique evidence types."""
        return {e.get("type", "unknown") for e in self.evidence_items}

    @property
    def latest_evidence_date(self) -> datetime | None:
        """Get most recent evidence date."""
        dates = [
            e.get("collected_at") for e in self.evidence_items
            if e.get("collected_at")
        ]
        if not dates:
            return None
        # Handle both datetime and string formats
        parsed = []
        for d in dates:
            if isinstance(d, datetime):
                parsed.append(d)
            elif isinstance(d, str):
                try:
                    parsed.append(datetime.fromisoformat(d.replace("Z", "+00:00")))
                except ValueError:
                    pass
        return max(parsed) if parsed else None


# =============================================================================
# Calculator Class
# =============================================================================


class HITRUSTMaturityCalculator:
    """
    Calculator for HITRUST CSF maturity scores.

    Implements the HITRUST 5-level maturity model with support for:
    - Individual control scoring
    - Category roll-up scoring
    - Overall organizational maturity
    - Certification eligibility analysis
    - Gap analysis and remediation prioritization

    Example:
        calculator = HITRUSTMaturityCalculator()

        # Score a single control
        control_score = calculator.calculate_control_maturity(
            "01.a", evidence_input
        )

        # Calculate full breakdown
        breakdown = calculator.calculate_all(evidence_inputs)

        # Check certification eligibility
        gap_analysis = calculator.analyze_certification_gap(
            breakdown, HITRUSTCertificationType.R2_VALIDATED
        )
    """

    def __init__(self, config: HITRUSTMaturityConfig | None = None) -> None:
        """
        Initialize the maturity calculator.

        Args:
            config: HITRUSTMaturityConfig with scoring thresholds.
        """
        self.config = config or HITRUSTMaturityConfig()

    def calculate_control_maturity(
        self,
        control_id: str,
        evidence_input: ControlEvidenceInput | None = None,
    ) -> HITRUSTControlScore:
        """
        Calculate maturity score for a single HITRUST control.

        Uses evidence items and automated check results to determine
        scores for each maturity level dimension.

        Args:
            control_id: HITRUST control ID (e.g., "01.a").
            evidence_input: Evidence and check results for the control.

        Returns:
            HITRUSTControlScore with level-by-level breakdown.
        """
        control = get_control(control_id)
        if not control:
            return HITRUSTControlScore(
                control_id=control_id,
                control_title="Unknown Control",
                category="00",
                explanation=f"Control {control_id} not found in HITRUST catalog.",
            )

        # Initialize scores
        scores = {
            MATURITY_POLICY: 0.0,
            MATURITY_PROCEDURE: 0.0,
            MATURITY_IMPLEMENTED: 0.0,
            MATURITY_MEASURED: 0.0,
            MATURITY_MANAGED: 0.0,
        }

        evidence_gaps = []
        evidence_count = 0
        last_evidence_date = None
        checks_passed = 0
        checks_total = 0

        if evidence_input:
            evidence_count = len(evidence_input.evidence_items)
            last_evidence_date = evidence_input.latest_evidence_date
            evidence_types = evidence_input.evidence_types

            # Score each level based on evidence types present
            for level, required_types in LEVEL_EVIDENCE_REQUIREMENTS.items():
                present_types = [t for t in required_types if t in evidence_types]
                if present_types:
                    coverage = len(present_types) / len(required_types)
                    scores[level] = coverage * 100
                else:
                    evidence_gaps.extend(required_types)

            # Apply stale evidence penalty
            if last_evidence_date:
                age_days = (datetime.now(UTC) - last_evidence_date).days
                if age_days > self.config.freshness_threshold_days:
                    for level in scores:
                        scores[level] *= self.config.stale_evidence_penalty

            # Process automated check results
            for check_result in evidence_input.automated_check_results:
                checks_total += 1
                if check_result.get("passed", False):
                    checks_passed += 1

            # Boost implemented score with automation results
            if checks_total > 0:
                automation_rate = checks_passed / checks_total
                automation_boost = automation_rate * self.config.automation_bonus
                scores[MATURITY_IMPLEMENTED] = min(
                    100, scores[MATURITY_IMPLEMENTED] + automation_boost
                )

        # Calculate overall level
        overall_level = self._calculate_overall_level(scores)

        # Build explanation
        explanation = self._build_control_explanation(
            control_id, control.title, scores, overall_level, evidence_count
        )

        return HITRUSTControlScore(
            control_id=control_id,
            control_title=control.title,
            category=control.category,
            policy_score=scores[MATURITY_POLICY],
            procedure_score=scores[MATURITY_PROCEDURE],
            implemented_score=scores[MATURITY_IMPLEMENTED],
            measured_score=scores[MATURITY_MEASURED],
            managed_score=scores[MATURITY_MANAGED],
            overall_level=overall_level,
            evidence_count=evidence_count,
            last_evidence_date=last_evidence_date,
            automated_checks_passed=checks_passed,
            automated_checks_total=checks_total,
            explanation=explanation,
            evidence_gaps=list(set(evidence_gaps)),
        )

    def calculate_category_maturity(
        self,
        category_code: str,
        control_scores: dict[str, HITRUSTControlScore],
    ) -> HITRUSTCategoryScore:
        """
        Calculate maturity score for a HITRUST category.

        Args:
            category_code: Category code (e.g., "01").
            control_scores: Pre-calculated control scores.

        Returns:
            HITRUSTCategoryScore with statistics.
        """
        category_name = CATEGORY_NAMES.get(category_code, f"Category {category_code}")

        # Get controls in this category
        category_controls = get_controls_by_category(category_code)
        if not category_controls:
            return HITRUSTCategoryScore(
                category_code=category_code,
                category_name=category_name,
            )

        # Collect scores for controls in this category
        contributing_scores = []
        levels = []

        for control in category_controls:
            score = control_scores.get(control.id)
            if score:
                contributing_scores.append(score)
                levels.append(score.overall_level)

        if not levels:
            return HITRUSTCategoryScore(
                category_code=category_code,
                category_name=category_name,
            )

        # Calculate statistics
        avg_level = sum(levels) / len(levels)
        min_level = min(levels)
        max_level = max(levels)

        # Level distribution
        level_distribution = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
        controls_at_level: dict[int, list[str]] = {0: [], 1: [], 2: [], 3: [], 4: [], 5: []}

        for score in contributing_scores:
            level_distribution[score.overall_level] += 1
            controls_at_level[score.overall_level].append(score.control_id)

        return HITRUSTCategoryScore(
            category_code=category_code,
            category_name=category_name,
            avg_level=avg_level,
            min_level=min_level,
            max_level=max_level,
            control_count=len(contributing_scores),
            level_distribution=level_distribution,
            controls_at_level=controls_at_level,
            contributing_scores=contributing_scores,
        )

    def calculate_overall_maturity(
        self,
        category_scores: dict[str, HITRUSTCategoryScore],
    ) -> tuple[int, float]:
        """
        Calculate overall organizational maturity.

        Args:
            category_scores: Pre-calculated category scores.

        Returns:
            Tuple of (overall_level, overall_average).
        """
        if not category_scores:
            return 0, 0.0

        # Weighted average of category levels
        total_weight = 0.0
        weighted_sum = 0.0

        for cat_code, cat_score in category_scores.items():
            weight = self.config.get_category_weight(cat_code)
            weighted_sum += cat_score.avg_level * weight
            total_weight += weight

        if total_weight == 0:
            return 0, 0.0

        overall_avg = weighted_sum / total_weight
        overall_level = int(overall_avg)  # Floor to get conservative level

        return overall_level, overall_avg

    def calculate_all(
        self,
        evidence_inputs: list[ControlEvidenceInput] | None = None,
    ) -> HITRUSTMaturityBreakdown:
        """
        Calculate complete HITRUST maturity breakdown.

        Args:
            evidence_inputs: List of evidence inputs for controls.

        Returns:
            HITRUSTMaturityBreakdown with full analysis.
        """
        # Index evidence inputs by control ID
        evidence_by_control: dict[str, ControlEvidenceInput] = {}
        if evidence_inputs:
            for ei in evidence_inputs:
                evidence_by_control[ei.control_id] = ei

        # Calculate control scores
        control_scores: dict[str, HITRUSTControlScore] = {}
        for control_id in HITRUST_CONTROLS.keys():
            evidence = evidence_by_control.get(control_id)
            score = self.calculate_control_maturity(control_id, evidence)
            control_scores[control_id] = score

        # Calculate category scores
        category_scores: dict[str, HITRUSTCategoryScore] = {}
        for category_code in get_all_categories():
            cat_score = self.calculate_category_maturity(category_code, control_scores)
            category_scores[category_code] = cat_score

        # Calculate overall
        overall_level, overall_avg = self.calculate_overall_maturity(category_scores)

        # Check certification eligibility
        certification_eligibility = {
            cert_type.value: self._check_certification_eligibility(
                control_scores, cert_type
            )
            for cert_type in HITRUSTCertificationType
        }

        # Calculate statistics
        level_counts = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
        for score in control_scores.values():
            level_counts[score.overall_level] += 1

        with_evidence = sum(1 for s in control_scores.values() if s.evidence_count > 0)
        with_automation = sum(1 for s in control_scores.values() if s.automated_checks_total > 0)

        statistics = {
            "total_controls": len(control_scores),
            "total_categories": len(category_scores),
            "controls_with_evidence": with_evidence,
            "controls_with_automation": with_automation,
            "level_distribution": level_counts,
            "category_summary": {
                code: {
                    "name": cat.category_name,
                    "avg_level": round(cat.avg_level, 2),
                    "control_count": cat.control_count,
                }
                for code, cat in category_scores.items()
            },
        }

        return HITRUSTMaturityBreakdown(
            timestamp=datetime.now(UTC),
            overall_level=overall_level,
            overall_avg=overall_avg,
            by_category=category_scores,
            by_control=control_scores,
            certification_eligibility=certification_eligibility,
            statistics=statistics,
        )

    def analyze_certification_gap(
        self,
        breakdown: HITRUSTMaturityBreakdown,
        target_certification: HITRUSTCertificationType,
    ) -> CertificationGapAnalysis:
        """
        Analyze gaps for certification eligibility.

        Args:
            breakdown: Complete maturity breakdown.
            target_certification: Target certification type.

        Returns:
            CertificationGapAnalysis with remediation guidance.
        """
        requirements = CERTIFICATION_REQUIREMENTS[target_certification]
        required_level = requirements["min_level"]

        # Find controls below threshold
        controls_below = []
        for control_id, score in breakdown.by_control.items():
            if score.overall_level < required_level:
                gap = required_level - score.overall_level
                controls_below.append({
                    "control_id": control_id,
                    "control_title": score.control_title,
                    "category": score.category,
                    "current_level": score.overall_level,
                    "required_level": required_level,
                    "gap": gap,
                    "evidence_gaps": score.evidence_gaps,
                })

        # Sort by gap size (largest first) then by category
        controls_below.sort(key=lambda x: (-x["gap"], x["category"]))

        # Determine remediation priority
        remediation_priority = [c["control_id"] for c in controls_below[:20]]

        # Estimate effort
        if len(controls_below) == 0:
            estimated_effort = "None - Already eligible"
        elif len(controls_below) <= 10:
            estimated_effort = "Low - Minor gaps to address"
        elif len(controls_below) <= 30:
            estimated_effort = "Medium - Moderate remediation needed"
        else:
            estimated_effort = "High - Significant work required"

        return CertificationGapAnalysis(
            certification_type=target_certification,
            is_eligible=len(controls_below) == 0,
            required_level=required_level,
            controls_below_threshold=controls_below,
            gap_count=len(controls_below),
            remediation_priority=remediation_priority,
            estimated_effort=estimated_effort,
        )

    def compare_breakdowns(
        self,
        current: HITRUSTMaturityBreakdown,
        previous: HITRUSTMaturityBreakdown,
    ) -> dict[str, Any]:
        """
        Compare two maturity breakdowns for trend analysis.

        Args:
            current: Current maturity breakdown.
            previous: Previous maturity breakdown.

        Returns:
            Dictionary with comparison results.
        """
        # Overall change
        overall_delta = current.overall_avg - previous.overall_avg
        level_delta = current.overall_level - previous.overall_level

        # Category changes
        category_deltas = {}
        for cat_code in current.by_category:
            if cat_code in previous.by_category:
                delta = current.by_category[cat_code].avg_level - previous.by_category[cat_code].avg_level
                category_deltas[cat_code] = round(delta, 2)

        # Control changes
        improved = 0
        regressed = 0
        unchanged = 0

        for control_id in current.by_control:
            if control_id in previous.by_control:
                current_level = current.by_control[control_id].overall_level
                previous_level = previous.by_control[control_id].overall_level
                if current_level > previous_level:
                    improved += 1
                elif current_level < previous_level:
                    regressed += 1
                else:
                    unchanged += 1

        return {
            "overall_delta": round(overall_delta, 2),
            "level_delta": level_delta,
            "direction": (
                "improved" if overall_delta > 0.1
                else "regressed" if overall_delta < -0.1
                else "unchanged"
            ),
            "category_deltas": category_deltas,
            "controls_improved": improved,
            "controls_regressed": regressed,
            "controls_unchanged": unchanged,
            "time_between": str(current.timestamp - previous.timestamp),
        }

    def generate_maturity_report(
        self,
        breakdown: HITRUSTMaturityBreakdown,
    ) -> dict[str, Any]:
        """
        Generate a comprehensive maturity report.

        Args:
            breakdown: Complete maturity breakdown.

        Returns:
            Report dictionary suitable for rendering.
        """
        # Executive summary
        executive_summary = {
            "overall_level": breakdown.overall_level,
            "overall_level_name": breakdown.overall_level_name,
            "overall_average": round(breakdown.overall_avg, 2),
            "assessment_date": breakdown.timestamp.isoformat(),
            "certification_eligibility": breakdown.certification_eligibility,
        }

        # Category summaries
        category_summaries = []
        for code in sorted(breakdown.by_category.keys()):
            cat = breakdown.by_category[code]
            category_summaries.append({
                "code": code,
                "name": cat.category_name,
                "level": cat.effective_level,
                "level_name": cat.level_name,
                "average": round(cat.avg_level, 2),
                "control_count": cat.control_count,
                "min_level": cat.min_level,
                "max_level": cat.max_level,
            })

        # Level distribution summary
        total = breakdown.statistics["total_controls"]
        distribution = breakdown.statistics["level_distribution"]
        level_percentages = {
            level: round((count / total * 100) if total > 0 else 0, 1)
            for level, count in distribution.items()
        }

        # Top gaps (controls at Level 0 or 1)
        top_gaps = [
            {
                "control_id": score.control_id,
                "title": score.control_title,
                "category": score.category,
                "level": score.overall_level,
                "evidence_gaps": score.evidence_gaps[:3],
            }
            for score in breakdown.by_control.values()
            if score.overall_level < 2
        ][:10]

        return {
            "executive_summary": executive_summary,
            "category_summaries": category_summaries,
            "level_distribution": {
                "counts": distribution,
                "percentages": level_percentages,
            },
            "top_gaps": top_gaps,
            "statistics": breakdown.statistics,
        }

    # =========================================================================
    # Private Helper Methods
    # =========================================================================

    def _calculate_overall_level(self, scores: dict[int, float]) -> int:
        """
        Calculate overall maturity level based on dimension scores.

        HITRUST requires all lower levels to be achieved before higher levels.
        """
        if scores[MATURITY_MANAGED] >= self.config.managed_threshold:
            if all(scores[l] >= self.config.managed_threshold for l in range(1, 5)):
                return MATURITY_MANAGED

        if scores[MATURITY_MEASURED] >= self.config.measured_threshold:
            if all(scores[l] >= self.config.measured_threshold for l in range(1, 4)):
                return MATURITY_MEASURED

        if scores[MATURITY_IMPLEMENTED] >= self.config.implemented_threshold:
            if all(scores[l] >= self.config.implemented_threshold for l in range(1, 3)):
                return MATURITY_IMPLEMENTED

        if scores[MATURITY_PROCEDURE] >= self.config.procedure_threshold:
            if scores[MATURITY_POLICY] >= self.config.policy_threshold:
                return MATURITY_PROCEDURE

        if scores[MATURITY_POLICY] >= self.config.policy_threshold:
            return MATURITY_POLICY

        return 0  # No level achieved

    def _build_control_explanation(
        self,
        control_id: str,
        title: str,
        scores: dict[int, float],
        overall_level: int,
        evidence_count: int,
    ) -> str:
        """Build human-readable explanation for control score."""
        level_name = MATURITY_LEVEL_NAMES.get(overall_level, "Not Achieved")

        parts = [
            f"Control {control_id} ({title}) achieved Level {overall_level} ({level_name}).",
        ]

        if evidence_count > 0:
            parts.append(f"Based on {evidence_count} evidence items.")
        else:
            parts.append("No evidence collected.")

        # Add score breakdown
        score_desc = []
        for level in [MATURITY_POLICY, MATURITY_PROCEDURE, MATURITY_IMPLEMENTED,
                      MATURITY_MEASURED, MATURITY_MANAGED]:
            level_label = MATURITY_LEVEL_NAMES[level][:3].upper()
            score_desc.append(f"{level_label}:{scores[level]:.0f}%")

        parts.append(f"Scores: {', '.join(score_desc)}.")

        return " ".join(parts)

    def _check_certification_eligibility(
        self,
        control_scores: dict[str, HITRUSTControlScore],
        certification_type: HITRUSTCertificationType,
    ) -> bool:
        """Check if all controls meet certification requirements."""
        requirements = CERTIFICATION_REQUIREMENTS[certification_type]
        min_level = requirements["min_level"]

        for score in control_scores.values():
            if score.overall_level < min_level:
                return False

        return True


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # Enums
    "HITRUSTCertificationType",
    "MaturityEntityType",
    # Constants
    "CERTIFICATION_REQUIREMENTS",
    "LEVEL_EVIDENCE_REQUIREMENTS",
    # Configuration
    "HITRUSTMaturityConfig",
    # Data classes
    "HITRUSTControlScore",
    "HITRUSTCategoryScore",
    "HITRUSTMaturityBreakdown",
    "CertificationGapAnalysis",
    "ControlEvidenceInput",
    # Calculator
    "HITRUSTMaturityCalculator",
]
