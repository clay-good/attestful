"""
NIST CSF 2.0 maturity scoring calculator.

This module calculates maturity levels (0-4) for NIST CSF 2.0 controls,
categories, and functions based on evidence mapping results. All scoring
is deterministic and auditable.

Maturity Levels (aligned with NIST implementation tiers):
    - Level 0: No evidence, control not addressed
    - Level 1: Partial evidence, informal/ad-hoc processes
    - Level 2: Evidence of documented processes, some automation
    - Level 3: Consistent evidence, automated controls, measured
    - Level 4: Optimized, continuous improvement, advanced automation

Scoring Algorithm:
    1. Subcategory scores are calculated from evidence mapping results
    2. Category scores are weighted averages of subcategory scores
    3. Function scores are weighted averages of category scores
    4. Overall score is weighted average of function scores

All thresholds are configurable via the MaturityConfig class.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from attestful.frameworks.nist.csf2_controls import (
    get_all_categories,
    get_all_functions,
    get_all_subcategories,
    get_category,
    get_function,
    get_subcategory,
)
from attestful.frameworks.nist.mapping_engine import ControlMappingResult, MappingStatus

logger = logging.getLogger(__name__)


class EntityType(str, Enum):
    """Type of entity being scored."""

    SUBCATEGORY = "subcategory"
    CATEGORY = "category"
    FUNCTION = "function"
    OVERALL = "overall"


@dataclass
class MaturityConfig:
    """
    Configuration for maturity scoring thresholds.

    All values are configurable to allow customization of the scoring
    algorithm based on organizational requirements.

    Attributes:
        satisfied_fresh_score: Base score for satisfied controls with fresh evidence.
        satisfied_stale_score: Base score for satisfied controls with stale evidence.
        partial_score: Base score for partially satisfied controls.
        unsatisfied_score: Base score for unsatisfied controls.
        automation_bonus: Bonus for automated evidence collection.
        improvement_bonus: Bonus for evidence showing improvement over time.
        coverage_gap_penalty: Penalty for evidence with coverage gaps.
        max_score: Maximum possible score.
        min_score: Minimum possible score.
        freshness_threshold_days: Days before evidence is considered stale.
        level_thresholds: Score thresholds for each maturity level.
    """

    # Base scores by mapping status
    satisfied_fresh_score: float = 3.0
    satisfied_stale_score: float = 2.0
    partial_score: float = 1.5
    unsatisfied_score: float = 0.0

    # Score modifiers
    automation_bonus: float = 0.5
    improvement_bonus: float = 0.5
    coverage_gap_penalty: float = 0.5

    # Bounds
    max_score: float = 4.0
    min_score: float = 0.0

    # Freshness
    freshness_threshold_days: int = 30

    # Level thresholds (score >= threshold = level)
    level_thresholds: dict[int, float] = field(
        default_factory=lambda: {
            0: 0.0,
            1: 0.5,
            2: 1.5,
            3: 2.5,
            4: 3.5,
        }
    )

    def score_to_level(self, score: float) -> int:
        """
        Convert a numeric score to a maturity level.

        Args:
            score: Numeric score (0.0 - 4.0).

        Returns:
            Maturity level (0-4).
        """
        level = 0
        for lvl, threshold in sorted(self.level_thresholds.items()):
            if score >= threshold:
                level = lvl
            else:
                break
        return level


@dataclass
class MaturityScore:
    """
    Maturity score for an entity (subcategory, category, function, or overall).

    Attributes:
        entity_id: ID of the entity (control/category/function or "overall").
        entity_type: Type of entity being scored.
        level: Maturity level (0-4).
        score: Numeric score (0.0 - 4.0) for decimal precision.
        evidence_count: Number of evidence items supporting this score.
        last_evidence_date: Most recent evidence date.
        confidence: Confidence in the score (0.0 - 1.0).
        explanation: Human-readable explanation of the score.
        contributing_scores: Scores that contributed to this roll-up (for aggregates).
        delta: Change from previous score (if available).
    """

    entity_id: str
    entity_type: EntityType
    level: int
    score: float
    evidence_count: int
    last_evidence_date: datetime | None
    confidence: float
    explanation: str
    contributing_scores: list[MaturityScore] = field(default_factory=list)
    delta: float | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type.value,
            "level": self.level,
            "score": round(self.score, 2),
            "evidence_count": self.evidence_count,
            "last_evidence_date": (
                self.last_evidence_date.isoformat()
                if self.last_evidence_date
                else None
            ),
            "confidence": round(self.confidence, 3),
            "explanation": self.explanation,
            "delta": round(self.delta, 2) if self.delta is not None else None,
        }


@dataclass
class MaturityBreakdown:
    """
    Complete maturity breakdown for the organization.

    Attributes:
        timestamp: When the breakdown was calculated.
        overall: Overall maturity score.
        by_function: Scores by function.
        by_category: Scores by category.
        by_subcategory: Scores by subcategory.
        statistics: Summary statistics.
    """

    timestamp: datetime
    overall: MaturityScore
    by_function: dict[str, MaturityScore]
    by_category: dict[str, MaturityScore]
    by_subcategory: dict[str, MaturityScore]
    statistics: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "overall": self.overall.to_dict(),
            "by_function": {k: v.to_dict() for k, v in self.by_function.items()},
            "by_category": {k: v.to_dict() for k, v in self.by_category.items()},
            "by_subcategory": {k: v.to_dict() for k, v in self.by_subcategory.items()},
            "statistics": self.statistics,
        }


class MaturityCalculator:
    """
    Calculator for NIST CSF 2.0 maturity scores.

    Calculates maturity levels for subcategories, categories, functions,
    and overall based on evidence mapping results. All scoring is
    deterministic and fully auditable.

    Example:
        calculator = MaturityCalculator()

        # Calculate from mapping results
        breakdown = calculator.calculate_all(mapping_results)

        # Get specific scores
        func_score = calculator.calculate_function_maturity("PR", mapping_results)
        cat_score = calculator.calculate_category_maturity("PR.AC", mapping_results)

        # Compare to previous
        delta = calculator.compare_to_previous(current_score, previous_score)

    Attributes:
        config: MaturityConfig with scoring thresholds.
    """

    def __init__(self, config: MaturityConfig | None = None) -> None:
        """
        Initialize the maturity calculator.

        Args:
            config: MaturityConfig with scoring thresholds.
                Defaults to standard thresholds.
        """
        self.config = config or MaturityConfig()

    def calculate_subcategory_maturity(
        self,
        control_id: str,
        mapping_result: ControlMappingResult | None,
        previous_score: MaturityScore | None = None,
    ) -> MaturityScore:
        """
        Calculate maturity score for a single subcategory.

        Args:
            control_id: NIST subcategory ID (e.g., "PR.AC-01").
            mapping_result: Mapping result for this control (or None if unmapped).
            previous_score: Previous score for delta calculation.

        Returns:
            MaturityScore for the subcategory.
        """
        subcategory = get_subcategory(control_id)
        control_name = subcategory.name if subcategory else control_id

        # No mapping result means no evidence
        if mapping_result is None:
            score = self.config.unsatisfied_score
            explanation = (
                f"Control {control_id} ({control_name}) has no evidence mapping. "
                "This control requires manual evidence or collector configuration."
            )
            return MaturityScore(
                entity_id=control_id,
                entity_type=EntityType.SUBCATEGORY,
                level=self.config.score_to_level(score),
                score=score,
                evidence_count=0,
                last_evidence_date=None,
                confidence=0.0,
                explanation=explanation,
                delta=self._calculate_delta(score, previous_score),
            )

        # Calculate base score from mapping status
        is_stale = self._is_stale(mapping_result.last_evidence_date)

        if mapping_result.status == MappingStatus.SATISFIED:
            if is_stale:
                base_score = self.config.satisfied_stale_score
                status_desc = "satisfied with stale evidence"
            else:
                base_score = self.config.satisfied_fresh_score
                status_desc = "satisfied with fresh evidence"
        elif mapping_result.status == MappingStatus.PARTIAL:
            base_score = self.config.partial_score
            status_desc = "partially satisfied"
        elif mapping_result.status == MappingStatus.NOT_APPLICABLE:
            # Not applicable controls get a neutral score
            base_score = self.config.satisfied_fresh_score
            status_desc = "not applicable (neutral score)"
        else:
            base_score = self.config.unsatisfied_score
            status_desc = "unsatisfied"

        # Apply modifiers
        modifiers = []
        score = base_score

        # Automation bonus: if evidence was collected recently and consistently
        if (
            mapping_result.status == MappingStatus.SATISFIED
            and not is_stale
            and len(mapping_result.evidence_ids) > 0
        ):
            # Assume automated if we have fresh evidence
            score += self.config.automation_bonus
            modifiers.append(f"+{self.config.automation_bonus} automation bonus")

        # Coverage gap penalty: if evidence types are missing
        if mapping_result.evidence_types_missing:
            score -= self.config.coverage_gap_penalty
            modifiers.append(
                f"-{self.config.coverage_gap_penalty} coverage gap "
                f"(missing: {', '.join(mapping_result.evidence_types_missing)})"
            )

        # Improvement bonus: compare to previous score
        if previous_score and previous_score.score < score:
            score += self.config.improvement_bonus
            modifiers.append(f"+{self.config.improvement_bonus} improvement bonus")

        # Apply bounds
        score = max(self.config.min_score, min(self.config.max_score, score))

        # Build explanation
        explanation_parts = [
            f"Control {control_id} ({control_name}) is {status_desc}.",
            f"Base score: {base_score:.1f}.",
        ]
        if modifiers:
            explanation_parts.append(f"Modifiers: {'; '.join(modifiers)}.")
        explanation_parts.append(f"Final score: {score:.2f} (Level {self.config.score_to_level(score)}).")

        if mapping_result.last_evidence_date:
            age_days = (datetime.now(UTC) - mapping_result.last_evidence_date).days
            explanation_parts.append(f"Evidence age: {age_days} days.")

        return MaturityScore(
            entity_id=control_id,
            entity_type=EntityType.SUBCATEGORY,
            level=self.config.score_to_level(score),
            score=score,
            evidence_count=len(mapping_result.evidence_ids),
            last_evidence_date=mapping_result.last_evidence_date,
            confidence=mapping_result.confidence,
            explanation=" ".join(explanation_parts),
            delta=self._calculate_delta(score, previous_score),
        )

    def calculate_category_maturity(
        self,
        category_id: str,
        mapping_results: dict[str, ControlMappingResult],
        previous_scores: dict[str, MaturityScore] | None = None,
        weights: dict[str, float] | None = None,
    ) -> MaturityScore:
        """
        Calculate maturity score for a category (average of subcategories).

        Args:
            category_id: NIST category ID (e.g., "PR.AC").
            mapping_results: Mapping results by control ID.
            previous_scores: Previous scores by control ID for delta calculation.
            weights: Custom weights for subcategories (default: equal weight).

        Returns:
            MaturityScore for the category.
        """
        category = get_category(category_id)
        category_name = category.name if category else category_id

        # Get all subcategories for this category
        all_subcategories = get_all_subcategories()
        category_subcategories = [
            s for s in all_subcategories if s.id.startswith(category_id)
        ]

        if not category_subcategories:
            return MaturityScore(
                entity_id=category_id,
                entity_type=EntityType.CATEGORY,
                level=0,
                score=0.0,
                evidence_count=0,
                last_evidence_date=None,
                confidence=0.0,
                explanation=f"Category {category_id} has no subcategories.",
            )

        # Calculate scores for each subcategory
        subcategory_scores: list[MaturityScore] = []
        total_evidence = 0
        latest_date: datetime | None = None
        total_confidence = 0.0

        for subcategory in category_subcategories:
            mapping = mapping_results.get(subcategory.id)
            prev_score = previous_scores.get(subcategory.id) if previous_scores else None

            sub_score = self.calculate_subcategory_maturity(
                subcategory.id, mapping, prev_score
            )
            subcategory_scores.append(sub_score)

            total_evidence += sub_score.evidence_count
            total_confidence += sub_score.confidence

            if sub_score.last_evidence_date:
                if latest_date is None or sub_score.last_evidence_date > latest_date:
                    latest_date = sub_score.last_evidence_date

        # Calculate weighted average
        if weights:
            total_weight = sum(weights.get(s.entity_id, 1.0) for s in subcategory_scores)
            weighted_sum = sum(
                s.score * weights.get(s.entity_id, 1.0) for s in subcategory_scores
            )
            avg_score = weighted_sum / total_weight if total_weight > 0 else 0.0
        else:
            avg_score = (
                sum(s.score for s in subcategory_scores) / len(subcategory_scores)
                if subcategory_scores
                else 0.0
            )

        avg_confidence = (
            total_confidence / len(subcategory_scores) if subcategory_scores else 0.0
        )

        # Count by level for explanation
        level_counts = dict.fromkeys(range(5), 0)
        for s in subcategory_scores:
            level_counts[s.level] += 1

        explanation = (
            f"Category {category_id} ({category_name}) has {len(subcategory_scores)} subcategories. "
            f"Level distribution: L0={level_counts[0]}, L1={level_counts[1]}, "
            f"L2={level_counts[2]}, L3={level_counts[3]}, L4={level_counts[4]}. "
            f"Average score: {avg_score:.2f} (Level {self.config.score_to_level(avg_score)})."
        )

        # Calculate delta from previous category score
        prev_cat_score = None
        if previous_scores:
            prev_scores_list = [
                previous_scores.get(s.id)
                for s in category_subcategories
                if s.id in previous_scores
            ]
            if prev_scores_list:
                prev_avg = sum(s.score for s in prev_scores_list if s) / len(prev_scores_list)
                prev_cat_score = MaturityScore(
                    entity_id=category_id,
                    entity_type=EntityType.CATEGORY,
                    level=0,
                    score=prev_avg,
                    evidence_count=0,
                    last_evidence_date=None,
                    confidence=0.0,
                    explanation="",
                )

        return MaturityScore(
            entity_id=category_id,
            entity_type=EntityType.CATEGORY,
            level=self.config.score_to_level(avg_score),
            score=avg_score,
            evidence_count=total_evidence,
            last_evidence_date=latest_date,
            confidence=avg_confidence,
            explanation=explanation,
            contributing_scores=subcategory_scores,
            delta=self._calculate_delta(avg_score, prev_cat_score),
        )

    def calculate_function_maturity(
        self,
        function_id: str,
        mapping_results: dict[str, ControlMappingResult],
        previous_scores: dict[str, MaturityScore] | None = None,
        weights: dict[str, float] | None = None,
    ) -> MaturityScore:
        """
        Calculate maturity score for a function (average of categories).

        Args:
            function_id: NIST function ID (e.g., "PR").
            mapping_results: Mapping results by control ID.
            previous_scores: Previous scores by control ID for delta calculation.
            weights: Custom weights for categories (default: equal weight).

        Returns:
            MaturityScore for the function.
        """
        function = get_function(function_id)
        function_name = function.name if function else function_id

        # Get all categories for this function
        all_categories = get_all_categories()
        function_categories = [
            c for c in all_categories if c.id.startswith(function_id + ".")
        ]

        if not function_categories:
            return MaturityScore(
                entity_id=function_id,
                entity_type=EntityType.FUNCTION,
                level=0,
                score=0.0,
                evidence_count=0,
                last_evidence_date=None,
                confidence=0.0,
                explanation=f"Function {function_id} has no categories.",
            )

        # Calculate scores for each category
        category_scores: list[MaturityScore] = []
        total_evidence = 0
        latest_date: datetime | None = None
        total_confidence = 0.0

        for category in function_categories:
            cat_score = self.calculate_category_maturity(
                category.id, mapping_results, previous_scores
            )
            category_scores.append(cat_score)

            total_evidence += cat_score.evidence_count
            total_confidence += cat_score.confidence

            if cat_score.last_evidence_date:
                if latest_date is None or cat_score.last_evidence_date > latest_date:
                    latest_date = cat_score.last_evidence_date

        # Calculate weighted average
        if weights:
            total_weight = sum(weights.get(s.entity_id, 1.0) for s in category_scores)
            weighted_sum = sum(
                s.score * weights.get(s.entity_id, 1.0) for s in category_scores
            )
            avg_score = weighted_sum / total_weight if total_weight > 0 else 0.0
        else:
            avg_score = (
                sum(s.score for s in category_scores) / len(category_scores)
                if category_scores
                else 0.0
            )

        avg_confidence = (
            total_confidence / len(category_scores) if category_scores else 0.0
        )

        # Build explanation
        category_summary = ", ".join(
            f"{c.entity_id}={c.score:.1f}" for c in category_scores
        )
        explanation = (
            f"Function {function_id} ({function_name}) has {len(category_scores)} categories. "
            f"Category scores: {category_summary}. "
            f"Average score: {avg_score:.2f} (Level {self.config.score_to_level(avg_score)})."
        )

        return MaturityScore(
            entity_id=function_id,
            entity_type=EntityType.FUNCTION,
            level=self.config.score_to_level(avg_score),
            score=avg_score,
            evidence_count=total_evidence,
            last_evidence_date=latest_date,
            confidence=avg_confidence,
            explanation=explanation,
            contributing_scores=category_scores,
        )

    def calculate_overall_maturity(
        self,
        mapping_results: dict[str, ControlMappingResult],
        previous_scores: dict[str, MaturityScore] | None = None,
        weights: dict[str, float] | None = None,
    ) -> MaturityScore:
        """
        Calculate overall maturity score (average of functions).

        Args:
            mapping_results: Mapping results by control ID.
            previous_scores: Previous scores by control ID for delta calculation.
            weights: Custom weights for functions (default: equal weight).

        Returns:
            MaturityScore for overall organization.
        """
        all_functions = get_all_functions()

        function_scores: list[MaturityScore] = []
        total_evidence = 0
        latest_date: datetime | None = None
        total_confidence = 0.0

        for function in all_functions:
            func_score = self.calculate_function_maturity(
                function.id, mapping_results, previous_scores
            )
            function_scores.append(func_score)

            total_evidence += func_score.evidence_count
            total_confidence += func_score.confidence

            if func_score.last_evidence_date:
                if latest_date is None or func_score.last_evidence_date > latest_date:
                    latest_date = func_score.last_evidence_date

        # Calculate weighted average
        if weights:
            total_weight = sum(weights.get(s.entity_id, 1.0) for s in function_scores)
            weighted_sum = sum(
                s.score * weights.get(s.entity_id, 1.0) for s in function_scores
            )
            avg_score = weighted_sum / total_weight if total_weight > 0 else 0.0
        else:
            avg_score = (
                sum(s.score for s in function_scores) / len(function_scores)
                if function_scores
                else 0.0
            )

        avg_confidence = (
            total_confidence / len(function_scores) if function_scores else 0.0
        )

        # Build explanation
        function_summary = ", ".join(
            f"{f.entity_id}={f.score:.1f}" for f in function_scores
        )
        explanation = (
            f"Overall NIST CSF 2.0 maturity across {len(function_scores)} functions. "
            f"Function scores: {function_summary}. "
            f"Overall score: {avg_score:.2f} (Level {self.config.score_to_level(avg_score)})."
        )

        return MaturityScore(
            entity_id="overall",
            entity_type=EntityType.OVERALL,
            level=self.config.score_to_level(avg_score),
            score=avg_score,
            evidence_count=total_evidence,
            last_evidence_date=latest_date,
            confidence=avg_confidence,
            explanation=explanation,
            contributing_scores=function_scores,
        )

    def calculate_all(
        self,
        mapping_results: list[ControlMappingResult],
        previous_scores: dict[str, MaturityScore] | None = None,
    ) -> MaturityBreakdown:
        """
        Calculate complete maturity breakdown.

        Args:
            mapping_results: List of mapping results from MappingEngine.
            previous_scores: Previous scores by entity ID for delta calculation.

        Returns:
            MaturityBreakdown with all scores.
        """
        # Index mapping results by control ID
        results_by_id = {r.control_id: r for r in mapping_results}

        # Calculate all subcategory scores
        all_subcategories = get_all_subcategories()
        subcategory_scores: dict[str, MaturityScore] = {}

        for subcategory in all_subcategories:
            mapping = results_by_id.get(subcategory.id)
            prev_score = previous_scores.get(subcategory.id) if previous_scores else None
            score = self.calculate_subcategory_maturity(subcategory.id, mapping, prev_score)
            subcategory_scores[subcategory.id] = score

        # Calculate all category scores
        all_categories = get_all_categories()
        category_scores: dict[str, MaturityScore] = {}

        for category in all_categories:
            score = self.calculate_category_maturity(
                category.id, results_by_id, previous_scores
            )
            category_scores[category.id] = score

        # Calculate all function scores
        all_functions = get_all_functions()
        function_scores: dict[str, MaturityScore] = {}

        for function in all_functions:
            score = self.calculate_function_maturity(
                function.id, results_by_id, previous_scores
            )
            function_scores[function.id] = score

        # Calculate overall
        overall = self.calculate_overall_maturity(results_by_id, previous_scores)

        # Calculate statistics
        level_counts = dict.fromkeys(range(5), 0)
        for score in subcategory_scores.values():
            level_counts[score.level] += 1

        with_evidence = sum(1 for s in subcategory_scores.values() if s.evidence_count > 0)

        statistics = {
            "total_subcategories": len(subcategory_scores),
            "total_categories": len(category_scores),
            "total_functions": len(function_scores),
            "subcategories_with_evidence": with_evidence,
            "subcategories_without_evidence": len(subcategory_scores) - with_evidence,
            "level_distribution": level_counts,
            "average_confidence": overall.confidence,
        }

        return MaturityBreakdown(
            timestamp=datetime.now(UTC),
            overall=overall,
            by_function=function_scores,
            by_category=category_scores,
            by_subcategory=subcategory_scores,
            statistics=statistics,
        )

    def _is_stale(self, evidence_date: datetime | None) -> bool:
        """Check if evidence is older than freshness threshold."""
        if evidence_date is None:
            return True
        age = datetime.now(UTC) - evidence_date
        return age.days > self.config.freshness_threshold_days

    def _calculate_delta(
        self,
        current_score: float,
        previous: MaturityScore | None,
    ) -> float | None:
        """Calculate score change from previous."""
        if previous is None:
            return None
        return round(current_score - previous.score, 2)

    def compare_breakdowns(
        self,
        current: MaturityBreakdown,
        previous: MaturityBreakdown,
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
        overall_delta = current.overall.score - previous.overall.score

        # Function changes
        function_deltas = {}
        for func_id, current_score in current.by_function.items():
            if func_id in previous.by_function:
                delta = current_score.score - previous.by_function[func_id].score
                function_deltas[func_id] = round(delta, 2)

        # Count improvements and regressions
        improved = 0
        regressed = 0
        unchanged = 0

        for sub_id, current_score in current.by_subcategory.items():
            if sub_id in previous.by_subcategory:
                delta = current_score.score - previous.by_subcategory[sub_id].score
                if delta > 0.1:
                    improved += 1
                elif delta < -0.1:
                    regressed += 1
                else:
                    unchanged += 1

        return {
            "overall_delta": round(overall_delta, 2),
            "overall_direction": (
                "improved" if overall_delta > 0.1
                else "regressed" if overall_delta < -0.1
                else "unchanged"
            ),
            "function_deltas": function_deltas,
            "subcategories_improved": improved,
            "subcategories_regressed": regressed,
            "subcategories_unchanged": unchanged,
            "time_between": str(current.timestamp - previous.timestamp),
        }

    # =========================================================================
    # OSCAL Integration Methods
    # =========================================================================

    def to_oscal_assessment_results(
        self,
        breakdown: MaturityBreakdown,
        *,
        title: str = "NIST CSF 2.0 Maturity Assessment",
        ssp_uuid: str | None = None,
    ) -> "AssessmentResults":
        """
        Convert maturity breakdown to OSCAL Assessment Results.

        Maps maturity scores to OSCAL findings and observations, enabling
        interoperability with other OSCAL-based tools.

        Args:
            breakdown: Complete maturity breakdown
            title: Title for the assessment results document
            ssp_uuid: Optional SSP UUID reference

        Returns:
            OSCAL AssessmentResults document
        """
        from uuid import uuid4
        from attestful.oscal.models import (
            AssessmentResults,
            Finding,
            Metadata,
            Observation,
            Property,
            Result,
        )

        # Create observations for each subcategory score
        observations = []
        findings = []

        for control_id, score in breakdown.by_subcategory.items():
            # Create observation
            obs_uuid = uuid4()
            obs = Observation(
                uuid=obs_uuid,
                title=f"Maturity Assessment: {control_id}",
                description=score.explanation,
                collected=breakdown.timestamp,
                methods=["EXAMINE", "INTERVIEW"],
                props=[
                    Property(name="maturity-level", value=str(score.level)),
                    Property(name="maturity-score", value=f"{score.score:.2f}"),
                    Property(name="evidence-count", value=str(score.evidence_count)),
                    Property(name="confidence", value=f"{score.confidence:.3f}"),
                ] + (
                    [Property(name="delta", value=f"{score.delta:+.2f}")]
                    if score.delta is not None else []
                ),
            )
            observations.append(obs)

            # Create finding (only for low maturity levels)
            if score.level < 2:  # Level 0 or 1
                finding = Finding(
                    uuid=uuid4(),
                    title=f"Low Maturity: {control_id}",
                    description=f"Control {control_id} has maturity level {score.level} "
                               f"(score: {score.score:.2f}). {score.explanation}",
                    target={
                        "type": "control-id",
                        "target-id": control_id,
                        "status": {
                            "state": self._level_to_state(score.level),
                        },
                    },
                    related_observations=[{"observation-uuid": str(obs_uuid)}],
                    props=[
                        Property(name="maturity-level", value=str(score.level)),
                        Property(name="risk-level", value=self._level_to_risk(score.level)),
                        Property(name="framework", value="NIST-CSF"),
                        Property(name="framework-version", value="2.0"),
                    ],
                )
                findings.append(finding)

        # Add function-level observations
        for func_id, score in breakdown.by_function.items():
            obs = Observation(
                uuid=uuid4(),
                title=f"Function Maturity: {func_id}",
                description=score.explanation,
                collected=breakdown.timestamp,
                methods=["EXAMINE"],
                props=[
                    Property(name="entity-type", value="function"),
                    Property(name="maturity-level", value=str(score.level)),
                    Property(name="maturity-score", value=f"{score.score:.2f}"),
                ],
            )
            observations.append(obs)

        # Create overall observation
        observations.append(
            Observation(
                uuid=uuid4(),
                title="Overall NIST CSF 2.0 Maturity",
                description=breakdown.overall.explanation,
                collected=breakdown.timestamp,
                methods=["EXAMINE"],
                props=[
                    Property(name="entity-type", value="overall"),
                    Property(name="maturity-level", value=str(breakdown.overall.level)),
                    Property(name="maturity-score", value=f"{breakdown.overall.score:.2f}"),
                    Property(name="total-controls", value=str(breakdown.statistics["total_subcategories"])),
                    Property(name="controls-with-evidence", value=str(breakdown.statistics["subcategories_with_evidence"])),
                ],
            )
        )

        # Create the result
        result = Result(
            uuid=uuid4(),
            title=f"Maturity Assessment - {breakdown.timestamp.strftime('%Y-%m-%d')}",
            description="NIST CSF 2.0 maturity assessment results",
            start=breakdown.timestamp,
            end=breakdown.timestamp,
            observations=observations,
            findings=findings if findings else None,
            props=[
                Property(name="overall-maturity-level", value=str(breakdown.overall.level)),
                Property(name="overall-maturity-score", value=f"{breakdown.overall.score:.2f}"),
                Property(
                    name="level-distribution",
                    value=str(breakdown.statistics["level_distribution"]),
                ),
            ],
        )

        # Create metadata
        metadata = Metadata(
            title=title,
            version="1.0.0",
            oscal_version="1.1.2",
            last_modified=breakdown.timestamp,
            props=[
                Property(name="framework", value="NIST-CSF"),
                Property(name="framework-version", value="2.0"),
                Property(name="assessment-type", value="maturity"),
            ],
        )

        # Create assessment results
        return AssessmentResults(
            uuid=uuid4(),
            metadata=metadata,
            import_ap={"href": "#ap-1"} if not ssp_uuid else None,
            results=[result],
        )

    def from_oscal_assessment_results(
        self,
        results: "AssessmentResults",
    ) -> dict[str, MaturityScore]:
        """
        Extract maturity scores from OSCAL Assessment Results.

        Enables loading previous assessment data for trend analysis.

        Args:
            results: OSCAL AssessmentResults document

        Returns:
            Dictionary mapping control IDs to MaturityScore objects
        """
        scores: dict[str, MaturityScore] = {}

        if not results.results:
            return scores

        for result in results.results:
            if not result.observations:
                continue

            for obs in result.observations:
                # Skip non-control observations
                if not obs.title or not obs.title.startswith("Maturity Assessment:"):
                    continue

                # Extract control ID from title
                control_id = obs.title.replace("Maturity Assessment:", "").strip()

                # Extract properties
                level = 0
                score_value = 0.0
                evidence_count = 0
                confidence = 0.0
                delta = None

                if obs.props:
                    for prop in obs.props:
                        if prop.name == "maturity-level":
                            level = int(prop.value)
                        elif prop.name == "maturity-score":
                            score_value = float(prop.value)
                        elif prop.name == "evidence-count":
                            evidence_count = int(prop.value)
                        elif prop.name == "confidence":
                            confidence = float(prop.value)
                        elif prop.name == "delta":
                            delta = float(prop.value)

                scores[control_id] = MaturityScore(
                    entity_id=control_id,
                    entity_type=EntityType.SUBCATEGORY,
                    level=level,
                    score=score_value,
                    evidence_count=evidence_count,
                    last_evidence_date=obs.collected,
                    confidence=confidence,
                    explanation=obs.description or "",
                    delta=delta,
                )

        return scores

    def _level_to_state(self, level: int) -> str:
        """Convert maturity level to OSCAL finding state."""
        if level >= 3:
            return "satisfied"
        elif level >= 2:
            return "not-satisfied"
        else:
            return "not-satisfied"

    def _level_to_risk(self, level: int) -> str:
        """Convert maturity level to risk level."""
        if level == 0:
            return "very-high"
        elif level == 1:
            return "high"
        elif level == 2:
            return "moderate"
        elif level == 3:
            return "low"
        else:
            return "very-low"
