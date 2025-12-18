"""
Trend tracking for NIST CSF 2.0 compliance maturity over time.

This module analyzes historical maturity snapshots to identify trends,
improvements, and regressions in compliance posture. All analysis is
deterministic and based on stored maturity snapshots.

Trend Types:
    - improving: Consistent upward movement in maturity score
    - regressing: Consistent downward movement in maturity score
    - stable: No significant change in maturity score
    - volatile: Fluctuating scores without clear direction
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from attestful.frameworks.nist.csf2_controls import (
    get_all_categories,
    get_all_functions,
    get_all_subcategories,
)
from attestful.frameworks.nist.maturity_calculator import MaturityBreakdown

logger = logging.getLogger(__name__)


class TrendDirection(str, Enum):
    """Direction of maturity trend."""

    IMPROVING = "improving"
    REGRESSING = "regressing"
    STABLE = "stable"
    VOLATILE = "volatile"
    INSUFFICIENT_DATA = "insufficient_data"


@dataclass
class TrendPoint:
    """
    A single point in a maturity trend.

    Attributes:
        timestamp: When this snapshot was taken.
        score: Maturity score at this point.
        level: Maturity level at this point.
        evidence_count: Number of evidence items at this point.
    """

    timestamp: datetime
    score: float
    level: int
    evidence_count: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "score": round(self.score, 2),
            "level": self.level,
            "evidence_count": self.evidence_count,
        }


@dataclass
class TrendItem:
    """
    Trend analysis for a single entity (control, category, function, or overall).

    Attributes:
        entity_id: ID of the entity being tracked.
        entity_type: Type of entity (subcategory, category, function, overall).
        entity_name: Human-readable name.
        direction: Overall trend direction.
        current_score: Most recent maturity score.
        previous_score: Previous maturity score (for comparison).
        score_delta: Change in score from previous to current.
        score_delta_percent: Percentage change in score.
        period_start: Start of trend period.
        period_end: End of trend period.
        data_points: Historical data points for charting.
        analysis: Human-readable trend analysis.
    """

    entity_id: str
    entity_type: str
    entity_name: str
    direction: TrendDirection
    current_score: float
    previous_score: float | None
    score_delta: float | None
    score_delta_percent: float | None
    period_start: datetime
    period_end: datetime
    data_points: list[TrendPoint] = field(default_factory=list)
    analysis: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "entity_name": self.entity_name,
            "direction": self.direction.value,
            "current_score": round(self.current_score, 2),
            "previous_score": (
                round(self.previous_score, 2) if self.previous_score else None
            ),
            "score_delta": round(self.score_delta, 2) if self.score_delta else None,
            "score_delta_percent": (
                round(self.score_delta_percent, 1) if self.score_delta_percent else None
            ),
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "data_points": [p.to_dict() for p in self.data_points],
            "analysis": self.analysis,
        }


@dataclass
class TrendAnalysis:
    """
    Complete trend analysis results.

    Attributes:
        timestamp: When the analysis was performed.
        period_days: Number of days analyzed.
        overall_trend: Overall organization trend.
        function_trends: Trends by NIST function.
        category_trends: Trends by NIST category.
        improving_controls: Controls showing improvement.
        regressing_controls: Controls showing regression.
        stable_controls: Controls with stable scores.
        volatile_controls: Controls with volatile scores.
        statistics: Summary statistics.
        chart_data: Data formatted for dashboard charts.
    """

    timestamp: datetime
    period_days: int
    overall_trend: TrendItem
    function_trends: dict[str, TrendItem]
    category_trends: dict[str, TrendItem]
    improving_controls: list[TrendItem]
    regressing_controls: list[TrendItem]
    stable_controls: list[TrendItem]
    volatile_controls: list[TrendItem]
    statistics: dict[str, Any]
    chart_data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "period_days": self.period_days,
            "overall_trend": self.overall_trend.to_dict(),
            "function_trends": {k: v.to_dict() for k, v in self.function_trends.items()},
            "category_trends": {k: v.to_dict() for k, v in self.category_trends.items()},
            "improving_controls": [t.to_dict() for t in self.improving_controls],
            "regressing_controls": [t.to_dict() for t in self.regressing_controls],
            "stable_controls": [t.to_dict() for t in self.stable_controls],
            "volatile_controls": [t.to_dict() for t in self.volatile_controls],
            "statistics": self.statistics,
            "chart_data": self.chart_data,
        }


@dataclass
class TrendTrackerConfig:
    """
    Configuration for trend tracking.

    Attributes:
        default_period_days: Default number of days to analyze.
        improvement_threshold: Minimum score change to be considered improvement.
        regression_threshold: Minimum score change to be considered regression.
        volatility_threshold: Score change that indicates volatility.
        min_data_points: Minimum data points needed for trend analysis.
    """

    default_period_days: int = 90
    improvement_threshold: float = 0.2
    regression_threshold: float = -0.2
    volatility_threshold: float = 0.5
    min_data_points: int = 2


class TrendTracker:
    """
    Tracker for analyzing compliance maturity trends over time.

    Compares current maturity to historical snapshots to identify
    improvements, regressions, and patterns in compliance posture.

    Example:
        tracker = TrendTracker(evidence_store)

        # Calculate trends for last 90 days
        analysis = tracker.calculate_trends(days=90)

        # Get controls that are improving
        improving = tracker.get_improving_controls()

        # Get controls that have regressed
        regressing = tracker.get_regressing_controls()

        # Get chart data for dashboard
        chart_data = analysis.chart_data

    Attributes:
        config: TrendTrackerConfig with analysis settings.
    """

    def __init__(
        self,
        config: TrendTrackerConfig | None = None,
    ) -> None:
        """
        Initialize the trend tracker.

        Args:
            config: TrendTrackerConfig with analysis settings.
                Defaults to standard settings.
        """
        self.config = config or TrendTrackerConfig()
        self._last_analysis: TrendAnalysis | None = None

    def calculate_trends(
        self,
        snapshots: list[MaturityBreakdown],
        days: int | None = None,
    ) -> TrendAnalysis:
        """
        Calculate trends from historical maturity snapshots.

        Args:
            snapshots: List of MaturityBreakdown snapshots, ordered by timestamp.
            days: Number of days to analyze (overrides config).

        Returns:
            TrendAnalysis with complete trend information.
        """
        period_days = days or self.config.default_period_days

        if not snapshots:
            return self._create_empty_analysis(period_days)

        # Sort snapshots by timestamp
        sorted_snapshots = sorted(snapshots, key=lambda s: s.timestamp)

        # Filter to requested period
        cutoff = datetime.now(UTC) - timedelta(days=period_days)
        period_snapshots = [s for s in sorted_snapshots if s.timestamp >= cutoff]

        if len(period_snapshots) < self.config.min_data_points:
            return self._create_empty_analysis(period_days)

        # Calculate overall trend
        overall_trend = self._calculate_entity_trend(
            entity_id="overall",
            entity_type="overall",
            entity_name="Overall Maturity",
            snapshots=period_snapshots,
            score_extractor=lambda s: s.overall.score,
            level_extractor=lambda s: s.overall.level,
            evidence_extractor=lambda s: s.overall.evidence_count,
        )

        # Calculate function trends
        function_trends: dict[str, TrendItem] = {}
        for function in get_all_functions():
            trend = self._calculate_entity_trend(
                entity_id=function.id,
                entity_type="function",
                entity_name=function.name,
                snapshots=period_snapshots,
                score_extractor=lambda s, fid=function.id: (
                    s.by_function[fid].score if fid in s.by_function else 0.0
                ),
                level_extractor=lambda s, fid=function.id: (
                    s.by_function[fid].level if fid in s.by_function else 0
                ),
                evidence_extractor=lambda s, fid=function.id: (
                    s.by_function[fid].evidence_count if fid in s.by_function else 0
                ),
            )
            function_trends[function.id] = trend

        # Calculate category trends
        category_trends: dict[str, TrendItem] = {}
        for category in get_all_categories():
            trend = self._calculate_entity_trend(
                entity_id=category.id,
                entity_type="category",
                entity_name=category.name,
                snapshots=period_snapshots,
                score_extractor=lambda s, cid=category.id: (
                    s.by_category[cid].score if cid in s.by_category else 0.0
                ),
                level_extractor=lambda s, cid=category.id: (
                    s.by_category[cid].level if cid in s.by_category else 0
                ),
                evidence_extractor=lambda s, cid=category.id: (
                    s.by_category[cid].evidence_count if cid in s.by_category else 0
                ),
            )
            category_trends[category.id] = trend

        # Calculate subcategory trends and categorize
        improving_controls: list[TrendItem] = []
        regressing_controls: list[TrendItem] = []
        stable_controls: list[TrendItem] = []
        volatile_controls: list[TrendItem] = []

        for subcategory in get_all_subcategories():
            trend = self._calculate_entity_trend(
                entity_id=subcategory.id,
                entity_type="subcategory",
                entity_name=subcategory.name,
                snapshots=period_snapshots,
                score_extractor=lambda s, sid=subcategory.id: (
                    s.by_subcategory[sid].score if sid in s.by_subcategory else 0.0
                ),
                level_extractor=lambda s, sid=subcategory.id: (
                    s.by_subcategory[sid].level if sid in s.by_subcategory else 0
                ),
                evidence_extractor=lambda s, sid=subcategory.id: (
                    s.by_subcategory[sid].evidence_count if sid in s.by_subcategory else 0
                ),
            )

            if trend.direction == TrendDirection.IMPROVING:
                improving_controls.append(trend)
            elif trend.direction == TrendDirection.REGRESSING:
                regressing_controls.append(trend)
            elif trend.direction == TrendDirection.VOLATILE:
                volatile_controls.append(trend)
            else:
                stable_controls.append(trend)

        # Sort by magnitude of change
        improving_controls.sort(
            key=lambda t: t.score_delta or 0.0, reverse=True
        )
        regressing_controls.sort(
            key=lambda t: t.score_delta or 0.0
        )

        # Calculate statistics
        statistics = self._calculate_statistics(
            overall_trend=overall_trend,
            improving=len(improving_controls),
            regressing=len(regressing_controls),
            stable=len(stable_controls),
            volatile=len(volatile_controls),
            period_snapshots=period_snapshots,
        )

        # Generate chart data
        chart_data = self._generate_chart_data(
            overall_trend=overall_trend,
            function_trends=function_trends,
            period_snapshots=period_snapshots,
        )

        analysis = TrendAnalysis(
            timestamp=datetime.now(UTC),
            period_days=period_days,
            overall_trend=overall_trend,
            function_trends=function_trends,
            category_trends=category_trends,
            improving_controls=improving_controls,
            regressing_controls=regressing_controls,
            stable_controls=stable_controls,
            volatile_controls=volatile_controls,
            statistics=statistics,
            chart_data=chart_data,
        )

        self._last_analysis = analysis
        logger.info(
            "Trend analysis complete: %d improving, %d regressing, %d stable, %d volatile",
            len(improving_controls),
            len(regressing_controls),
            len(stable_controls),
            len(volatile_controls),
        )

        return analysis

    def _calculate_entity_trend(
        self,
        entity_id: str,
        entity_type: str,
        entity_name: str,
        snapshots: list[MaturityBreakdown],
        score_extractor: Any,
        level_extractor: Any,
        evidence_extractor: Any,
    ) -> TrendItem:
        """Calculate trend for a single entity."""
        if not snapshots:
            return TrendItem(
                entity_id=entity_id,
                entity_type=entity_type,
                entity_name=entity_name,
                direction=TrendDirection.INSUFFICIENT_DATA,
                current_score=0.0,
                previous_score=None,
                score_delta=None,
                score_delta_percent=None,
                period_start=datetime.now(UTC),
                period_end=datetime.now(UTC),
                analysis="Insufficient data for trend analysis.",
            )

        # Extract data points
        data_points: list[TrendPoint] = []
        for snapshot in snapshots:
            point = TrendPoint(
                timestamp=snapshot.timestamp,
                score=score_extractor(snapshot),
                level=level_extractor(snapshot),
                evidence_count=evidence_extractor(snapshot),
            )
            data_points.append(point)

        # Get current and previous scores
        current_score = data_points[-1].score
        previous_score = data_points[0].score if len(data_points) > 1 else None

        # Calculate delta
        score_delta = None
        score_delta_percent = None
        if previous_score is not None:
            score_delta = current_score - previous_score
            if previous_score > 0:
                score_delta_percent = (score_delta / previous_score) * 100

        # Determine direction
        direction = self._determine_direction(data_points, score_delta)

        # Build analysis text
        analysis = self._build_trend_analysis(
            entity_name=entity_name,
            direction=direction,
            current_score=current_score,
            score_delta=score_delta,
            data_points=data_points,
        )

        return TrendItem(
            entity_id=entity_id,
            entity_type=entity_type,
            entity_name=entity_name,
            direction=direction,
            current_score=current_score,
            previous_score=previous_score,
            score_delta=score_delta,
            score_delta_percent=score_delta_percent,
            period_start=data_points[0].timestamp,
            period_end=data_points[-1].timestamp,
            data_points=data_points,
            analysis=analysis,
        )

    def _determine_direction(
        self,
        data_points: list[TrendPoint],
        score_delta: float | None,
    ) -> TrendDirection:
        """Determine trend direction from data points."""
        if len(data_points) < self.config.min_data_points:
            return TrendDirection.INSUFFICIENT_DATA

        if score_delta is None:
            return TrendDirection.INSUFFICIENT_DATA

        # Check for volatility (large swings in the data)
        if len(data_points) >= 3:
            scores = [p.score for p in data_points]
            max_swing = max(scores) - min(scores)
            if max_swing >= self.config.volatility_threshold:
                # Check if it's actually volatile or just a consistent change
                deltas = [scores[i + 1] - scores[i] for i in range(len(scores) - 1)]
                sign_changes = sum(
                    1 for i in range(len(deltas) - 1)
                    if (deltas[i] > 0) != (deltas[i + 1] > 0)
                )
                if sign_changes >= len(deltas) / 2:
                    return TrendDirection.VOLATILE

        # Check for improvement or regression
        if score_delta >= self.config.improvement_threshold:
            return TrendDirection.IMPROVING
        elif score_delta <= self.config.regression_threshold:
            return TrendDirection.REGRESSING
        else:
            return TrendDirection.STABLE

    def _build_trend_analysis(
        self,
        entity_name: str,
        direction: TrendDirection,
        current_score: float,
        score_delta: float | None,
        data_points: list[TrendPoint],
    ) -> str:
        """Build human-readable trend analysis."""
        if direction == TrendDirection.INSUFFICIENT_DATA:
            return f"{entity_name}: Insufficient historical data for trend analysis."

        delta_str = ""
        if score_delta is not None:
            sign = "+" if score_delta > 0 else ""
            delta_str = f" ({sign}{score_delta:.2f})"

        if direction == TrendDirection.IMPROVING:
            return (
                f"{entity_name} is improving. "
                f"Current score: {current_score:.2f}{delta_str}. "
                f"Analyzed {len(data_points)} snapshots over the period."
            )
        elif direction == TrendDirection.REGRESSING:
            return (
                f"{entity_name} has regressed. "
                f"Current score: {current_score:.2f}{delta_str}. "
                "Review recent changes and evidence collection."
            )
        elif direction == TrendDirection.VOLATILE:
            return (
                f"{entity_name} shows volatile scores. "
                f"Current score: {current_score:.2f}. "
                "Investigate causes of inconsistent maturity levels."
            )
        else:
            return (
                f"{entity_name} is stable. "
                f"Current score: {current_score:.2f}. "
                "No significant change over the analyzed period."
            )

    def _calculate_statistics(
        self,
        overall_trend: TrendItem,
        improving: int,
        regressing: int,
        stable: int,
        volatile: int,
        period_snapshots: list[MaturityBreakdown],
    ) -> dict[str, Any]:
        """Calculate summary statistics."""
        total_controls = improving + regressing + stable + volatile

        # Calculate average scores over time
        if period_snapshots:
            avg_scores = [s.overall.score for s in period_snapshots]
            avg_score = sum(avg_scores) / len(avg_scores)
            min_score = min(avg_scores)
            max_score = max(avg_scores)
        else:
            avg_score = 0.0
            min_score = 0.0
            max_score = 0.0

        return {
            "total_controls_analyzed": total_controls,
            "improving_count": improving,
            "regressing_count": regressing,
            "stable_count": stable,
            "volatile_count": volatile,
            "improving_percentage": (
                round(improving / total_controls * 100, 1) if total_controls > 0 else 0.0
            ),
            "regressing_percentage": (
                round(regressing / total_controls * 100, 1) if total_controls > 0 else 0.0
            ),
            "snapshots_analyzed": len(period_snapshots),
            "average_overall_score": round(avg_score, 2),
            "min_overall_score": round(min_score, 2),
            "max_overall_score": round(max_score, 2),
            "overall_direction": overall_trend.direction.value,
            "overall_delta": (
                round(overall_trend.score_delta, 2)
                if overall_trend.score_delta
                else None
            ),
        }

    def _generate_chart_data(
        self,
        overall_trend: TrendItem,
        function_trends: dict[str, TrendItem],
        period_snapshots: list[MaturityBreakdown],
    ) -> dict[str, Any]:
        """Generate data formatted for dashboard charts."""
        # Overall trend line chart data
        overall_line_data = {
            "labels": [p.timestamp.strftime("%Y-%m-%d") for p in overall_trend.data_points],
            "datasets": [
                {
                    "label": "Overall Maturity",
                    "data": [p.score for p in overall_trend.data_points],
                }
            ],
        }

        # Function comparison bar chart data
        function_bar_data = {
            "labels": list(function_trends.keys()),
            "datasets": [
                {
                    "label": "Current Score",
                    "data": [t.current_score for t in function_trends.values()],
                },
                {
                    "label": "Previous Score",
                    "data": [
                        t.previous_score if t.previous_score else 0.0
                        for t in function_trends.values()
                    ],
                },
            ],
        }

        # Function trend lines
        function_line_data: dict[str, Any] = {}
        for func_id, trend in function_trends.items():
            function_line_data[func_id] = {
                "labels": [p.timestamp.strftime("%Y-%m-%d") for p in trend.data_points],
                "data": [p.score for p in trend.data_points],
            }

        # Trend distribution pie chart data
        if self._last_analysis:
            trend_distribution = {
                "labels": ["Improving", "Stable", "Regressing", "Volatile"],
                "data": [
                    len(self._last_analysis.improving_controls),
                    len(self._last_analysis.stable_controls),
                    len(self._last_analysis.regressing_controls),
                    len(self._last_analysis.volatile_controls),
                ],
            }
        else:
            trend_distribution = {"labels": [], "data": []}

        return {
            "overall_line": overall_line_data,
            "function_bar": function_bar_data,
            "function_lines": function_line_data,
            "trend_distribution": trend_distribution,
        }

    def _create_empty_analysis(self, period_days: int) -> TrendAnalysis:
        """Create an empty analysis when no data is available."""
        now = datetime.now(UTC)
        empty_trend = TrendItem(
            entity_id="overall",
            entity_type="overall",
            entity_name="Overall Maturity",
            direction=TrendDirection.INSUFFICIENT_DATA,
            current_score=0.0,
            previous_score=None,
            score_delta=None,
            score_delta_percent=None,
            period_start=now - timedelta(days=period_days),
            period_end=now,
            analysis="No historical data available for trend analysis.",
        )

        return TrendAnalysis(
            timestamp=now,
            period_days=period_days,
            overall_trend=empty_trend,
            function_trends={},
            category_trends={},
            improving_controls=[],
            regressing_controls=[],
            stable_controls=[],
            volatile_controls=[],
            statistics={
                "total_controls_analyzed": 0,
                "improving_count": 0,
                "regressing_count": 0,
                "stable_count": 0,
                "volatile_count": 0,
                "snapshots_analyzed": 0,
            },
            chart_data={
                "overall_line": {"labels": [], "datasets": []},
                "function_bar": {"labels": [], "datasets": []},
                "function_lines": {},
                "trend_distribution": {"labels": [], "data": []},
            },
        )

    def get_improving_controls(self) -> list[TrendItem]:
        """
        Get controls that show consistent improvement.

        Returns:
            List of TrendItems for improving controls, sorted by magnitude.
        """
        if not self._last_analysis:
            return []
        return self._last_analysis.improving_controls

    def get_regressing_controls(self) -> list[TrendItem]:
        """
        Get controls that have regressed.

        Returns:
            List of TrendItems for regressing controls, sorted by magnitude.
        """
        if not self._last_analysis:
            return []
        return self._last_analysis.regressing_controls

    def get_stable_controls(self) -> list[TrendItem]:
        """
        Get controls with stable scores.

        Returns:
            List of TrendItems for stable controls.
        """
        if not self._last_analysis:
            return []
        return self._last_analysis.stable_controls

    def get_volatile_controls(self) -> list[TrendItem]:
        """
        Get controls with volatile/fluctuating scores.

        Returns:
            List of TrendItems for volatile controls.
        """
        if not self._last_analysis:
            return []
        return self._last_analysis.volatile_controls

    def get_function_trend(self, function_id: str) -> TrendItem | None:
        """
        Get trend for a specific NIST function.

        Args:
            function_id: NIST function ID (e.g., "PR").

        Returns:
            TrendItem for the function, or None if not found.
        """
        if not self._last_analysis:
            return None
        return self._last_analysis.function_trends.get(function_id)

    def get_category_trend(self, category_id: str) -> TrendItem | None:
        """
        Get trend for a specific NIST category.

        Args:
            category_id: NIST category ID (e.g., "PR.AC").

        Returns:
            TrendItem for the category, or None if not found.
        """
        if not self._last_analysis:
            return None
        return self._last_analysis.category_trends.get(category_id)
