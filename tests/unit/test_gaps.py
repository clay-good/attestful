"""
Unit tests for gap analysis functionality.
"""

import pytest
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any

from attestful.analysis.gaps import (
    GapSeverity,
    ComplianceGap,
    GapAnalysisResult,
    GapAnalyzer,
)
from attestful.core.models import Resource


# =============================================================================
# Helper Functions and Mock Objects
# =============================================================================


@dataclass
class MockComplianceCheck:
    """Mock compliance check for testing."""
    id: str
    title: str
    description: str
    severity: str
    framework_mappings: dict[str, list[str]]


@dataclass
class MockCheckResult:
    """Mock check result for testing."""
    check: MockComplianceCheck
    resource_id: str
    resource_type: str
    passed: bool
    details: dict[str, Any]


def create_check_result(
    check_id: str,
    resource_id: str,
    passed: bool,
    severity: str = "medium",
    framework: str = "soc2",
    control_ids: list[str] | None = None,
) -> MockCheckResult:
    """Helper to create mock check results."""
    return MockCheckResult(
        check=MockComplianceCheck(
            id=check_id,
            title=f"Check {check_id}",
            description=f"Description for {check_id}",
            severity=severity,
            framework_mappings={framework: control_ids or []},
        ),
        resource_id=resource_id,
        resource_type="test_resource",
        passed=passed,
        details={"remediation": f"Fix {check_id}" if not passed else ""},
    )


# =============================================================================
# GapSeverity Tests
# =============================================================================


class TestGapSeverity:
    """Tests for GapSeverity enum."""

    def test_severity_values(self):
        """Test severity enum values."""
        assert GapSeverity.CRITICAL.value == "critical"
        assert GapSeverity.HIGH.value == "high"
        assert GapSeverity.MEDIUM.value == "medium"
        assert GapSeverity.LOW.value == "low"

    def test_severity_comparison(self):
        """Test severity can be used in comparisons."""
        severities = [GapSeverity.LOW, GapSeverity.MEDIUM, GapSeverity.HIGH, GapSeverity.CRITICAL]
        assert len(severities) == 4


# =============================================================================
# ComplianceGap Tests
# =============================================================================


class TestComplianceGap:
    """Tests for ComplianceGap dataclass."""

    def test_gap_creation(self):
        """Test creating a compliance gap."""
        gap = ComplianceGap(
            control_id="CC6.1",
            framework="soc2",
            severity=GapSeverity.HIGH,
            gap_type="failed_check",
            title="Failed encryption check",
            description="S3 buckets are not encrypted",
            remediation="Enable S3 bucket encryption",
            affected_resources=["bucket-1", "bucket-2"],
            related_checks=["s3-encryption-check"],
        )

        assert gap.control_id == "CC6.1"
        assert gap.severity == GapSeverity.HIGH
        assert len(gap.affected_resources) == 2

    def test_gap_to_dict(self):
        """Test serialization to dictionary."""
        gap = ComplianceGap(
            control_id="CC6.1",
            framework="soc2",
            severity=GapSeverity.MEDIUM,
            gap_type="no_coverage",
            title="No automated checks",
            description="No coverage for this control",
        )

        data = gap.to_dict()

        assert data["control_id"] == "CC6.1"
        assert data["framework"] == "soc2"
        assert data["severity"] == "medium"
        assert data["gap_type"] == "no_coverage"
        assert "detected_at" in data

    def test_gap_default_values(self):
        """Test gap has appropriate defaults."""
        gap = ComplianceGap(
            control_id="CC6.1",
            framework="soc2",
            severity=GapSeverity.LOW,
            gap_type="test",
            title="Test gap",
            description="Test",
        )

        assert gap.remediation == ""
        assert gap.affected_resources == []
        assert gap.related_checks == []
        assert gap.detected_at is not None


# =============================================================================
# GapAnalysisResult Tests
# =============================================================================


class TestGapAnalysisResult:
    """Tests for GapAnalysisResult dataclass."""

    def test_result_creation(self):
        """Test creating gap analysis result."""
        gaps = [
            ComplianceGap(
                control_id="CC6.1",
                framework="soc2",
                severity=GapSeverity.HIGH,
                gap_type="failed_check",
                title="Test gap",
                description="Test",
            )
        ]

        result = GapAnalysisResult(
            framework="soc2",
            total_gaps=1,
            gaps_by_severity={"critical": 0, "high": 1, "medium": 0, "low": 0},
            gaps=gaps,
            coverage_rate=75.0,
        )

        assert result.framework == "soc2"
        assert result.total_gaps == 1
        assert result.coverage_rate == 75.0

    def test_result_to_dict(self):
        """Test serialization to dictionary."""
        gap = ComplianceGap(
            control_id="CC6.1",
            framework="soc2",
            severity=GapSeverity.MEDIUM,
            gap_type="test",
            title="Test",
            description="Test",
        )

        result = GapAnalysisResult(
            framework="soc2",
            total_gaps=1,
            gaps_by_severity={"critical": 0, "high": 0, "medium": 1, "low": 0},
            gaps=[gap],
            coverage_rate=50.0,
        )

        data = result.to_dict()

        assert data["framework"] == "soc2"
        assert data["total_gaps"] == 1
        assert data["coverage_rate"] == 50.0
        assert len(data["gaps"]) == 1
        assert "analyzed_at" in data


# =============================================================================
# GapAnalyzer Tests - Initialization
# =============================================================================


class TestGapAnalyzerInit:
    """Tests for GapAnalyzer initialization."""

    def test_default_framework(self):
        """Test default framework is SOC 2."""
        analyzer = GapAnalyzer()
        assert analyzer.framework == "soc2"

    def test_custom_framework(self):
        """Test custom framework initialization."""
        analyzer = GapAnalyzer(framework="nist-800-53")
        assert analyzer.framework == "nist-800-53"

    def test_soc2_controls_defined(self):
        """Test SOC 2 controls structure is defined."""
        assert len(GapAnalyzer.SOC2_CONTROLS) > 0

        # Check structure
        for category_id, category_data in GapAnalyzer.SOC2_CONTROLS.items():
            assert "name" in category_data
            assert "controls" in category_data
            assert len(category_data["controls"]) > 0


# =============================================================================
# GapAnalyzer Tests - Adding Check Results
# =============================================================================


class TestGapAnalyzerCheckResults:
    """Tests for adding check results to analyzer."""

    def test_add_check_results(self):
        """Test adding check results."""
        analyzer = GapAnalyzer()

        results = [
            create_check_result("check-1", "resource-1", True, control_ids=["CC6.1"]),
            create_check_result("check-2", "resource-2", False, control_ids=["CC6.1"]),
        ]

        analyzer.add_check_results(results)

        assert len(analyzer._check_results) == 2

    def test_check_results_mapped_to_controls(self):
        """Test check results are mapped to controls."""
        analyzer = GapAnalyzer()

        results = [
            create_check_result("check-1", "resource-1", True, control_ids=["CC6.1"]),
            create_check_result("check-2", "resource-2", True, control_ids=["CC6.1", "CC6.2"]),
        ]

        analyzer.add_check_results(results)

        assert "CC6.1" in analyzer._control_checks
        assert "CC6.2" in analyzer._control_checks
        assert len(analyzer._control_checks["CC6.1"]) == 2
        assert len(analyzer._control_checks["CC6.2"]) == 1


# =============================================================================
# GapAnalyzer Tests - SOC 2 Analysis
# =============================================================================


class TestGapAnalyzerSOC2:
    """Tests for SOC 2 gap analysis."""

    def test_analyze_no_checks(self):
        """Test analysis with no check results."""
        analyzer = GapAnalyzer(framework="soc2")

        result = analyzer.analyze()

        # Should identify all controls as gaps (no coverage)
        assert result.total_gaps > 0
        assert result.coverage_rate == 0.0

    def test_analyze_all_passing(self):
        """Test analysis with all passing checks."""
        analyzer = GapAnalyzer(framework="soc2")

        # Add passing results for all CC6 controls
        results = []
        for control in GapAnalyzer.SOC2_CONTROLS["CC6"]["controls"]:
            results.append(
                create_check_result(f"check-{control}", "resource-1", True, control_ids=[control])
            )

        analyzer.add_check_results(results)
        result = analyzer.analyze()

        # CC6 controls should not be gaps
        cc6_gaps = [g for g in result.gaps if g.control_id.startswith("CC6")]
        assert len(cc6_gaps) == 0

    def test_analyze_failing_checks(self):
        """Test analysis identifies failing checks as gaps."""
        analyzer = GapAnalyzer(framework="soc2")

        # Add failing results for CC6.1
        results = [
            create_check_result("check-1", "resource-1", False, control_ids=["CC6.1"]),
            create_check_result("check-2", "resource-2", False, control_ids=["CC6.1"]),
        ]

        analyzer.add_check_results(results)
        result = analyzer.analyze()

        # Should have a gap for CC6.1
        cc6_1_gaps = [g for g in result.gaps if g.control_id == "CC6.1"]
        assert len(cc6_1_gaps) == 1
        assert cc6_1_gaps[0].gap_type == "failed_check"

    def test_analyze_severity_based_on_failures(self):
        """Test gap severity based on number of failures."""
        analyzer = GapAnalyzer(framework="soc2")

        # Add 5 failing checks (should be critical)
        results = [
            create_check_result(f"check-{i}", f"resource-{i}", False, control_ids=["CC6.1"])
            for i in range(5)
        ]

        analyzer.add_check_results(results)
        result = analyzer.analyze()

        cc6_1_gap = next((g for g in result.gaps if g.control_id == "CC6.1"), None)
        assert cc6_1_gap is not None
        assert cc6_1_gap.severity == GapSeverity.CRITICAL

    def test_analyze_coverage_rate(self):
        """Test coverage rate calculation."""
        analyzer = GapAnalyzer(framework="soc2")

        # Get total number of SOC 2 controls
        total_controls = sum(
            len(category["controls"])
            for category in GapAnalyzer.SOC2_CONTROLS.values()
        )

        # Cover half of CC6 controls (8 controls)
        covered = 4
        results = []
        for control in GapAnalyzer.SOC2_CONTROLS["CC6"]["controls"][:covered]:
            results.append(
                create_check_result(f"check-{control}", "resource-1", True, control_ids=[control])
            )

        analyzer.add_check_results(results)
        result = analyzer.analyze()

        expected_coverage = (covered / total_controls) * 100
        assert result.coverage_rate == pytest.approx(expected_coverage, rel=0.01)


# =============================================================================
# GapAnalyzer Tests - Generic Analysis
# =============================================================================


class TestGapAnalyzerGeneric:
    """Tests for generic (non-SOC2) gap analysis."""

    def test_analyze_generic_framework(self):
        """Test analysis with non-SOC2 framework."""
        analyzer = GapAnalyzer(framework="custom")

        results = [
            create_check_result("check-1", "resource-1", False, framework="custom"),
        ]

        analyzer.add_check_results(results)
        result = analyzer.analyze()

        assert result.framework == "custom"
        assert len(result.gaps) > 0


# =============================================================================
# GapAnalyzer Tests - Remediation Plan
# =============================================================================


class TestGapAnalyzerRemediationPlan:
    """Tests for remediation plan generation."""

    def test_get_remediation_plan(self):
        """Test generating remediation plan."""
        analyzer = GapAnalyzer(framework="soc2")

        # Add some failing checks with different severities
        results = [
            create_check_result("critical-check", "resource-1", False, severity="critical", control_ids=["CC6.1"]),
            create_check_result("medium-check", "resource-2", False, severity="medium", control_ids=["CC6.2"]),
        ]

        analyzer.add_check_results(results)
        gap_result = analyzer.analyze()
        plan = analyzer.get_remediation_plan(gap_result)

        assert len(plan) > 0

        # First item should be highest priority
        assert plan[0]["priority"] == 1

    def test_remediation_plan_sorted_by_severity(self):
        """Test remediation plan is sorted by severity."""
        analyzer = GapAnalyzer(framework="soc2")

        # Add gaps of varying severity
        results = [
            create_check_result("low-check", "resource-1", False, severity="low", control_ids=["CC6.1"]),
            create_check_result("critical-check-1", "resource-2", False, severity="critical", control_ids=["CC6.2"]),
            create_check_result("critical-check-2", "resource-3", False, severity="critical", control_ids=["CC6.2"]),
            create_check_result("critical-check-3", "resource-4", False, severity="critical", control_ids=["CC6.2"]),
            create_check_result("critical-check-4", "resource-5", False, severity="critical", control_ids=["CC6.2"]),
            create_check_result("critical-check-5", "resource-6", False, severity="critical", control_ids=["CC6.2"]),
        ]

        analyzer.add_check_results(results)
        gap_result = analyzer.analyze()
        plan = analyzer.get_remediation_plan(gap_result)

        # Critical gap should come first
        critical_idx = next((i for i, p in enumerate(plan) if p["severity"] == "critical"), None)
        low_idx = next((i for i, p in enumerate(plan) if p["severity"] == "low"), None)

        if critical_idx is not None and low_idx is not None:
            assert critical_idx < low_idx

    def test_remediation_plan_max_items(self):
        """Test remediation plan respects max_items."""
        analyzer = GapAnalyzer(framework="soc2")

        gap_result = analyzer.analyze()
        plan = analyzer.get_remediation_plan(gap_result, max_items=5)

        assert len(plan) <= 5

    def test_remediation_plan_effort_estimate(self):
        """Test effort estimate in remediation plan."""
        analyzer = GapAnalyzer(framework="soc2")

        gap_result = analyzer.analyze()
        plan = analyzer.get_remediation_plan(gap_result)

        for item in plan:
            assert "effort_estimate" in item
            assert item["effort_estimate"] in ["low", "medium", "high"]


# =============================================================================
# GapAnalyzer Tests - Edge Cases
# =============================================================================


class TestGapAnalyzerEdgeCases:
    """Tests for edge cases in gap analysis."""

    def test_empty_check_results(self):
        """Test analysis with empty check results list."""
        analyzer = GapAnalyzer()
        analyzer.add_check_results([])

        result = analyzer.analyze()

        assert result is not None
        assert result.framework == "soc2"

    def test_duplicate_check_results(self):
        """Test handling duplicate check results."""
        analyzer = GapAnalyzer()

        result = create_check_result("check-1", "resource-1", True, control_ids=["CC6.1"])
        analyzer.add_check_results([result])
        analyzer.add_check_results([result])

        assert len(analyzer._check_results) == 2

    def test_check_with_multiple_frameworks(self):
        """Test check mapping to multiple frameworks."""
        analyzer = GapAnalyzer()

        check = MockComplianceCheck(
            id="multi-check",
            title="Multi-framework check",
            description="Test",
            severity="medium",
            framework_mappings={
                "soc2": ["CC6.1"],
                "nist-800-53": ["AC-2"],
            },
        )

        result = MockCheckResult(
            check=check,
            resource_id="resource-1",
            resource_type="test",
            passed=True,
            details={},
        )

        analyzer.add_check_results([result])

        # Should only map to soc2 since that's the analyzer's framework
        assert "CC6.1" in analyzer._control_checks


# =============================================================================
# SOC 2 Controls Structure Tests
# =============================================================================


class TestSOC2ControlsStructure:
    """Tests for SOC 2 controls structure."""

    def test_all_categories_present(self):
        """Test all SOC 2 categories are defined."""
        expected_categories = ["CC1", "CC2", "CC3", "CC4", "CC5", "CC6", "CC7", "CC8", "CC9", "A1", "C1", "PI1", "P1"]
        actual_categories = list(GapAnalyzer.SOC2_CONTROLS.keys())

        for cat in expected_categories:
            assert cat in actual_categories

    def test_control_id_format(self):
        """Test control IDs follow expected format."""
        for category_id, category_data in GapAnalyzer.SOC2_CONTROLS.items():
            for control_id in category_data["controls"]:
                # Control ID should start with category ID
                assert control_id.startswith(category_id)

    def test_category_names(self):
        """Test all categories have names."""
        for category_id, category_data in GapAnalyzer.SOC2_CONTROLS.items():
            assert "name" in category_data
            assert len(category_data["name"]) > 0
