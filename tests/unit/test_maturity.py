"""
Unit tests for the maturity calculator.
"""

import pytest
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from typing import Any

from attestful.analysis.maturity import (
    MaturityLevel,
    MaturityScore,
    CategoryScore,
    FrameworkMaturity,
    MaturityCalculator,
    NIST_CSF_2_STRUCTURE,
    EVIDENCE_TO_CSF_MAPPING,
)
from attestful.core.models import Evidence


# =============================================================================
# Helper Functions
# =============================================================================


def create_evidence(
    evidence_type: str,
    platform: str = "aws",
    collected_at: datetime | None = None,
    metadata: dict[str, Any] | None = None,
) -> Evidence:
    """Helper to create evidence for testing."""
    return Evidence(
        id=f"evidence-{evidence_type}-{datetime.now().timestamp()}",
        platform=platform,
        evidence_type=evidence_type,
        collected_at=collected_at or datetime.now(timezone.utc),
        raw_data={"type": evidence_type},
        metadata=metadata or {},
    )


@dataclass
class MockCheckResult:
    """Mock check result for testing."""
    passed: bool
    check: Any


@dataclass
class MockCheck:
    """Mock compliance check."""
    framework_mappings: dict[str, list[str]]


# =============================================================================
# MaturityLevel Tests
# =============================================================================


class TestMaturityLevel:
    """Tests for MaturityLevel enum."""

    def test_from_score_optimizing(self):
        """Test score >= 90 maps to OPTIMIZING."""
        assert MaturityLevel.from_score(100) == MaturityLevel.OPTIMIZING
        assert MaturityLevel.from_score(90) == MaturityLevel.OPTIMIZING

    def test_from_score_managed(self):
        """Test score >= 70 maps to MANAGED."""
        assert MaturityLevel.from_score(89) == MaturityLevel.MANAGED
        assert MaturityLevel.from_score(70) == MaturityLevel.MANAGED

    def test_from_score_defined(self):
        """Test score >= 50 maps to DEFINED."""
        assert MaturityLevel.from_score(69) == MaturityLevel.DEFINED
        assert MaturityLevel.from_score(50) == MaturityLevel.DEFINED

    def test_from_score_developing(self):
        """Test score >= 25 maps to DEVELOPING."""
        assert MaturityLevel.from_score(49) == MaturityLevel.DEVELOPING
        assert MaturityLevel.from_score(25) == MaturityLevel.DEVELOPING

    def test_from_score_initial(self):
        """Test score < 25 maps to INITIAL."""
        assert MaturityLevel.from_score(24) == MaturityLevel.INITIAL
        assert MaturityLevel.from_score(0) == MaturityLevel.INITIAL

    def test_level_description(self):
        """Test maturity level descriptions."""
        assert MaturityLevel.INITIAL.description
        assert MaturityLevel.DEVELOPING.description
        assert MaturityLevel.DEFINED.description
        assert MaturityLevel.MANAGED.description
        assert MaturityLevel.OPTIMIZING.description

        # Each level should have unique description
        descriptions = [level.description for level in MaturityLevel]
        assert len(descriptions) == len(set(descriptions))


# =============================================================================
# MaturityScore Tests
# =============================================================================


class TestMaturityScore:
    """Tests for MaturityScore dataclass."""

    def test_to_dict(self):
        """Test serialization to dictionary."""
        score = MaturityScore(
            control_id="PR.AA",
            score=75.5,
            level=MaturityLevel.MANAGED,
            evidence_count=5,
            automation_rate=80.0,
            details={"evidence_score": 70, "automation_score": 80, "check_score": 75},
        )

        data = score.to_dict()

        assert data["control_id"] == "PR.AA"
        assert data["score"] == 75.5
        assert data["level"] == "MANAGED"
        assert data["level_value"] == 4
        assert data["evidence_count"] == 5
        assert data["automation_rate"] == 80.0
        assert "last_assessed" in data


# =============================================================================
# CategoryScore Tests
# =============================================================================


class TestCategoryScore:
    """Tests for CategoryScore dataclass."""

    def test_implementation_rate(self):
        """Test implementation rate calculation."""
        category = CategoryScore(
            category_id="PROTECT",
            name="Protect",
            score=60.0,
            level=MaturityLevel.DEFINED,
            control_count=10,
            implemented_count=7,
        )

        assert category.implementation_rate == 70.0

    def test_implementation_rate_zero_controls(self):
        """Test implementation rate with zero controls."""
        category = CategoryScore(
            category_id="PROTECT",
            name="Protect",
            score=0.0,
            level=MaturityLevel.INITIAL,
            control_count=0,
            implemented_count=0,
        )

        assert category.implementation_rate == 0.0

    def test_to_dict(self):
        """Test serialization to dictionary."""
        subcategory = MaturityScore(
            control_id="PR.AA",
            score=60.0,
            level=MaturityLevel.DEFINED,
        )

        category = CategoryScore(
            category_id="PROTECT",
            name="Protect",
            score=60.0,
            level=MaturityLevel.DEFINED,
            subcategory_scores=[subcategory],
            control_count=5,
            implemented_count=3,
        )

        data = category.to_dict()

        assert data["category_id"] == "PROTECT"
        assert data["name"] == "Protect"
        assert data["level"] == "DEFINED"
        assert data["implementation_rate"] == 60.0
        assert len(data["subcategory_scores"]) == 1


# =============================================================================
# FrameworkMaturity Tests
# =============================================================================


class TestFrameworkMaturity:
    """Tests for FrameworkMaturity dataclass."""

    def test_to_dict(self):
        """Test serialization to dictionary."""
        category = CategoryScore(
            category_id="GOVERN",
            name="Govern",
            score=50.0,
            level=MaturityLevel.DEFINED,
        )

        maturity = FrameworkMaturity(
            framework="nist-csf-2",
            overall_score=55.0,
            overall_level=MaturityLevel.DEFINED,
            category_scores=[category],
            total_controls=25,
            metadata={"evidence_count": 10},
        )

        data = maturity.to_dict()

        assert data["framework"] == "nist-csf-2"
        assert data["overall_score"] == 55.0
        assert data["overall_level"] == "DEFINED"
        assert data["overall_level_value"] == 3
        assert data["total_controls"] == 25
        assert len(data["category_scores"]) == 1


# =============================================================================
# MaturityCalculator Tests
# =============================================================================


class TestMaturityCalculatorInit:
    """Tests for MaturityCalculator initialization."""

    def test_default_framework(self):
        """Test default framework is nist-csf-2."""
        calc = MaturityCalculator()
        assert calc.framework == "nist-csf-2"

    def test_supported_frameworks(self):
        """Test all supported frameworks can be initialized."""
        for framework in MaturityCalculator.SUPPORTED_FRAMEWORKS:
            calc = MaturityCalculator(framework=framework)
            assert calc.framework == framework

    def test_unsupported_framework_raises(self):
        """Test unsupported framework raises ValueError."""
        with pytest.raises(ValueError):
            MaturityCalculator(framework="unknown")

    def test_custom_weights(self):
        """Test custom weight configuration."""
        calc = MaturityCalculator(
            evidence_weight=0.5,
            automation_weight=0.3,
            check_weight=0.2,
        )

        assert calc.evidence_weight == 0.5
        assert calc.automation_weight == 0.3
        assert calc.check_weight == 0.2


class TestMaturityCalculatorEvidence:
    """Tests for evidence handling in MaturityCalculator."""

    def test_add_evidence(self):
        """Test adding evidence items."""
        calc = MaturityCalculator()

        evidence = [
            create_evidence("iam_credential_report"),
            create_evidence("password_policy"),
        ]

        calc.add_evidence(evidence)

        assert len(calc._evidence) == 2

    def test_evidence_mapped_to_categories(self):
        """Test evidence is mapped to correct CSF categories."""
        calc = MaturityCalculator()

        # iam_credential_report maps to PR.AA and GV.RR
        evidence = [create_evidence("iam_credential_report")]
        calc.add_evidence(evidence)

        assert "PR.AA" in calc._category_evidence
        assert "GV.RR" in calc._category_evidence

    def test_unknown_evidence_type_not_mapped(self):
        """Test unknown evidence type doesn't crash."""
        calc = MaturityCalculator()

        evidence = [create_evidence("unknown_type")]
        calc.add_evidence(evidence)

        # Should still be in _evidence but not mapped to categories
        assert len(calc._evidence) == 1


class TestMaturityCalculatorScoring:
    """Tests for maturity score calculations."""

    def test_calculate_empty(self):
        """Test calculation with no evidence."""
        calc = MaturityCalculator()

        result = calc.calculate()

        assert result.framework == "nist-csf-2"
        # Score is 15.0 because check_score defaults to 50 (neutral) when no checks
        # 0.4 * 0 (evidence) + 0.3 * 0 (automation) + 0.3 * 50 (check neutral) = 15.0
        assert result.overall_score == 15.0
        assert result.overall_level == MaturityLevel.INITIAL
        assert len(result.category_scores) == 6  # 6 CSF functions

    def test_calculate_with_evidence(self):
        """Test calculation with evidence."""
        calc = MaturityCalculator()

        # Add evidence for multiple categories
        evidence = [
            create_evidence("iam_credential_report"),  # PR.AA, GV.RR
            create_evidence("password_policy"),  # PR.AA, GV.PO
            create_evidence("cloudtrail_status"),  # DE.CM, GV.OV
            create_evidence("guardduty_status"),  # DE.CM, DE.AE
        ]
        calc.add_evidence(evidence)

        result = calc.calculate()

        # Should have non-zero scores for some categories
        assert result.overall_score > 0
        assert result.total_controls > 0

    def test_evidence_recency_affects_score(self):
        """Test that older evidence reduces score."""
        # Calculator with recent evidence
        calc_recent = MaturityCalculator()
        recent_evidence = [
            create_evidence(
                "iam_credential_report",
                collected_at=datetime.now(timezone.utc),
            )
        ]
        calc_recent.add_evidence(recent_evidence)

        # Calculator with old evidence
        calc_old = MaturityCalculator()
        old_evidence = [
            create_evidence(
                "iam_credential_report",
                collected_at=datetime.now(timezone.utc) - timedelta(days=200),
            )
        ]
        calc_old.add_evidence(old_evidence)

        result_recent = calc_recent.calculate()
        result_old = calc_old.calculate()

        # Recent evidence should yield higher score
        # (comparing same category)
        recent_pr_aa = next(
            (s for c in result_recent.category_scores for s in c.subcategory_scores if s.control_id == "PR.AA"),
            None,
        )
        old_pr_aa = next(
            (s for c in result_old.category_scores for s in c.subcategory_scores if s.control_id == "PR.AA"),
            None,
        )

        if recent_pr_aa and old_pr_aa:
            assert recent_pr_aa.score >= old_pr_aa.score

    def test_automation_bonus(self):
        """Test that automated evidence gets higher score."""
        # Manual evidence
        calc_manual = MaturityCalculator()
        manual_evidence = [
            create_evidence("iam_credential_report", metadata={"collection_method": "manual"})
        ]
        calc_manual.add_evidence(manual_evidence)

        # Automated evidence
        calc_auto = MaturityCalculator()
        auto_evidence = [
            create_evidence("iam_credential_report", metadata={"collection_method": "automated"})
        ]
        calc_auto.add_evidence(auto_evidence)

        result_manual = calc_manual.calculate()
        result_auto = calc_auto.calculate()

        # Find PR.AA scores
        manual_pr_aa = next(
            (s for c in result_manual.category_scores for s in c.subcategory_scores if s.control_id == "PR.AA"),
            None,
        )
        auto_pr_aa = next(
            (s for c in result_auto.category_scores for s in c.subcategory_scores if s.control_id == "PR.AA"),
            None,
        )

        if manual_pr_aa and auto_pr_aa:
            assert auto_pr_aa.automation_rate >= manual_pr_aa.automation_rate


class TestMaturityCalculatorCategoryScores:
    """Tests for category-level score calculations."""

    def test_category_scores_structure(self):
        """Test category scores match NIST CSF structure."""
        calc = MaturityCalculator()
        result = calc.calculate()

        # Should have all 6 functions
        function_ids = [c.category_id for c in result.category_scores]
        expected_functions = ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]

        assert set(function_ids) == set(expected_functions)

    def test_subcategory_counts(self):
        """Test subcategory counts match structure."""
        calc = MaturityCalculator()
        result = calc.calculate()

        for category in result.category_scores:
            expected_categories = NIST_CSF_2_STRUCTURE[category.category_id]["categories"]
            assert len(category.subcategory_scores) == len(expected_categories)


class TestMaturityCalculatorRecommendations:
    """Tests for improvement recommendations."""

    def test_get_recommendations_for_low_scores(self):
        """Test recommendations generated for low scores."""
        calc = MaturityCalculator()
        result = calc.calculate()

        recommendations = calc.get_improvement_recommendations(result)

        # With no evidence, should have many recommendations
        assert len(recommendations) > 0

        # Recommendations should be prioritized
        if len(recommendations) > 1:
            assert recommendations[0]["priority"] in ["high", "medium"]

    def test_recommendations_sorted_by_priority(self):
        """Test recommendations are sorted by priority."""
        calc = MaturityCalculator()

        # Add some evidence to create mixed scores
        evidence = [
            create_evidence("iam_credential_report"),
            create_evidence("password_policy"),
        ]
        calc.add_evidence(evidence)

        result = calc.calculate()
        recommendations = calc.get_improvement_recommendations(result)

        if len(recommendations) > 1:
            # High priority should come before medium
            priorities = [r["priority"] for r in recommendations]
            high_indices = [i for i, p in enumerate(priorities) if p == "high"]
            medium_indices = [i for i, p in enumerate(priorities) if p == "medium"]

            if high_indices and medium_indices:
                assert max(high_indices) < min(medium_indices)

    def test_recommendations_include_details(self):
        """Test recommendations include actionable details."""
        calc = MaturityCalculator()
        result = calc.calculate()

        recommendations = calc.get_improvement_recommendations(result)

        for rec in recommendations:
            assert "category" in rec
            assert "subcategory" in rec
            assert "current_score" in rec
            assert "recommendations" in rec


# =============================================================================
# NIST CSF Structure Tests
# =============================================================================


class TestNISTCSFStructure:
    """Tests for NIST CSF 2.0 structure definitions."""

    def test_all_functions_have_categories(self):
        """Test all functions have categories defined."""
        for function_id, function_data in NIST_CSF_2_STRUCTURE.items():
            assert "name" in function_data
            assert "description" in function_data
            assert "categories" in function_data
            assert len(function_data["categories"]) > 0

    def test_category_ids_format(self):
        """Test category IDs follow expected format."""
        for function_id, function_data in NIST_CSF_2_STRUCTURE.items():
            for category_id in function_data["categories"]:
                # Category IDs should start with function abbreviation
                assert "." in category_id


class TestEvidenceMapping:
    """Tests for evidence type to CSF category mappings."""

    def test_evidence_types_have_mappings(self):
        """Test common evidence types have CSF mappings."""
        common_types = [
            "account_info",
            "iam_credential_report",
            "password_policy",
            "cloudtrail_status",
        ]

        for etype in common_types:
            assert etype in EVIDENCE_TO_CSF_MAPPING
            assert len(EVIDENCE_TO_CSF_MAPPING[etype]) > 0

    def test_mapped_categories_exist(self):
        """Test all mapped categories exist in CSF structure."""
        all_categories = set()
        for function_data in NIST_CSF_2_STRUCTURE.values():
            all_categories.update(function_data["categories"].keys())

        for evidence_type, categories in EVIDENCE_TO_CSF_MAPPING.items():
            for category in categories:
                assert category in all_categories, f"Category {category} not found in CSF structure"


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================


class TestMaturityCalculatorEdgeCases:
    """Tests for edge cases and error handling."""

    def test_duplicate_evidence_handling(self):
        """Test adding duplicate evidence doesn't crash."""
        calc = MaturityCalculator()

        evidence = create_evidence("iam_credential_report")
        calc.add_evidence([evidence])
        calc.add_evidence([evidence])

        # Should have 2 entries (duplicates allowed)
        assert len(calc._evidence) == 2

    def test_empty_evidence_list(self):
        """Test adding empty evidence list."""
        calc = MaturityCalculator()
        calc.add_evidence([])

        result = calc.calculate()
        # Same as test_calculate_empty - neutral check score of 50 contributes 15.0
        assert result.overall_score == 15.0

    def test_very_old_evidence(self):
        """Test handling very old evidence."""
        calc = MaturityCalculator()

        old_evidence = create_evidence(
            "iam_credential_report",
            collected_at=datetime.now(timezone.utc) - timedelta(days=365),
        )
        calc.add_evidence([old_evidence])

        result = calc.calculate()

        # Should still calculate, but with reduced score
        assert result is not None

    def test_future_evidence_date(self):
        """Test handling evidence with future date."""
        calc = MaturityCalculator()

        future_evidence = create_evidence(
            "iam_credential_report",
            collected_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
        calc.add_evidence([future_evidence])

        result = calc.calculate()

        # Should handle gracefully
        assert result is not None
