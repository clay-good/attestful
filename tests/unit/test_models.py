"""
Unit tests for core data models.
"""

import pytest
from datetime import datetime, timezone, timedelta
from uuid import UUID

from attestful.core.models import (
    Severity,
    CheckStatus,
    MaturityLevel,
    Resource,
    Evidence,
    CollectionResult,
    ComplianceCheck,
    CheckResult,
    MaturityScore,
    MaturityBreakdown,
)


# =============================================================================
# Severity Tests
# =============================================================================


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        """Test severity enum values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_ordering(self):
        """Test severity comparison ordering."""
        assert Severity.INFO < Severity.LOW
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL

    def test_severity_sorting(self):
        """Test severities can be sorted."""
        severities = [Severity.MEDIUM, Severity.CRITICAL, Severity.LOW, Severity.HIGH, Severity.INFO]
        sorted_severities = sorted(severities)

        assert sorted_severities == [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]


# =============================================================================
# CheckStatus Tests
# =============================================================================


class TestCheckStatus:
    """Tests for CheckStatus enum."""

    def test_status_values(self):
        """Test status enum values."""
        assert CheckStatus.PASS.value == "pass"
        assert CheckStatus.FAIL.value == "fail"
        assert CheckStatus.ERROR.value == "error"
        assert CheckStatus.SKIP.value == "skip"
        assert CheckStatus.UNKNOWN.value == "unknown"


# =============================================================================
# MaturityLevel Tests
# =============================================================================


class TestMaturityLevel:
    """Tests for MaturityLevel enum."""

    def test_maturity_values(self):
        """Test maturity level integer values."""
        assert MaturityLevel.LEVEL_0.value == 0
        assert MaturityLevel.LEVEL_1.value == 1
        assert MaturityLevel.LEVEL_2.value == 2
        assert MaturityLevel.LEVEL_3.value == 3
        assert MaturityLevel.LEVEL_4.value == 4

    def test_maturity_is_int_enum(self):
        """Test maturity levels are integers."""
        assert isinstance(MaturityLevel.LEVEL_2.value, int)
        assert MaturityLevel.LEVEL_2 == 2


# =============================================================================
# Resource Tests
# =============================================================================


class TestResource:
    """Tests for Resource dataclass."""

    def test_resource_creation(self):
        """Test creating a resource."""
        resource = Resource(
            id="i-1234567890abcdef0",
            type="ec2_instance",
            provider="aws",
            region="us-east-1",
            name="my-instance",
        )

        assert resource.id == "i-1234567890abcdef0"
        assert resource.type == "ec2_instance"
        assert resource.provider == "aws"
        assert resource.region == "us-east-1"
        assert resource.name == "my-instance"

    def test_resource_defaults(self):
        """Test resource default values."""
        resource = Resource(
            id="test-id",
            type="test_type",
            provider="test",
        )

        assert resource.region is None
        assert resource.account is None
        assert resource.name is None
        assert resource.raw_data == {}
        assert resource.metadata == {}
        assert resource.tags == {}
        assert resource.collected_at is not None

    def test_resource_get_method(self):
        """Test get method for raw_data access."""
        resource = Resource(
            id="test-id",
            type="test",
            provider="test",
            raw_data={"key": "value", "nested": {"inner": "data"}},
        )

        assert resource.get("key") == "value"
        assert resource.get("nested") == {"inner": "data"}
        assert resource.get("missing") is None
        assert resource.get("missing", "default") == "default"

    def test_resource_to_dict(self):
        """Test serialization to dictionary."""
        resource = Resource(
            id="test-id",
            type="test",
            provider="aws",
            region="us-east-1",
            raw_data={"key": "value"},
            tags={"Environment": "production"},
        )

        data = resource.to_dict()

        assert data["id"] == "test-id"
        assert data["type"] == "test"
        assert data["provider"] == "aws"
        assert data["region"] == "us-east-1"
        assert data["raw_data"]["key"] == "value"
        assert data["tags"]["Environment"] == "production"
        assert "collected_at" in data


# =============================================================================
# Evidence Tests
# =============================================================================


class TestEvidence:
    """Tests for Evidence dataclass."""

    def test_evidence_creation(self):
        """Test creating evidence."""
        evidence = Evidence(
            platform="okta",
            evidence_type="users",
            raw_data={"users": [{"name": "admin"}]},
        )

        assert evidence.platform == "okta"
        assert evidence.evidence_type == "users"
        assert evidence.raw_data["users"][0]["name"] == "admin"

    def test_evidence_auto_generated_id(self):
        """Test evidence gets auto-generated UUID."""
        evidence = Evidence(
            platform="aws",
            evidence_type="iam_report",
        )

        assert evidence.id is not None
        # Should be a valid UUID string
        UUID(evidence.id)

    def test_evidence_defaults(self):
        """Test evidence default values."""
        evidence = Evidence()

        assert evidence.platform == ""
        assert evidence.evidence_type == ""
        assert evidence.raw_data == {}
        assert evidence.metadata == {}
        assert evidence.source_id is None
        assert evidence.file_hash is None
        assert evidence.collected_at is not None

    def test_evidence_to_dict(self):
        """Test serialization to dictionary."""
        evidence = Evidence(
            id="evidence-123",
            platform="aws",
            evidence_type="iam_report",
            raw_data={"data": "value"},
            metadata={"source": "automated"},
            source_id="src-123",
        )

        data = evidence.to_dict()

        assert data["id"] == "evidence-123"
        assert data["platform"] == "aws"
        assert data["evidence_type"] == "iam_report"
        assert data["raw_data"]["data"] == "value"
        assert data["metadata"]["source"] == "automated"
        assert data["source_id"] == "src-123"
        assert "collected_at" in data


# =============================================================================
# CollectionResult Tests
# =============================================================================


class TestCollectionResult:
    """Tests for CollectionResult dataclass."""

    def test_collection_result_creation(self):
        """Test creating a collection result."""
        result = CollectionResult(
            success=True,
            platform="aws",
        )

        assert result.success is True
        assert result.platform == "aws"
        assert result.partial is False
        assert result.evidence_items == []
        assert result.errors == []

    def test_add_evidence(self):
        """Test adding evidence to result."""
        result = CollectionResult(platform="aws")

        evidence = Evidence(
            platform="aws",
            evidence_type="iam_report",
        )

        result.add_evidence(evidence)

        assert result.evidence_count == 1
        assert "iam_report" in result.evidence_types_collected

    def test_add_error_marks_partial(self):
        """Test adding error marks result as partial."""
        result = CollectionResult(platform="aws")

        assert result.partial is False

        result.add_error("Something went wrong")

        assert result.partial is True
        assert "Something went wrong" in result.errors

    def test_add_warning_does_not_affect_success(self):
        """Test adding warning doesn't affect success status."""
        result = CollectionResult(success=True, platform="aws")

        result.add_warning("Minor issue")

        assert result.success is True
        assert "Minor issue" in result.warnings

    def test_complete_calculates_duration(self):
        """Test completing result calculates duration."""
        result = CollectionResult(platform="aws")

        # Small delay
        import time
        time.sleep(0.01)

        result.complete()

        assert result.completed_at is not None
        assert result.duration_seconds is not None
        assert result.duration_seconds > 0

    def test_complete_sets_success_false_on_errors_only(self):
        """Test completion with errors but no evidence sets success to False."""
        result = CollectionResult(platform="aws")
        result.add_error("Critical error")

        result.complete()

        assert result.success is False

    def test_complete_with_partial_success(self):
        """Test completion with both evidence and errors."""
        result = CollectionResult(platform="aws")
        result.add_evidence(Evidence(platform="aws", evidence_type="test"))
        result.add_error("Minor error")

        result.complete()

        # Still successful because we got some evidence
        assert result.success is True
        assert result.partial is True

    def test_evidence_count_property(self):
        """Test evidence_count property."""
        result = CollectionResult(platform="aws")

        assert result.evidence_count == 0

        for i in range(5):
            result.add_evidence(Evidence(platform="aws", evidence_type=f"type-{i}"))

        assert result.evidence_count == 5

    def test_to_dict(self):
        """Test serialization to dictionary."""
        result = CollectionResult(platform="aws")
        result.add_evidence(Evidence(platform="aws", evidence_type="test"))
        result.add_error("Error 1")
        result.add_warning("Warning 1")
        result.complete()

        data = result.to_dict()

        assert data["success"] is True
        assert data["partial"] is True
        assert data["evidence_count"] == 1
        assert "Error 1" in data["errors"]
        assert "Warning 1" in data["warnings"]
        assert data["platform"] == "aws"
        assert data["duration_seconds"] is not None


# =============================================================================
# ComplianceCheck Tests
# =============================================================================


class TestComplianceCheck:
    """Tests for ComplianceCheck dataclass."""

    def test_check_creation(self):
        """Test creating a compliance check."""
        check = ComplianceCheck(
            id="s3-encryption",
            title="S3 Encryption Check",
            description="Ensure S3 buckets are encrypted",
            severity="high",
            resource_types=["s3_bucket"],
            remediation="Enable bucket encryption",
        )

        assert check.id == "s3-encryption"
        assert check.title == "S3 Encryption Check"
        assert check.severity == "high"

    def test_check_defaults(self):
        """Test check default values."""
        check = ComplianceCheck(
            id="test",
            title="Test",
        )

        assert check.description == ""
        assert check.severity == "medium"
        assert check.resource_types == []
        assert check.condition == ""
        assert check.remediation == ""
        assert check.references == []
        assert check.tags == []
        assert check.enabled is True
        assert check.framework_controls == {}


# =============================================================================
# CheckResult Tests
# =============================================================================


class TestCheckResult:
    """Tests for CheckResult dataclass."""

    def test_result_creation(self):
        """Test creating a check result."""
        result = CheckResult(
            check_id="s3-encryption",
            resource_id="bucket-123",
            status=CheckStatus.PASS,
            severity=Severity.HIGH,
            message="Encryption is enabled",
        )

        assert result.check_id == "s3-encryption"
        assert result.resource_id == "bucket-123"
        assert result.status == CheckStatus.PASS
        assert result.severity == Severity.HIGH

    def test_result_auto_generated_id(self):
        """Test result gets auto-generated UUID."""
        result = CheckResult()

        assert result.id is not None
        UUID(result.id)

    def test_result_defaults(self):
        """Test result default values."""
        result = CheckResult()

        assert result.check_id == ""
        assert result.resource_id == ""
        assert result.resource_type == ""
        assert result.status == CheckStatus.UNKNOWN
        assert result.severity == Severity.MEDIUM
        assert result.message == ""
        assert result.evidence == {}
        assert result.details == {}
        assert result.evaluated_at is not None
        assert result.check is None
        assert result.passed is None

    def test_result_to_dict(self):
        """Test serialization to dictionary."""
        result = CheckResult(
            id="result-123",
            check_id="s3-encryption",
            resource_id="bucket-123",
            status=CheckStatus.FAIL,
            severity=Severity.HIGH,
            message="Encryption not enabled",
            evidence={"encrypted": False},
        )

        data = result.to_dict()

        assert data["id"] == "result-123"
        assert data["check_id"] == "s3-encryption"
        assert data["resource_id"] == "bucket-123"
        assert data["status"] == "fail"
        assert data["severity"] == "high"
        assert data["message"] == "Encryption not enabled"
        assert data["evidence"]["encrypted"] is False
        assert "evaluated_at" in data


# =============================================================================
# MaturityScore Tests
# =============================================================================


class TestMaturityScore:
    """Tests for MaturityScore dataclass."""

    def test_score_creation(self):
        """Test creating a maturity score."""
        score = MaturityScore(
            entity_id="PR.AA",
            entity_type="category",
            level=MaturityLevel.LEVEL_3,
            score=3.5,
            evidence_count=10,
            confidence=0.8,
        )

        assert score.entity_id == "PR.AA"
        assert score.entity_type == "category"
        assert score.level == MaturityLevel.LEVEL_3
        assert score.score == 3.5

    def test_score_defaults(self):
        """Test score default values."""
        score = MaturityScore(
            entity_id="test",
            entity_type="control",
        )

        assert score.level == MaturityLevel.LEVEL_0
        assert score.score == 0.0
        assert score.evidence_count == 0
        assert score.confidence == 0.0
        assert score.missing_evidence_types == []

    def test_score_to_dict(self):
        """Test serialization to dictionary."""
        score = MaturityScore(
            entity_id="GV.OC",
            entity_type="subcategory",
            level=MaturityLevel.LEVEL_2,
            score=2.5,
            evidence_count=5,
            confidence=0.75,
            missing_evidence_types=["policy_docs"],
        )

        data = score.to_dict()

        assert data["entity_id"] == "GV.OC"
        assert data["entity_type"] == "subcategory"
        assert data["level"] == 2
        assert data["score"] == 2.5
        assert data["evidence_count"] == 5
        assert data["confidence"] == 0.75
        assert "policy_docs" in data["missing_evidence_types"]
        assert "calculated_at" in data


# =============================================================================
# MaturityBreakdown Tests
# =============================================================================


class TestMaturityBreakdown:
    """Tests for MaturityBreakdown dataclass."""

    def test_breakdown_creation(self):
        """Test creating a maturity breakdown."""
        overall = MaturityScore(
            entity_id="overall",
            entity_type="overall",
            level=MaturityLevel.LEVEL_2,
            score=2.5,
        )

        breakdown = MaturityBreakdown(
            overall=overall,
            framework="nist-csf-2",
        )

        assert breakdown.overall == overall
        assert breakdown.framework == "nist-csf-2"

    def test_breakdown_defaults(self):
        """Test breakdown default values."""
        breakdown = MaturityBreakdown()

        assert breakdown.overall is None
        assert breakdown.by_function == {}
        assert breakdown.by_category == {}
        assert breakdown.by_subcategory == {}
        assert breakdown.framework == ""

    def test_breakdown_to_dict(self):
        """Test serialization to dictionary."""
        overall = MaturityScore(
            entity_id="overall",
            entity_type="overall",
            level=MaturityLevel.LEVEL_3,
            score=3.0,
        )

        function_score = MaturityScore(
            entity_id="PROTECT",
            entity_type="function",
            level=MaturityLevel.LEVEL_3,
            score=3.2,
        )

        breakdown = MaturityBreakdown(
            overall=overall,
            by_function={"PROTECT": function_score},
            framework="nist-csf-2",
        )

        data = breakdown.to_dict()

        assert data["overall"]["entity_id"] == "overall"
        assert data["framework"] == "nist-csf-2"
        assert "PROTECT" in data["by_function"]
        assert data["by_function"]["PROTECT"]["score"] == 3.2
        assert "calculated_at" in data

    def test_breakdown_to_dict_without_overall(self):
        """Test serialization when overall is None."""
        breakdown = MaturityBreakdown(framework="soc2")

        data = breakdown.to_dict()

        assert data["overall"] is None
        assert data["framework"] == "soc2"
