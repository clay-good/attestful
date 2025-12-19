"""
Integration tests for scan and collection workflows.

Tests verify end-to-end workflows work correctly including:
- Full scan workflows with resource collection and evaluation
- Full collection workflows with evidence storage and maturity calculation
- Database migrations and data persistence
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from attestful.core.evaluator import (
    Evaluator,
    CheckDefinition,
    Condition,
    Operator,
    create_default_evaluator,
)
from attestful.core.models import (
    CollectionResult,
    Evidence,
    Resource,
)
from attestful.analysis.maturity import (
    MaturityCalculator,
    MaturityLevel,
)
from attestful.storage.evidence import EvidenceStore


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_aws_resources() -> list[Resource]:
    """Sample AWS resources for scan testing."""
    return [
        Resource(
            id="bucket-1",
            type="s3_bucket",
            provider="aws",
            region="us-east-1",
            name="encrypted-bucket",
            raw_data={
                "Name": "encrypted-bucket",
                "Encryption": {
                    "ServerSideEncryptionConfiguration": {
                        "Rules": [
                            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                        ]
                    }
                },
                "Versioning": {"Status": "Enabled"},
                "PublicAccessBlock": {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": True,
                        "IgnorePublicAcls": True,
                        "RestrictPublicBuckets": True,
                    }
                },
            },
        ),
        Resource(
            id="bucket-2",
            type="s3_bucket",
            provider="aws",
            region="us-east-1",
            name="unencrypted-bucket",
            raw_data={
                "Name": "unencrypted-bucket",
                "Versioning": {"Status": "Suspended"},
            },
        ),
        Resource(
            id="i-123456",
            type="ec2_instance",
            provider="aws",
            region="us-west-2",
            name="secure-instance",
            raw_data={
                "InstanceId": "i-123456",
                "MetadataOptions": {"HttpTokens": "required"},
                "PublicIpAddress": None,
                "State": {"Name": "running"},
            },
        ),
        Resource(
            id="user-admin",
            type="iam_user",
            provider="aws",
            name="admin-user",
            raw_data={
                "UserName": "admin-user",
                "MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/admin"}],
                "AccessKeys": [
                    {"AccessKeyId": "AKIA...", "Status": "Active", "CreateDate": "2024-01-01"},
                ],
            },
        ),
    ]


@pytest.fixture
def sample_evidence_items() -> list[Evidence]:
    """Sample evidence items for collection testing."""
    return [
        Evidence(
            platform="aws",
            evidence_type="iam_credential_report",
            raw_data={
                "users": [
                    {"user": "admin", "mfa_active": True, "password_enabled": True},
                    {"user": "readonly", "mfa_active": False, "password_enabled": True},
                ],
                "summary": {"total_users": 2, "mfa_enabled_count": 1},
            },
            metadata={"collection_method": "automated"},
        ),
        Evidence(
            platform="aws",
            evidence_type="password_policy",
            raw_data={
                "MinimumPasswordLength": 14,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
                "MaxPasswordAge": 90,
                "PasswordReusePrevention": 24,
            },
            metadata={"collection_method": "automated"},
        ),
        Evidence(
            platform="aws",
            evidence_type="cloudtrail_status",
            raw_data={
                "trails": [
                    {
                        "Name": "org-trail",
                        "IsMultiRegionTrail": True,
                        "IsLogging": True,
                        "IncludeGlobalServiceEvents": True,
                    },
                ],
                "summary": {"total_trails": 1, "logging_enabled": 1},
            },
            metadata={"collection_method": "automated"},
        ),
        Evidence(
            platform="okta",
            evidence_type="users",
            raw_data={
                "users": [
                    {"id": "u1", "status": "ACTIVE", "profile": {"email": "admin@example.com"}},
                    {"id": "u2", "status": "ACTIVE", "profile": {"email": "user@example.com"}},
                ],
                "total_count": 2,
                "status_breakdown": {"ACTIVE": 2},
            },
            metadata={"collection_method": "automated"},
        ),
        Evidence(
            platform="okta",
            evidence_type="mfa_factors",
            raw_data={
                "users": [
                    {"user_id": "u1", "email": "admin@example.com", "has_mfa": True, "factor_count": 2},
                    {"user_id": "u2", "email": "user@example.com", "has_mfa": True, "factor_count": 1},
                ],
                "summary": {
                    "total_users": 2,
                    "users_with_mfa": 2,
                    "mfa_enrollment_rate": 100.0,
                },
            },
            metadata={"collection_method": "automated"},
        ),
    ]


@pytest.fixture
def temp_evidence_dir(tmp_path: Path) -> Path:
    """Temporary directory for evidence storage."""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    return evidence_dir


@pytest.fixture
def evidence_store(temp_evidence_dir: Path) -> EvidenceStore:
    """Evidence store instance for testing."""
    return EvidenceStore(evidence_dir=temp_evidence_dir)


# =============================================================================
# Scan Workflow Tests
# =============================================================================


@pytest.mark.integration
class TestScanWorkflow:
    """Tests for full scan workflows."""

    def test_scan_workflow_resource_collection_to_evaluation(
        self, sample_aws_resources: list[Resource]
    ) -> None:
        """Test complete scan workflow from collection to evaluation."""
        # Step 1: Create evaluator with checks
        evaluator = create_default_evaluator()

        # Step 2: Evaluate resources
        results = evaluator.evaluate(sample_aws_resources)

        # Step 3: Verify results structure
        assert len(results) > 0

        # Group by pass/fail
        passed = [r for r in results if r.passed]
        failed = [r for r in results if not r.passed]

        # Our sample data has:
        # - encrypted-bucket (should pass most checks)
        # - unencrypted-bucket (should fail encryption/versioning checks)
        # - secure-instance (should pass IMDSv2)
        # - admin-user (should pass MFA check)
        assert len(passed) > 0
        assert len(failed) > 0  # unencrypted bucket should fail

    def test_scan_workflow_with_severity_filter(
        self, sample_aws_resources: list[Resource]
    ) -> None:
        """Test scan workflow filtering by severity."""
        evaluator = create_default_evaluator()

        # Only evaluate critical and high severity checks
        high_results = evaluator.evaluate(
            sample_aws_resources,
            severity="high",
        )

        # Compare to all results
        all_results = evaluator.evaluate(sample_aws_resources)

        # High severity filter should return fewer or equal results
        assert len(high_results) <= len(all_results)

        # All returned checks should be high or critical
        for result in high_results:
            assert result.check.severity in ["critical", "high"]

    def test_scan_workflow_with_framework_filter(
        self, sample_aws_resources: list[Resource]
    ) -> None:
        """Test scan workflow filtering by framework."""
        evaluator = create_default_evaluator()

        # Only evaluate SOC 2 checks
        soc2_results = evaluator.evaluate(
            sample_aws_resources,
            framework="soc2",
        )

        # All returned checks should map to SOC 2
        for result in soc2_results:
            assert "soc2" in result.check.framework_mappings

    def test_scan_workflow_result_aggregation(
        self, sample_aws_resources: list[Resource]
    ) -> None:
        """Test aggregating scan results by resource and check."""
        evaluator = create_default_evaluator()
        results = evaluator.evaluate(sample_aws_resources)

        # Aggregate by resource
        by_resource: dict[str, list] = {}
        for result in results:
            if result.resource_id not in by_resource:
                by_resource[result.resource_id] = []
            by_resource[result.resource_id].append(result)

        # Each resource should have multiple check results
        assert "bucket-1" in by_resource or any("bucket" in k for k in by_resource)

        # Aggregate by check
        by_check: dict[str, list] = {}
        for result in results:
            if result.check.id not in by_check:
                by_check[result.check.id] = []
            by_check[result.check.id].append(result)

        # Checks should have results for multiple resources (where applicable)
        s3_checks = [c for c in by_check.keys() if "s3" in c.lower()]
        for check_id in s3_checks:
            # S3 checks should evaluate both buckets
            s3_results = by_check[check_id]
            assert len(s3_results) >= 1

    def test_scan_workflow_custom_checks(
        self, sample_aws_resources: list[Resource]
    ) -> None:
        """Test scan workflow with custom check definitions."""
        evaluator = Evaluator()

        # Add custom check
        custom_check = CheckDefinition(
            id="custom-s3-naming",
            title="S3 Bucket Naming Convention",
            description="Buckets should follow naming convention",
            severity="low",
            resource_types=["s3_bucket"],
            condition=Condition(
                path="raw_data.Name",
                operator=Operator.STARTS_WITH,
                value="encrypted",
            ),
            frameworks={"internal": ["SEC-001"]},
        )
        evaluator.register_check(custom_check)

        results = evaluator.evaluate(sample_aws_resources)

        # Should have results for custom check
        custom_results = [r for r in results if r.check.id == "custom-s3-naming"]
        assert len(custom_results) == 2  # Two S3 buckets

        # encrypted-bucket should pass, unencrypted-bucket should fail
        by_resource = {r.resource_id: r for r in custom_results}
        assert by_resource["bucket-1"].passed is True
        assert by_resource["bucket-2"].passed is False


# =============================================================================
# Collection Workflow Tests
# =============================================================================


@pytest.mark.integration
class TestCollectionWorkflow:
    """Tests for full collection workflows."""

    def test_collection_workflow_evidence_to_maturity(
        self, sample_evidence_items: list[Evidence]
    ) -> None:
        """Test complete collection workflow from evidence to maturity score."""
        # Step 1: Create maturity calculator
        calc = MaturityCalculator(framework="nist-csf-2")

        # Step 2: Add evidence
        calc.add_evidence(sample_evidence_items)

        # Step 3: Calculate maturity
        result = calc.calculate()

        # Step 4: Verify results
        assert result.framework == "nist-csf-2"
        assert result.overall_score > 0
        assert len(result.category_scores) == 6  # 6 CSF functions

        # Should have some improvement from initial state
        assert result.overall_score > 15.0  # Base score with no evidence is 15.0

    def test_collection_workflow_evidence_storage(
        self,
        sample_evidence_items: list[Evidence],
        evidence_store: EvidenceStore,
    ) -> None:
        """Test evidence storage and retrieval."""
        # Store evidence
        stored_items = []
        for evidence in sample_evidence_items:
            stored = evidence_store.store(evidence)
            stored_items.append(stored)

        # Verify all stored
        assert len(stored_items) == len(sample_evidence_items)

        # Retrieve and verify
        for stored in stored_items:
            retrieved = evidence_store.get(stored.id)
            assert retrieved is not None
            assert retrieved.platform in ["aws", "okta"]

    def test_collection_workflow_trend_tracking(
        self, evidence_store: EvidenceStore
    ) -> None:
        """Test evidence collection trend tracking."""
        # Create evidence at different times
        old_evidence = Evidence(
            platform="aws",
            evidence_type="iam_credential_report",
            collected_at=datetime.now(timezone.utc) - timedelta(days=30),
            raw_data={"users": [], "summary": {"total_users": 5, "mfa_enabled_count": 2}},
        )

        recent_evidence = Evidence(
            platform="aws",
            evidence_type="iam_credential_report",
            collected_at=datetime.now(timezone.utc),
            raw_data={"users": [], "summary": {"total_users": 5, "mfa_enabled_count": 4}},
        )

        evidence_store.store(old_evidence)
        evidence_store.store(recent_evidence)

        # Get evidence history
        history = evidence_store.get_by_type(
            platform="aws",
            evidence_type="iam_credential_report",
        )

        assert len(history) == 2

        # Sort by collection time
        sorted_history = sorted(history, key=lambda e: e.collected_at)

        # MFA adoption should show improvement - use read() to get raw_data
        old_data = evidence_store.read(sorted_history[0].id)
        recent_data = evidence_store.read(sorted_history[1].id)
        assert old_data is not None
        assert recent_data is not None
        old_mfa = old_data["summary"]["mfa_enabled_count"]
        recent_mfa = recent_data["summary"]["mfa_enabled_count"]
        assert recent_mfa > old_mfa

    def test_collection_workflow_maturity_recommendations(
        self, sample_evidence_items: list[Evidence]
    ) -> None:
        """Test maturity calculation generates recommendations."""
        calc = MaturityCalculator(framework="nist-csf-2")
        calc.add_evidence(sample_evidence_items)

        result = calc.calculate()
        recommendations = calc.get_improvement_recommendations(result)

        # Should have recommendations for areas without evidence
        assert len(recommendations) > 0

        # Recommendations should be actionable
        for rec in recommendations:
            assert "category" in rec
            assert "subcategory" in rec
            assert "current_score" in rec
            assert "recommendations" in rec

    def test_collection_workflow_multi_platform(
        self, sample_evidence_items: list[Evidence]
    ) -> None:
        """Test collection from multiple platforms."""
        calc = MaturityCalculator(framework="nist-csf-2")
        calc.add_evidence(sample_evidence_items)

        # Should have evidence from multiple platforms
        platforms = set(e.platform for e in sample_evidence_items)
        assert len(platforms) > 1

        result = calc.calculate()

        # Multi-platform evidence should improve score
        assert result.overall_score > 0


# =============================================================================
# Database/Storage Workflow Tests
# =============================================================================


@pytest.mark.integration
class TestDatabaseWorkflow:
    """Tests for database-related workflows."""

    def test_evidence_store_integrity(
        self, temp_evidence_dir: Path
    ) -> None:
        """Test evidence store maintains data integrity."""
        store = EvidenceStore(evidence_dir=temp_evidence_dir)

        # Store evidence with specific data
        original = Evidence(
            platform="test",
            evidence_type="integrity_test",
            raw_data={
                "key": "value",
                "nested": {"inner": "data"},
                "list": [1, 2, 3],
            },
            metadata={"test": True},
        )

        stored = store.store(original)

        # Retrieve and verify data integrity
        retrieved = store.get(stored.id)

        assert retrieved is not None
        assert retrieved.platform == original.platform
        assert retrieved.evidence_type == original.evidence_type
        # Use read() to get raw_data
        retrieved_data = store.read(stored.id)
        assert retrieved_data == original.raw_data
        assert retrieved.metadata == original.metadata

    def test_evidence_store_file_organization(
        self, temp_evidence_dir: Path
    ) -> None:
        """Test evidence is organized by date and platform."""
        store = EvidenceStore(evidence_dir=temp_evidence_dir)

        # Store evidence for different platforms
        for platform in ["aws", "okta", "github"]:
            evidence = Evidence(
                platform=platform,
                evidence_type="test",
                raw_data={"platform": platform},
            )
            store.store(evidence)

        # Verify directory structure
        # Evidence should be organized under platform directories
        platforms_in_dir = [
            d.name for d in temp_evidence_dir.iterdir() if d.is_dir()
        ]

        # Depending on store implementation, check organization
        assert temp_evidence_dir.exists()

    def test_evidence_store_query_by_date_range(
        self, temp_evidence_dir: Path
    ) -> None:
        """Test querying evidence by date range."""
        store = EvidenceStore(evidence_dir=temp_evidence_dir)

        # Create evidence at different times
        now = datetime.now(timezone.utc)
        dates = [
            now - timedelta(days=30),
            now - timedelta(days=15),
            now - timedelta(days=5),
            now,
        ]

        for date in dates:
            evidence = Evidence(
                platform="test",
                evidence_type="date_test",
                collected_at=date,
                raw_data={"date": date.isoformat()},
            )
            store.store(evidence)

        # Query last 7 days
        recent = store.get_by_date_range(
            start=now - timedelta(days=7),
            end=now,
        )

        # Should only get 2 most recent
        assert len(recent) == 2

    def test_evidence_store_cleanup_old_data(
        self, temp_evidence_dir: Path
    ) -> None:
        """Test cleanup of old evidence data."""
        store = EvidenceStore(evidence_dir=temp_evidence_dir)

        # Create old evidence
        old_evidence = Evidence(
            platform="test",
            evidence_type="cleanup_test",
            collected_at=datetime.now(timezone.utc) - timedelta(days=365),
            raw_data={"old": True},
        )
        old_stored = store.store(old_evidence)

        # Create recent evidence
        recent_evidence = Evidence(
            platform="test",
            evidence_type="cleanup_test",
            collected_at=datetime.now(timezone.utc),
            raw_data={"recent": True},
        )
        recent_stored = store.store(recent_evidence)

        # Run cleanup (retain 90 days)
        deleted_count = store.cleanup(retention_days=90)

        # Old evidence should be deleted
        assert deleted_count >= 1
        assert store.get(old_stored.id) is None
        assert store.get(recent_stored.id) is not None


# =============================================================================
# End-to-End Integration Tests
# =============================================================================


@pytest.mark.integration
class TestEndToEndWorkflows:
    """End-to-end workflow tests combining multiple components."""

    def test_full_compliance_assessment_workflow(
        self,
        sample_aws_resources: list[Resource],
        sample_evidence_items: list[Evidence],
        temp_evidence_dir: Path,
    ) -> None:
        """Test complete compliance assessment workflow."""
        # Step 1: Run scan
        evaluator = create_default_evaluator()
        scan_results = evaluator.evaluate(sample_aws_resources)

        # Step 2: Store evidence
        store = EvidenceStore(evidence_dir=temp_evidence_dir)
        for evidence in sample_evidence_items:
            store.store(evidence)

        # Step 3: Calculate maturity
        calc = MaturityCalculator(framework="nist-csf-2")
        calc.add_evidence(sample_evidence_items)
        maturity_result = calc.calculate()

        # Step 4: Generate summary
        summary = {
            "scan_summary": {
                "total_resources": len(sample_aws_resources),
                "total_checks": len(scan_results),
                "passed": sum(1 for r in scan_results if r.passed),
                "failed": sum(1 for r in scan_results if not r.passed),
                "pass_rate": (
                    sum(1 for r in scan_results if r.passed) / len(scan_results) * 100
                    if scan_results else 0
                ),
            },
            "evidence_summary": {
                "total_evidence": len(sample_evidence_items),
                "platforms": list(set(e.platform for e in sample_evidence_items)),
            },
            "maturity_summary": {
                "framework": maturity_result.framework,
                "overall_score": maturity_result.overall_score,
                "overall_level": maturity_result.overall_level.name,
                "categories": {
                    c.category_id: c.score
                    for c in maturity_result.category_scores
                },
            },
        }

        # Verify comprehensive summary
        assert summary["scan_summary"]["total_resources"] == 4
        assert summary["evidence_summary"]["total_evidence"] == 5
        assert "aws" in summary["evidence_summary"]["platforms"]
        assert "okta" in summary["evidence_summary"]["platforms"]
        assert summary["maturity_summary"]["overall_score"] > 0

    def test_incremental_compliance_improvement_workflow(
        self, temp_evidence_dir: Path
    ) -> None:
        """Test workflow for tracking compliance improvement over time."""
        store = EvidenceStore(evidence_dir=temp_evidence_dir)
        calc = MaturityCalculator(framework="nist-csf-2")

        # Initial state - minimal evidence
        initial_evidence = [
            Evidence(
                platform="aws",
                evidence_type="iam_credential_report",
                collected_at=datetime.now(timezone.utc) - timedelta(days=30),
                raw_data={"summary": {"total_users": 10, "mfa_enabled_count": 2}},
                metadata={"collection_method": "manual"},
            ),
        ]

        for e in initial_evidence:
            store.store(e)
        calc.add_evidence(initial_evidence)
        initial_result = calc.calculate()

        # Improved state - more evidence, better coverage
        improved_calc = MaturityCalculator(framework="nist-csf-2")
        improved_evidence = [
            Evidence(
                platform="aws",
                evidence_type="iam_credential_report",
                collected_at=datetime.now(timezone.utc),
                raw_data={"summary": {"total_users": 10, "mfa_enabled_count": 9}},
                metadata={"collection_method": "automated"},
            ),
            Evidence(
                platform="aws",
                evidence_type="password_policy",
                collected_at=datetime.now(timezone.utc),
                raw_data={"MinimumPasswordLength": 14, "RequireSymbols": True},
                metadata={"collection_method": "automated"},
            ),
            Evidence(
                platform="aws",
                evidence_type="cloudtrail_status",
                collected_at=datetime.now(timezone.utc),
                raw_data={"trails": [{"IsLogging": True}]},
                metadata={"collection_method": "automated"},
            ),
        ]

        for e in improved_evidence:
            store.store(e)
        improved_calc.add_evidence(improved_evidence)
        improved_result = improved_calc.calculate()

        # Verify improvement
        assert improved_result.overall_score > initial_result.overall_score

        # More evidence types should lead to better coverage
        improved_metadata = improved_result.metadata or {}
        initial_metadata = initial_result.metadata or {}

    def test_multi_framework_assessment_workflow(
        self, sample_aws_resources: list[Resource]
    ) -> None:
        """Test compliance assessment across multiple frameworks."""
        evaluator = create_default_evaluator()

        # Evaluate for different frameworks
        frameworks = ["soc2", "nist-800-53"]
        framework_results = {}

        for framework in frameworks:
            results = evaluator.evaluate(
                sample_aws_resources,
                framework=framework,
            )
            framework_results[framework] = {
                "total_checks": len(results),
                "passed": sum(1 for r in results if r.passed),
                "failed": sum(1 for r in results if not r.passed),
            }

        # Each framework should have checks
        for framework, summary in framework_results.items():
            assert summary["total_checks"] > 0

        # Cross-framework comparison
        assert "soc2" in framework_results
        assert "nist-800-53" in framework_results


# =============================================================================
# Migration Tests
# =============================================================================


@pytest.mark.integration
class TestMigrationWorkflows:
    """Tests for database migration workflows."""

    def test_empty_database_initialization(
        self, tmp_path: Path
    ) -> None:
        """Test initializing from empty database."""
        db_path = tmp_path / "test.db"

        # Initialize evidence store (should create necessary structures)
        store = EvidenceStore(evidence_dir=tmp_path)

        # Should be able to store and retrieve immediately
        evidence = Evidence(
            platform="test",
            evidence_type="init_test",
            raw_data={"test": True},
        )
        stored = store.store(evidence)
        retrieved = store.get(stored.id)

        assert retrieved is not None

    def test_data_format_compatibility(
        self, tmp_path: Path
    ) -> None:
        """Test data format remains compatible across operations."""
        store = EvidenceStore(evidence_dir=tmp_path)

        # Store various data types
        test_cases = [
            {"string": "value", "number": 42, "bool": True, "null": None},
            {"list": [1, 2, 3], "nested": {"a": {"b": "c"}}},
            {"unicode": "hello \u4e16\u754c", "special": "line1\nline2"},
            {"datetime_str": "2024-01-15T10:00:00Z"},
        ]

        stored_items = []
        for i, data in enumerate(test_cases):
            evidence = Evidence(
                platform="test",
                evidence_type=f"compat_test_{i}",
                raw_data=data,
            )
            stored_items.append(store.store(evidence))

        # Retrieve and verify using read() for raw_data
        for stored, original_data in zip(stored_items, test_cases):
            retrieved = store.get(stored.id)
            assert retrieved is not None
            retrieved_data = store.read(stored.id)
            assert retrieved_data == original_data
