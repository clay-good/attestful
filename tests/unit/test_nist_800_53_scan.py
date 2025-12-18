"""
Unit tests for NIST 800-53 scan integration.

Tests that NIST 800-53 checks are properly integrated with the evaluator
and can be used to scan resources.
"""

import pytest
from datetime import datetime, timezone

from attestful.core import (
    Resource,
    create_default_evaluator,
    Evaluator,
)
from attestful.frameworks.nist_800_53 import (
    get_nist_800_53_aws_checks,
    create_nist_800_53_evaluator,
)


# =============================================================================
# Default Evaluator Integration Tests
# =============================================================================


class TestDefaultEvaluatorNIST80053Integration:
    """Tests that NIST 800-53 checks are loaded in the default evaluator."""

    def test_default_evaluator_has_nist_800_53_checks(self):
        """Test that the default evaluator includes NIST 800-53 checks."""
        evaluator = create_default_evaluator()
        checks = evaluator.list_checks()

        # Should have NIST 800-53 checks
        nist_checks = [c for c in checks if "nist-800-53" in c.frameworks]
        assert len(nist_checks) > 0

    def test_default_evaluator_has_specific_nist_checks(self):
        """Test that specific NIST 800-53 checks are present."""
        evaluator = create_default_evaluator()

        # Check for MFA check
        mfa_check = evaluator.get_check("nist-800-53-aws-ac-2-1")
        assert mfa_check is not None
        assert mfa_check.title == "IAM users should have MFA enabled"

        # Check for CloudTrail check
        cloudtrail_check = evaluator.get_check("nist-800-53-aws-au-2-1")
        assert cloudtrail_check is not None

        # Check for S3 encryption check
        s3_check = evaluator.get_check("nist-800-53-aws-sc-13-1")
        assert s3_check is not None

    def test_filter_by_nist_800_53_framework(self):
        """Test filtering checks by NIST 800-53 framework."""
        evaluator = create_default_evaluator()
        nist_checks = evaluator.list_checks(framework="nist-800-53")

        assert len(nist_checks) > 0
        for check in nist_checks:
            assert "nist-800-53" in check.frameworks


# =============================================================================
# Resource Evaluation Tests
# =============================================================================


class TestNIST80053ResourceEvaluation:
    """Tests for evaluating resources against NIST 800-53 checks."""

    def test_evaluate_iam_user_with_mfa(self):
        """Test evaluating IAM user with MFA enabled."""
        evaluator = create_nist_800_53_evaluator()

        resource = Resource(
            id="iam-user-123",
            type="iam_user",
            provider="aws",
            region="us-east-1",
            name="test-user",
            raw_data={
                "UserName": "test-user",
                "MFADevices": [{"SerialNumber": "mfa-123"}],
            },
        )

        results = evaluator.evaluate([resource], framework="nist-800-53")

        # Find the MFA check result
        mfa_results = [r for r in results if r.check.id == "nist-800-53-aws-ac-2-1"]
        assert len(mfa_results) == 1
        assert mfa_results[0].passed is True

    def test_evaluate_iam_user_without_mfa(self):
        """Test evaluating IAM user without MFA enabled."""
        evaluator = create_nist_800_53_evaluator()

        resource = Resource(
            id="iam-user-456",
            type="iam_user",
            provider="aws",
            region="us-east-1",
            name="test-user-no-mfa",
            raw_data={
                "UserName": "test-user-no-mfa",
                "MFADevices": [],
            },
        )

        results = evaluator.evaluate([resource], framework="nist-800-53")

        # Find the MFA check result
        mfa_results = [r for r in results if r.check.id == "nist-800-53-aws-ac-2-1"]
        assert len(mfa_results) == 1
        assert mfa_results[0].passed is False

    def test_evaluate_cloudtrail_enabled(self):
        """Test evaluating CloudTrail with logging enabled."""
        evaluator = create_nist_800_53_evaluator()

        # Note: NIST 800-53 checks use "cloudtrail" as the resource type
        resource = Resource(
            id="cloudtrail-123",
            type="cloudtrail",
            provider="aws",
            region="us-east-1",
            name="my-trail",
            raw_data={
                "Name": "my-trail",
                "IsMultiRegionTrail": True,
                "IsLogging": True,
            },
        )

        results = evaluator.evaluate([resource], framework="nist-800-53")

        # Find the CloudTrail enabled check result
        ct_results = [r for r in results if r.check.id == "nist-800-53-aws-au-2-1"]
        assert len(ct_results) == 1
        assert ct_results[0].passed is True

    def test_evaluate_cloudtrail_disabled(self):
        """Test evaluating CloudTrail with logging disabled."""
        evaluator = create_nist_800_53_evaluator()

        # Note: NIST 800-53 checks use "cloudtrail" as the resource type
        resource = Resource(
            id="cloudtrail-456",
            type="cloudtrail",
            provider="aws",
            region="us-east-1",
            name="disabled-trail",
            raw_data={
                "Name": "disabled-trail",
                "IsMultiRegionTrail": False,
                "IsLogging": False,
            },
        )

        results = evaluator.evaluate([resource], framework="nist-800-53")

        # Find the CloudTrail enabled check result
        ct_results = [r for r in results if r.check.id == "nist-800-53-aws-au-2-1"]
        assert len(ct_results) == 1
        assert ct_results[0].passed is False

    def test_evaluate_s3_encrypted(self):
        """Test evaluating S3 bucket with encryption enabled."""
        evaluator = create_nist_800_53_evaluator()

        # NIST 800-53 check looks for raw_data.ServerSideEncryptionEnabled as boolean
        resource = Resource(
            id="s3-bucket-123",
            type="s3_bucket",
            provider="aws",
            region="us-east-1",
            name="encrypted-bucket",
            raw_data={
                "Name": "encrypted-bucket",
                "ServerSideEncryptionEnabled": True,
            },
        )

        results = evaluator.evaluate([resource], framework="nist-800-53")

        # Find the S3 encryption check result
        s3_results = [r for r in results if r.check.id == "nist-800-53-aws-sc-13-1"]
        assert len(s3_results) == 1
        assert s3_results[0].passed is True

    def test_evaluate_s3_not_encrypted(self):
        """Test evaluating S3 bucket without encryption."""
        evaluator = create_nist_800_53_evaluator()

        # NIST 800-53 check looks for raw_data.ServerSideEncryptionEnabled as boolean
        resource = Resource(
            id="s3-bucket-456",
            type="s3_bucket",
            provider="aws",
            region="us-east-1",
            name="unencrypted-bucket",
            raw_data={
                "Name": "unencrypted-bucket",
                "ServerSideEncryptionEnabled": False,
            },
        )

        results = evaluator.evaluate([resource], framework="nist-800-53")

        # Find the S3 encryption check result
        s3_results = [r for r in results if r.check.id == "nist-800-53-aws-sc-13-1"]
        assert len(s3_results) == 1
        assert s3_results[0].passed is False

    def test_evaluate_ebs_encrypted(self):
        """Test evaluating EBS volume with encryption enabled."""
        evaluator = create_nist_800_53_evaluator()

        resource = Resource(
            id="ebs-vol-123",
            type="ebs_volume",
            provider="aws",
            region="us-east-1",
            name="encrypted-volume",
            raw_data={
                "VolumeId": "vol-123",
                "Encrypted": True,
                "KmsKeyId": "kms-key-123",
            },
        )

        results = evaluator.evaluate([resource], framework="nist-800-53")

        # Find the EBS encryption check result
        ebs_results = [r for r in results if r.check.id == "nist-800-53-aws-sc-13-2"]
        assert len(ebs_results) == 1
        assert ebs_results[0].passed is True

    def test_evaluate_rds_encrypted(self):
        """Test evaluating RDS instance with encryption enabled."""
        evaluator = create_nist_800_53_evaluator()

        resource = Resource(
            id="rds-123",
            type="rds_instance",
            provider="aws",
            region="us-east-1",
            name="encrypted-db",
            raw_data={
                "DBInstanceIdentifier": "encrypted-db",
                "StorageEncrypted": True,
            },
        )

        results = evaluator.evaluate([resource], framework="nist-800-53")

        # Find the RDS encryption check result
        rds_results = [r for r in results if r.check.id == "nist-800-53-aws-sc-13-3"]
        assert len(rds_results) == 1
        assert rds_results[0].passed is True


# =============================================================================
# Severity Filtering Tests
# =============================================================================


class TestNIST80053SeverityFiltering:
    """Tests for severity filtering with NIST 800-53 checks."""

    def test_filter_by_critical_severity(self):
        """Test filtering NIST 800-53 checks by critical severity."""
        evaluator = create_nist_800_53_evaluator()
        checks = evaluator.list_checks(severity="critical", framework="nist-800-53")

        for check in checks:
            assert check.severity == "critical"

    def test_filter_by_high_severity(self):
        """Test filtering NIST 800-53 checks by high severity."""
        evaluator = create_nist_800_53_evaluator()
        checks = evaluator.list_checks(severity="high", framework="nist-800-53")

        for check in checks:
            assert check.severity == "high"

    def test_evaluate_with_severity_filter(self):
        """Test evaluating resources with severity filter."""
        evaluator = create_nist_800_53_evaluator()

        resource = Resource(
            id="iam-user-123",
            type="iam_user",
            provider="aws",
            region="us-east-1",
            name="test-user",
            raw_data={
                "UserName": "test-user",
                "MFADevices": [],
            },
        )

        # Evaluate with high severity filter
        high_results = evaluator.evaluate(
            [resource], severity="high", framework="nist-800-53"
        )

        # All results should be high severity or above
        for result in high_results:
            assert result.check.severity in ["critical", "high"]


# =============================================================================
# Multi-Resource Evaluation Tests
# =============================================================================


class TestNIST80053MultiResourceEvaluation:
    """Tests for evaluating multiple resources against NIST 800-53."""

    def test_evaluate_mixed_resources(self):
        """Test evaluating multiple resource types."""
        evaluator = create_nist_800_53_evaluator()

        resources = [
            Resource(
                id="iam-user-1",
                type="iam_user",
                provider="aws",
                region="us-east-1",
                name="user1",
                raw_data={"UserName": "user1", "MFADevices": [{"SerialNumber": "mfa-1"}]},
            ),
            Resource(
                id="s3-bucket-1",
                type="s3_bucket",
                provider="aws",
                region="us-east-1",
                name="bucket1",
                raw_data={"Name": "bucket1", "ServerSideEncryptionEnabled": True},
            ),
            Resource(
                id="cloudtrail-1",
                type="cloudtrail",  # NIST 800-53 checks use "cloudtrail" not "cloudtrail_trail"
                provider="aws",
                region="us-east-1",
                name="trail1",
                raw_data={"Name": "trail1", "IsLogging": True},
            ),
        ]

        results = evaluator.evaluate(resources, framework="nist-800-53")

        # Should have results for different resource types
        resource_ids = set(r.resource_id for r in results)
        assert "iam-user-1" in resource_ids
        assert "s3-bucket-1" in resource_ids
        assert "cloudtrail-1" in resource_ids

    def test_evaluate_multiple_same_type(self):
        """Test evaluating multiple resources of the same type."""
        evaluator = create_nist_800_53_evaluator()

        resources = [
            Resource(
                id="iam-user-1",
                type="iam_user",
                provider="aws",
                region="us-east-1",
                name="user1",
                raw_data={"UserName": "user1", "MFADevices": [{"SerialNumber": "mfa-1"}]},
            ),
            Resource(
                id="iam-user-2",
                type="iam_user",
                provider="aws",
                region="us-east-1",
                name="user2",
                raw_data={"UserName": "user2", "MFADevices": []},
            ),
        ]

        results = evaluator.evaluate(resources, framework="nist-800-53")

        # Get MFA check results
        mfa_results = [r for r in results if r.check.id == "nist-800-53-aws-ac-2-1"]
        assert len(mfa_results) == 2

        # One should pass, one should fail
        passed = sum(1 for r in mfa_results if r.passed)
        failed = sum(1 for r in mfa_results if not r.passed)
        assert passed == 1
        assert failed == 1


# =============================================================================
# Framework Mapping Tests
# =============================================================================


class TestNIST80053FrameworkMappings:
    """Tests for NIST 800-53 control mappings."""

    def test_checks_have_control_mappings(self):
        """Test that all NIST 800-53 checks have control mappings."""
        checks = get_nist_800_53_aws_checks()

        for check in checks:
            assert "nist-800-53" in check.frameworks
            assert len(check.frameworks["nist-800-53"]) > 0

    def test_check_control_families(self):
        """Test that checks map to expected control families."""
        checks = get_nist_800_53_aws_checks()

        # Collect all mapped controls
        all_controls = []
        for check in checks:
            all_controls.extend(check.frameworks.get("nist-800-53", []))

        # Should have controls from various families
        families = set()
        for control in all_controls:
            # Extract family (e.g., "AC" from "AC-2" or "IA-2(1)")
            family = control.split("-")[0]
            families.add(family)

        # Should have controls from expected families
        assert "AC" in families  # Access Control
        assert "AU" in families  # Audit and Accountability
        assert "SC" in families  # System and Communications Protection

    def test_result_has_framework_mappings(self):
        """Test that evaluation results include framework mappings."""
        evaluator = create_nist_800_53_evaluator()

        resource = Resource(
            id="iam-user-123",
            type="iam_user",
            provider="aws",
            region="us-east-1",
            name="test-user",
            raw_data={"UserName": "test-user", "MFADevices": []},
        )

        results = evaluator.evaluate([resource], framework="nist-800-53")

        for result in results:
            assert result.check.framework_mappings is not None
            assert "nist-800-53" in result.check.framework_mappings
