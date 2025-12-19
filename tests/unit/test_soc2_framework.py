"""
Unit tests for SOC 2 framework module.

Tests the SOC 2 Trust Services Criteria controls, check definitions,
and evaluator functionality.
"""

import pytest

from attestful.core.evaluator import Evaluator, Operator
from attestful.core.models import Resource
from attestful.frameworks.soc2 import (
    SOC2_CONTROLS,
    SOC2_FRAMEWORK_ID,
    SOC2_VERSION,
    SOC2Control,
    SOC2Framework,
    TSC_AVAILABILITY,
    TSC_CONFIDENTIALITY,
    TSC_PRIVACY,
    TSC_PROCESSING_INTEGRITY,
    TSC_SECURITY,
    create_soc2_evaluator,
    get_soc2_aws_checks,
    get_soc2_framework,
)


# =============================================================================
# SOC 2 Control Tests
# =============================================================================


class TestSOC2Controls:
    """Test SOC 2 control definitions."""

    def test_soc2_controls_exist(self):
        """SOC 2 controls should be defined."""
        assert len(SOC2_CONTROLS) > 0
        assert "CC6.1" in SOC2_CONTROLS
        assert "CC7.2" in SOC2_CONTROLS
        assert "CC8.1" in SOC2_CONTROLS
        assert "CC9.1" in SOC2_CONTROLS

    def test_cc6_controls_complete(self):
        """CC6 controls should be complete."""
        cc6_controls = [c for c in SOC2_CONTROLS if c.startswith("CC6")]
        assert len(cc6_controls) >= 6  # CC6.1, CC6.2, CC6.3, CC6.6, CC6.7, CC6.8

    def test_cc7_controls_complete(self):
        """CC7 controls should be complete."""
        cc7_controls = [c for c in SOC2_CONTROLS if c.startswith("CC7")]
        assert len(cc7_controls) >= 4  # CC7.1, CC7.2, CC7.3, CC7.4, CC7.5

    def test_availability_controls_exist(self):
        """Availability (A1) controls should be defined."""
        a1_controls = [c for c in SOC2_CONTROLS if c.startswith("A1")]
        assert len(a1_controls) >= 2  # A1.1, A1.2, A1.3

    def test_control_has_required_fields(self):
        """Each control should have required fields."""
        valid_categories = [
            TSC_SECURITY,
            TSC_AVAILABILITY,
            TSC_PROCESSING_INTEGRITY,
            TSC_CONFIDENTIALITY,
            TSC_PRIVACY,
        ]
        for control_id, control in SOC2_CONTROLS.items():
            assert control.id == control_id
            assert control.title
            assert control.description
            assert control.category in valid_categories

    def test_cc6_1_control_details(self):
        """CC6.1 control should have correct details."""
        control = SOC2_CONTROLS["CC6.1"]
        assert control.id == "CC6.1"
        assert "logical access security" in control.title.lower()
        assert control.category == TSC_SECURITY
        assert len(control.points_of_focus) >= 5


# =============================================================================
# SOC 2 Framework Tests
# =============================================================================


class TestSOC2Framework:
    """Test SOC 2 framework definition."""

    def test_framework_constants(self):
        """Framework constants should be defined."""
        assert SOC2_FRAMEWORK_ID == "soc2"
        assert SOC2_VERSION == "2017"

    def test_get_soc2_framework(self):
        """get_soc2_framework should return complete framework."""
        framework = get_soc2_framework()

        assert isinstance(framework, SOC2Framework)
        assert framework.version == SOC2_VERSION
        assert len(framework.controls) > 0
        assert len(framework.check_mappings) > 0

    def test_framework_control_lookup(self):
        """Framework should allow control lookup."""
        framework = get_soc2_framework()

        control = framework.get_control("CC6.1")
        assert control is not None
        assert control.id == "CC6.1"

        control = framework.get_control("nonexistent")
        assert control is None

    def test_framework_check_mappings(self):
        """Framework should map checks to controls."""
        framework = get_soc2_framework()

        cc6_1_checks = framework.get_checks_for_control("CC6.1")
        assert len(cc6_1_checks) > 0

        # All check IDs should start with soc2-
        for check_id in cc6_1_checks:
            assert check_id.startswith("soc2-")


# =============================================================================
# SOC 2 Check Definition Tests
# =============================================================================


class TestSOC2CheckDefinitions:
    """Test SOC 2 check definitions."""

    def test_get_soc2_aws_checks(self):
        """get_soc2_aws_checks should return check definitions."""
        checks = get_soc2_aws_checks()
        assert len(checks) > 0

    def test_check_has_required_fields(self):
        """Each check should have required fields."""
        checks = get_soc2_aws_checks()

        for check in checks:
            assert check.id
            assert check.title
            assert check.description
            assert check.severity in ["critical", "high", "medium", "low", "info"]
            assert len(check.resource_types) > 0
            assert check.condition is not None

    def test_check_has_soc2_mapping(self):
        """Each check should be mapped to SOC 2 controls."""
        checks = get_soc2_aws_checks()

        for check in checks:
            assert "soc2" in check.frameworks
            soc2_controls = check.frameworks["soc2"]
            assert len(soc2_controls) > 0
            # Each control should be a valid CC or A reference
            for control in soc2_controls:
                assert control.startswith("CC") or control.startswith("A")

    def test_mfa_check_exists(self):
        """MFA check should exist for CC6.1."""
        checks = get_soc2_aws_checks()
        mfa_checks = [c for c in checks if "mfa" in c.id.lower()]
        assert len(mfa_checks) >= 1

        mfa_check = mfa_checks[0]
        assert "CC6.1" in mfa_check.frameworks["soc2"]
        assert mfa_check.severity == "critical"

    def test_encryption_checks_exist(self):
        """Encryption checks should exist for CC6.1."""
        checks = get_soc2_aws_checks()
        encryption_checks = [c for c in checks if "encrypt" in c.id.lower()]
        assert len(encryption_checks) >= 3  # S3, RDS, EBS

    def test_public_access_checks_exist(self):
        """Public access checks should exist for CC6.6."""
        checks = get_soc2_aws_checks()
        public_checks = [c for c in checks if "public" in c.id.lower()]
        assert len(public_checks) >= 2  # S3, RDS

    def test_monitoring_checks_exist(self):
        """Monitoring checks should exist for CC7.2."""
        checks = get_soc2_aws_checks()
        monitoring_checks = [
            c for c in checks if "cloudtrail" in c.id.lower() or "guardduty" in c.id.lower()
        ]
        assert len(monitoring_checks) >= 3


# =============================================================================
# SOC 2 Evaluator Tests
# =============================================================================


class TestSOC2Evaluator:
    """Test SOC 2 evaluator functionality."""

    def test_create_soc2_evaluator(self):
        """create_soc2_evaluator should return configured evaluator."""
        evaluator = create_soc2_evaluator()

        assert isinstance(evaluator, Evaluator)
        assert len(evaluator._checks) > 0

    def test_evaluator_lists_checks(self):
        """Evaluator should list checks with filtering."""
        evaluator = create_soc2_evaluator()

        # List all checks
        all_checks = evaluator.list_checks()
        assert len(all_checks) > 0

        # Filter by resource type
        iam_checks = evaluator.list_checks(resource_type="iam_user")
        assert len(iam_checks) > 0
        for check in iam_checks:
            assert "iam_user" in check.resource_types

        # Filter by severity
        critical_checks = evaluator.list_checks(severity="critical")
        assert len(critical_checks) > 0
        for check in critical_checks:
            assert check.severity == "critical"

        # Filter by framework
        soc2_checks = evaluator.list_checks(framework="soc2")
        assert len(soc2_checks) == len(all_checks)  # All should be SOC 2

    def test_evaluator_evaluates_iam_user_mfa(self):
        """Evaluator should evaluate MFA check on IAM user resource."""
        evaluator = create_soc2_evaluator()

        # User with MFA
        user_with_mfa = Resource(
            id="user-123",
            type="iam_user",
            provider="aws",
            name="test-user",
            raw_data={"MFADevices": [{"SerialNumber": "arn:aws:iam::123:mfa/user"}]},
        )

        # User without MFA
        user_without_mfa = Resource(
            id="user-456",
            type="iam_user",
            provider="aws",
            name="test-user-no-mfa",
            raw_data={"MFADevices": []},
        )

        # Evaluate both
        results = evaluator.evaluate([user_with_mfa, user_without_mfa])

        # Find MFA results
        mfa_results = [r for r in results if "mfa" in r.check.id.lower()]
        assert len(mfa_results) == 2

        # User with MFA should pass
        mfa_pass = [r for r in mfa_results if r.resource_id == "user-123"]
        assert len(mfa_pass) == 1
        assert mfa_pass[0].passed is True

        # User without MFA should fail
        mfa_fail = [r for r in mfa_results if r.resource_id == "user-456"]
        assert len(mfa_fail) == 1
        assert mfa_fail[0].passed is False

    def test_evaluator_evaluates_s3_encryption(self):
        """Evaluator should evaluate S3 encryption check."""
        evaluator = create_soc2_evaluator()

        # Bucket with encryption
        encrypted_bucket = Resource(
            id="bucket-123",
            type="s3_bucket",
            provider="aws",
            name="encrypted-bucket",
            raw_data={
                "Encryption": {
                    "ServerSideEncryptionConfiguration": {
                        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                    }
                }
            },
        )

        # Bucket without encryption
        unencrypted_bucket = Resource(
            id="bucket-456",
            type="s3_bucket",
            provider="aws",
            name="unencrypted-bucket",
            raw_data={},
        )

        results = evaluator.evaluate([encrypted_bucket, unencrypted_bucket])

        # Find encryption results
        encryption_results = [r for r in results if "s3" in r.check.id.lower() and "encrypt" in r.check.id.lower()]

        # Should have results for both buckets
        assert len(encryption_results) == 2

    def test_evaluator_evaluates_rds_not_public(self):
        """Evaluator should evaluate RDS public access check."""
        evaluator = create_soc2_evaluator()

        # Private RDS
        private_rds = Resource(
            id="rds-123",
            type="rds_instance",
            provider="aws",
            name="private-db",
            raw_data={"PubliclyAccessible": False},
        )

        # Public RDS
        public_rds = Resource(
            id="rds-456",
            type="rds_instance",
            provider="aws",
            name="public-db",
            raw_data={"PubliclyAccessible": True},
        )

        results = evaluator.evaluate([private_rds, public_rds])

        # Find public access results
        public_results = [r for r in results if "rds-not-public" in r.check.id.lower()]
        assert len(public_results) == 2

        # Private RDS should pass
        private_result = [r for r in public_results if r.resource_id == "rds-123"]
        assert len(private_result) == 1
        assert private_result[0].passed is True

        # Public RDS should fail
        public_result = [r for r in public_results if r.resource_id == "rds-456"]
        assert len(public_result) == 1
        assert public_result[0].passed is False

    def test_evaluator_filters_by_check_ids(self):
        """Evaluator should filter by specific check IDs."""
        evaluator = create_soc2_evaluator()

        resource = Resource(
            id="test-123",
            type="iam_user",
            provider="aws",
            name="test-user",
            raw_data={"MFADevices": []},
        )

        # Evaluate only MFA check
        results = evaluator.evaluate([resource], check_ids=["soc2-cc6.1-mfa-enabled"])
        assert len(results) == 1
        assert results[0].check.id == "soc2-cc6.1-mfa-enabled"


# =============================================================================
# SOC 2 Control-Check Mapping Tests
# =============================================================================


class TestSOC2ControlCheckMapping:
    """Test mapping between SOC 2 controls and checks."""

    def test_cc6_1_has_multiple_checks(self):
        """CC6.1 should have multiple checks mapped."""
        framework = get_soc2_framework()
        checks = framework.get_checks_for_control("CC6.1")

        assert len(checks) >= 5  # MFA, password, encryption checks

    def test_cc7_2_has_monitoring_checks(self):
        """CC7.2 should have monitoring checks."""
        framework = get_soc2_framework()
        checks = framework.get_checks_for_control("CC7.2")

        assert len(checks) >= 3  # CloudTrail, Config, GuardDuty

    def test_all_checks_mapped_to_framework(self):
        """All checks should be mapped to at least one control."""
        from attestful.frameworks import get_soc2_azure_checks, get_soc2_gcp_checks

        framework = get_soc2_framework()
        # Get all checks (AWS + Azure + GCP)
        aws_checks = get_soc2_aws_checks()
        azure_checks = get_soc2_azure_checks()
        gcp_checks = get_soc2_gcp_checks()
        all_checks = aws_checks + azure_checks + gcp_checks

        # Collect all mapped check IDs
        mapped_check_ids = set()
        for control_checks in framework.check_mappings.values():
            mapped_check_ids.update(control_checks)

        # All checks should be mapped
        all_check_ids = {c.id for c in all_checks}
        assert all_check_ids == mapped_check_ids


# =============================================================================
# YAML Check Loading Tests
# =============================================================================


class TestYAMLCheckLoading:
    """Test loading checks from YAML files."""

    def test_yaml_checks_loadable(self):
        """YAML check definitions should be loadable."""
        from pathlib import Path

        yaml_path = (
            Path(__file__).parent.parent.parent / "data" / "standards" / "soc2-trust-services-criteria.yaml"
        )

        if yaml_path.exists():
            evaluator = Evaluator()
            loaded = evaluator.load_checks_from_yaml(str(yaml_path))
            assert loaded > 0

    def test_yaml_checks_have_correct_structure(self):
        """YAML checks should have correct structure."""
        import yaml
        from pathlib import Path

        yaml_path = (
            Path(__file__).parent.parent.parent / "data" / "standards" / "soc2-trust-services-criteria.yaml"
        )

        if yaml_path.exists():
            content = yaml_path.read_text()
            data = yaml.safe_load(content)

            assert "id" in data
            assert "name" in data
            assert "checks" in data
            assert len(data["checks"]) > 0

            for check in data["checks"]:
                assert "id" in check
                assert "title" in check
                assert "severity" in check
                assert "resource_types" in check
                assert "condition" in check


# =============================================================================
# Integration Tests
# =============================================================================


class TestSOC2Integration:
    """Integration tests for SOC 2 framework."""

    def test_full_scan_workflow(self):
        """Test a full scan workflow with multiple resources."""
        evaluator = create_soc2_evaluator()

        # Create a set of resources simulating an AWS account
        resources = [
            Resource(
                id="user-admin",
                type="iam_user",
                provider="aws",
                name="admin",
                raw_data={
                    "MFADevices": [{"SerialNumber": "arn:aws:iam::123:mfa/admin"}],
                    "AttachedPolicies": ["ReadOnlyAccess"],
                },
            ),
            Resource(
                id="user-developer",
                type="iam_user",
                provider="aws",
                name="developer",
                raw_data={
                    "MFADevices": [],  # No MFA - should fail
                    "AttachedPolicies": [],
                },
            ),
            Resource(
                id="bucket-logs",
                type="s3_bucket",
                provider="aws",
                name="company-logs",
                raw_data={
                    "Encryption": {"ServerSideEncryptionConfiguration": {}},
                    "PublicAccessBlock": {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": True,
                        "IgnorePublicAcls": True,
                        "RestrictPublicBuckets": True,
                    },
                    "Versioning": {"Status": "Enabled"},
                },
            ),
            Resource(
                id="bucket-public",
                type="s3_bucket",
                provider="aws",
                name="public-website",
                raw_data={
                    "Encryption": {},  # No encryption - should fail
                    "PublicAccessBlock": {
                        "BlockPublicAcls": False,  # Public - should fail
                        "BlockPublicPolicy": False,
                        "IgnorePublicAcls": False,
                        "RestrictPublicBuckets": False,
                    },
                },
            ),
            Resource(
                id="rds-prod",
                type="rds_instance",
                provider="aws",
                name="production-db",
                raw_data={
                    "StorageEncrypted": True,
                    "PubliclyAccessible": False,
                    "BackupRetentionPeriod": 7,
                    "MultiAZ": True,
                },
            ),
        ]

        # Run evaluation
        results = evaluator.evaluate(resources)

        # Verify we got results
        assert len(results) > 0

        # Count pass/fail
        passed = [r for r in results if r.passed is True]
        failed = [r for r in results if r.passed is False]

        # We should have some passes and some failures
        assert len(passed) > 0
        assert len(failed) > 0

        # Verify specific failures we expect
        developer_mfa_fail = [
            r for r in failed if r.resource_id == "user-developer" and "mfa" in r.check.id.lower()
        ]
        assert len(developer_mfa_fail) == 1

    def test_compliance_score_calculation(self):
        """Test calculating compliance score from results."""
        evaluator = create_soc2_evaluator()

        # All compliant resources
        resources = [
            Resource(
                id="user-1",
                type="iam_user",
                provider="aws",
                raw_data={"MFADevices": [{"SerialNumber": "mfa-1"}]},
            ),
        ]

        results = evaluator.evaluate(resources)

        # Calculate score
        if results:
            passed = len([r for r in results if r.passed is True])
            total = len(results)
            score = (passed / total) * 100 if total > 0 else 0

            assert 0 <= score <= 100
