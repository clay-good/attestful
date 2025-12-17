"""
Unit tests for remediation module.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from attestful.remediation.base import (
    RemediationAction,
    RemediationEngine,
    RemediationPlan,
    RemediationResult,
    RemediationStatus,
    RiskLevel,
)
from attestful.remediation.aws import (
    REMEDIATION_REGISTRY,
    BlockS3PublicAccessAction,
    EnableCloudTrailLogValidationAction,
    EnableKMSKeyRotationAction,
    EnableS3BucketEncryptionAction,
    EnableS3BucketVersioningAction,
    RemoveOpenSSHAccessAction,
    UpdateIAMPasswordPolicyAction,
    get_remediation_action,
)


# =============================================================================
# Test RemediationResult
# =============================================================================


class TestRemediationResult:
    """Tests for RemediationResult dataclass."""

    def test_create_result(self):
        """Test creating a remediation result."""
        result = RemediationResult(
            action_id="test-123",
            check_id="soc2-cc6.1-s3-encryption",
            resource_id="my-bucket",
            resource_type="s3_bucket",
            status=RemediationStatus.SUCCESS,
            message="Successfully enabled encryption",
            started_at=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            completed_at=datetime(2024, 1, 1, 12, 0, 5, tzinfo=timezone.utc),
            changes_made=["Enabled AES-256 encryption"],
            dry_run=False,
            risk_level=RiskLevel.LOW,
        )

        assert result.action_id == "test-123"
        assert result.check_id == "soc2-cc6.1-s3-encryption"
        assert result.resource_id == "my-bucket"
        assert result.status == RemediationStatus.SUCCESS
        assert len(result.changes_made) == 1

    def test_result_to_dict(self):
        """Test converting result to dictionary."""
        result = RemediationResult(
            action_id="test-123",
            check_id="soc2-cc6.1-s3-encryption",
            resource_id="my-bucket",
            resource_type="s3_bucket",
            status=RemediationStatus.SUCCESS,
            message="Success",
            started_at=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            completed_at=datetime(2024, 1, 1, 12, 0, 5, tzinfo=timezone.utc),
        )

        data = result.to_dict()

        assert data["action_id"] == "test-123"
        assert data["status"] == "success"
        assert data["risk_level"] == "low"
        assert "started_at" in data
        assert "completed_at" in data

    def test_result_with_error(self):
        """Test result with error."""
        result = RemediationResult(
            action_id="test-123",
            check_id="soc2-cc6.1-s3-encryption",
            resource_id="my-bucket",
            resource_type="s3_bucket",
            status=RemediationStatus.FAILED,
            message="Failed to enable encryption",
            started_at=datetime.now(timezone.utc),
            error="AccessDenied: Permission denied",
        )

        assert result.status == RemediationStatus.FAILED
        assert result.error is not None


# =============================================================================
# Test RemediationPlan
# =============================================================================


class TestRemediationPlan:
    """Tests for RemediationPlan."""

    def test_create_empty_plan(self):
        """Test creating an empty plan."""
        plan = RemediationPlan()

        assert len(plan.actions) == 0
        assert plan.created_at is not None

    def test_add_action(self):
        """Test adding an action to the plan."""
        plan = RemediationPlan()
        action = EnableS3BucketVersioningAction(
            check_id="soc2-cc7.3-s3-versioning",
            resource_id="my-bucket",
            resource_data={"name": "my-bucket"},
            dry_run=True,
        )

        plan.add_action(action)

        assert len(plan.actions) == 1
        assert plan.actions[0].check_id == "soc2-cc7.3-s3-versioning"

    def test_get_actions_by_risk(self):
        """Test filtering actions by risk level."""
        plan = RemediationPlan()

        # Add LOW risk action
        plan.add_action(
            EnableS3BucketVersioningAction(
                check_id="soc2-cc7.3-s3-versioning",
                resource_id="bucket-1",
                resource_data={"name": "bucket-1"},
                dry_run=True,
            )
        )

        # Add MEDIUM risk action
        plan.add_action(
            BlockS3PublicAccessAction(
                check_id="soc2-cc6.6-s3-public-access-blocked",
                resource_id="bucket-2",
                resource_data={"name": "bucket-2"},
                dry_run=True,
            )
        )

        # Add HIGH risk action
        plan.add_action(
            RemoveOpenSSHAccessAction(
                check_id="soc2-cc6.3-no-public-ssh",
                resource_id="sg-123",
                resource_data={},
                dry_run=True,
            )
        )

        low_actions = plan.get_actions_by_risk(RiskLevel.LOW)
        medium_actions = plan.get_actions_by_risk(RiskLevel.MEDIUM)
        high_actions = plan.get_actions_by_risk(RiskLevel.HIGH)

        assert len(low_actions) == 1
        assert len(medium_actions) == 1
        assert len(high_actions) == 1

    def test_get_summary(self):
        """Test getting plan summary."""
        plan = RemediationPlan()

        plan.add_action(
            EnableS3BucketVersioningAction(
                check_id="soc2-cc7.3-s3-versioning",
                resource_id="bucket-1",
                resource_data={"name": "bucket-1"},
                dry_run=True,
            )
        )

        plan.add_action(
            EnableS3BucketEncryptionAction(
                check_id="soc2-cc6.1-s3-encryption",
                resource_id="bucket-2",
                resource_data={"name": "bucket-2"},
                dry_run=True,
            )
        )

        summary = plan.get_summary()

        assert summary["total_actions"] == 2
        assert summary["by_risk_level"]["low"] == 2
        assert summary["by_resource_type"]["s3_bucket"] == 2


# =============================================================================
# Test RemediationEngine
# =============================================================================


class TestRemediationEngine:
    """Tests for RemediationEngine."""

    def test_create_engine(self):
        """Test creating remediation engine."""
        engine = RemediationEngine(
            max_concurrent=3,
            require_approval=False,
            max_risk_level=RiskLevel.HIGH,
        )

        assert engine.max_concurrent == 3
        assert engine.require_approval is False
        assert engine.max_risk_level == RiskLevel.HIGH

    def test_create_engine_with_callback(self):
        """Test creating engine with approval callback."""

        def my_callback(action):
            return True

        engine = RemediationEngine(
            require_approval=True,
            approval_callback=my_callback,
        )

        assert engine.approval_callback is not None

    @pytest.mark.asyncio
    async def test_execute_action_dry_run(self):
        """Test executing action in dry-run mode."""
        engine = RemediationEngine(require_approval=False)

        action = EnableS3BucketVersioningAction(
            check_id="soc2-cc7.3-s3-versioning",
            resource_id="my-bucket",
            resource_data={"name": "my-bucket"},
            dry_run=True,
        )

        # Mock validation to skip AWS call
        async def mock_validate():
            return (True, "Mock validation passed")

        action.validate = mock_validate

        result = await engine.execute_action(action, auto_approve=True)

        assert result.status == RemediationStatus.SUCCESS
        assert result.dry_run is True
        assert "[DRY RUN]" in result.message

    @pytest.mark.asyncio
    async def test_execute_action_skipped_without_approval(self):
        """Test that actions are skipped without approval."""
        engine = RemediationEngine(require_approval=True)

        action = EnableS3BucketVersioningAction(
            check_id="soc2-cc7.3-s3-versioning",
            resource_id="my-bucket",
            resource_data={"name": "my-bucket"},
            dry_run=False,
        )

        # Mock validation to skip AWS call
        async def mock_validate():
            return (True, "Mock validation passed")

        action.validate = mock_validate

        result = await engine.execute_action(action, auto_approve=False)

        assert result.status == RemediationStatus.SKIPPED
        assert "requires approval" in result.message

    @pytest.mark.asyncio
    async def test_execute_action_with_callback_approval(self):
        """Test executing action with callback approval."""
        approved_actions = []

        def approval_callback(action):
            approved_actions.append(action)
            return True

        engine = RemediationEngine(
            require_approval=True,
            approval_callback=approval_callback,
        )

        # Use dry_run=False to test approval callback (dry runs skip approval)
        action = EnableS3BucketVersioningAction(
            check_id="soc2-cc7.3-s3-versioning",
            resource_id="my-bucket",
            resource_data={"name": "my-bucket"},
            dry_run=False,
        )

        # Mock validation to skip AWS call
        async def mock_validate():
            return (True, "Mock validation passed")
        action.validate = mock_validate

        # Mock execute to return success without AWS call
        async def mock_execute():
            return action._create_result(
                status=RemediationStatus.SUCCESS,
                message="Mock execution success",
                changes_made=["Mock change"],
            )
        action.execute = mock_execute

        result = await engine.execute_action(action, auto_approve=False)

        assert result.status == RemediationStatus.SUCCESS
        assert len(approved_actions) == 1

    @pytest.mark.asyncio
    async def test_execute_action_callback_rejection(self):
        """Test that rejected actions are skipped."""

        def rejection_callback(action):
            return False

        engine = RemediationEngine(
            require_approval=True,
            approval_callback=rejection_callback,
        )

        action = EnableS3BucketVersioningAction(
            check_id="soc2-cc7.3-s3-versioning",
            resource_id="my-bucket",
            resource_data={"name": "my-bucket"},
            dry_run=False,
        )

        # Mock validation to skip AWS call
        async def mock_validate():
            return (True, "Mock validation passed")

        action.validate = mock_validate

        result = await engine.execute_action(action, auto_approve=False)

        assert result.status == RemediationStatus.SKIPPED
        assert "not approved" in result.message

    @pytest.mark.asyncio
    async def test_execute_action_risk_check(self):
        """Test that high-risk actions are skipped when exceeding max_risk_level."""
        engine = RemediationEngine(
            require_approval=False,
            max_risk_level=RiskLevel.LOW,
        )

        # MEDIUM risk action should be skipped
        action = BlockS3PublicAccessAction(
            check_id="soc2-cc6.6-s3-public-access-blocked",
            resource_id="my-bucket",
            resource_data={"name": "my-bucket"},
            dry_run=True,
        )

        result = await engine.execute_action(action, auto_approve=False)

        assert result.status == RemediationStatus.SKIPPED
        assert "exceeds maximum" in result.message

    @pytest.mark.asyncio
    async def test_execute_batch_dry_run(self):
        """Test executing batch of actions in dry-run mode."""
        engine = RemediationEngine(require_approval=False)

        actions = []
        for i in range(3):
            action = EnableS3BucketVersioningAction(
                check_id="soc2-cc7.3-s3-versioning",
                resource_id=f"bucket-{i}",
                resource_data={"name": f"bucket-{i}"},
                dry_run=True,
            )
            # Mock validation to skip AWS call
            async def mock_validate():
                return (True, "Mock validation passed")
            action.validate = mock_validate
            actions.append(action)

        results = await engine.execute_batch(actions, auto_approve=True)

        assert len(results) == 3
        assert all(r.status == RemediationStatus.SUCCESS for r in results)

    @pytest.mark.asyncio
    async def test_execute_plan_skip_high_risk(self):
        """Test that plan execution skips high-risk actions by default."""
        engine = RemediationEngine(require_approval=False)

        plan = RemediationPlan()

        # LOW risk action
        low_action = EnableS3BucketVersioningAction(
            check_id="soc2-cc7.3-s3-versioning",
            resource_id="bucket-1",
            resource_data={"name": "bucket-1"},
            dry_run=True,
        )
        # Mock validation
        async def mock_validate():
            return (True, "Mock validation passed")
        low_action.validate = mock_validate
        plan.add_action(low_action)

        # HIGH risk action
        high_action = RemoveOpenSSHAccessAction(
            check_id="soc2-cc6.3-no-public-ssh",
            resource_id="sg-123",
            resource_data={},
            dry_run=True,
        )
        high_action.validate = mock_validate
        plan.add_action(high_action)

        results = await engine.execute_plan(plan, auto_approve=True, skip_high_risk=True)

        assert len(results) == 2
        # LOW risk should succeed
        assert results[0].status == RemediationStatus.SUCCESS
        # HIGH risk should be skipped
        assert results[1].status == RemediationStatus.SKIPPED
        assert "high risk" in results[1].message

    def test_get_summary(self):
        """Test getting engine summary."""
        engine = RemediationEngine()

        # Add some mock results
        engine.results = [
            RemediationResult(
                action_id="1",
                check_id="test",
                resource_id="r1",
                resource_type="s3_bucket",
                status=RemediationStatus.SUCCESS,
                message="Success",
                started_at=datetime.now(timezone.utc),
            ),
            RemediationResult(
                action_id="2",
                check_id="test",
                resource_id="r2",
                resource_type="s3_bucket",
                status=RemediationStatus.FAILED,
                message="Failed",
                started_at=datetime.now(timezone.utc),
            ),
        ]

        summary = engine.get_summary()

        assert summary["total"] == 2
        assert summary["success"] == 1
        assert summary["failed"] == 1

    def test_clear_results(self):
        """Test clearing engine results."""
        engine = RemediationEngine()
        engine.results = [
            RemediationResult(
                action_id="1",
                check_id="test",
                resource_id="r1",
                resource_type="s3_bucket",
                status=RemediationStatus.SUCCESS,
                message="Success",
                started_at=datetime.now(timezone.utc),
            )
        ]

        engine.clear_results()

        assert len(engine.results) == 0


# =============================================================================
# Test AWS Remediation Actions
# =============================================================================


class TestEnableS3BucketVersioningAction:
    """Tests for EnableS3BucketVersioningAction."""

    def test_create_action(self):
        """Test creating versioning action."""
        action = EnableS3BucketVersioningAction(
            check_id="soc2-cc7.3-s3-versioning",
            resource_id="my-bucket",
            resource_data={"name": "my-bucket"},
            region="us-west-2",
            dry_run=True,
        )

        assert action.check_id == "soc2-cc7.3-s3-versioning"
        assert action.bucket_name == "my-bucket"
        assert action.region == "us-west-2"
        assert action.dry_run is True

    def test_get_description(self):
        """Test getting action description."""
        action = EnableS3BucketVersioningAction(
            check_id="soc2-cc7.3-s3-versioning",
            resource_id="my-bucket",
            resource_data={"name": "my-bucket"},
        )

        description = action.get_description()

        assert "my-bucket" in description
        assert "versioning" in description.lower()

    def test_get_risk_level(self):
        """Test getting risk level."""
        action = EnableS3BucketVersioningAction(
            check_id="soc2-cc7.3-s3-versioning",
            resource_id="my-bucket",
            resource_data={"name": "my-bucket"},
        )

        assert action.get_risk_level() == RiskLevel.LOW

    @pytest.mark.asyncio
    async def test_execute_dry_run(self):
        """Test dry-run execution."""
        action = EnableS3BucketVersioningAction(
            check_id="soc2-cc7.3-s3-versioning",
            resource_id="my-bucket",
            resource_data={"name": "my-bucket"},
            dry_run=True,
        )

        result = await action.execute()

        assert result.status == RemediationStatus.SUCCESS
        assert result.dry_run is True
        assert "[DRY RUN]" in result.message


class TestEnableS3BucketEncryptionAction:
    """Tests for EnableS3BucketEncryptionAction."""

    def test_create_action_without_kms(self):
        """Test creating encryption action with AES-256."""
        action = EnableS3BucketEncryptionAction(
            check_id="soc2-cc6.1-s3-encryption",
            resource_id="my-bucket",
            resource_data={"name": "my-bucket"},
        )

        assert action.kms_key_id is None

    def test_create_action_with_kms(self):
        """Test creating encryption action with KMS."""
        action = EnableS3BucketEncryptionAction(
            check_id="soc2-cc6.1-s3-encryption",
            resource_id="my-bucket",
            resource_data={"name": "my-bucket"},
            kms_key_id="arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
        )

        assert action.kms_key_id is not None

    def test_get_risk_level(self):
        """Test getting risk level."""
        action = EnableS3BucketEncryptionAction(
            check_id="soc2-cc6.1-s3-encryption",
            resource_id="my-bucket",
            resource_data={"name": "my-bucket"},
        )

        assert action.get_risk_level() == RiskLevel.LOW

    @pytest.mark.asyncio
    async def test_execute_dry_run(self):
        """Test dry-run execution."""
        action = EnableS3BucketEncryptionAction(
            check_id="soc2-cc6.1-s3-encryption",
            resource_id="my-bucket",
            resource_data={"name": "my-bucket"},
            dry_run=True,
        )

        result = await action.execute()

        assert result.status == RemediationStatus.SUCCESS
        assert "[DRY RUN]" in result.message
        assert "AES-256" in result.message


class TestBlockS3PublicAccessAction:
    """Tests for BlockS3PublicAccessAction."""

    def test_get_risk_level(self):
        """Test that blocking public access is MEDIUM risk."""
        action = BlockS3PublicAccessAction(
            check_id="soc2-cc6.6-s3-public-access-blocked",
            resource_id="my-bucket",
            resource_data={"name": "my-bucket"},
        )

        assert action.get_risk_level() == RiskLevel.MEDIUM

    def test_get_description(self):
        """Test getting action description."""
        action = BlockS3PublicAccessAction(
            check_id="soc2-cc6.6-s3-public-access-blocked",
            resource_id="my-bucket",
            resource_data={"name": "my-bucket"},
        )

        description = action.get_description()

        assert "my-bucket" in description
        assert "public access" in description.lower()


class TestUpdateIAMPasswordPolicyAction:
    """Tests for UpdateIAMPasswordPolicyAction."""

    def test_create_action_with_defaults(self):
        """Test creating action with default values."""
        action = UpdateIAMPasswordPolicyAction(
            check_id="soc2-cc6.1-password-min-length",
            resource_id="account-password-policy",
            resource_data={},
        )

        assert action.min_password_length == 14
        assert action.require_symbols is True
        assert action.require_numbers is True
        assert action.require_uppercase is True
        assert action.require_lowercase is True
        assert action.max_password_age == 90
        assert action.password_reuse_prevention == 24

    def test_create_action_with_custom_values(self):
        """Test creating action with custom values."""
        action = UpdateIAMPasswordPolicyAction(
            check_id="soc2-cc6.1-password-min-length",
            resource_id="account-password-policy",
            resource_data={},
            min_password_length=16,
            max_password_age=60,
        )

        assert action.min_password_length == 16
        assert action.max_password_age == 60

    def test_get_risk_level(self):
        """Test that password policy is MEDIUM risk."""
        action = UpdateIAMPasswordPolicyAction(
            check_id="soc2-cc6.1-password-min-length",
            resource_id="account-password-policy",
            resource_data={},
        )

        assert action.get_risk_level() == RiskLevel.MEDIUM


class TestRemoveOpenSSHAccessAction:
    """Tests for RemoveOpenSSHAccessAction."""

    def test_get_risk_level(self):
        """Test that removing SSH access is HIGH risk."""
        action = RemoveOpenSSHAccessAction(
            check_id="soc2-cc6.3-no-public-ssh",
            resource_id="sg-123",
            resource_data={},
        )

        assert action.get_risk_level() == RiskLevel.HIGH

    def test_get_description(self):
        """Test getting action description."""
        action = RemoveOpenSSHAccessAction(
            check_id="soc2-cc6.3-no-public-ssh",
            resource_id="sg-123",
            resource_data={},
        )

        description = action.get_description()

        assert "sg-123" in description
        assert "SSH" in description


class TestEnableKMSKeyRotationAction:
    """Tests for EnableKMSKeyRotationAction."""

    def test_get_risk_level(self):
        """Test that enabling key rotation is LOW risk."""
        action = EnableKMSKeyRotationAction(
            check_id="soc2-cc6.1-kms-rotation",
            resource_id="key-123",
            resource_data={},
        )

        assert action.get_risk_level() == RiskLevel.LOW

    @pytest.mark.asyncio
    async def test_execute_dry_run(self):
        """Test dry-run execution."""
        action = EnableKMSKeyRotationAction(
            check_id="soc2-cc6.1-kms-rotation",
            resource_id="key-123",
            resource_data={},
            dry_run=True,
        )

        result = await action.execute()

        assert result.status == RemediationStatus.SUCCESS
        assert "[DRY RUN]" in result.message


class TestEnableCloudTrailLogValidationAction:
    """Tests for EnableCloudTrailLogValidationAction."""

    def test_create_action(self):
        """Test creating CloudTrail log validation action."""
        action = EnableCloudTrailLogValidationAction(
            check_id="soc2-cc7.2-cloudtrail-log-validation",
            resource_id="my-trail",
            resource_data={"TrailName": "my-trail"},
            trail_name="my-trail",
        )

        assert action.trail_name == "my-trail"

    def test_get_risk_level(self):
        """Test that enabling log validation is LOW risk."""
        action = EnableCloudTrailLogValidationAction(
            check_id="soc2-cc7.2-cloudtrail-log-validation",
            resource_id="my-trail",
            resource_data={},
            trail_name="my-trail",
        )

        assert action.get_risk_level() == RiskLevel.LOW


# =============================================================================
# Test Remediation Registry
# =============================================================================


class TestRemediationRegistry:
    """Tests for remediation action registry."""

    def test_registry_has_s3_actions(self):
        """Test that registry contains S3 actions."""
        assert "soc2-cc6.1-s3-encryption" in REMEDIATION_REGISTRY
        assert "soc2-cc6.6-s3-public-access-blocked" in REMEDIATION_REGISTRY
        assert "soc2-cc7.3-s3-versioning" in REMEDIATION_REGISTRY

    def test_registry_has_iam_actions(self):
        """Test that registry contains IAM actions."""
        assert "soc2-cc6.1-password-min-length" in REMEDIATION_REGISTRY
        assert "soc2-cc6.1-password-uppercase" in REMEDIATION_REGISTRY

    def test_registry_has_cloudtrail_actions(self):
        """Test that registry contains CloudTrail actions."""
        assert "soc2-cc7.2-cloudtrail-log-validation" in REMEDIATION_REGISTRY

    def test_registry_has_security_group_actions(self):
        """Test that registry contains security group actions."""
        assert "soc2-cc6.3-no-public-ssh" in REMEDIATION_REGISTRY

    def test_registry_has_kms_actions(self):
        """Test that registry contains KMS actions."""
        assert "soc2-cc6.1-kms-rotation" in REMEDIATION_REGISTRY


class TestGetRemediationAction:
    """Tests for get_remediation_action factory function."""

    def test_get_s3_versioning_action(self):
        """Test getting S3 versioning action."""
        action = get_remediation_action(
            check_id="soc2-cc7.3-s3-versioning",
            resource_id="my-bucket",
            resource_data={"name": "my-bucket"},
            region="us-west-2",
            dry_run=True,
        )

        assert action is not None
        assert isinstance(action, EnableS3BucketVersioningAction)
        assert action.bucket_name == "my-bucket"
        assert action.region == "us-west-2"
        assert action.dry_run is True

    def test_get_s3_encryption_action_with_kms(self):
        """Test getting S3 encryption action with KMS key."""
        action = get_remediation_action(
            check_id="soc2-cc6.1-s3-encryption",
            resource_id="my-bucket",
            resource_data={"name": "my-bucket"},
            kms_key_id="arn:aws:kms:us-east-1:123456789012:key/test-key",
        )

        assert action is not None
        assert isinstance(action, EnableS3BucketEncryptionAction)
        assert action.kms_key_id == "arn:aws:kms:us-east-1:123456789012:key/test-key"

    def test_get_iam_password_policy_action(self):
        """Test getting IAM password policy action with custom settings."""
        action = get_remediation_action(
            check_id="soc2-cc6.1-password-min-length",
            resource_id="account",
            resource_data={},
            min_password_length=16,
            max_password_age=60,
        )

        assert action is not None
        assert isinstance(action, UpdateIAMPasswordPolicyAction)
        assert action.min_password_length == 16
        assert action.max_password_age == 60

    def test_get_cloudtrail_action(self):
        """Test getting CloudTrail action."""
        action = get_remediation_action(
            check_id="soc2-cc7.2-cloudtrail-log-validation",
            resource_id="my-trail",
            resource_data={"TrailName": "my-trail"},
        )

        assert action is not None
        assert isinstance(action, EnableCloudTrailLogValidationAction)
        assert action.trail_name == "my-trail"

    def test_get_unknown_action_returns_none(self):
        """Test that unknown check ID returns None."""
        action = get_remediation_action(
            check_id="unknown-check-id",
            resource_id="resource",
            resource_data={},
        )

        assert action is None

    def test_get_security_group_action(self):
        """Test getting security group action."""
        action = get_remediation_action(
            check_id="soc2-cc6.3-no-public-ssh",
            resource_id="sg-123",
            resource_data={},
        )

        assert action is not None
        assert isinstance(action, RemoveOpenSSHAccessAction)

    def test_get_kms_action(self):
        """Test getting KMS action."""
        action = get_remediation_action(
            check_id="soc2-cc6.1-kms-rotation",
            resource_id="key-123",
            resource_data={},
        )

        assert action is not None
        assert isinstance(action, EnableKMSKeyRotationAction)


# =============================================================================
# Test Risk Level Ordering
# =============================================================================


class TestRiskLevelOrdering:
    """Tests for risk level ordering in engine."""

    @pytest.mark.asyncio
    async def test_low_risk_allowed_with_low_max(self):
        """Test that LOW risk is allowed when max is LOW."""
        engine = RemediationEngine(
            require_approval=False,
            max_risk_level=RiskLevel.LOW,
        )

        action = EnableS3BucketVersioningAction(
            check_id="soc2-cc7.3-s3-versioning",
            resource_id="bucket",
            resource_data={"name": "bucket"},
            dry_run=True,
        )

        # Mock validation to skip AWS call
        async def mock_validate():
            return (True, "Mock validation passed")
        action.validate = mock_validate

        result = await engine.execute_action(action, auto_approve=False)

        assert result.status == RemediationStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_medium_risk_blocked_with_low_max(self):
        """Test that MEDIUM risk is blocked when max is LOW."""
        engine = RemediationEngine(
            require_approval=False,
            max_risk_level=RiskLevel.LOW,
        )

        action = BlockS3PublicAccessAction(
            check_id="soc2-cc6.6-s3-public-access-blocked",
            resource_id="bucket",
            resource_data={"name": "bucket"},
            dry_run=True,
        )

        result = await engine.execute_action(action, auto_approve=False)

        assert result.status == RemediationStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_high_risk_allowed_with_critical_max(self):
        """Test that HIGH risk is allowed when max is CRITICAL."""
        engine = RemediationEngine(
            require_approval=False,
            max_risk_level=RiskLevel.CRITICAL,
        )

        action = RemoveOpenSSHAccessAction(
            check_id="soc2-cc6.3-no-public-ssh",
            resource_id="sg-123",
            resource_data={},
            dry_run=True,
        )

        # Mock validation to skip AWS call
        async def mock_validate():
            return (True, "Mock validation passed")
        action.validate = mock_validate

        result = await engine.execute_action(action, auto_approve=False)

        assert result.status == RemediationStatus.SUCCESS
