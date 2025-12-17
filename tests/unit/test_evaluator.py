"""
Unit tests for the compliance check evaluator.
"""

import pytest
from datetime import datetime, timezone

from attestful.core.evaluator import (
    Condition,
    ConditionGroup,
    Operator,
    LogicOperator,
    CheckDefinition,
    Evaluator,
    create_default_evaluator,
    get_aws_checks,
)
from attestful.core.models import Resource


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def sample_s3_bucket() -> Resource:
    """Sample S3 bucket resource for testing."""
    return Resource(
        id="bucket-123",
        type="s3_bucket",
        provider="aws",
        region="us-east-1",
        name="test-bucket",
        raw_data={
            "Name": "test-bucket",
            "Encryption": {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
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
        tags={"Environment": "production"},
    )


@pytest.fixture
def sample_ec2_instance() -> Resource:
    """Sample EC2 instance resource for testing."""
    return Resource(
        id="i-1234567890abcdef0",
        type="ec2_instance",
        provider="aws",
        region="us-west-2",
        name="test-instance",
        raw_data={
            "InstanceId": "i-1234567890abcdef0",
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
            "PublicIpAddress": None,
            "State": {"Name": "running"},
        },
        tags={"Name": "test-instance"},
    )


@pytest.fixture
def sample_iam_user() -> Resource:
    """Sample IAM user resource for testing."""
    return Resource(
        id="user-admin",
        type="iam_user",
        provider="aws",
        name="admin-user",
        raw_data={
            "UserName": "admin-user",
            "MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/admin"}],
            "AccessKeys": [
                {"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "Status": "Active"},
            ],
        },
    )


# =============================================================================
# Condition Tests
# =============================================================================


class TestCondition:
    """Tests for the Condition class."""

    def test_equals_operator(self, sample_s3_bucket: Resource):
        """Test EQUALS operator."""
        condition = Condition(
            path="raw_data.Versioning.Status",
            operator=Operator.EQUALS,
            value="Enabled",
        )
        assert condition.evaluate(sample_s3_bucket) is True

        condition_fail = Condition(
            path="raw_data.Versioning.Status",
            operator=Operator.EQUALS,
            value="Suspended",
        )
        assert condition_fail.evaluate(sample_s3_bucket) is False

    def test_not_equals_operator(self, sample_s3_bucket: Resource):
        """Test NOT_EQUALS operator."""
        condition = Condition(
            path="raw_data.Versioning.Status",
            operator=Operator.NOT_EQUALS,
            value="Suspended",
        )
        assert condition.evaluate(sample_s3_bucket) is True

    def test_exists_operator(self, sample_s3_bucket: Resource):
        """Test EXISTS operator."""
        condition = Condition(
            path="raw_data.Encryption",
            operator=Operator.EXISTS,
        )
        assert condition.evaluate(sample_s3_bucket) is True

        condition_missing = Condition(
            path="raw_data.NonExistent",
            operator=Operator.EXISTS,
        )
        assert condition_missing.evaluate(sample_s3_bucket) is False

    def test_not_exists_operator(self, sample_ec2_instance: Resource):
        """Test NOT_EXISTS operator."""
        condition = Condition(
            path="raw_data.PublicIpAddress",
            operator=Operator.NOT_EXISTS,
        )
        assert condition.evaluate(sample_ec2_instance) is True

    def test_is_empty_operator(self):
        """Test IS_EMPTY operator."""
        resource = Resource(
            id="test",
            type="test",
            provider="test",
            raw_data={"empty_list": [], "empty_str": "", "empty_dict": {}},
        )

        assert Condition(path="raw_data.empty_list", operator=Operator.IS_EMPTY).evaluate(resource) is True
        assert Condition(path="raw_data.empty_str", operator=Operator.IS_EMPTY).evaluate(resource) is True
        assert Condition(path="raw_data.empty_dict", operator=Operator.IS_EMPTY).evaluate(resource) is True
        assert Condition(path="raw_data.nonexistent", operator=Operator.IS_EMPTY).evaluate(resource) is True

    def test_is_not_empty_operator(self, sample_iam_user: Resource):
        """Test IS_NOT_EMPTY operator."""
        condition = Condition(
            path="raw_data.MFADevices",
            operator=Operator.IS_NOT_EMPTY,
        )
        assert condition.evaluate(sample_iam_user) is True

    def test_is_true_operator(self, sample_s3_bucket: Resource):
        """Test IS_TRUE operator."""
        condition = Condition(
            path="raw_data.PublicAccessBlock.PublicAccessBlockConfiguration.BlockPublicAcls",
            operator=Operator.IS_TRUE,
        )
        assert condition.evaluate(sample_s3_bucket) is True

    def test_is_false_operator(self):
        """Test IS_FALSE operator."""
        resource = Resource(
            id="test",
            type="test",
            provider="test",
            raw_data={"flag": False, "str_flag": "false"},
        )

        assert Condition(path="raw_data.flag", operator=Operator.IS_FALSE).evaluate(resource) is True
        assert Condition(path="raw_data.str_flag", operator=Operator.IS_FALSE).evaluate(resource) is True

    def test_contains_operator(self):
        """Test CONTAINS operator for strings and lists."""
        resource = Resource(
            id="test",
            type="test",
            provider="test",
            raw_data={"name": "production-server", "tags": ["web", "production", "critical"]},
        )

        # String contains
        condition_str = Condition(
            path="raw_data.name",
            operator=Operator.CONTAINS,
            value="production",
        )
        assert condition_str.evaluate(resource) is True

        # List contains
        condition_list = Condition(
            path="raw_data.tags",
            operator=Operator.CONTAINS,
            value="web",
        )
        assert condition_list.evaluate(resource) is True

    def test_not_contains_operator(self):
        """Test NOT_CONTAINS operator."""
        resource = Resource(
            id="test",
            type="test",
            provider="test",
            raw_data={"name": "production-server", "tags": ["web", "production"]},
        )

        condition = Condition(
            path="raw_data.tags",
            operator=Operator.NOT_CONTAINS,
            value="development",
        )
        assert condition.evaluate(resource) is True

    def test_starts_with_operator(self):
        """Test STARTS_WITH operator."""
        resource = Resource(
            id="test",
            type="test",
            provider="test",
            raw_data={"name": "prod-web-01"},
        )

        condition = Condition(
            path="raw_data.name",
            operator=Operator.STARTS_WITH,
            value="prod-",
        )
        assert condition.evaluate(resource) is True

    def test_ends_with_operator(self):
        """Test ENDS_WITH operator."""
        resource = Resource(
            id="test",
            type="test",
            provider="test",
            raw_data={"name": "server.production.local"},
        )

        condition = Condition(
            path="raw_data.name",
            operator=Operator.ENDS_WITH,
            value=".local",
        )
        assert condition.evaluate(resource) is True

    def test_matches_operator(self):
        """Test MATCHES (regex) operator."""
        resource = Resource(
            id="test",
            type="test",
            provider="test",
            raw_data={"ip": "192.168.1.100"},
        )

        condition = Condition(
            path="raw_data.ip",
            operator=Operator.MATCHES,
            value=r"^192\.168\.\d+\.\d+$",
        )
        assert condition.evaluate(resource) is True

    def test_in_operator(self):
        """Test IN operator."""
        resource = Resource(
            id="test",
            type="test",
            provider="test",
            raw_data={"status": "running"},
        )

        condition = Condition(
            path="raw_data.status",
            operator=Operator.IN,
            value=["running", "stopped", "pending"],
        )
        assert condition.evaluate(resource) is True

    def test_not_in_operator(self):
        """Test NOT_IN operator."""
        resource = Resource(
            id="test",
            type="test",
            provider="test",
            raw_data={"status": "running"},
        )

        condition = Condition(
            path="raw_data.status",
            operator=Operator.NOT_IN,
            value=["terminated", "failed"],
        )
        assert condition.evaluate(resource) is True

    def test_comparison_operators(self):
        """Test GT, GTE, LT, LTE operators."""
        resource = Resource(
            id="test",
            type="test",
            provider="test",
            raw_data={"count": 10, "price": 99.99},
        )

        assert Condition(path="raw_data.count", operator=Operator.GREATER_THAN, value=5).evaluate(resource) is True
        assert Condition(path="raw_data.count", operator=Operator.GREATER_THAN_OR_EQUAL, value=10).evaluate(resource) is True
        assert Condition(path="raw_data.count", operator=Operator.LESS_THAN, value=20).evaluate(resource) is True
        assert Condition(path="raw_data.count", operator=Operator.LESS_THAN_OR_EQUAL, value=10).evaluate(resource) is True

    def test_path_traversal_with_array_index(self):
        """Test path traversal with array indexing."""
        resource = Resource(
            id="test",
            type="test",
            provider="test",
            raw_data={
                "items": [
                    {"name": "first", "value": 1},
                    {"name": "second", "value": 2},
                ]
            },
        )

        condition = Condition(
            path="raw_data.items[0].name",
            operator=Operator.EQUALS,
            value="first",
        )
        assert condition.evaluate(resource) is True

    def test_none_value_handling(self):
        """Test handling of None values."""
        resource = Resource(
            id="test",
            type="test",
            provider="test",
            raw_data={"value": None},
        )

        # None should satisfy NOT_EXISTS
        assert Condition(path="raw_data.missing", operator=Operator.NOT_EXISTS).evaluate(resource) is True

        # None should fail EQUALS
        assert Condition(path="raw_data.value", operator=Operator.EQUALS, value="something").evaluate(resource) is False


# =============================================================================
# ConditionGroup Tests
# =============================================================================


class TestConditionGroup:
    """Tests for ConditionGroup class."""

    def test_and_logic(self, sample_s3_bucket: Resource):
        """Test AND logic operator."""
        group = ConditionGroup(
            logic=LogicOperator.AND,
            conditions=[
                Condition(path="raw_data.Versioning.Status", operator=Operator.EQUALS, value="Enabled"),
                Condition(path="raw_data.Encryption", operator=Operator.EXISTS),
            ],
        )
        assert group.evaluate(sample_s3_bucket) is True

        # One condition fails
        group_fail = ConditionGroup(
            logic=LogicOperator.AND,
            conditions=[
                Condition(path="raw_data.Versioning.Status", operator=Operator.EQUALS, value="Enabled"),
                Condition(path="raw_data.NonExistent", operator=Operator.EXISTS),
            ],
        )
        assert group_fail.evaluate(sample_s3_bucket) is False

    def test_or_logic(self, sample_s3_bucket: Resource):
        """Test OR logic operator."""
        group = ConditionGroup(
            logic=LogicOperator.OR,
            conditions=[
                Condition(path="raw_data.Versioning.Status", operator=Operator.EQUALS, value="Suspended"),
                Condition(path="raw_data.Encryption", operator=Operator.EXISTS),
            ],
        )
        assert group.evaluate(sample_s3_bucket) is True

        # All conditions fail
        group_fail = ConditionGroup(
            logic=LogicOperator.OR,
            conditions=[
                Condition(path="raw_data.NonExistent1", operator=Operator.EXISTS),
                Condition(path="raw_data.NonExistent2", operator=Operator.EXISTS),
            ],
        )
        assert group_fail.evaluate(sample_s3_bucket) is False

    def test_not_logic(self, sample_s3_bucket: Resource):
        """Test NOT logic operator."""
        group = ConditionGroup(
            logic=LogicOperator.NOT,
            conditions=[
                Condition(path="raw_data.NonExistent", operator=Operator.EXISTS),
            ],
        )
        assert group.evaluate(sample_s3_bucket) is True

        group_fail = ConditionGroup(
            logic=LogicOperator.NOT,
            conditions=[
                Condition(path="raw_data.Encryption", operator=Operator.EXISTS),
            ],
        )
        assert group_fail.evaluate(sample_s3_bucket) is False

    def test_nested_groups(self, sample_s3_bucket: Resource):
        """Test nested condition groups: (A AND B) OR (C AND D)."""
        group = ConditionGroup(
            logic=LogicOperator.OR,
            conditions=[
                ConditionGroup(
                    logic=LogicOperator.AND,
                    conditions=[
                        Condition(path="raw_data.NonExistent", operator=Operator.EXISTS),
                        Condition(path="raw_data.AnotherNonExistent", operator=Operator.EXISTS),
                    ],
                ),
                ConditionGroup(
                    logic=LogicOperator.AND,
                    conditions=[
                        Condition(path="raw_data.Encryption", operator=Operator.EXISTS),
                        Condition(path="raw_data.Versioning.Status", operator=Operator.EQUALS, value="Enabled"),
                    ],
                ),
            ],
        )
        # First group fails, second group passes -> overall passes
        assert group.evaluate(sample_s3_bucket) is True

    def test_empty_conditions(self):
        """Test empty condition group returns True."""
        resource = Resource(id="test", type="test", provider="test")
        group = ConditionGroup(logic=LogicOperator.AND, conditions=[])
        assert group.evaluate(resource) is True


# =============================================================================
# CheckDefinition Tests
# =============================================================================


class TestCheckDefinition:
    """Tests for CheckDefinition class."""

    def test_applies_to(self, sample_s3_bucket: Resource, sample_ec2_instance: Resource):
        """Test resource type matching."""
        check = CheckDefinition(
            id="test-check",
            title="Test Check",
            description="Test",
            severity="medium",
            resource_types=["s3_bucket"],
            condition=Condition(path="raw_data.Encryption", operator=Operator.EXISTS),
        )

        assert check.applies_to(sample_s3_bucket) is True
        assert check.applies_to(sample_ec2_instance) is False

    def test_evaluate_passing(self, sample_s3_bucket: Resource):
        """Test check evaluation that passes."""
        check = CheckDefinition(
            id="s3-encryption",
            title="S3 Encryption",
            description="Check S3 encryption",
            severity="high",
            resource_types=["s3_bucket"],
            condition=Condition(path="raw_data.Encryption", operator=Operator.EXISTS),
            frameworks={"soc2": ["CC6.1"]},
        )

        result = check.evaluate(sample_s3_bucket)

        assert result.passed is True
        assert result.resource_id == "bucket-123"
        assert result.check.id == "s3-encryption"
        assert result.check.severity == "high"
        assert result.check.framework_mappings == {"soc2": ["CC6.1"]}

    def test_evaluate_failing(self):
        """Test check evaluation that fails."""
        resource = Resource(
            id="unencrypted-bucket",
            type="s3_bucket",
            provider="aws",
            raw_data={"Name": "unencrypted"},
        )

        check = CheckDefinition(
            id="s3-encryption",
            title="S3 Encryption",
            description="Check S3 encryption",
            severity="high",
            resource_types=["s3_bucket"],
            condition=Condition(path="raw_data.Encryption", operator=Operator.EXISTS),
            remediation="Enable encryption",
        )

        result = check.evaluate(resource)

        assert result.passed is False
        assert result.details.get("remediation") == "Enable encryption"

    def test_evaluate_wrong_resource_type(self, sample_ec2_instance: Resource):
        """Test that evaluating wrong resource type raises error."""
        check = CheckDefinition(
            id="s3-encryption",
            title="S3 Encryption",
            description="Check S3 encryption",
            severity="high",
            resource_types=["s3_bucket"],
            condition=Condition(path="raw_data.Encryption", operator=Operator.EXISTS),
        )

        with pytest.raises(Exception):  # EvaluationError
            check.evaluate(sample_ec2_instance)


# =============================================================================
# Evaluator Tests
# =============================================================================


class TestEvaluator:
    """Tests for Evaluator class."""

    def test_register_and_get_check(self):
        """Test registering and retrieving checks."""
        evaluator = Evaluator()
        check = CheckDefinition(
            id="test-check",
            title="Test",
            description="Test",
            severity="medium",
            resource_types=["test"],
            condition=Condition(path="id", operator=Operator.EXISTS),
        )

        evaluator.register_check(check)

        retrieved = evaluator.get_check("test-check")
        assert retrieved is not None
        assert retrieved.id == "test-check"

        assert evaluator.get_check("nonexistent") is None

    def test_list_checks_filtering(self):
        """Test listing checks with filters."""
        evaluator = Evaluator()

        checks = [
            CheckDefinition(
                id="s3-check-1",
                title="S3 Check 1",
                description="",
                severity="high",
                resource_types=["s3_bucket"],
                condition=Condition(path="id", operator=Operator.EXISTS),
                frameworks={"soc2": ["CC6.1"]},
                tags=["encryption"],
            ),
            CheckDefinition(
                id="ec2-check-1",
                title="EC2 Check 1",
                description="",
                severity="medium",
                resource_types=["ec2_instance"],
                condition=Condition(path="id", operator=Operator.EXISTS),
                frameworks={"soc2": ["CC6.6"]},
                tags=["network"],
            ),
            CheckDefinition(
                id="s3-check-2",
                title="S3 Check 2",
                description="",
                severity="low",
                resource_types=["s3_bucket"],
                condition=Condition(path="id", operator=Operator.EXISTS),
                frameworks={"nist-800-53": ["SC-28"]},
                tags=["encryption"],
            ),
        ]

        for check in checks:
            evaluator.register_check(check)

        # Filter by resource type
        s3_checks = evaluator.list_checks(resource_type="s3_bucket")
        assert len(s3_checks) == 2

        # Filter by severity
        high_checks = evaluator.list_checks(severity="high")
        assert len(high_checks) == 1

        # Filter by framework
        soc2_checks = evaluator.list_checks(framework="soc2")
        assert len(soc2_checks) == 2

        # Filter by tags
        encryption_checks = evaluator.list_checks(tags=["encryption"])
        assert len(encryption_checks) == 2

    def test_evaluate_resources(self, sample_s3_bucket: Resource, sample_ec2_instance: Resource):
        """Test evaluating multiple resources."""
        evaluator = Evaluator()

        evaluator.register_check(
            CheckDefinition(
                id="s3-encryption",
                title="S3 Encryption",
                description="",
                severity="high",
                resource_types=["s3_bucket"],
                condition=Condition(path="raw_data.Encryption", operator=Operator.EXISTS),
            )
        )
        evaluator.register_check(
            CheckDefinition(
                id="ec2-imdsv2",
                title="EC2 IMDSv2",
                description="",
                severity="high",
                resource_types=["ec2_instance"],
                condition=Condition(
                    path="raw_data.MetadataOptions.HttpTokens",
                    operator=Operator.EQUALS,
                    value="required",
                ),
            )
        )

        results = evaluator.evaluate([sample_s3_bucket, sample_ec2_instance])

        assert len(results) == 2
        assert all(r.passed for r in results)

    def test_evaluate_with_severity_filter(self, sample_s3_bucket: Resource):
        """Test evaluation with severity filter."""
        evaluator = Evaluator()

        evaluator.register_check(
            CheckDefinition(
                id="critical-check",
                title="Critical",
                description="",
                severity="critical",
                resource_types=["s3_bucket"],
                condition=Condition(path="id", operator=Operator.EXISTS),
            )
        )
        evaluator.register_check(
            CheckDefinition(
                id="low-check",
                title="Low",
                description="",
                severity="low",
                resource_types=["s3_bucket"],
                condition=Condition(path="id", operator=Operator.EXISTS),
            )
        )

        # Only evaluate high and above
        results = evaluator.evaluate([sample_s3_bucket], severity="high")
        assert len(results) == 1
        assert results[0].check.id == "critical-check"

    def test_evaluate_with_framework_filter(self, sample_s3_bucket: Resource):
        """Test evaluation with framework filter."""
        evaluator = Evaluator()

        evaluator.register_check(
            CheckDefinition(
                id="soc2-check",
                title="SOC2",
                description="",
                severity="medium",
                resource_types=["s3_bucket"],
                condition=Condition(path="id", operator=Operator.EXISTS),
                frameworks={"soc2": ["CC6.1"]},
            )
        )
        evaluator.register_check(
            CheckDefinition(
                id="nist-check",
                title="NIST",
                description="",
                severity="medium",
                resource_types=["s3_bucket"],
                condition=Condition(path="id", operator=Operator.EXISTS),
                frameworks={"nist-800-53": ["SC-28"]},
            )
        )

        results = evaluator.evaluate([sample_s3_bucket], framework="soc2")
        assert len(results) == 1
        assert results[0].check.id == "soc2-check"

    def test_load_checks_from_dict(self):
        """Test loading checks from dictionary."""
        evaluator = Evaluator()

        data = {
            "checks": [
                {
                    "id": "test-check",
                    "title": "Test Check",
                    "description": "A test check",
                    "severity": "high",
                    "resource_types": ["s3_bucket"],
                    "condition": {
                        "path": "raw_data.Encrypted",
                        "operator": "eq",
                        "value": True,
                    },
                    "remediation": "Enable encryption",
                    "frameworks": {"soc2": ["CC6.1"]},
                    "tags": ["encryption"],
                }
            ]
        }

        loaded = evaluator.load_checks_from_dict(data)
        assert loaded == 1

        check = evaluator.get_check("test-check")
        assert check is not None
        assert check.title == "Test Check"
        assert check.severity == "high"

    def test_load_checks_with_nested_conditions(self):
        """Test loading checks with nested AND/OR conditions."""
        evaluator = Evaluator()

        data = {
            "checks": [
                {
                    "id": "complex-check",
                    "title": "Complex Check",
                    "description": "",
                    "severity": "medium",
                    "resource_types": ["s3_bucket"],
                    "condition": {
                        "and": [
                            {"path": "raw_data.Encrypted", "operator": "eq", "value": True},
                            {
                                "or": [
                                    {"path": "raw_data.Versioning", "operator": "eq", "value": "Enabled"},
                                    {"path": "raw_data.Backup", "operator": "exists"},
                                ]
                            },
                        ]
                    },
                }
            ]
        }

        loaded = evaluator.load_checks_from_dict(data)
        assert loaded == 1

        check = evaluator.get_check("complex-check")
        assert check is not None
        assert isinstance(check.condition, ConditionGroup)


# =============================================================================
# Built-in Checks Tests
# =============================================================================


class TestBuiltInChecks:
    """Tests for built-in AWS checks."""

    def test_get_aws_checks(self):
        """Test that built-in AWS checks are properly defined."""
        checks = get_aws_checks()

        assert len(checks) > 0

        # Verify all checks have required fields
        for check in checks:
            assert check.id
            assert check.title
            assert check.severity in ["critical", "high", "medium", "low", "info"]
            assert len(check.resource_types) > 0
            assert check.condition is not None

    def test_create_default_evaluator(self):
        """Test creating evaluator with default checks."""
        evaluator = create_default_evaluator()

        # Should have AWS checks loaded
        checks = evaluator.list_checks()
        assert len(checks) > 0

        # Should have S3 checks
        s3_checks = evaluator.list_checks(resource_type="s3_bucket")
        assert len(s3_checks) > 0

        # Should have IAM checks
        iam_checks = evaluator.list_checks(resource_type="iam_user")
        assert len(iam_checks) > 0

    def test_s3_encryption_check(self, sample_s3_bucket: Resource):
        """Test S3 encryption check with sample bucket."""
        evaluator = create_default_evaluator()

        results = evaluator.evaluate([sample_s3_bucket])
        s3_results = [r for r in results if r.resource_id == "bucket-123"]

        # Our sample bucket has encryption enabled
        encryption_result = next(
            (r for r in s3_results if "encryption" in r.check.id.lower()),
            None,
        )
        assert encryption_result is not None
        assert encryption_result.passed is True

    def test_ec2_imdsv2_check(self, sample_ec2_instance: Resource):
        """Test EC2 IMDSv2 check with sample instance."""
        evaluator = create_default_evaluator()

        results = evaluator.evaluate([sample_ec2_instance])
        ec2_results = [r for r in results if r.resource_id == "i-1234567890abcdef0"]

        # Our sample instance has IMDSv2 required
        imds_result = next(
            (r for r in ec2_results if "imds" in r.check.id.lower()),
            None,
        )
        assert imds_result is not None
        assert imds_result.passed is True

    def test_iam_mfa_check(self, sample_iam_user: Resource):
        """Test IAM MFA check with sample user."""
        evaluator = create_default_evaluator()

        results = evaluator.evaluate([sample_iam_user])
        iam_results = [r for r in results if r.resource_id == "user-admin"]

        # Our sample user has MFA enabled
        mfa_result = next(
            (r for r in iam_results if "mfa" in r.check.id.lower()),
            None,
        )
        assert mfa_result is not None
        assert mfa_result.passed is True
