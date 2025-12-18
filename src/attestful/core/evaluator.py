"""
Compliance check evaluator engine for Attestful.

Evaluates resources against compliance checks using a flexible
condition-based system. Supports multiple operators and nested logic.
"""

from __future__ import annotations

import operator
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

from attestful.core.exceptions import EvaluationError
from attestful.core.logging import get_logger
from attestful.core.models import CheckResult, ComplianceCheck, Resource

logger = get_logger(__name__)


class Operator(str, Enum):
    """Supported comparison operators."""

    EQUALS = "eq"
    NOT_EQUALS = "ne"
    GREATER_THAN = "gt"
    GREATER_THAN_OR_EQUAL = "gte"
    LESS_THAN = "lt"
    LESS_THAN_OR_EQUAL = "lte"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    MATCHES = "matches"  # Regex
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    IS_EMPTY = "is_empty"
    IS_NOT_EMPTY = "is_not_empty"
    IS_TRUE = "is_true"
    IS_FALSE = "is_false"


class LogicOperator(str, Enum):
    """Logical operators for combining conditions."""

    AND = "and"
    OR = "or"
    NOT = "not"


@dataclass
class Condition:
    """
    A single condition to evaluate against a resource.

    Attributes:
        path: JSONPath-like path to the value (e.g., "raw_data.Encrypted").
        operator: Comparison operator.
        value: Expected value (optional for some operators).
    """

    path: str
    operator: Operator
    value: Any = None

    def evaluate(self, resource: Resource) -> bool:
        """
        Evaluate this condition against a resource.

        Args:
            resource: Resource to evaluate.

        Returns:
            True if condition is satisfied, False otherwise.
        """
        actual_value = self._get_value(resource)
        return self._compare(actual_value)

    def _get_value(self, resource: Resource) -> Any:
        """Extract value from resource using path."""
        # Convert resource to dict for path traversal
        data = {
            "id": resource.id,
            "type": resource.type,
            "provider": resource.provider,
            "region": resource.region,
            "name": resource.name,
            "tags": resource.tags,
            "raw_data": resource.raw_data,
        }

        parts = self.path.split(".")
        current = data

        for part in parts:
            if current is None:
                return None

            # Handle array indexing: field[0]
            match = re.match(r"(\w+)\[(\d+)\]", part)
            if match:
                field_name, index = match.groups()
                if isinstance(current, dict):
                    current = current.get(field_name)
                if isinstance(current, list) and len(current) > int(index):
                    current = current[int(index)]
                else:
                    return None
            elif isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list):
                # Return list of values for this field from all items
                current = [
                    item.get(part) if isinstance(item, dict) else None
                    for item in current
                ]
            else:
                return None

        return current

    def _compare(self, actual: Any) -> bool:
        """Compare actual value against expected using operator."""
        op = self.operator
        expected = self.value

        # Handle None/missing values
        if op == Operator.EXISTS:
            return actual is not None
        if op == Operator.NOT_EXISTS:
            return actual is None
        if op == Operator.IS_EMPTY:
            return actual is None or actual == "" or actual == [] or actual == {}
        if op == Operator.IS_NOT_EMPTY:
            return actual is not None and actual != "" and actual != [] and actual != {}
        if op == Operator.IS_TRUE:
            return actual is True or actual == "true" or actual == "True"
        if op == Operator.IS_FALSE:
            return actual is False or actual == "false" or actual == "False"

        # For other operators, None actual means condition fails
        if actual is None:
            return False

        # String operations
        if op == Operator.CONTAINS:
            if isinstance(actual, str):
                return str(expected) in actual
            if isinstance(actual, list):
                return expected in actual
            return False
        if op == Operator.NOT_CONTAINS:
            if isinstance(actual, str):
                return str(expected) not in actual
            if isinstance(actual, list):
                return expected not in actual
            return True
        if op == Operator.STARTS_WITH:
            return isinstance(actual, str) and actual.startswith(str(expected))
        if op == Operator.ENDS_WITH:
            return isinstance(actual, str) and actual.endswith(str(expected))
        if op == Operator.MATCHES:
            return isinstance(actual, str) and bool(re.match(str(expected), actual))

        # Collection operations
        if op == Operator.IN:
            return actual in expected if isinstance(expected, (list, tuple, set)) else False
        if op == Operator.NOT_IN:
            return actual not in expected if isinstance(expected, (list, tuple, set)) else True

        # Comparison operations
        ops_map: dict[Operator, Callable[[Any, Any], bool]] = {
            Operator.EQUALS: operator.eq,
            Operator.NOT_EQUALS: operator.ne,
            Operator.GREATER_THAN: operator.gt,
            Operator.GREATER_THAN_OR_EQUAL: operator.ge,
            Operator.LESS_THAN: operator.lt,
            Operator.LESS_THAN_OR_EQUAL: operator.le,
        }

        if op in ops_map:
            try:
                return ops_map[op](actual, expected)
            except TypeError:
                # Type mismatch in comparison
                return False

        return False


@dataclass
class ConditionGroup:
    """
    A group of conditions combined with a logical operator.

    Supports nested groups for complex logic like:
    (A AND B) OR (C AND D)
    """

    logic: LogicOperator
    conditions: list[Condition | ConditionGroup] = field(default_factory=list)

    def evaluate(self, resource: Resource) -> bool:
        """
        Evaluate all conditions in this group.

        Args:
            resource: Resource to evaluate.

        Returns:
            True if the group condition is satisfied.
        """
        if not self.conditions:
            return True

        results = [c.evaluate(resource) for c in self.conditions]

        if self.logic == LogicOperator.AND:
            return all(results)
        elif self.logic == LogicOperator.OR:
            return any(results)
        elif self.logic == LogicOperator.NOT:
            # NOT applies to the first condition only
            return not results[0] if results else True

        return False


@dataclass
class CheckDefinition:
    """
    Definition of a compliance check.

    Attributes:
        id: Unique check identifier.
        title: Human-readable title.
        description: Detailed description.
        severity: Check severity (critical, high, medium, low, info).
        resource_types: Resource types this check applies to.
        condition: Condition or condition group to evaluate.
        remediation: Remediation guidance.
        references: Links to documentation or standards.
        frameworks: Framework mappings (e.g., {"soc2": ["CC6.1"], "nist-800-53": ["AC-2"]}).
        tags: Additional tags for categorization.
    """

    id: str
    title: str
    description: str
    severity: str
    resource_types: list[str]
    condition: Condition | ConditionGroup
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    frameworks: dict[str, list[str]] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def applies_to(self, resource: Resource) -> bool:
        """Check if this definition applies to the given resource."""
        return resource.type in self.resource_types

    def evaluate(self, resource: Resource) -> CheckResult:
        """
        Evaluate this check against a resource.

        Args:
            resource: Resource to evaluate.

        Returns:
            CheckResult with pass/fail status.
        """
        if not self.applies_to(resource):
            raise EvaluationError(
                f"Check {self.id} does not apply to resource type {resource.type}",
                details={"check_id": self.id, "resource_type": resource.type},
            )

        try:
            passed = self.condition.evaluate(resource)

            return CheckResult(
                check=ComplianceCheck(
                    id=self.id,
                    title=self.title,
                    description=self.description,
                    severity=self.severity,
                    framework_mappings=self.frameworks,
                ),
                resource_id=resource.id,
                resource_type=resource.type,
                passed=passed,
                evaluated_at=datetime.now(timezone.utc),
                details={
                    "remediation": self.remediation if not passed else None,
                    "references": self.references,
                },
            )
        except Exception as e:
            logger.error(f"Error evaluating check {self.id}: {e}")
            return CheckResult(
                check=ComplianceCheck(
                    id=self.id,
                    title=self.title,
                    description=self.description,
                    severity=self.severity,
                    framework_mappings=self.frameworks,
                ),
                resource_id=resource.id,
                resource_type=resource.type,
                passed=False,
                evaluated_at=datetime.now(timezone.utc),
                details={"error": str(e)},
            )


class Evaluator:
    """
    Compliance check evaluator.

    Evaluates resources against a set of check definitions.

    Example:
        evaluator = Evaluator()
        evaluator.load_checks_from_yaml("checks/aws.yaml")

        results = evaluator.evaluate(resources)
        for result in results:
            print(f"{result.check.id}: {'PASS' if result.passed else 'FAIL'}")
    """

    def __init__(self) -> None:
        """Initialize the evaluator."""
        self._checks: dict[str, CheckDefinition] = {}

    def register_check(self, check: CheckDefinition) -> None:
        """
        Register a check definition.

        Args:
            check: Check definition to register.
        """
        self._checks[check.id] = check
        logger.debug(f"Registered check: {check.id}")

    def get_check(self, check_id: str) -> CheckDefinition | None:
        """Get a check definition by ID."""
        return self._checks.get(check_id)

    def list_checks(
        self,
        *,
        resource_type: str | None = None,
        severity: str | None = None,
        framework: str | None = None,
        tags: list[str] | None = None,
    ) -> list[CheckDefinition]:
        """
        List registered checks with optional filtering.

        Args:
            resource_type: Filter by resource type.
            severity: Filter by severity.
            framework: Filter by framework.
            tags: Filter by tags (any match).

        Returns:
            List of matching check definitions.
        """
        checks = list(self._checks.values())

        if resource_type:
            checks = [c for c in checks if resource_type in c.resource_types]
        if severity:
            checks = [c for c in checks if c.severity == severity]
        if framework:
            checks = [c for c in checks if framework in c.frameworks]
        if tags:
            checks = [c for c in checks if any(t in c.tags for t in tags)]

        return checks

    def evaluate(
        self,
        resources: list[Resource],
        *,
        check_ids: list[str] | None = None,
        severity: str | None = None,
        framework: str | None = None,
    ) -> list[CheckResult]:
        """
        Evaluate resources against registered checks.

        Args:
            resources: Resources to evaluate.
            check_ids: Specific check IDs to run (optional).
            severity: Minimum severity to evaluate (optional).
            framework: Only run checks for this framework (optional).

        Returns:
            List of check results.
        """
        results: list[CheckResult] = []
        severity_order = ["critical", "high", "medium", "low", "info"]

        # Get checks to run
        if check_ids:
            checks = [self._checks[cid] for cid in check_ids if cid in self._checks]
        else:
            checks = list(self._checks.values())

        # Filter by severity
        if severity and severity in severity_order:
            min_idx = severity_order.index(severity)
            checks = [c for c in checks if severity_order.index(c.severity) <= min_idx]

        # Filter by framework
        if framework:
            checks = [c for c in checks if framework in c.frameworks]

        # Evaluate each resource against applicable checks
        for resource in resources:
            applicable_checks = [c for c in checks if c.applies_to(resource)]

            for check in applicable_checks:
                result = check.evaluate(resource)
                results.append(result)

        logger.info(
            f"Evaluated {len(resources)} resources against {len(checks)} checks, "
            f"produced {len(results)} results"
        )
        return results

    def load_checks_from_dict(self, data: dict[str, Any]) -> int:
        """
        Load check definitions from a dictionary.

        Args:
            data: Dictionary with check definitions.

        Returns:
            Number of checks loaded.
        """
        checks_data = data.get("checks", [])
        loaded = 0

        for check_data in checks_data:
            try:
                check = self._parse_check(check_data)
                self.register_check(check)
                loaded += 1
            except Exception as e:
                logger.error(f"Failed to parse check: {e}")

        return loaded

    def load_checks_from_yaml(self, path: str) -> int:
        """
        Load check definitions from a YAML file.

        Args:
            path: Path to YAML file.

        Returns:
            Number of checks loaded.
        """
        import yaml
        from pathlib import Path

        content = Path(path).read_text()
        data = yaml.safe_load(content)
        return self.load_checks_from_dict(data)

    def _parse_check(self, data: dict[str, Any]) -> CheckDefinition:
        """Parse a check definition from dictionary."""
        condition = self._parse_condition(data.get("condition", {}))

        return CheckDefinition(
            id=data["id"],
            title=data["title"],
            description=data.get("description", ""),
            severity=data.get("severity", "medium"),
            resource_types=data.get("resource_types", []),
            condition=condition,
            remediation=data.get("remediation", ""),
            references=data.get("references", []),
            frameworks=data.get("frameworks", {}),
            tags=data.get("tags", []),
        )

    def _parse_condition(
        self, data: dict[str, Any]
    ) -> Condition | ConditionGroup:
        """Parse a condition or condition group from dictionary."""
        # Check if it's a condition group
        if "and" in data:
            return ConditionGroup(
                logic=LogicOperator.AND,
                conditions=[self._parse_condition(c) for c in data["and"]],
            )
        if "or" in data:
            return ConditionGroup(
                logic=LogicOperator.OR,
                conditions=[self._parse_condition(c) for c in data["or"]],
            )
        if "not" in data:
            return ConditionGroup(
                logic=LogicOperator.NOT,
                conditions=[self._parse_condition(data["not"])],
            )

        # It's a simple condition
        return Condition(
            path=data.get("path", ""),
            operator=Operator(data.get("operator", "eq")),
            value=data.get("value"),
        )


# =============================================================================
# Built-in AWS Checks
# =============================================================================


def get_aws_checks() -> list[CheckDefinition]:
    """Get built-in AWS compliance checks."""
    return [
        # S3 Checks
        CheckDefinition(
            id="aws-s3-encryption-enabled",
            title="S3 Bucket Encryption Enabled",
            description="Ensure S3 buckets have server-side encryption enabled",
            severity="high",
            resource_types=["s3_bucket"],
            condition=Condition(
                path="raw_data.Encryption",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Enable default encryption on the S3 bucket using AES-256 or AWS KMS",
            frameworks={
                "soc2": ["CC6.1"],
                "nist-800-53": ["SC-28"],
                "cis-aws": ["2.1.1"],
            },
            tags=["encryption", "s3", "data-protection"],
        ),
        CheckDefinition(
            id="aws-s3-public-access-blocked",
            title="S3 Bucket Public Access Blocked",
            description="Ensure S3 buckets block public access",
            severity="critical",
            resource_types=["s3_bucket"],
            condition=ConditionGroup(
                logic=LogicOperator.AND,
                conditions=[
                    Condition(
                        path="raw_data.PublicAccessBlock.PublicAccessBlockConfiguration.BlockPublicAcls",
                        operator=Operator.IS_TRUE,
                    ),
                    Condition(
                        path="raw_data.PublicAccessBlock.PublicAccessBlockConfiguration.BlockPublicPolicy",
                        operator=Operator.IS_TRUE,
                    ),
                ],
            ),
            remediation="Enable S3 Block Public Access settings at the bucket level",
            frameworks={
                "soc2": ["CC6.1", "CC6.6"],
                "nist-800-53": ["AC-3", "AC-21"],
                "cis-aws": ["2.1.5"],
            },
            tags=["public-access", "s3", "data-protection"],
        ),
        CheckDefinition(
            id="aws-s3-versioning-enabled",
            title="S3 Bucket Versioning Enabled",
            description="Ensure S3 buckets have versioning enabled for data protection",
            severity="medium",
            resource_types=["s3_bucket"],
            condition=Condition(
                path="raw_data.Versioning.Status",
                operator=Operator.EQUALS,
                value="Enabled",
            ),
            remediation="Enable versioning on the S3 bucket",
            frameworks={
                "soc2": ["CC6.1"],
                "nist-800-53": ["CP-9"],
                "cis-aws": ["2.1.3"],
            },
            tags=["versioning", "s3", "backup"],
        ),
        # EC2 Checks
        CheckDefinition(
            id="aws-ec2-imdsv2-required",
            title="EC2 Instance Metadata Service v2 Required",
            description="Ensure EC2 instances require IMDSv2 for enhanced security",
            severity="high",
            resource_types=["ec2_instance"],
            condition=Condition(
                path="raw_data.MetadataOptions.HttpTokens",
                operator=Operator.EQUALS,
                value="required",
            ),
            remediation="Modify the instance metadata options to require IMDSv2",
            frameworks={
                "soc2": ["CC6.1"],
                "nist-800-53": ["AC-3"],
                "cis-aws": ["5.6"],
            },
            tags=["ec2", "metadata", "imds"],
        ),
        CheckDefinition(
            id="aws-ec2-public-ip",
            title="EC2 Instance Public IP Check",
            description="Identify EC2 instances with public IP addresses",
            severity="medium",
            resource_types=["ec2_instance"],
            condition=Condition(
                path="raw_data.PublicIpAddress",
                operator=Operator.NOT_EXISTS,
            ),
            remediation="Consider using private subnets with NAT gateways instead of public IPs",
            frameworks={
                "soc2": ["CC6.6"],
                "nist-800-53": ["SC-7"],
            },
            tags=["ec2", "network", "public-access"],
        ),
        # Security Group Checks
        CheckDefinition(
            id="aws-sg-no-ingress-all",
            title="Security Group No Unrestricted Ingress",
            description="Ensure security groups don't allow unrestricted ingress (0.0.0.0/0)",
            severity="critical",
            resource_types=["ec2_security_group"],
            condition=ConditionGroup(
                logic=LogicOperator.NOT,
                conditions=[
                    Condition(
                        path="raw_data.IpPermissions",
                        operator=Operator.CONTAINS,
                        value="0.0.0.0/0",
                    ),
                ],
            ),
            remediation="Restrict security group rules to specific IP ranges",
            frameworks={
                "soc2": ["CC6.1", "CC6.6"],
                "nist-800-53": ["AC-4", "SC-7"],
                "cis-aws": ["5.2"],
            },
            tags=["security-group", "network", "ingress"],
        ),
        # IAM Checks
        CheckDefinition(
            id="aws-iam-user-mfa-enabled",
            title="IAM User MFA Enabled",
            description="Ensure IAM users have MFA enabled",
            severity="high",
            resource_types=["iam_user"],
            condition=Condition(
                path="raw_data.MFADevices",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Enable MFA for the IAM user",
            frameworks={
                "soc2": ["CC6.1"],
                "nist-800-53": ["IA-2"],
                "cis-aws": ["1.10"],
            },
            tags=["iam", "mfa", "authentication"],
        ),
        CheckDefinition(
            id="aws-iam-user-no-active-keys-90-days",
            title="IAM User Access Keys Rotated",
            description="Ensure IAM user access keys are rotated within 90 days",
            severity="medium",
            resource_types=["iam_user"],
            condition=Condition(
                path="raw_data.AccessKeys",
                operator=Operator.EXISTS,
            ),
            remediation="Rotate IAM user access keys that are older than 90 days",
            frameworks={
                "soc2": ["CC6.1"],
                "nist-800-53": ["AC-2"],
                "cis-aws": ["1.14"],
            },
            tags=["iam", "access-keys", "rotation"],
        ),
        # RDS Checks
        CheckDefinition(
            id="aws-rds-encryption-enabled",
            title="RDS Instance Encryption Enabled",
            description="Ensure RDS instances have encryption at rest enabled",
            severity="high",
            resource_types=["rds_instance"],
            condition=Condition(
                path="raw_data.StorageEncrypted",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable encryption for the RDS instance (requires recreation)",
            frameworks={
                "soc2": ["CC6.1"],
                "nist-800-53": ["SC-28"],
                "cis-aws": ["2.3.1"],
            },
            tags=["rds", "encryption", "data-protection"],
        ),
        CheckDefinition(
            id="aws-rds-public-access-disabled",
            title="RDS Instance Not Publicly Accessible",
            description="Ensure RDS instances are not publicly accessible",
            severity="critical",
            resource_types=["rds_instance"],
            condition=Condition(
                path="raw_data.PubliclyAccessible",
                operator=Operator.IS_FALSE,
            ),
            remediation="Disable public accessibility for the RDS instance",
            frameworks={
                "soc2": ["CC6.1", "CC6.6"],
                "nist-800-53": ["AC-3", "SC-7"],
                "cis-aws": ["2.3.2"],
            },
            tags=["rds", "public-access", "network"],
        ),
        CheckDefinition(
            id="aws-rds-multi-az-enabled",
            title="RDS Instance Multi-AZ Enabled",
            description="Ensure RDS instances have Multi-AZ deployment enabled",
            severity="medium",
            resource_types=["rds_instance"],
            condition=Condition(
                path="raw_data.MultiAZ",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable Multi-AZ deployment for the RDS instance",
            frameworks={
                "soc2": ["A1.2"],
                "nist-800-53": ["CP-10"],
            },
            tags=["rds", "availability", "disaster-recovery"],
        ),
        # CloudTrail Checks
        CheckDefinition(
            id="aws-cloudtrail-enabled",
            title="CloudTrail Logging Enabled",
            description="Ensure CloudTrail is enabled and logging",
            severity="critical",
            resource_types=["cloudtrail_trail"],
            condition=Condition(
                path="raw_data.Status.IsLogging",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable logging for the CloudTrail trail",
            frameworks={
                "soc2": ["CC7.2"],
                "nist-800-53": ["AU-2", "AU-3"],
                "cis-aws": ["3.1"],
            },
            tags=["cloudtrail", "logging", "audit"],
        ),
        CheckDefinition(
            id="aws-cloudtrail-encryption-enabled",
            title="CloudTrail Log Encryption Enabled",
            description="Ensure CloudTrail logs are encrypted with KMS",
            severity="high",
            resource_types=["cloudtrail_trail"],
            condition=Condition(
                path="raw_data.KMSKeyId",
                operator=Operator.EXISTS,
            ),
            remediation="Enable KMS encryption for CloudTrail logs",
            frameworks={
                "soc2": ["CC6.1"],
                "nist-800-53": ["SC-28"],
                "cis-aws": ["3.7"],
            },
            tags=["cloudtrail", "encryption", "logging"],
        ),
        # KMS Checks
        CheckDefinition(
            id="aws-kms-key-rotation-enabled",
            title="KMS Key Rotation Enabled",
            description="Ensure KMS keys have automatic rotation enabled",
            severity="medium",
            resource_types=["kms_key"],
            condition=Condition(
                path="raw_data.KeyRotationEnabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable automatic key rotation for the KMS key",
            frameworks={
                "soc2": ["CC6.1"],
                "nist-800-53": ["SC-12"],
                "cis-aws": ["3.8"],
            },
            tags=["kms", "encryption", "key-rotation"],
        ),
        # Lambda Checks
        CheckDefinition(
            id="aws-lambda-vpc-enabled",
            title="Lambda Function VPC Configuration",
            description="Ensure Lambda functions are configured within a VPC when accessing private resources",
            severity="medium",
            resource_types=["lambda_function"],
            condition=Condition(
                path="raw_data.VpcConfig.VpcId",
                operator=Operator.EXISTS,
            ),
            remediation="Configure the Lambda function to run within a VPC",
            frameworks={
                "soc2": ["CC6.6"],
                "nist-800-53": ["SC-7"],
            },
            tags=["lambda", "vpc", "network"],
        ),
    ]


def create_default_evaluator() -> Evaluator:
    """Create an evaluator with default built-in checks from all frameworks."""
    evaluator = Evaluator()

    # Load built-in AWS checks
    for check in get_aws_checks():
        evaluator.register_check(check)

    # Load SOC 2 framework checks
    try:
        from attestful.frameworks.soc2 import (
            get_soc2_aws_checks,
            get_soc2_azure_checks,
            get_soc2_gcp_checks,
        )

        for check in get_soc2_aws_checks():
            if check.id not in evaluator._checks:
                evaluator.register_check(check)
        for check in get_soc2_azure_checks():
            if check.id not in evaluator._checks:
                evaluator.register_check(check)
        for check in get_soc2_gcp_checks():
            if check.id not in evaluator._checks:
                evaluator.register_check(check)
    except ImportError:
        logger.debug("SOC 2 framework checks not available")

    # Load NIST 800-53 framework checks
    try:
        from attestful.frameworks.nist_800_53 import get_nist_800_53_aws_checks

        for check in get_nist_800_53_aws_checks():
            if check.id not in evaluator._checks:
                evaluator.register_check(check)
    except ImportError:
        logger.debug("NIST 800-53 framework checks not available")

    # Load ISO 27001 framework checks
    try:
        from attestful.frameworks.iso_27001 import get_iso_27001_aws_checks

        for check in get_iso_27001_aws_checks():
            if check.id not in evaluator._checks:
                evaluator.register_check(check)
    except ImportError:
        logger.debug("ISO 27001 framework checks not available")

    # Load HITRUST framework checks
    try:
        from attestful.frameworks.hitrust import get_hitrust_aws_checks

        for check in get_hitrust_aws_checks():
            if check.id not in evaluator._checks:
                evaluator.register_check(check)
    except ImportError:
        logger.debug("HITRUST framework checks not available")

    logger.info(f"Created evaluator with {len(evaluator._checks)} built-in checks")
    return evaluator
