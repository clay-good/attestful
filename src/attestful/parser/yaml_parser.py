"""
YAML parser for compliance standards.

This module parses YAML-formatted compliance standard definitions
and converts them into executable compliance checks.

Migrated from Compliy (Step 4.2.9 of instructions.txt).
"""

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from attestful.core.evaluator import ConditionEvaluator
from attestful.core.exceptions import ParserError
from attestful.core.logging import get_logger
from attestful.core.models import Severity

logger = get_logger(__name__)


class CheckDefinition(BaseModel):
    """Schema for a compliance check definition in YAML."""

    id: str = Field(..., description="Unique check identifier")
    name: str = Field(..., description="Human-readable check name")
    description: str = Field(..., description="Detailed description")
    severity: Severity = Field(..., description="Severity level")
    resource_types: list[str] = Field(..., description="Applicable resource types")
    condition: str = Field(..., description="Check condition expression")
    remediation: str | None = Field(None, description="Remediation guidance")
    references: list[str] = Field(default_factory=list, description="Reference URLs")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, v: Any) -> Severity:
        """Validate and convert severity to enum."""
        if isinstance(v, str):
            return Severity(v.lower())
        return v


class StandardDefinition(BaseModel):
    """Schema for a compliance standard definition in YAML."""

    id: str = Field(..., description="Unique standard identifier")
    name: str = Field(..., description="Human-readable standard name")
    version: str = Field(..., description="Standard version")
    description: str = Field(..., description="Detailed description")
    checks: list[CheckDefinition] = Field(..., description="List of compliance checks")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class ComplianceResult:
    """Result of a compliance check execution."""

    def __init__(
        self,
        status: str,
        resource_id: str,
        resource_type: str,
        check_id: str,
        check_name: str,
        message: str,
        severity: Severity,
        evidence: dict[str, Any] | None = None,
        remediation: str | None = None,
        references: list[str] | None = None,
    ) -> None:
        self.status = status
        self.resource_id = resource_id
        self.resource_type = resource_type
        self.check_id = check_id
        self.check_name = check_name
        self.message = message
        self.severity = severity
        self.evidence = evidence or {}
        self.remediation = remediation
        self.references = references or []


class DynamicComplianceCheck:
    """
    A dynamically created compliance check from YAML definition.

    This check evaluates a condition expression against resource data.
    """

    def __init__(
        self,
        check_id: str,
        name: str,
        description: str,
        severity: Severity,
        resource_types: list[str],
        condition: str,
        remediation: str | None = None,
        references: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Initialize dynamic compliance check."""
        self.check_id = check_id
        self.name = name
        self.description = description
        self.severity = severity
        self.resource_types = resource_types
        self.condition = condition
        self.remediation = remediation
        self.references = references or []
        self.metadata = metadata or {}
        self.evaluator = ConditionEvaluator()

    def create_result(
        self,
        status: str,
        resource_id: str,
        resource_type: str,
        message: str,
        evidence: dict[str, Any] | None = None,
    ) -> ComplianceResult:
        """Create a compliance result."""
        return ComplianceResult(
            status=status,
            resource_id=resource_id,
            resource_type=resource_type,
            check_id=self.check_id,
            check_name=self.name,
            message=message,
            severity=self.severity,
            evidence=evidence,
            remediation=self.remediation,
            references=self.references,
        )

    async def execute(self, resource: dict[str, Any]) -> ComplianceResult:
        """
        Execute the compliance check against a resource.

        Args:
            resource: The resource to check

        Returns:
            ComplianceResult with the check outcome
        """
        resource_id = resource.get("id", "unknown")
        resource_type = resource.get("type", "unknown")

        # Check if this check applies to this resource type
        if resource_type not in self.resource_types:
            return self.create_result(
                status="skip",
                resource_id=resource_id,
                resource_type=resource_type,
                message=f"Check not applicable to resource type: {resource_type}",
            )

        try:
            # Evaluate the condition
            result = self._evaluate_condition(resource)

            if result:
                return self.create_result(
                    status="pass",
                    resource_id=resource_id,
                    resource_type=resource_type,
                    message=f"Check passed: {self.name}",
                    evidence={"condition": self.condition, "resource": resource},
                )
            else:
                return self.create_result(
                    status="fail",
                    resource_id=resource_id,
                    resource_type=resource_type,
                    message=f"Check failed: {self.name}",
                    evidence={"condition": self.condition, "resource": resource},
                )

        except Exception as e:
            logger.error(
                "check_execution_error",
                check_id=self.check_id,
                resource_id=resource_id,
                error=str(e),
            )
            return self.create_result(
                status="error",
                resource_id=resource_id,
                resource_type=resource_type,
                message=f"Error executing check: {str(e)}",
                evidence={"error": str(e)},
            )

    def _evaluate_condition(self, resource: dict[str, Any]) -> bool:
        """
        Evaluate the condition expression using the condition evaluator.

        Args:
            resource: The resource data

        Returns:
            True if condition passes, False otherwise

        Raises:
            Exception: If condition evaluation encounters an error
        """
        # Normalize condition by removing newlines and extra whitespace
        normalized_condition = " ".join(self.condition.split())
        return self.evaluator.evaluate(normalized_condition, resource, raise_on_error=True)


class DynamicComplianceStandard:
    """A dynamically created compliance standard from YAML definition."""

    def __init__(
        self,
        standard_id: str,
        name: str,
        version: str,
        description: str,
        check_definitions: list[CheckDefinition],
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Initialize dynamic compliance standard."""
        self.standard_id = standard_id
        self.name = name
        self.version = version
        self.description = description
        self.check_definitions = check_definitions
        self.metadata = metadata or {}
        self._checks: list[DynamicComplianceCheck] = []

    def register_check(self, check: DynamicComplianceCheck) -> None:
        """Register a compliance check."""
        self._checks.append(check)

    async def load_checks(self) -> None:
        """Load all compliance checks from definitions."""
        for check_def in self.check_definitions:
            check = DynamicComplianceCheck(
                check_id=check_def.id,
                name=check_def.name,
                description=check_def.description,
                severity=check_def.severity,
                resource_types=check_def.resource_types,
                condition=check_def.condition,
                remediation=check_def.remediation,
                references=check_def.references,
                metadata=check_def.metadata,
            )
            self.register_check(check)

        logger.info(
            "checks_loaded",
            standard_id=self.standard_id,
            total_checks=len(self._checks),
        )


class YAMLStandardParser:
    """Parser for YAML-formatted compliance standards."""

    @staticmethod
    def parse_file(file_path: str | Path) -> DynamicComplianceStandard:
        """
        Parse a YAML file containing a compliance standard definition.

        Args:
            file_path: Path to the YAML file

        Returns:
            DynamicComplianceStandard instance

        Raises:
            ParserError: If parsing fails
        """
        file_path = Path(file_path)
        try:
            logger.info("parsing_standard", file_path=str(file_path))

            with open(file_path) as f:
                data = yaml.safe_load(f)

            # Validate against schema
            standard_def = StandardDefinition(**data)

            # Create standard instance
            standard = DynamicComplianceStandard(
                standard_id=standard_def.id,
                name=standard_def.name,
                version=standard_def.version,
                description=standard_def.description,
                check_definitions=standard_def.checks,
                metadata=standard_def.metadata,
            )

            logger.info(
                "standard_parsed",
                standard_id=standard.standard_id,
                version=standard.version,
                total_checks=len(standard_def.checks),
            )

            return standard

        except FileNotFoundError as e:
            raise ParserError(f"Standard file not found: {file_path}") from e
        except yaml.YAMLError as e:
            raise ParserError(f"Invalid YAML syntax: {e!s}") from e
        except Exception as e:
            raise ParserError(f"Failed to parse standard: {e!s}") from e

    @staticmethod
    def parse_string(yaml_content: str) -> DynamicComplianceStandard:
        """
        Parse a YAML string containing a compliance standard definition.

        Args:
            yaml_content: YAML content as string

        Returns:
            DynamicComplianceStandard instance

        Raises:
            ParserError: If parsing fails
        """
        try:
            data = yaml.safe_load(yaml_content)
            standard_def = StandardDefinition(**data)

            standard = DynamicComplianceStandard(
                standard_id=standard_def.id,
                name=standard_def.name,
                version=standard_def.version,
                description=standard_def.description,
                check_definitions=standard_def.checks,
                metadata=standard_def.metadata,
            )

            return standard

        except yaml.YAMLError as e:
            raise ParserError(f"Invalid YAML syntax: {e!s}") from e
        except Exception as e:
            raise ParserError(f"Failed to parse standard: {e!s}") from e
