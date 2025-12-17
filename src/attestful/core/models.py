"""
Core data models used throughout Attestful.

These models represent the fundamental data structures for resources,
evidence, and collection results that flow through the system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4


class Severity(str, Enum):
    """Severity levels for compliance findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other: Severity) -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)


class CheckStatus(str, Enum):
    """Status of a compliance check result."""

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    SKIP = "skip"
    UNKNOWN = "unknown"


class MaturityLevel(int, Enum):
    """NIST-style maturity levels (0-4)."""

    LEVEL_0 = 0  # No implementation
    LEVEL_1 = 1  # Partial/informal
    LEVEL_2 = 2  # Documented processes
    LEVEL_3 = 3  # Automated, consistent
    LEVEL_4 = 4  # Optimized, continuous improvement


# =============================================================================
# Resource Models (for compliance checking)
# =============================================================================


@dataclass
class Resource:
    """
    A cloud or infrastructure resource to be checked for compliance.

    This is the Compliy-style model for resource-based compliance checking.
    """

    id: str
    type: str
    provider: str
    region: str | None = None
    account: str | None = None
    name: str | None = None
    raw_data: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def get(self, key: str, default: Any = None) -> Any:
        """Get a value from raw_data with a default."""
        return self.raw_data.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "type": self.type,
            "provider": self.provider,
            "region": self.region,
            "account": self.account,
            "name": self.name,
            "raw_data": self.raw_data,
            "metadata": self.metadata,
            "tags": self.tags,
            "collected_at": self.collected_at.isoformat(),
        }


# =============================================================================
# Evidence Models (for proof gathering)
# =============================================================================


@dataclass
class Evidence:
    """
    An evidence artifact collected from a platform.

    This is the Nisify-style model for evidence-based compliance verification.
    """

    id: str = field(default_factory=lambda: str(uuid4()))
    platform: str = ""
    evidence_type: str = ""
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_data: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    # Optional identifiers for deduplication
    source_id: str | None = None  # Platform-specific identifier
    file_hash: str | None = None  # SHA-256 of stored file

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "platform": self.platform,
            "evidence_type": self.evidence_type,
            "collected_at": self.collected_at.isoformat(),
            "raw_data": self.raw_data,
            "metadata": self.metadata,
            "source_id": self.source_id,
            "file_hash": self.file_hash,
        }


@dataclass
class CollectionResult:
    """
    Result of an evidence collection run.

    Supports partial success - some evidence may be collected even if
    errors occurred.
    """

    success: bool = True
    partial: bool = False
    evidence_items: list[Evidence] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    duration_seconds: float | None = None
    platform: str = ""
    evidence_types_collected: list[str] = field(default_factory=list)

    def add_evidence(self, evidence: Evidence) -> None:
        """Add an evidence item to the result."""
        self.evidence_items.append(evidence)
        if evidence.evidence_type not in self.evidence_types_collected:
            self.evidence_types_collected.append(evidence.evidence_type)

    def add_error(self, error: str) -> None:
        """Add an error and mark as partial success."""
        self.errors.append(error)
        self.partial = True

    def add_warning(self, warning: str) -> None:
        """Add a warning (doesn't affect success status)."""
        self.warnings.append(warning)

    def complete(self) -> None:
        """Mark the collection as complete."""
        self.completed_at = datetime.now(timezone.utc)
        self.duration_seconds = (self.completed_at - self.started_at).total_seconds()
        if self.errors and not self.evidence_items:
            self.success = False

    @property
    def evidence_count(self) -> int:
        """Number of evidence items collected."""
        return len(self.evidence_items)

    @property
    def evidence(self) -> list[Evidence]:
        """Alias for evidence_items for backward compatibility."""
        return self.evidence_items

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "success": self.success,
            "partial": self.partial,
            "evidence_count": self.evidence_count,
            "errors": self.errors,
            "warnings": self.warnings,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "platform": self.platform,
            "evidence_types_collected": self.evidence_types_collected,
        }


# =============================================================================
# Check Models (for compliance scanning)
# =============================================================================


@dataclass
class ComplianceCheck:
    """
    A compliance check definition.

    Checks are defined in YAML and evaluated against resources.
    """

    id: str
    title: str = ""  # Short title for the check
    name: str = ""  # Alias for title (legacy)
    description: str = ""
    severity: str = "medium"  # String to support evaluator usage
    resource_types: list[str] = field(default_factory=list)
    condition: str = ""  # Python expression or JMESPath
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    enabled: bool = True

    # Framework mappings - support both field names
    framework_controls: dict[str, list[str]] = field(default_factory=dict)
    framework_mappings: dict[str, list[str]] | None = None  # Used by evaluator
    # e.g., {"soc2": ["CC6.1"], "nist_800_53": ["AC-2"]}


@dataclass
class CheckResult:
    """
    Result of evaluating a compliance check against a resource.
    """

    id: str = field(default_factory=lambda: str(uuid4()))
    check_id: str = ""
    resource_id: str = ""
    resource_type: str = ""  # Resource type that was checked
    status: CheckStatus = CheckStatus.UNKNOWN
    severity: Severity = Severity.MEDIUM
    message: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)  # Additional details
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # For evaluator compatibility
    check: ComplianceCheck | None = None
    passed: bool | None = None  # True = pass, False = fail, None = unknown

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "check_id": self.check_id or (self.check.id if self.check else ""),
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "status": self.status.value,
            "severity": self.severity.value,
            "passed": self.passed,
            "message": self.message,
            "evidence": self.evidence,
            "details": self.details,
            "evaluated_at": self.evaluated_at.isoformat(),
        }


# =============================================================================
# Maturity Models (for NIST-style scoring)
# =============================================================================


@dataclass
class MaturityScore:
    """
    Maturity score for a control or category.
    """

    entity_id: str  # Control, category, or function ID
    entity_type: str  # "control", "category", "function", "overall"
    level: MaturityLevel = MaturityLevel.LEVEL_0
    score: float = 0.0  # 0.0 - 4.0
    evidence_count: int = 0
    confidence: float = 0.0  # 0.0 - 1.0
    missing_evidence_types: list[str] = field(default_factory=list)
    calculated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "level": self.level.value,
            "score": self.score,
            "evidence_count": self.evidence_count,
            "confidence": self.confidence,
            "missing_evidence_types": self.missing_evidence_types,
            "calculated_at": self.calculated_at.isoformat(),
        }


@dataclass
class MaturityBreakdown:
    """
    Complete maturity breakdown for an organization.
    """

    overall: MaturityScore | None = None
    by_function: dict[str, MaturityScore] = field(default_factory=dict)
    by_category: dict[str, MaturityScore] = field(default_factory=dict)
    by_subcategory: dict[str, MaturityScore] = field(default_factory=dict)
    framework: str = ""
    calculated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "overall": self.overall.to_dict() if self.overall else None,
            "by_function": {k: v.to_dict() for k, v in self.by_function.items()},
            "by_category": {k: v.to_dict() for k, v in self.by_category.items()},
            "by_subcategory": {k: v.to_dict() for k, v in self.by_subcategory.items()},
            "framework": self.framework,
            "calculated_at": self.calculated_at.isoformat(),
        }
