"""
SQLAlchemy database models for Attestful.

These models represent the unified database schema for compliance scanning,
evidence collection, and maturity scoring.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum as SQLEnum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)

from attestful.core.models import CheckStatus, MaturityLevel, Severity


# =============================================================================
# Base
# =============================================================================


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


def generate_uuid() -> str:
    """Generate a UUID string."""
    return str(uuid4())


def utc_now() -> datetime:
    """Get current UTC datetime."""
    return datetime.now(timezone.utc)


# =============================================================================
# Organization & Users
# =============================================================================


class Organization(Base):
    """An organization using Attestful."""

    __tablename__ = "attestful_organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    # Relationships
    users: Mapped[list[User]] = relationship("User", back_populates="organization")
    scans: Mapped[list[Scan]] = relationship("Scan", back_populates="organization")
    collection_runs: Mapped[list[CollectionRun]] = relationship(
        "CollectionRun", back_populates="organization"
    )


class User(Base):
    """A user in the system."""

    __tablename__ = "attestful_users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attestful_organizations.id"), nullable=False
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="viewer")  # admin, analyst, auditor, viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    organization: Mapped[Organization] = relationship("Organization", back_populates="users")

    __table_args__ = (
        Index("ix_users_org_email", "organization_id", "email"),
    )


# =============================================================================
# Compliance Scanning
# =============================================================================


class Scan(Base):
    """A compliance scan run."""

    __tablename__ = "attestful_scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attestful_organizations.id"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False)  # aws, azure, gcp, k8s, docker
    framework: Mapped[str] = mapped_column(String(50), nullable=False)  # soc2, nist, iso27001
    status: Mapped[str] = mapped_column(String(20), default="running")  # running, completed, failed
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Summary statistics
    total_resources: Mapped[int] = mapped_column(Integer, default=0)
    total_checks: Mapped[int] = mapped_column(Integer, default=0)
    passed_checks: Mapped[int] = mapped_column(Integer, default=0)
    failed_checks: Mapped[int] = mapped_column(Integer, default=0)
    error_checks: Mapped[int] = mapped_column(Integer, default=0)

    # Configuration used
    regions: Mapped[list[str]] = mapped_column(JSON, default=list)
    accounts: Mapped[list[str]] = mapped_column(JSON, default=list)
    resource_types: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Relationships
    organization: Mapped[Organization] = relationship("Organization", back_populates="scans")
    results: Mapped[list[ScanResult]] = relationship("ScanResult", back_populates="scan")

    __table_args__ = (
        Index("ix_scans_org_started", "organization_id", "started_at"),
        Index("ix_scans_provider_framework", "provider", "framework"),
    )


class ScanResult(Base):
    """A single check result from a scan."""

    __tablename__ = "attestful_scan_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attestful_scans.id"), nullable=False
    )
    check_id: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(500), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)

    status: Mapped[str] = mapped_column(
        SQLEnum(CheckStatus), default=CheckStatus.UNKNOWN
    )
    severity: Mapped[str] = mapped_column(
        SQLEnum(Severity), default=Severity.MEDIUM
    )
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    # Relationships
    scan: Mapped[Scan] = relationship("Scan", back_populates="results")

    __table_args__ = (
        Index("ix_results_scan_check", "scan_id", "check_id"),
        Index("ix_results_status_severity", "status", "severity"),
    )


# =============================================================================
# Evidence Collection
# =============================================================================


class CollectionRun(Base):
    """An evidence collection run."""

    __tablename__ = "attestful_collection_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attestful_organizations.id"), nullable=False
    )
    platform: Mapped[str] = mapped_column(String(50), nullable=False)  # okta, jamf, aws, etc.
    status: Mapped[str] = mapped_column(String(20), default="running")  # running, completed, partial, failed
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Statistics
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    evidence_types: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Errors if any
    errors: Mapped[list[str]] = mapped_column(JSON, default=list)
    warnings: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Relationships
    organization: Mapped[Organization] = relationship("Organization", back_populates="collection_runs")
    evidence_items: Mapped[list[EvidenceItem]] = relationship(
        "EvidenceItem", back_populates="collection_run"
    )

    __table_args__ = (
        Index("ix_collection_org_started", "organization_id", "started_at"),
        Index("ix_collection_platform", "platform"),
    )


class EvidenceItem(Base):
    """
    A stored evidence item.

    Evidence data is stored in files; this table tracks metadata.
    """

    __tablename__ = "attestful_evidence_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    collection_run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attestful_collection_runs.id"), nullable=False
    )
    platform: Mapped[str] = mapped_column(String(50), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(100), nullable=False)

    # File storage
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    file_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256
    file_size: Mapped[int] = mapped_column(Integer, default=0)
    compressed: Mapped[bool] = mapped_column(Boolean, default=False)

    # Item metadata
    source_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    extra_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    # Relationships
    collection_run: Mapped[CollectionRun] = relationship(
        "CollectionRun", back_populates="evidence_items"
    )

    __table_args__ = (
        Index("ix_evidence_platform_type", "platform", "evidence_type"),
        Index("ix_evidence_collected", "collected_at"),
        UniqueConstraint("file_hash", name="uq_evidence_hash"),
    )


# =============================================================================
# Maturity Scoring
# =============================================================================


class MaturitySnapshot(Base):
    """A point-in-time maturity score snapshot."""

    __tablename__ = "attestful_maturity_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attestful_organizations.id"), nullable=False
    )
    framework: Mapped[str] = mapped_column(String(50), nullable=False)  # nist-csf, nist-800-53, etc.
    snapshot_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    # Overall scores
    overall_level: Mapped[int] = mapped_column(
        SQLEnum(MaturityLevel), default=MaturityLevel.LEVEL_0
    )
    overall_score: Mapped[float] = mapped_column(Float, default=0.0)
    overall_confidence: Mapped[float] = mapped_column(Float, default=0.0)

    # Detailed breakdown (JSON for flexibility)
    by_function: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    by_category: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    by_subcategory: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    # Evidence summary
    total_evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    missing_evidence_types: Mapped[list[str]] = mapped_column(JSON, default=list)

    __table_args__ = (
        Index("ix_maturity_org_framework", "organization_id", "framework"),
        Index("ix_maturity_date", "snapshot_date"),
    )


# =============================================================================
# Audit Logging
# =============================================================================


class AuditLog(Base):
    """
    Audit log with tamper detection.

    Each entry includes a checksum that chains to the previous entry,
    making tampering detectable.
    """

    __tablename__ = "attestful_audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    organization_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("attestful_organizations.id"), nullable=True
    )
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("attestful_users.id"), nullable=True
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    # Action details
    action: Mapped[str] = mapped_column(String(100), nullable=False)  # scan.started, evidence.collected, etc.
    resource_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    # Client info
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Tamper detection
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256
    previous_checksum: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_audit_org_timestamp", "organization_id", "timestamp"),
        Index("ix_audit_action", "action"),
        Index("ix_audit_user", "user_id"),
    )


# =============================================================================
# Resources (collected during scans)
# =============================================================================


class Resource(Base):
    """
    A cloud resource collected during a scan.

    Stores the raw resource data along with metadata for compliance checking.
    """

    __tablename__ = "attestful_resources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attestful_scans.id"), nullable=False
    )
    resource_id: Mapped[str] = mapped_column(String(500), nullable=False)  # Provider's resource ID
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)  # aws, azure, gcp, k8s
    region: Mapped[str | None] = mapped_column(String(100), nullable=True)
    account: Mapped[str | None] = mapped_column(String(100), nullable=True)  # AWS account, Azure subscription, etc.
    name: Mapped[str | None] = mapped_column(String(500), nullable=True)
    raw_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    tags: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    # Relationships
    scan: Mapped[Scan] = relationship("Scan")

    __table_args__ = (
        Index("ix_resources_scan", "scan_id"),
        Index("ix_resources_type_provider", "resource_type", "provider"),
        Index("ix_resources_region", "region"),
        UniqueConstraint("scan_id", "resource_id", name="uq_scan_resource"),
    )


# =============================================================================
# OSCAL Document Storage
# =============================================================================


class OSCALCatalog(Base):
    """
    An OSCAL catalog document (control definitions).

    Stores catalogs like NIST 800-53, NIST CSF, SOC 2 TSC, ISO 27001, HITRUST.
    """

    __tablename__ = "attestful_oscal_catalogs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    source: Mapped[str | None] = mapped_column(String(500), nullable=True)  # URL or file path
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256
    content: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # Full OSCAL JSON
    control_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    # Relationships
    profiles: Mapped[list[OSCALProfile]] = relationship("OSCALProfile", back_populates="catalog")

    __table_args__ = (
        Index("ix_catalogs_name_version", "name", "version"),
        UniqueConstraint("content_hash", name="uq_catalog_hash"),
    )


class OSCALProfile(Base):
    """
    An OSCAL profile (baseline selection from a catalog).

    Represents tailored baselines like FedRAMP Moderate, custom organizational profiles.
    """

    __tablename__ = "attestful_oscal_profiles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    catalog_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attestful_oscal_catalogs.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    source: Mapped[str | None] = mapped_column(String(500), nullable=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    control_count: Mapped[int] = mapped_column(Integer, default=0)  # After selection/tailoring
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    # Relationships
    catalog: Mapped[OSCALCatalog] = relationship("OSCALCatalog", back_populates="profiles")
    ssps: Mapped[list[OSCALSSP]] = relationship("OSCALSSP", back_populates="profile")

    __table_args__ = (
        Index("ix_profiles_catalog", "catalog_id"),
        Index("ix_profiles_name_version", "name", "version"),
    )


class OSCALSSP(Base):
    """
    An OSCAL System Security Plan.

    Documents how an organization implements controls for a specific system.
    """

    __tablename__ = "attestful_oscal_ssps"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attestful_organizations.id"), nullable=False
    )
    profile_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attestful_oscal_profiles.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    system_name: Mapped[str] = mapped_column(String(255), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(50), default="draft")  # draft, approved, active, archived
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(36), nullable=True)

    # Relationships
    profile: Mapped[OSCALProfile] = relationship("OSCALProfile", back_populates="ssps")
    assessments: Mapped[list[OSCALAssessment]] = relationship("OSCALAssessment", back_populates="ssp")

    __table_args__ = (
        Index("ix_ssps_org", "organization_id"),
        Index("ix_ssps_profile", "profile_id"),
        Index("ix_ssps_status", "status"),
    )


class OSCALAssessment(Base):
    """
    An OSCAL Assessment Result.

    Records the results of assessing an SSP, including findings and POA&Ms.
    """

    __tablename__ = "attestful_oscal_assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    ssp_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attestful_oscal_ssps.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    assessment_type: Mapped[str] = mapped_column(String(50), nullable=False)  # automated, manual, hybrid
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="in_progress")  # in_progress, completed, archived

    # Summary statistics
    total_controls: Mapped[int] = mapped_column(Integer, default=0)
    satisfied_controls: Mapped[int] = mapped_column(Integer, default=0)
    other_than_satisfied: Mapped[int] = mapped_column(Integer, default=0)
    not_applicable: Mapped[int] = mapped_column(Integer, default=0)

    # Full assessment results
    content: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    poams: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)  # Plan of Action & Milestones

    # Relationships
    ssp: Mapped[OSCALSSP] = relationship("OSCALSSP", back_populates="assessments")

    __table_args__ = (
        Index("ix_assessments_ssp", "ssp_id"),
        Index("ix_assessments_started", "started_at"),
        Index("ix_assessments_status", "status"),
    )


# =============================================================================
# Framework Configuration
# =============================================================================


class Framework(Base):
    """
    A compliance framework configuration.

    Links frameworks to their OSCAL catalogs and stores framework-specific settings.
    """

    __tablename__ = "attestful_frameworks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)  # nist-csf-2.0, soc2, etc.
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    catalog_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("attestful_oscal_catalogs.id"), nullable=True
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    # Relationships
    source_mappings: Mapped[list[FrameworkMapping]] = relationship(
        "FrameworkMapping",
        foreign_keys="FrameworkMapping.source_framework_id",
        back_populates="source_framework",
    )
    target_mappings: Mapped[list[FrameworkMapping]] = relationship(
        "FrameworkMapping",
        foreign_keys="FrameworkMapping.target_framework_id",
        back_populates="target_framework",
    )

    __table_args__ = (
        Index("ix_frameworks_active", "is_active"),
    )


class FrameworkMapping(Base):
    """
    A mapping between two compliance frameworks.

    Stores bidirectional control mappings with strength scores.
    """

    __tablename__ = "attestful_framework_mappings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    source_framework_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attestful_frameworks.id"), nullable=False
    )
    target_framework_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attestful_frameworks.id"), nullable=False
    )
    source_control_id: Mapped[str] = mapped_column(String(100), nullable=False)
    target_control_id: Mapped[str] = mapped_column(String(100), nullable=False)
    mapping_strength: Mapped[float] = mapped_column(Float, default=0.8)  # 0.0 to 1.0
    mapping_type: Mapped[str] = mapped_column(String(50), default="equivalent")  # equivalent, partial, related
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_bidirectional: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    # Relationships
    source_framework: Mapped[Framework] = relationship(
        "Framework",
        foreign_keys=[source_framework_id],
        back_populates="source_mappings",
    )
    target_framework: Mapped[Framework] = relationship(
        "Framework",
        foreign_keys=[target_framework_id],
        back_populates="target_mappings",
    )

    __table_args__ = (
        Index("ix_mappings_source", "source_framework_id", "source_control_id"),
        Index("ix_mappings_target", "target_framework_id", "target_control_id"),
        UniqueConstraint(
            "source_framework_id", "target_framework_id",
            "source_control_id", "target_control_id",
            name="uq_framework_mapping"
        ),
    )


# =============================================================================
# Remediation
# =============================================================================


class RemediationAction(Base):
    """
    A remediation action for a compliance finding.

    Tracks planned and executed remediation steps.
    """

    __tablename__ = "attestful_remediation_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    scan_result_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attestful_scan_results.id"), nullable=False
    )
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)  # auto_fix, manual, exception
    action_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, approved, in_progress, completed, failed, skipped
    priority: Mapped[str] = mapped_column(String(20), default="medium")  # critical, high, medium, low
    assigned_to: Mapped[str | None] = mapped_column(String(36), nullable=True)  # User ID

    # For automated remediation
    automation_script: Mapped[str | None] = mapped_column(Text, nullable=True)
    automation_params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    dry_run_result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    scan_result: Mapped[ScanResult] = relationship("ScanResult")
    history: Mapped[list[RemediationHistory]] = relationship(
        "RemediationHistory", back_populates="action"
    )

    __table_args__ = (
        Index("ix_remediation_result", "scan_result_id"),
        Index("ix_remediation_status", "status"),
        Index("ix_remediation_assigned", "assigned_to"),
    )


class RemediationHistory(Base):
    """
    History of remediation action execution.

    Records each attempt to execute a remediation action.
    """

    __tablename__ = "attestful_remediation_history"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    action_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attestful_remediation_actions.id"), nullable=False
    )
    executed_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    result: Mapped[str] = mapped_column(String(50), nullable=False)  # success, failure, partial, rollback
    result_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    execution_details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)

    # For rollback tracking
    can_rollback: Mapped[bool] = mapped_column(Boolean, default=False)
    rollback_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    rolled_back: Mapped[bool] = mapped_column(Boolean, default=False)
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    action: Mapped[RemediationAction] = relationship(
        "RemediationAction", back_populates="history"
    )

    __table_args__ = (
        Index("ix_remediation_history_action", "action_id"),
        Index("ix_remediation_history_executed", "executed_at"),
    )


# =============================================================================
# Teams (for multi-tenancy)
# =============================================================================


class Team(Base):
    """
    A team within an organization.

    Enables grouping users for access control and ownership.
    """

    __tablename__ = "attestful_teams"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attestful_organizations.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    # Relationships
    members: Mapped[list[TeamMember]] = relationship("TeamMember", back_populates="team")

    __table_args__ = (
        Index("ix_teams_org", "organization_id"),
        UniqueConstraint("organization_id", "name", name="uq_team_name"),
    )


class TeamMember(Base):
    """
    A user's membership in a team.
    """

    __tablename__ = "attestful_team_members"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    team_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attestful_teams.id"), nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("attestful_users.id"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(50), default="member")  # owner, admin, member
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    # Relationships
    team: Mapped[Team] = relationship("Team", back_populates="members")
    user: Mapped[User] = relationship("User")

    __table_args__ = (
        UniqueConstraint("team_id", "user_id", name="uq_team_member"),
    )
