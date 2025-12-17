"""
SQLAlchemy database models for Attestful.

These models represent the unified database schema combining
Compliy (scans, results) and Nisify (evidence, maturity) patterns.
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
# Compliance Scanning (Compliy pattern)
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
# Evidence Collection (Nisify pattern)
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
