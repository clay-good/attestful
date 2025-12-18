"""
Nisify database migration for backward compatibility.

Migrates data from existing Nisify SQLite databases to the unified
Attestful schema while preserving:
- Historical evidence collection records
- Maturity snapshots and scores
- Trend data for continuity analysis

This migration supports both direct database-to-database migration
and file-based evidence store migration.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

from sqlalchemy.orm import Session

from attestful.core.exceptions import MigrationError
from attestful.core.logging import get_logger
from attestful.core.models import Evidence, MaturityLevel
from attestful.storage.database import get_session
from attestful.storage.evidence import EvidenceStore
from attestful.storage.models import (
    CollectionRun,
    EvidenceItem,
    MaturitySnapshot,
    Organization,
)

logger = get_logger("storage.migrations.nisify")


# =============================================================================
# Old Nisify Schema Definitions
# =============================================================================

# These represent the expected table structures in legacy Nisify databases.
# Used for validation and mapping to new schema.

NISIFY_TABLES = {
    "collection_runs": {
        "id": "TEXT PRIMARY KEY",
        "platform": "TEXT NOT NULL",
        "status": "TEXT DEFAULT 'pending'",
        "started_at": "TIMESTAMP",
        "completed_at": "TIMESTAMP",
        "evidence_count": "INTEGER DEFAULT 0",
        "errors": "TEXT",  # JSON array
    },
    "evidence": {
        "id": "TEXT PRIMARY KEY",
        "collection_run_id": "TEXT",
        "platform": "TEXT NOT NULL",
        "evidence_type": "TEXT NOT NULL",
        "file_path": "TEXT",
        "file_hash": "TEXT",
        "collected_at": "TIMESTAMP",
        "metadata": "TEXT",  # JSON object
    },
    "maturity_scores": {
        "id": "TEXT PRIMARY KEY",
        "timestamp": "TIMESTAMP",
        "entity_type": "TEXT",  # 'function', 'category', 'subcategory', 'overall'
        "entity_id": "TEXT",
        "level": "INTEGER",
        "score": "REAL",
        "evidence_count": "INTEGER",
        "confidence": "REAL",
        "metadata": "TEXT",  # JSON object
    },
    "maturity_snapshots": {
        "id": "TEXT PRIMARY KEY",
        "timestamp": "TIMESTAMP",
        "overall_level": "INTEGER",
        "overall_score": "REAL",
        "overall_confidence": "REAL",
        "by_function": "TEXT",  # JSON object
        "by_category": "TEXT",  # JSON object
        "by_subcategory": "TEXT",  # JSON object
    },
    "trend_data": {
        "id": "TEXT PRIMARY KEY",
        "entity_type": "TEXT",
        "entity_id": "TEXT",
        "metric": "TEXT",  # 'level', 'score', 'confidence', 'evidence_count'
        "value": "REAL",
        "timestamp": "TIMESTAMP",
    },
}


@dataclass
class MigrationResult:
    """Result of a migration operation."""

    success: bool = True
    records_migrated: int = 0
    records_skipped: int = 0
    records_failed: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def add_error(self, error: str) -> None:
        """Add an error and mark migration as failed."""
        self.errors.append(error)
        self.records_failed += 1

    def add_warning(self, warning: str) -> None:
        """Add a warning (migration continues)."""
        self.warnings.append(warning)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/reporting."""
        return {
            "success": self.success,
            "records_migrated": self.records_migrated,
            "records_skipped": self.records_skipped,
            "records_failed": self.records_failed,
            "errors": self.errors,
            "warnings": self.warnings,
            "details": self.details,
        }


# =============================================================================
# Schema Mapper
# =============================================================================


class NisifySchemaMapper:
    """
    Maps old Nisify table structures to new Attestful schema.

    Handles column name changes, type conversions, and structural differences.
    """

    # Column mappings: old_name -> new_name
    COLLECTION_RUN_MAPPING = {
        "id": "id",
        "platform": "platform",
        "status": "status",
        "started_at": "started_at",
        "completed_at": "completed_at",
        "evidence_count": "evidence_count",
        "errors": "errors",  # JSON array -> JSON array
    }

    EVIDENCE_MAPPING = {
        "id": "id",
        "collection_run_id": "collection_run_id",
        "platform": "platform",
        "evidence_type": "evidence_type",
        "file_path": "file_path",
        "file_hash": "file_hash",
        "collected_at": "collected_at",
        "metadata": "extra_metadata",  # Renamed in new schema
    }

    MATURITY_SNAPSHOT_MAPPING = {
        "id": "id",
        "timestamp": "snapshot_date",  # Renamed
        "overall_level": "overall_level",
        "overall_score": "overall_score",
        "overall_confidence": "overall_confidence",
        "by_function": "by_function",
        "by_category": "by_category",
        "by_subcategory": "by_subcategory",
    }

    def __init__(self, source_conn: sqlite3.Connection) -> None:
        """
        Initialize the schema mapper.

        Args:
            source_conn: Connection to the source Nisify database.
        """
        self.source_conn = source_conn
        self._detected_tables: set[str] = set()
        self._schema_version: str | None = None

    def detect_schema(self) -> dict[str, list[str]]:
        """
        Detect the schema of the source database.

        Returns:
            Dictionary mapping table names to column lists.
        """
        cursor = self.source_conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()

        schema: dict[str, list[str]] = {}
        for (table_name,) in tables:
            if table_name.startswith("sqlite_"):
                continue
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = [row[1] for row in cursor.fetchall()]
            schema[table_name] = columns
            self._detected_tables.add(table_name)

        # Detect schema version based on table structure
        self._schema_version = self._detect_version(schema)
        logger.info(f"Detected Nisify schema version: {self._schema_version}")

        return schema

    def _detect_version(self, schema: dict[str, list[str]]) -> str:
        """Detect the Nisify schema version."""
        # Check for version indicators
        if "trend_data" in schema:
            if "metric" in schema.get("trend_data", []):
                return "1.2"  # Latest version with trend metrics
            return "1.1"  # Had trend_data but simpler structure
        if "maturity_snapshots" in schema:
            return "1.0"  # Original version with snapshots
        return "0.9"  # Pre-release version

    def validate_schema(self) -> list[str]:
        """
        Validate the source schema is compatible with migration.

        Returns:
            List of validation errors (empty if valid).
        """
        errors: list[str] = []

        required_tables = {"collection_runs", "evidence"}
        missing = required_tables - self._detected_tables

        if missing:
            errors.append(f"Missing required tables: {missing}")

        # Check for critical columns
        cursor = self.source_conn.cursor()
        for table in required_tables & self._detected_tables:
            cursor.execute(f"PRAGMA table_info({table})")
            columns = {row[1] for row in cursor.fetchall()}

            if table == "evidence" and "platform" not in columns:
                errors.append(f"Table '{table}' missing 'platform' column")
            if table == "collection_runs" and "status" not in columns:
                errors.append(f"Table '{table}' missing 'status' column")

        return errors

    def map_collection_run(self, row: dict[str, Any]) -> dict[str, Any]:
        """Map a collection run row to new schema."""
        mapped = {}
        for old_col, new_col in self.COLLECTION_RUN_MAPPING.items():
            if old_col in row:
                value = row[old_col]
                # Handle JSON columns
                if old_col == "errors" and isinstance(value, str):
                    try:
                        value = json.loads(value) if value else []
                    except json.JSONDecodeError:
                        value = [value] if value else []
                mapped[new_col] = value

        # Add new required fields with defaults
        if "organization_id" not in mapped:
            mapped["organization_id"] = None  # Will be set during migration
        if "error_count" not in mapped:
            mapped["error_count"] = len(mapped.get("errors", []))
        if "evidence_types" not in mapped:
            mapped["evidence_types"] = []
        if "warnings" not in mapped:
            mapped["warnings"] = []

        return mapped

    def map_evidence_item(self, row: dict[str, Any]) -> dict[str, Any]:
        """Map an evidence row to new schema."""
        mapped = {}
        for old_col, new_col in self.EVIDENCE_MAPPING.items():
            if old_col in row:
                value = row[old_col]
                # Handle JSON metadata
                if old_col == "metadata" and isinstance(value, str):
                    try:
                        value = json.loads(value) if value else {}
                    except json.JSONDecodeError:
                        value = {}
                mapped[new_col] = value

        # Add new required fields
        if "file_size" not in mapped:
            mapped["file_size"] = 0
        if "compressed" not in mapped:
            mapped["compressed"] = mapped.get("file_path", "").endswith(".gz")

        return mapped

    def map_maturity_snapshot(self, row: dict[str, Any]) -> dict[str, Any]:
        """Map a maturity snapshot row to new schema."""
        mapped = {}
        for old_col, new_col in self.MATURITY_SNAPSHOT_MAPPING.items():
            if old_col in row:
                value = row[old_col]
                # Handle JSON columns
                if old_col in ("by_function", "by_category", "by_subcategory"):
                    if isinstance(value, str):
                        try:
                            value = json.loads(value) if value else {}
                        except json.JSONDecodeError:
                            value = {}
                mapped[new_col] = value

        # Add required new fields
        if "organization_id" not in mapped:
            mapped["organization_id"] = None
        if "framework" not in mapped:
            mapped["framework"] = "nist-csf-2.0"  # Default for Nisify
        if "total_evidence_count" not in mapped:
            # Calculate from breakdown if available
            total = 0
            for category_data in mapped.get("by_category", {}).values():
                if isinstance(category_data, dict):
                    total += category_data.get("evidence_count", 0)
            mapped["total_evidence_count"] = total
        if "missing_evidence_types" not in mapped:
            mapped["missing_evidence_types"] = []

        return mapped


# =============================================================================
# Evidence Converter
# =============================================================================


class NisifyEvidenceConverter:
    """
    Converts stored evidence from Nisify format to Attestful format.

    Handles:
    - File path remapping to new directory structure
    - Metadata schema conversion
    - Hash verification and recomputation
    """

    def __init__(
        self,
        source_evidence_dir: Path,
        target_store: EvidenceStore,
    ) -> None:
        """
        Initialize the evidence converter.

        Args:
            source_evidence_dir: Path to Nisify evidence directory.
            target_store: Target EvidenceStore for Attestful.
        """
        self.source_dir = Path(source_evidence_dir)
        self.target_store = target_store

    def convert_evidence(
        self,
        evidence_record: dict[str, Any],
    ) -> tuple[Evidence | None, str | None]:
        """
        Convert a single evidence record to Attestful format.

        Args:
            evidence_record: Evidence record from Nisify database.

        Returns:
            Tuple of (Evidence object, error message if failed).
        """
        try:
            # Build source file path
            source_path = self._resolve_source_path(evidence_record)
            if not source_path or not source_path.exists():
                return None, f"Evidence file not found: {evidence_record.get('file_path')}"

            # Read and verify the evidence data
            data, verified = self._read_and_verify(
                source_path,
                evidence_record.get("file_hash"),
            )
            if not verified:
                logger.warning(
                    f"Hash mismatch for evidence {evidence_record.get('id')}, "
                    "file may have been modified"
                )

            # Parse collected_at timestamp
            collected_at = evidence_record.get("collected_at")
            if isinstance(collected_at, str):
                collected_at = datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
            elif collected_at is None:
                collected_at = datetime.now(timezone.utc)

            # Create Evidence object
            evidence = Evidence(
                id=evidence_record.get("id", str(uuid4())),
                platform=evidence_record.get("platform", "unknown"),
                evidence_type=evidence_record.get("evidence_type", "unknown"),
                collected_at=collected_at,
                raw_data=data,
                metadata=evidence_record.get("extra_metadata", {}),
                source_id=evidence_record.get("source_id"),
            )

            return evidence, None

        except Exception as e:
            return None, f"Failed to convert evidence: {e}"

    def _resolve_source_path(self, record: dict[str, Any]) -> Path | None:
        """Resolve the source file path from the record."""
        file_path = record.get("file_path")
        if not file_path:
            return None

        path = Path(file_path)

        # If absolute and exists, use directly
        if path.is_absolute() and path.exists():
            return path

        # Try relative to source directory
        relative = self.source_dir / path
        if relative.exists():
            return relative

        # Try just the filename in various locations
        filename = path.name
        for candidate in [
            self.source_dir / filename,
            self.source_dir / record.get("platform", "") / filename,
        ]:
            if candidate.exists():
                return candidate

        return None

    def _read_and_verify(
        self,
        path: Path,
        expected_hash: str | None,
    ) -> tuple[dict[str, Any], bool]:
        """Read evidence file and verify hash."""
        import gzip

        data_bytes = path.read_bytes()

        # Decompress if needed
        if path.suffix == ".gz" or data_bytes[:2] == b"\x1f\x8b":
            data_bytes = gzip.decompress(data_bytes)

        # Verify hash
        actual_hash = hashlib.sha256(data_bytes).hexdigest()
        verified = expected_hash is None or actual_hash == expected_hash

        # Parse JSON
        data = json.loads(data_bytes.decode("utf-8"))

        return data, verified

    def migrate_all(
        self,
        evidence_records: list[dict[str, Any]],
    ) -> MigrationResult:
        """
        Migrate all evidence records.

        Args:
            evidence_records: List of evidence records from database.

        Returns:
            MigrationResult with statistics and errors.
        """
        result = MigrationResult()
        result.details["evidence_types"] = {}

        for record in evidence_records:
            evidence, error = self.convert_evidence(record)

            if error:
                result.add_error(error)
                continue

            if evidence is None:
                result.records_skipped += 1
                continue

            try:
                # Store in new format
                self.target_store.store(evidence)
                result.records_migrated += 1

                # Track evidence types
                et = evidence.evidence_type
                result.details["evidence_types"][et] = (
                    result.details["evidence_types"].get(et, 0) + 1
                )
            except Exception as e:
                result.add_error(f"Failed to store evidence {evidence.id}: {e}")

        result.success = result.records_failed == 0
        return result


# =============================================================================
# Maturity Preserver
# =============================================================================


class NisifyMaturityPreserver:
    """
    Preserves historical maturity snapshots during migration.

    Ensures maturity scoring history is maintained for trend analysis
    and compliance reporting continuity.
    """

    def __init__(
        self,
        schema_mapper: NisifySchemaMapper,
        target_session: Session,
        organization_id: str,
    ) -> None:
        """
        Initialize the maturity preserver.

        Args:
            schema_mapper: Schema mapper for data transformation.
            target_session: SQLAlchemy session for target database.
            organization_id: ID of the organization to assign snapshots to.
        """
        self.mapper = schema_mapper
        self.session = target_session
        self.organization_id = organization_id

    def migrate_snapshots(
        self,
        source_conn: sqlite3.Connection,
    ) -> MigrationResult:
        """
        Migrate all maturity snapshots.

        Args:
            source_conn: Connection to source Nisify database.

        Returns:
            MigrationResult with statistics.
        """
        result = MigrationResult()

        # Check if maturity_snapshots table exists
        cursor = source_conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='maturity_snapshots'"
        )
        if not cursor.fetchone():
            result.add_warning("No maturity_snapshots table found, skipping")
            return result

        # Fetch all snapshots
        cursor.execute("SELECT * FROM maturity_snapshots ORDER BY timestamp")
        columns = [desc[0] for desc in cursor.description]

        for row in cursor.fetchall():
            row_dict = dict(zip(columns, row))

            try:
                mapped = self.mapper.map_maturity_snapshot(row_dict)
                mapped["organization_id"] = self.organization_id

                # Convert to MaturitySnapshot model
                snapshot = self._create_snapshot(mapped)
                self.session.add(snapshot)
                result.records_migrated += 1

            except Exception as e:
                result.add_error(f"Failed to migrate snapshot {row_dict.get('id')}: {e}")

        try:
            self.session.commit()
        except Exception as e:
            self.session.rollback()
            result.add_error(f"Failed to commit snapshots: {e}")
            result.success = False

        return result

    def _create_snapshot(self, data: dict[str, Any]) -> MaturitySnapshot:
        """Create a MaturitySnapshot model from mapped data."""
        # Parse timestamp
        snapshot_date = data.get("snapshot_date")
        if isinstance(snapshot_date, str):
            snapshot_date = datetime.fromisoformat(
                snapshot_date.replace("Z", "+00:00")
            )
        elif snapshot_date is None:
            snapshot_date = datetime.now(timezone.utc)

        # Map level to enum
        level_value = data.get("overall_level", 0)
        if isinstance(level_value, int):
            level = MaturityLevel(min(level_value, 4))
        else:
            level = MaturityLevel.LEVEL_0

        return MaturitySnapshot(
            id=data.get("id", str(uuid4())),
            organization_id=data["organization_id"],
            framework=data.get("framework", "nist-csf-2.0"),
            snapshot_date=snapshot_date,
            overall_level=level,
            overall_score=float(data.get("overall_score", 0.0)),
            overall_confidence=float(data.get("overall_confidence", 0.0)),
            by_function=data.get("by_function", {}),
            by_category=data.get("by_category", {}),
            by_subcategory=data.get("by_subcategory", {}),
            total_evidence_count=data.get("total_evidence_count", 0),
            missing_evidence_types=data.get("missing_evidence_types", []),
        )


# =============================================================================
# Trend Migrator
# =============================================================================


class NisifyTrendMigrator:
    """
    Migrates trend data for continuity in reporting.

    Trend data captures historical metric values over time for
    showing progress and regression in maturity scores.
    """

    def __init__(
        self,
        target_session: Session,
        organization_id: str,
    ) -> None:
        """
        Initialize the trend migrator.

        Args:
            target_session: SQLAlchemy session for target database.
            organization_id: ID of the organization.
        """
        self.session = target_session
        self.organization_id = organization_id

    def migrate_trends(
        self,
        source_conn: sqlite3.Connection,
    ) -> MigrationResult:
        """
        Migrate trend data from source database.

        Trend data is converted to a series of maturity snapshots
        to maintain continuity in the new schema.

        Args:
            source_conn: Connection to source Nisify database.

        Returns:
            MigrationResult with statistics.
        """
        result = MigrationResult()

        # Check if trend_data table exists
        cursor = source_conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='trend_data'"
        )
        if not cursor.fetchone():
            result.add_warning("No trend_data table found, skipping")
            return result

        # Fetch trend data grouped by timestamp
        cursor.execute("""
            SELECT timestamp, entity_type, entity_id, metric, value
            FROM trend_data
            ORDER BY timestamp
        """)

        # Group by timestamp to create point-in-time snapshots
        trends_by_time: dict[str, list[dict[str, Any]]] = {}
        for row in cursor.fetchall():
            timestamp, entity_type, entity_id, metric, value = row
            if timestamp not in trends_by_time:
                trends_by_time[timestamp] = []
            trends_by_time[timestamp].append({
                "entity_type": entity_type,
                "entity_id": entity_id,
                "metric": metric,
                "value": value,
            })

        # Convert trend points to snapshot-like records
        for timestamp, trends in trends_by_time.items():
            try:
                snapshot_data = self._aggregate_trends(timestamp, trends)
                if snapshot_data:
                    # Check if snapshot already exists
                    existing = (
                        self.session.query(MaturitySnapshot)
                        .filter(
                            MaturitySnapshot.organization_id == self.organization_id,
                            MaturitySnapshot.snapshot_date == snapshot_data["snapshot_date"],
                        )
                        .first()
                    )

                    if existing:
                        # Update with trend data
                        self._update_snapshot(existing, snapshot_data)
                        result.records_skipped += 1
                    else:
                        # Create new snapshot from trend data
                        snapshot = self._create_snapshot_from_trends(snapshot_data)
                        self.session.add(snapshot)
                        result.records_migrated += 1

            except Exception as e:
                result.add_error(f"Failed to migrate trend data at {timestamp}: {e}")

        try:
            self.session.commit()
        except Exception as e:
            self.session.rollback()
            result.add_error(f"Failed to commit trend data: {e}")
            result.success = False

        return result

    def _aggregate_trends(
        self,
        timestamp: str,
        trends: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        """Aggregate trend points into snapshot data."""
        if not trends:
            return None

        # Parse timestamp
        if isinstance(timestamp, str):
            snapshot_date = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        else:
            snapshot_date = datetime.now(timezone.utc)

        data = {
            "snapshot_date": snapshot_date,
            "organization_id": self.organization_id,
            "framework": "nist-csf-2.0",
            "by_function": {},
            "by_category": {},
            "by_subcategory": {},
        }

        # Process each trend point
        for trend in trends:
            entity_type = trend.get("entity_type", "")
            entity_id = trend.get("entity_id", "")
            metric = trend.get("metric", "")
            value = trend.get("value", 0)

            if entity_type == "overall":
                if metric == "level":
                    data["overall_level"] = int(value)
                elif metric == "score":
                    data["overall_score"] = float(value)
                elif metric == "confidence":
                    data["overall_confidence"] = float(value)
            elif entity_type == "function":
                if entity_id not in data["by_function"]:
                    data["by_function"][entity_id] = {}
                data["by_function"][entity_id][metric] = value
            elif entity_type == "category":
                if entity_id not in data["by_category"]:
                    data["by_category"][entity_id] = {}
                data["by_category"][entity_id][metric] = value
            elif entity_type == "subcategory":
                if entity_id not in data["by_subcategory"]:
                    data["by_subcategory"][entity_id] = {}
                data["by_subcategory"][entity_id][metric] = value

        return data

    def _update_snapshot(
        self,
        snapshot: MaturitySnapshot,
        data: dict[str, Any],
    ) -> None:
        """Update an existing snapshot with trend data."""
        # Merge function/category/subcategory data
        for func_id, func_data in data.get("by_function", {}).items():
            if func_id not in snapshot.by_function:
                snapshot.by_function[func_id] = {}
            snapshot.by_function[func_id].update(func_data)

        for cat_id, cat_data in data.get("by_category", {}).items():
            if cat_id not in snapshot.by_category:
                snapshot.by_category[cat_id] = {}
            snapshot.by_category[cat_id].update(cat_data)

        for sub_id, sub_data in data.get("by_subcategory", {}).items():
            if sub_id not in snapshot.by_subcategory:
                snapshot.by_subcategory[sub_id] = {}
            snapshot.by_subcategory[sub_id].update(sub_data)

    def _create_snapshot_from_trends(
        self,
        data: dict[str, Any],
    ) -> MaturitySnapshot:
        """Create a new snapshot from trend data."""
        level_value = data.get("overall_level", 0)
        if isinstance(level_value, (int, float)):
            level = MaturityLevel(min(int(level_value), 4))
        else:
            level = MaturityLevel.LEVEL_0

        return MaturitySnapshot(
            id=str(uuid4()),
            organization_id=data["organization_id"],
            framework=data.get("framework", "nist-csf-2.0"),
            snapshot_date=data["snapshot_date"],
            overall_level=level,
            overall_score=float(data.get("overall_score", 0.0)),
            overall_confidence=float(data.get("overall_confidence", 0.0)),
            by_function=data.get("by_function", {}),
            by_category=data.get("by_category", {}),
            by_subcategory=data.get("by_subcategory", {}),
            total_evidence_count=0,
            missing_evidence_types=[],
        )


# =============================================================================
# Main Migration Class
# =============================================================================


class NisifyMigration:
    """
    Complete migration from Nisify database to Attestful.

    Coordinates all migration components:
    - Schema mapping and validation
    - Evidence conversion and storage
    - Maturity snapshot preservation
    - Trend data continuity

    Example:
        migration = NisifyMigration(
            source_db=Path("~/.nisify/nisify.db"),
            source_evidence_dir=Path("~/.nisify/evidence"),
            target_evidence_dir=Path("~/.attestful/evidence"),
        )

        # Run full migration
        result = migration.migrate()

        if result.success:
            print(f"Migrated {result.records_migrated} records")
        else:
            for error in result.errors:
                print(f"Error: {error}")
    """

    def __init__(
        self,
        source_db: Path,
        source_evidence_dir: Path | None = None,
        target_evidence_dir: Path | None = None,
        organization_name: str = "Default Organization",
    ) -> None:
        """
        Initialize the Nisify migration.

        Args:
            source_db: Path to the source Nisify SQLite database.
            source_evidence_dir: Path to Nisify evidence files.
            target_evidence_dir: Path for Attestful evidence storage.
            organization_name: Name for the organization record.
        """
        self.source_db = Path(source_db).expanduser()
        self.source_evidence_dir = (
            Path(source_evidence_dir).expanduser()
            if source_evidence_dir
            else self.source_db.parent / "evidence"
        )
        self.target_evidence_dir = (
            Path(target_evidence_dir).expanduser()
            if target_evidence_dir
            else Path.home() / ".attestful" / "evidence"
        )
        self.organization_name = organization_name
        self._organization_id: str | None = None

    def validate(self) -> list[str]:
        """
        Validate the migration can proceed.

        Returns:
            List of validation errors (empty if valid).
        """
        errors: list[str] = []

        # Check source database exists
        if not self.source_db.exists():
            errors.append(f"Source database not found: {self.source_db}")
            return errors

        # Check source evidence directory
        if not self.source_evidence_dir.exists():
            errors.append(f"Source evidence directory not found: {self.source_evidence_dir}")

        # Validate schema
        try:
            conn = sqlite3.connect(str(self.source_db))
            mapper = NisifySchemaMapper(conn)
            mapper.detect_schema()
            schema_errors = mapper.validate_schema()
            errors.extend(schema_errors)
            conn.close()
        except Exception as e:
            errors.append(f"Failed to validate source schema: {e}")

        return errors

    def migrate(
        self,
        *,
        dry_run: bool = False,
        skip_evidence: bool = False,
    ) -> MigrationResult:
        """
        Execute the full migration.

        Args:
            dry_run: If True, validate without making changes.
            skip_evidence: If True, skip evidence file migration.

        Returns:
            MigrationResult with complete statistics.
        """
        result = MigrationResult()
        result.details = {
            "source_db": str(self.source_db),
            "source_evidence": str(self.source_evidence_dir),
            "target_evidence": str(self.target_evidence_dir),
            "organization": self.organization_name,
            "dry_run": dry_run,
            "phases": {},
        }

        # Validate first
        validation_errors = self.validate()
        if validation_errors:
            for error in validation_errors:
                result.add_error(error)
            result.success = False
            return result

        if dry_run:
            logger.info("Dry run mode - no changes will be made")
            result.add_warning("Dry run mode - migration validated but not executed")
            return result

        try:
            # Connect to source database
            source_conn = sqlite3.connect(str(self.source_db))
            source_conn.row_factory = sqlite3.Row

            # Create schema mapper
            mapper = NisifySchemaMapper(source_conn)
            mapper.detect_schema()

            # Phase 1: Create organization and get session
            with get_session() as session:
                org = self._get_or_create_organization(session)
                self._organization_id = org.id
                session.commit()

            # Phase 2: Migrate collection runs
            with get_session() as session:
                runs_result = self._migrate_collection_runs(source_conn, mapper, session)
                result.details["phases"]["collection_runs"] = runs_result.to_dict()
                result.records_migrated += runs_result.records_migrated
                result.errors.extend(runs_result.errors)
                session.commit()

            # Phase 3: Migrate evidence
            if not skip_evidence and self.source_evidence_dir.exists():
                evidence_result = self._migrate_evidence(source_conn, mapper)
                result.details["phases"]["evidence"] = evidence_result.to_dict()
                result.records_migrated += evidence_result.records_migrated
                result.errors.extend(evidence_result.errors)

            # Phase 4: Migrate maturity snapshots
            with get_session() as session:
                maturity_result = self._migrate_maturity(source_conn, mapper, session)
                result.details["phases"]["maturity"] = maturity_result.to_dict()
                result.records_migrated += maturity_result.records_migrated
                result.errors.extend(maturity_result.errors)

            # Phase 5: Migrate trend data
            with get_session() as session:
                trend_result = self._migrate_trends(source_conn, session)
                result.details["phases"]["trends"] = trend_result.to_dict()
                result.records_migrated += trend_result.records_migrated
                result.errors.extend(trend_result.errors)

            source_conn.close()

            result.success = len(result.errors) == 0
            logger.info(
                f"Migration complete: {result.records_migrated} records migrated, "
                f"{result.records_failed} failed"
            )

        except Exception as e:
            result.add_error(f"Migration failed: {e}")
            result.success = False
            logger.exception("Migration failed with unexpected error")

        return result

    def _get_or_create_organization(self, session: Session) -> Organization:
        """Get or create the organization record."""
        # Try to find existing organization
        org = (
            session.query(Organization)
            .filter(Organization.name == self.organization_name)
            .first()
        )

        if org:
            logger.info(f"Using existing organization: {org.name} ({org.id})")
            return org

        # Create new organization
        org = Organization(
            id=str(uuid4()),
            name=self.organization_name,
            slug=self.organization_name.lower().replace(" ", "-"),
            settings={"migrated_from": "nisify"},
        )
        session.add(org)
        logger.info(f"Created organization: {org.name} ({org.id})")
        return org

    def _migrate_collection_runs(
        self,
        source_conn: sqlite3.Connection,
        mapper: NisifySchemaMapper,
        session: Session,
    ) -> MigrationResult:
        """Migrate collection run records."""
        result = MigrationResult()

        cursor = source_conn.cursor()
        cursor.execute("SELECT * FROM collection_runs ORDER BY started_at")
        columns = [desc[0] for desc in cursor.description]

        for row in cursor.fetchall():
            row_dict = dict(zip(columns, row))

            try:
                mapped = mapper.map_collection_run(row_dict)
                mapped["organization_id"] = self._organization_id

                # Parse timestamps
                for ts_field in ("started_at", "completed_at"):
                    if mapped.get(ts_field) and isinstance(mapped[ts_field], str):
                        mapped[ts_field] = datetime.fromisoformat(
                            mapped[ts_field].replace("Z", "+00:00")
                        )

                # Calculate duration
                if mapped.get("started_at") and mapped.get("completed_at"):
                    duration = (mapped["completed_at"] - mapped["started_at"]).total_seconds()
                    mapped["duration_seconds"] = duration

                run = CollectionRun(**mapped)
                session.add(run)
                result.records_migrated += 1

            except Exception as e:
                result.add_error(f"Failed to migrate collection run {row_dict.get('id')}: {e}")

        return result

    def _migrate_evidence(
        self,
        source_conn: sqlite3.Connection,
        mapper: NisifySchemaMapper,
    ) -> MigrationResult:
        """Migrate evidence records and files."""
        # Create target evidence store
        store = EvidenceStore(self.target_evidence_dir)

        # Create converter
        converter = NisifyEvidenceConverter(
            source_evidence_dir=self.source_evidence_dir,
            target_store=store,
        )

        # Fetch evidence records
        cursor = source_conn.cursor()
        cursor.execute("SELECT * FROM evidence ORDER BY collected_at")
        columns = [desc[0] for desc in cursor.description]

        records = []
        for row in cursor.fetchall():
            row_dict = dict(zip(columns, row))
            mapped = mapper.map_evidence_item(row_dict)
            records.append(mapped)

        # Migrate all evidence
        return converter.migrate_all(records)

    def _migrate_maturity(
        self,
        source_conn: sqlite3.Connection,
        mapper: NisifySchemaMapper,
        session: Session,
    ) -> MigrationResult:
        """Migrate maturity snapshots."""
        preserver = NisifyMaturityPreserver(
            schema_mapper=mapper,
            target_session=session,
            organization_id=self._organization_id,
        )
        return preserver.migrate_snapshots(source_conn)

    def _migrate_trends(
        self,
        source_conn: sqlite3.Connection,
        session: Session,
    ) -> MigrationResult:
        """Migrate trend data."""
        migrator = NisifyTrendMigrator(
            target_session=session,
            organization_id=self._organization_id,
        )
        return migrator.migrate_trends(source_conn)


# =============================================================================
# Convenience Function
# =============================================================================


def migrate_nisify_database(
    source_db: str | Path,
    source_evidence_dir: str | Path | None = None,
    target_evidence_dir: str | Path | None = None,
    organization_name: str = "Default Organization",
    dry_run: bool = False,
    skip_evidence: bool = False,
) -> MigrationResult:
    """
    Migrate a Nisify database to Attestful.

    This is the main entry point for Nisify migration.

    Args:
        source_db: Path to the Nisify SQLite database.
        source_evidence_dir: Path to Nisify evidence files.
        target_evidence_dir: Path for Attestful evidence storage.
        organization_name: Name for the organization.
        dry_run: If True, validate without making changes.
        skip_evidence: If True, skip evidence file migration.

    Returns:
        MigrationResult with complete statistics.

    Example:
        from attestful.storage.migrations import migrate_nisify_database

        result = migrate_nisify_database(
            source_db="~/.nisify/nisify.db",
            organization_name="My Company",
        )

        if result.success:
            print(f"Successfully migrated {result.records_migrated} records")
        else:
            print(f"Migration failed with {len(result.errors)} errors")
    """
    migration = NisifyMigration(
        source_db=Path(source_db),
        source_evidence_dir=Path(source_evidence_dir) if source_evidence_dir else None,
        target_evidence_dir=Path(target_evidence_dir) if target_evidence_dir else None,
        organization_name=organization_name,
    )

    return migration.migrate(dry_run=dry_run, skip_evidence=skip_evidence)
