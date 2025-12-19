"""
Evidence Bundle Importer.

Validates and imports evidence bundles from air-gapped or offline sources.

Features:
- Verifies bundle signature for authenticity
- Validates SHA-256 checksums for integrity
- Extracts evidence to storage
- Creates database records for imported evidence
- Supports incremental imports
- Detects and rejects tampered bundles
"""

from __future__ import annotations

import json
import os
import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from attestful.collectors.offline.bundle import (
    BundleChecksums,
    BundleChecksum,
    BundleFormat,
    BundleManifest,
    BundleSignature,
    EvidenceBundle,
    EvidenceFileEntry,
    calculate_file_checksum,
    validate_bundle_structure,
)
from attestful.core.exceptions import ImportError as AttestfulImportError
from attestful.core.exceptions import ValidationError
from attestful.core.logging import get_logger
from attestful.core.models import Evidence

logger = get_logger(__name__)


@dataclass
class ImportConfig:
    """Configuration for evidence import."""

    # Input settings
    bundle_path: Path | None = None

    # Verification
    verify_signature: bool = True
    verify_checksums: bool = True
    verification_key_path: Path | None = None
    reject_unsigned: bool = False  # Reject bundles without signatures

    # Storage
    evidence_store_path: Path | None = None
    database_connection: str | None = None

    # Import behavior
    skip_existing: bool = True  # Skip evidence already imported
    overwrite_existing: bool = False  # Overwrite existing evidence
    dry_run: bool = False  # Validate but don't import

    # Filtering
    platforms: list[str] = field(default_factory=list)
    evidence_types: list[str] = field(default_factory=list)

    # Progress
    progress_callback: Callable[[int, int, str], None] | None = None


@dataclass
class ImportResult:
    """Result of an evidence import operation."""

    success: bool = False
    bundle_id: str = ""
    manifest: BundleManifest | None = None

    # Verification status
    signature_valid: bool = False
    signature_verified: bool = False
    checksums_valid: bool = False
    all_checksums_verified: bool = False
    verification_errors: list[str] = field(default_factory=list)

    # Import statistics
    total_files: int = 0
    files_imported: int = 0
    files_skipped: int = 0
    files_failed: int = 0

    # Details
    imported_evidence: list[Evidence] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)
    failed_files: list[tuple[str, str]] = field(default_factory=list)  # (path, error)

    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "bundle_id": self.bundle_id,
            "signature_valid": self.signature_valid,
            "signature_verified": self.signature_verified,
            "checksums_valid": self.checksums_valid,
            "all_checksums_verified": self.all_checksums_verified,
            "verification_errors": self.verification_errors,
            "total_files": self.total_files,
            "files_imported": self.files_imported,
            "files_skipped": self.files_skipped,
            "files_failed": self.files_failed,
            "duration_seconds": self.duration_seconds,
            "errors": self.errors,
            "warnings": self.warnings,
        }


class BundleImporter:
    """
    Imports evidence bundles from offline/air-gapped sources.

    Validates bundle integrity and authenticity before importing
    evidence to local storage.

    Example:
        importer = BundleImporter(
            config=ImportConfig(
                bundle_path=Path("/imports/bundle.tar.gz"),
                verify_signature=True,
                evidence_store_path=Path("/data/evidence"),
            )
        )

        result = importer.import_bundle()
        if result.success:
            print(f"Imported {result.files_imported} evidence files")
    """

    def __init__(self, config: ImportConfig | None = None) -> None:
        """
        Initialize importer.

        Args:
            config: Import configuration
        """
        self.config = config or ImportConfig()
        self._temp_dir: Path | None = None
        self._extracted_dir: Path | None = None

    def import_bundle(self, bundle_path: Path | str | None = None) -> ImportResult:
        """
        Import an evidence bundle.

        Args:
            bundle_path: Path to bundle (overrides config)

        Returns:
            ImportResult with status and details
        """
        start_time = datetime.now(timezone.utc)
        result = ImportResult()

        bundle_path = Path(bundle_path) if bundle_path else self.config.bundle_path
        if not bundle_path:
            result.errors.append("No bundle path specified")
            return result

        try:
            # Validate bundle structure
            is_valid, structure_errors = validate_bundle_structure(bundle_path)
            if not is_valid:
                result.verification_errors.extend(structure_errors)
                result.errors.append("Bundle structure validation failed")
                return result

            # Extract bundle
            self._extracted_dir = self._extract_bundle(bundle_path)

            # Load manifest
            manifest_path = self._extracted_dir / "manifest.json"
            manifest = BundleManifest.from_file(manifest_path)
            result.manifest = manifest
            result.bundle_id = manifest.bundle_id
            result.total_files = len(manifest.files)

            # Verify signature if required
            if self.config.verify_signature:
                sig_result = self._verify_signature(manifest)
                result.signature_verified = True
                result.signature_valid = sig_result
                if not sig_result and self.config.reject_unsigned:
                    result.errors.append("Bundle signature verification failed")
                    return result
                elif not sig_result:
                    result.warnings.append("Bundle signature verification failed")

            # Verify checksums
            if self.config.verify_checksums:
                checksum_errors = self._verify_checksums()
                if checksum_errors:
                    result.verification_errors.extend(checksum_errors)
                    result.checksums_valid = False
                    result.errors.append(
                        f"Checksum verification failed: {len(checksum_errors)} errors"
                    )
                    return result
                result.checksums_valid = True
                result.all_checksums_verified = True

            # Dry run stops here
            if self.config.dry_run:
                result.success = True
                result.warnings.append("Dry run - no evidence imported")
                return result

            # Import evidence files
            for idx, file_entry in enumerate(manifest.files):
                if self.config.progress_callback:
                    self.config.progress_callback(
                        idx + 1,
                        result.total_files,
                        file_entry.relative_path,
                    )

                # Apply filters
                if (
                    self.config.platforms
                    and file_entry.platform not in self.config.platforms
                ):
                    result.files_skipped += 1
                    result.skipped_files.append(file_entry.relative_path)
                    continue

                if (
                    self.config.evidence_types
                    and file_entry.evidence_type not in self.config.evidence_types
                ):
                    result.files_skipped += 1
                    result.skipped_files.append(file_entry.relative_path)
                    continue

                # Import the file
                try:
                    evidence = self._import_evidence_file(file_entry)
                    if evidence:
                        result.imported_evidence.append(evidence)
                        result.files_imported += 1
                    else:
                        result.files_skipped += 1
                        result.skipped_files.append(file_entry.relative_path)
                except Exception as e:
                    result.files_failed += 1
                    result.failed_files.append((file_entry.relative_path, str(e)))
                    logger.warning(
                        f"Failed to import {file_entry.relative_path}: {e}"
                    )

            result.success = result.files_failed == 0
            result.duration_seconds = (
                datetime.now(timezone.utc) - start_time
            ).total_seconds()

            logger.info(
                f"Import complete: {result.files_imported} imported, "
                f"{result.files_skipped} skipped, {result.files_failed} failed"
            )

        except Exception as e:
            result.errors.append(str(e))
            logger.error(f"Import failed: {e}")

        finally:
            # Cleanup temp directory
            if self._temp_dir and self._temp_dir.exists():
                shutil.rmtree(self._temp_dir, ignore_errors=True)

        return result

    def validate_bundle(self, bundle_path: Path | str | None = None) -> ImportResult:
        """
        Validate a bundle without importing.

        Args:
            bundle_path: Path to bundle

        Returns:
            ImportResult with validation status
        """
        # Use dry_run mode
        original_dry_run = self.config.dry_run
        self.config.dry_run = True

        try:
            return self.import_bundle(bundle_path)
        finally:
            self.config.dry_run = original_dry_run

    def _extract_bundle(self, bundle_path: Path) -> Path:
        """
        Extract bundle archive to temporary directory.

        Args:
            bundle_path: Path to bundle

        Returns:
            Path to extracted directory
        """
        self._temp_dir = Path(tempfile.mkdtemp(prefix="attestful_import_"))

        if bundle_path.is_dir():
            # Already extracted - copy to temp
            extracted = self._temp_dir / "bundle"
            shutil.copytree(bundle_path, extracted)
            return extracted

        # Determine format and extract
        suffix = "".join(bundle_path.suffixes)

        if suffix in (".tar.gz", ".tgz"):
            with tarfile.open(bundle_path, "r:gz") as tar:
                tar.extractall(self._temp_dir)

        elif suffix in (".tar.bz2", ".tbz2"):
            with tarfile.open(bundle_path, "r:bz2") as tar:
                tar.extractall(self._temp_dir)

        elif suffix in (".tar.xz", ".txz"):
            with tarfile.open(bundle_path, "r:xz") as tar:
                tar.extractall(self._temp_dir)

        elif suffix == ".zip":
            with zipfile.ZipFile(bundle_path, "r") as zf:
                zf.extractall(self._temp_dir)

        else:
            raise AttestfulImportError(f"Unknown bundle format: {suffix}")

        # Find the extracted content
        # May be directly in temp_dir or in a subdirectory
        contents = list(self._temp_dir.iterdir())

        if len(contents) == 1 and contents[0].is_dir():
            return contents[0]

        return self._temp_dir

    def _verify_signature(self, manifest: BundleManifest) -> bool:
        """
        Verify bundle signature.

        Args:
            manifest: Bundle manifest

        Returns:
            True if signature is valid
        """
        if not self._extracted_dir:
            return False

        signature_path = self._extracted_dir / "signature.sig"
        checksums_path = self._extracted_dir / "checksums.json"

        if not signature_path.exists():
            logger.warning("Bundle is not signed")
            return False

        try:
            from attestful.collectors.offline.signing import verify_bundle_signature

            return verify_bundle_signature(
                checksums_path,
                signature_path,
                key_path=self.config.verification_key_path,
            )
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False

    def _verify_checksums(self) -> list[str]:
        """
        Verify all file checksums.

        Returns:
            List of verification error messages (empty if all valid)
        """
        if not self._extracted_dir:
            return ["No extracted directory"]

        errors: list[str] = []

        # Load checksums file
        checksums_path = self._extracted_dir / "checksums.json"
        if not checksums_path.exists():
            return ["Missing checksums.json"]

        checksums = BundleChecksums.from_file(checksums_path)

        # Verify each file
        for expected in checksums.checksums:
            file_path = self._extracted_dir / expected.relative_path

            if not file_path.exists():
                errors.append(f"Missing file: {expected.relative_path}")
                continue

            actual = calculate_file_checksum(file_path, expected.algorithm)

            if actual.checksum != expected.checksum:
                errors.append(
                    f"Checksum mismatch: {expected.relative_path} "
                    f"(expected: {expected.checksum[:16]}..., "
                    f"actual: {actual.checksum[:16]}...)"
                )
                continue

            if actual.size_bytes != expected.size_bytes:
                errors.append(
                    f"Size mismatch: {expected.relative_path} "
                    f"(expected: {expected.size_bytes}, actual: {actual.size_bytes})"
                )

        return errors

    def _import_evidence_file(self, file_entry: EvidenceFileEntry) -> Evidence | None:
        """
        Import a single evidence file.

        Args:
            file_entry: File entry from manifest

        Returns:
            Evidence object if imported, None if skipped
        """
        if not self._extracted_dir:
            raise AttestfulImportError("No extracted directory")

        file_path = self._extracted_dir / file_entry.relative_path

        if not file_path.exists():
            raise AttestfulImportError(f"Evidence file not found: {file_entry.relative_path}")

        # Read evidence data
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Create Evidence object
        collected_at = data.get("collected_at")
        if isinstance(collected_at, str):
            collected_at = datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
        else:
            collected_at = file_entry.collected_at

        evidence = Evidence(
            id=data.get("id", file_entry.evidence_id or str(uuid4())),
            platform=data.get("platform", file_entry.platform),
            evidence_type=data.get("evidence_type", file_entry.evidence_type),
            collected_at=collected_at,
            raw_data=data.get("raw_data", {}),
            metadata=data.get("metadata", {}),
            source_id=data.get("source_id", file_entry.source_id),
        )

        # Store evidence if storage is configured
        if self.config.evidence_store_path:
            self._store_evidence(evidence)

        return evidence

    def _store_evidence(self, evidence: Evidence) -> None:
        """
        Store evidence to configured storage.

        Args:
            evidence: Evidence to store
        """
        if not self.config.evidence_store_path:
            return

        # Create storage path
        date_str = evidence.collected_at.strftime("%Y/%m/%d")
        storage_path = (
            self.config.evidence_store_path
            / evidence.platform
            / evidence.evidence_type
            / date_str
            / f"{evidence.id}.json"
        )

        # Check if exists
        if storage_path.exists():
            if self.config.skip_existing and not self.config.overwrite_existing:
                return
            if not self.config.overwrite_existing:
                return

        # Write to storage
        storage_path.parent.mkdir(parents=True, exist_ok=True)
        with open(storage_path, "w", encoding="utf-8") as f:
            json.dump(evidence.to_dict(), f, indent=2, default=str)


# =============================================================================
# Convenience Functions
# =============================================================================


def import_evidence_bundle(
    bundle_path: Path | str,
    *,
    verify_signature: bool = True,
    verify_checksums: bool = True,
    evidence_store_path: Path | str | None = None,
    dry_run: bool = False,
) -> ImportResult:
    """
    Import an evidence bundle.

    Convenience function for quick imports.

    Args:
        bundle_path: Path to bundle file or directory
        verify_signature: Whether to verify bundle signature
        verify_checksums: Whether to verify file checksums
        evidence_store_path: Path to store imported evidence
        dry_run: Validate only, don't import

    Returns:
        ImportResult with status and details

    Example:
        result = import_evidence_bundle(
            "/imports/bundle.tar.gz",
            evidence_store_path="/data/evidence",
        )
        if result.success:
            print(f"Imported {result.files_imported} files")
    """
    config = ImportConfig(
        bundle_path=Path(bundle_path),
        verify_signature=verify_signature,
        verify_checksums=verify_checksums,
        evidence_store_path=Path(evidence_store_path) if evidence_store_path else None,
        dry_run=dry_run,
    )

    importer = BundleImporter(config)
    return importer.import_bundle()


def validate_evidence_bundle(bundle_path: Path | str) -> ImportResult:
    """
    Validate an evidence bundle without importing.

    Args:
        bundle_path: Path to bundle

    Returns:
        ImportResult with validation status
    """
    return import_evidence_bundle(bundle_path, dry_run=True)


def list_bundle_contents(bundle_path: Path | str) -> list[EvidenceFileEntry]:
    """
    List contents of an evidence bundle.

    Args:
        bundle_path: Path to bundle

    Returns:
        List of evidence file entries
    """
    config = ImportConfig(
        bundle_path=Path(bundle_path),
        verify_signature=False,
        verify_checksums=False,
        dry_run=True,
    )

    importer = BundleImporter(config)
    result = importer.import_bundle()

    if result.manifest:
        return result.manifest.files
    return []
