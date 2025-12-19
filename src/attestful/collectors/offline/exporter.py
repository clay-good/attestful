"""
Evidence Bundle Exporter.

Creates signed, checksummed evidence bundles for offline transfer
to air-gapped environments.

Features:
- Packages collected evidence into portable bundles
- Generates SHA-256 integrity checksums for all files
- Signs bundles with GPG or organization RSA keys
- Supports multiple compression formats (tar.gz, tar.bz2, zip)
- Progress reporting for large exports
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
from typing import Any, Callable, Iterator
from uuid import uuid4

from attestful.collectors.offline.bundle import (
    BundleChecksums,
    BundleFormat,
    BundleManifest,
    BundleMetadata,
    BundleSignature,
    CollectionMetadata,
    EvidenceBundle,
    EvidenceFileEntry,
    calculate_file_checksum,
    get_evidence_relative_path,
)
from attestful.core.exceptions import ExportError
from attestful.core.logging import get_logger
from attestful.core.models import CollectionResult, Evidence

logger = get_logger(__name__)


@dataclass
class ExportConfig:
    """Configuration for evidence export."""

    # Output settings
    output_dir: Path = field(default_factory=lambda: Path.cwd())
    bundle_name: str = ""  # Auto-generated if empty
    bundle_format: BundleFormat = BundleFormat.TAR_GZ
    compress_level: int = 6  # Compression level (1-9)

    # Metadata
    organization_id: str = ""
    organization_name: str = ""
    description: str = ""

    # Signing
    sign_bundle: bool = True
    signing_key_path: Path | None = None
    signing_key_id: str = ""

    # Filtering
    platforms: list[str] = field(default_factory=list)  # Empty = all
    evidence_types: list[str] = field(default_factory=list)  # Empty = all
    since: datetime | None = None  # Only export evidence after this time

    # Performance
    chunk_size: int = 8192  # Read chunk size for checksums
    progress_callback: Callable[[int, int], None] | None = None


@dataclass
class ExportResult:
    """Result of an evidence export operation."""

    success: bool = False
    bundle_path: Path | None = None
    bundle_id: str = ""
    manifest: BundleManifest | None = None
    total_files: int = 0
    total_size_bytes: int = 0
    compressed_size_bytes: int = 0
    compression_ratio: float = 0.0
    duration_seconds: float = 0.0
    is_signed: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "bundle_path": str(self.bundle_path) if self.bundle_path else None,
            "bundle_id": self.bundle_id,
            "total_files": self.total_files,
            "total_size_bytes": self.total_size_bytes,
            "compressed_size_bytes": self.compressed_size_bytes,
            "compression_ratio": self.compression_ratio,
            "duration_seconds": self.duration_seconds,
            "is_signed": self.is_signed,
            "errors": self.errors,
            "warnings": self.warnings,
        }


class BundleExporter:
    """
    Exports evidence to portable bundles for offline transfer.

    Creates compressed, checksummed, and optionally signed bundles
    that can be transferred to air-gapped environments via USB or
    other offline means.

    Example:
        exporter = BundleExporter(
            config=ExportConfig(
                output_dir=Path("/exports"),
                organization_name="Acme Corp",
                sign_bundle=True,
            )
        )

        # Export from collection results
        result = exporter.export_collection_results(collection_results)

        # Or export from evidence store
        result = exporter.export_from_store(evidence_store, since=last_export)
    """

    def __init__(self, config: ExportConfig | None = None) -> None:
        """
        Initialize exporter.

        Args:
            config: Export configuration
        """
        self.config = config or ExportConfig()
        self._temp_dir: Path | None = None

    def export_collection_results(
        self,
        results: list[CollectionResult],
    ) -> ExportResult:
        """
        Export evidence from collection results to a bundle.

        Args:
            results: List of CollectionResult from collectors

        Returns:
            ExportResult with bundle details
        """
        start_time = datetime.now(timezone.utc)
        export_result = ExportResult()

        try:
            # Create temporary staging directory
            self._temp_dir = Path(tempfile.mkdtemp(prefix="attestful_export_"))
            evidence_dir = self._temp_dir / "evidence"
            evidence_dir.mkdir(parents=True)

            # Create manifest
            manifest = self._create_manifest()
            export_result.bundle_id = manifest.bundle_id

            # Process all evidence items
            all_evidence: list[Evidence] = []
            platforms_seen: set[str] = set()
            types_seen: set[str] = set()

            for result in results:
                for evidence in result.evidence_items:
                    # Apply filters
                    if self.config.platforms and evidence.platform not in self.config.platforms:
                        continue
                    if (
                        self.config.evidence_types
                        and evidence.evidence_type not in self.config.evidence_types
                    ):
                        continue
                    if (
                        self.config.since
                        and evidence.collected_at < self.config.since
                    ):
                        continue

                    all_evidence.append(evidence)
                    platforms_seen.add(evidence.platform)
                    types_seen.add(evidence.evidence_type)

            # Export each evidence item
            total = len(all_evidence)
            for idx, evidence in enumerate(all_evidence):
                if self.config.progress_callback:
                    self.config.progress_callback(idx + 1, total)

                file_entry = self._write_evidence_file(evidence, evidence_dir)
                manifest.add_file(file_entry)
                export_result.total_size_bytes += file_entry.size_bytes

            # Update manifest metadata
            manifest.collection_metadata.platforms_collected = list(platforms_seen)
            manifest.collection_metadata.evidence_types_collected = list(types_seen)
            manifest.collection_metadata.total_evidence_count = len(all_evidence)
            manifest.collection_metadata.total_size_bytes = export_result.total_size_bytes
            manifest.collection_metadata.completed_at = datetime.now(timezone.utc)

            # Calculate checksums
            checksums = self._calculate_checksums(evidence_dir)

            # Save manifest and checksums
            manifest.save(self._temp_dir / "manifest.json")
            checksums.save(self._temp_dir / "checksums.json")

            # Sign bundle if configured
            signature: BundleSignature | None = None
            if self.config.sign_bundle:
                try:
                    signature = self._sign_bundle(self._temp_dir, manifest.bundle_id)
                    export_result.is_signed = True
                except Exception as e:
                    export_result.warnings.append(f"Failed to sign bundle: {e}")

            # Create archive
            bundle_path = self._create_archive(manifest.bundle_id)
            export_result.bundle_path = bundle_path
            export_result.compressed_size_bytes = bundle_path.stat().st_size

            if export_result.total_size_bytes > 0:
                export_result.compression_ratio = (
                    1 - export_result.compressed_size_bytes / export_result.total_size_bytes
                )

            # Finalize
            export_result.success = True
            export_result.total_files = len(all_evidence)
            export_result.manifest = manifest
            export_result.duration_seconds = (
                datetime.now(timezone.utc) - start_time
            ).total_seconds()

            logger.info(
                f"Exported bundle {manifest.bundle_id}: {export_result.total_files} files, "
                f"{export_result.compressed_size_bytes / 1024 / 1024:.2f} MB"
            )

        except Exception as e:
            export_result.errors.append(str(e))
            logger.error(f"Export failed: {e}")

        finally:
            # Cleanup temp directory
            if self._temp_dir and self._temp_dir.exists():
                shutil.rmtree(self._temp_dir, ignore_errors=True)

        return export_result

    def export_evidence_list(
        self,
        evidence_items: list[Evidence],
    ) -> ExportResult:
        """
        Export a list of evidence items directly.

        Args:
            evidence_items: List of Evidence objects

        Returns:
            ExportResult with bundle details
        """
        # Wrap in CollectionResult for unified processing
        result = CollectionResult(
            success=True,
            evidence_items=evidence_items,
        )
        return self.export_collection_results([result])

    def _create_manifest(self) -> BundleManifest:
        """Create initial bundle manifest."""
        import socket

        return BundleManifest(
            bundle_id=str(uuid4()),
            bundle_metadata=BundleMetadata(
                description=self.config.description,
                format=self.config.bundle_format.value,
            ),
            collection_metadata=CollectionMetadata(
                organization_id=self.config.organization_id,
                organization_name=self.config.organization_name,
                collector_hostname=socket.gethostname(),
            ),
        )

    def _write_evidence_file(
        self,
        evidence: Evidence,
        evidence_dir: Path,
    ) -> EvidenceFileEntry:
        """
        Write an evidence item to file.

        Args:
            evidence: Evidence item to write
            evidence_dir: Directory to write to

        Returns:
            EvidenceFileEntry for the written file
        """
        # Generate file path
        relative_path = get_evidence_relative_path(
            platform=evidence.platform,
            evidence_type=evidence.evidence_type,
            collected_at=evidence.collected_at,
            evidence_id=evidence.id,
        )
        file_path = evidence_dir.parent / relative_path
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Write evidence data
        evidence_data = evidence.to_dict()
        content = json.dumps(evidence_data, indent=2, default=str)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

        size = file_path.stat().st_size

        return EvidenceFileEntry(
            file_id=str(uuid4()),
            relative_path=relative_path,
            platform=evidence.platform,
            evidence_type=evidence.evidence_type,
            collected_at=evidence.collected_at,
            size_bytes=size,
            evidence_id=evidence.id,
            source_id=evidence.source_id,
            metadata=evidence.metadata,
        )

    def _calculate_checksums(self, evidence_dir: Path) -> BundleChecksums:
        """Calculate checksums for all evidence files."""
        checksums = BundleChecksums()

        for file_path in evidence_dir.rglob("*"):
            if file_path.is_file():
                relative_path = str(file_path.relative_to(evidence_dir.parent))
                checksum = calculate_file_checksum(file_path)
                checksum.relative_path = relative_path
                checksums.add_checksum(checksum)

        # Also checksum the manifest
        manifest_path = evidence_dir.parent / "manifest.json"
        if manifest_path.exists():
            checksum = calculate_file_checksum(manifest_path)
            checksum.relative_path = "manifest.json"
            checksums.add_checksum(checksum)

        return checksums

    def _sign_bundle(
        self,
        bundle_dir: Path,
        bundle_id: str,
    ) -> BundleSignature:
        """
        Sign the bundle contents.

        Signs the checksums file to verify integrity of all contents.
        """
        # This will be implemented in signing.py
        # For now, return placeholder
        from attestful.collectors.offline.signing import sign_bundle

        checksums_path = bundle_dir / "checksums.json"
        return sign_bundle(
            checksums_path,
            key_path=self.config.signing_key_path,
            key_id=self.config.signing_key_id,
        )

    def _create_archive(self, bundle_id: str) -> Path:
        """
        Create compressed archive from staging directory.

        Args:
            bundle_id: Bundle identifier for filename

        Returns:
            Path to created archive
        """
        if not self._temp_dir:
            raise ExportError("No staging directory")

        # Generate output filename
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        bundle_name = self.config.bundle_name or f"attestful_bundle_{timestamp}"

        format_extensions = {
            BundleFormat.TAR_GZ: ".tar.gz",
            BundleFormat.TAR_BZ2: ".tar.bz2",
            BundleFormat.TAR_XZ: ".tar.xz",
            BundleFormat.ZIP: ".zip",
            BundleFormat.DIRECTORY: "",
        }
        extension = format_extensions.get(self.config.bundle_format, ".tar.gz")
        output_path = self.config.output_dir / f"{bundle_name}{extension}"

        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        if self.config.bundle_format == BundleFormat.DIRECTORY:
            # Just copy the directory
            if output_path.exists():
                shutil.rmtree(output_path)
            shutil.copytree(self._temp_dir, output_path)

        elif self.config.bundle_format == BundleFormat.ZIP:
            with zipfile.ZipFile(
                output_path,
                "w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=self.config.compress_level,
            ) as zf:
                for file_path in self._temp_dir.rglob("*"):
                    if file_path.is_file():
                        arcname = str(file_path.relative_to(self._temp_dir))
                        zf.write(file_path, arcname)

        else:
            # Tar formats
            mode_map = {
                BundleFormat.TAR_GZ: "w:gz",
                BundleFormat.TAR_BZ2: "w:bz2",
                BundleFormat.TAR_XZ: "w:xz",
            }
            mode = mode_map.get(self.config.bundle_format, "w:gz")

            with tarfile.open(output_path, mode) as tar:
                for file_path in self._temp_dir.rglob("*"):
                    if file_path.is_file():
                        arcname = str(file_path.relative_to(self._temp_dir))
                        tar.add(file_path, arcname=arcname)

        return output_path


# =============================================================================
# Convenience Functions
# =============================================================================


def export_evidence_bundle(
    evidence: list[Evidence] | list[CollectionResult],
    *,
    output_dir: Path | str = ".",
    organization_name: str = "",
    bundle_format: BundleFormat = BundleFormat.TAR_GZ,
    sign_bundle: bool = True,
    signing_key_path: Path | str | None = None,
) -> ExportResult:
    """
    Export evidence to a bundle file.

    Convenience function for quick exports.

    Args:
        evidence: List of Evidence items or CollectionResult objects
        output_dir: Directory for output bundle
        organization_name: Organization name for metadata
        bundle_format: Archive format
        sign_bundle: Whether to sign the bundle
        signing_key_path: Path to signing key

    Returns:
        ExportResult with bundle path and status

    Example:
        result = export_evidence_bundle(
            evidence_items,
            output_dir="/exports",
            organization_name="Acme Corp",
        )
        print(f"Bundle created: {result.bundle_path}")
    """
    config = ExportConfig(
        output_dir=Path(output_dir),
        organization_name=organization_name,
        bundle_format=bundle_format,
        sign_bundle=sign_bundle,
        signing_key_path=Path(signing_key_path) if signing_key_path else None,
    )

    exporter = BundleExporter(config)

    # Determine input type
    if evidence and isinstance(evidence[0], CollectionResult):
        return exporter.export_collection_results(evidence)  # type: ignore
    else:
        return exporter.export_evidence_list(evidence)  # type: ignore


def export_incremental_bundle(
    evidence_store: Any,  # Will be EvidenceStore type
    *,
    since: datetime,
    output_dir: Path | str = ".",
    **kwargs: Any,
) -> ExportResult:
    """
    Export only evidence collected since a specific time.

    Useful for incremental transfers to air-gapped environments.

    Args:
        evidence_store: Evidence storage instance
        since: Only export evidence after this timestamp
        output_dir: Directory for output bundle
        **kwargs: Additional ExportConfig options

    Returns:
        ExportResult with bundle path and status
    """
    config = ExportConfig(
        output_dir=Path(output_dir),
        since=since,
        **kwargs,
    )

    exporter = BundleExporter(config)

    # Get evidence from store (implementation depends on store API)
    # This is a placeholder - actual implementation would query the store
    evidence_items: list[Evidence] = []
    if hasattr(evidence_store, "get_evidence_since"):
        evidence_items = evidence_store.get_evidence_since(since)

    return exporter.export_evidence_list(evidence_items)
