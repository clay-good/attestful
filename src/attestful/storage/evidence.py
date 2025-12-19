"""
Evidence storage for Attestful.

Provides file-based evidence storage with SHA-256 integrity verification,
organized by date and platform for easy retrieval and auditing.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

from attestful.core.exceptions import StorageError
from attestful.core.logging import get_logger
from attestful.core.models import CollectionResult, Evidence

logger = get_logger(__name__)


@dataclass
class StoredEvidence:
    """
    Metadata about stored evidence.

    Attributes:
        id: Unique evidence ID.
        platform: Platform the evidence came from.
        evidence_type: Type of evidence.
        file_path: Path to the stored evidence file.
        file_hash: SHA-256 hash of the file contents.
        file_size: Size of the file in bytes.
        compressed: Whether the file is gzip compressed.
        collected_at: When the evidence was collected.
        stored_at: When the evidence was stored.
        metadata: Additional metadata.
    """

    id: str
    platform: str
    evidence_type: str
    file_path: Path
    file_hash: str
    file_size: int
    compressed: bool
    collected_at: datetime
    stored_at: datetime
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "platform": self.platform,
            "evidence_type": self.evidence_type,
            "file_path": str(self.file_path),
            "file_hash": self.file_hash,
            "file_size": self.file_size,
            "compressed": self.compressed,
            "collected_at": self.collected_at.isoformat(),
            "stored_at": self.stored_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StoredEvidence:
        """Create from dictionary."""
        return cls(
            id=data["id"],
            platform=data["platform"],
            evidence_type=data["evidence_type"],
            file_path=Path(data["file_path"]),
            file_hash=data["file_hash"],
            file_size=data["file_size"],
            compressed=data.get("compressed", False),
            collected_at=datetime.fromisoformat(data["collected_at"]),
            stored_at=datetime.fromisoformat(data["stored_at"]),
            metadata=data.get("metadata", {}),
        )


class EvidenceStore:
    """
    File-based evidence storage with integrity verification.

    Evidence is stored in a directory structure organized by date and platform:
        evidence_dir/
            2024/
                01/
                    15/
                        aws/
                            account_info_abc123.json.gz
                            iam_credential_report_def456.json.gz
                        okta/
                            users_ghi789.json.gz
            index.json  # Index of all stored evidence

    Features:
    - SHA-256 hash verification for integrity
    - Optional gzip compression for large files
    - Date-based organization for easy retrieval
    - Index file for fast lookups
    - Retention policy support

    Example:
        store = EvidenceStore(evidence_dir=Path("~/.attestful/evidence"))

        # Store evidence from a collection run
        stored = store.store_collection_result(result)

        # Retrieve evidence
        evidence = store.get("abc123")

        # Verify integrity
        if store.verify("abc123"):
            print("Evidence integrity verified")
    """

    INDEX_FILE = "index.json"
    COMPRESSION_THRESHOLD = 10 * 1024  # 10 KB

    def __init__(
        self,
        evidence_dir: Path,
        *,
        compress: bool = True,
        compression_threshold: int | None = None,
    ) -> None:
        """
        Initialize the evidence store.

        Args:
            evidence_dir: Directory for storing evidence files.
            compress: Whether to compress large files.
            compression_threshold: Size threshold for compression (bytes).
        """
        self.evidence_dir = Path(evidence_dir).expanduser()
        self.compress = compress
        self.compression_threshold = compression_threshold or self.COMPRESSION_THRESHOLD

        self._index: dict[str, StoredEvidence] = {}
        self._index_loaded = False

    def _ensure_dir(self) -> None:
        """Create evidence directory if it doesn't exist."""
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def _get_date_path(self, dt: datetime) -> Path:
        """Get the date-based subdirectory path."""
        return self.evidence_dir / str(dt.year) / f"{dt.month:02d}" / f"{dt.day:02d}"

    def _compute_hash(self, data: bytes) -> str:
        """Compute SHA-256 hash of data."""
        return hashlib.sha256(data).hexdigest()

    def _load_index(self) -> None:
        """Load the index file."""
        if self._index_loaded:
            return

        index_path = self.evidence_dir / self.INDEX_FILE

        if index_path.exists():
            try:
                content = index_path.read_text()
                data = json.loads(content)
                self._index = {
                    k: StoredEvidence.from_dict(v) for k, v in data.items()
                }
                logger.debug(f"Loaded index with {len(self._index)} entries")
            except Exception as e:
                logger.error(f"Failed to load index: {e}")
                self._index = {}
        else:
            self._index = {}

        self._index_loaded = True

    def _save_index(self) -> None:
        """Save the index file."""
        self._ensure_dir()
        index_path = self.evidence_dir / self.INDEX_FILE

        data = {k: v.to_dict() for k, v in self._index.items()}
        content = json.dumps(data, indent=2)
        index_path.write_text(content)

    def store(self, evidence: Evidence) -> StoredEvidence:
        """
        Store a single evidence item.

        Args:
            evidence: Evidence to store.

        Returns:
            StoredEvidence with file location and hash.
        """
        self._load_index()
        self._ensure_dir()

        # Serialize evidence data
        data = json.dumps(evidence.raw_data, indent=2, default=str)
        data_bytes = data.encode("utf-8")

        # Determine if we should compress
        should_compress = self.compress and len(data_bytes) > self.compression_threshold

        if should_compress:
            data_bytes = gzip.compress(data_bytes)

        # Compute hash
        file_hash = self._compute_hash(data_bytes)

        # Determine file path
        date_path = self._get_date_path(evidence.collected_at)
        platform_path = date_path / evidence.platform
        platform_path.mkdir(parents=True, exist_ok=True)

        filename = f"{evidence.evidence_type}_{evidence.id[:8]}"
        filename += ".json.gz" if should_compress else ".json"
        file_path = platform_path / filename

        # Write file
        file_path.write_bytes(data_bytes)

        # Create stored evidence record
        stored = StoredEvidence(
            id=evidence.id,
            platform=evidence.platform,
            evidence_type=evidence.evidence_type,
            file_path=file_path,
            file_hash=file_hash,
            file_size=len(data_bytes),
            compressed=should_compress,
            collected_at=evidence.collected_at,
            stored_at=datetime.now(timezone.utc),
            metadata=evidence.metadata,
        )

        # Update index
        self._index[evidence.id] = stored
        self._save_index()

        logger.debug(f"Stored evidence {evidence.id} at {file_path}")
        return stored

    def store_collection_result(self, result: CollectionResult) -> list[StoredEvidence]:
        """
        Store all evidence from a collection result.

        Args:
            result: Collection result containing evidence items.

        Returns:
            List of stored evidence records.
        """
        stored_items: list[StoredEvidence] = []

        # Support both .evidence and .evidence_items for compatibility
        evidence_list = getattr(result, 'evidence_items', None) or getattr(result, 'evidence', [])

        for evidence in evidence_list:
            try:
                stored = self.store(evidence)
                stored_items.append(stored)
            except Exception as e:
                logger.error(f"Failed to store evidence {evidence.id}: {e}")

        logger.info(
            f"Stored {len(stored_items)}/{len(evidence_list)} evidence items "
            f"from {result.platform}"
        )
        return stored_items

    def get(self, evidence_id: str) -> StoredEvidence | None:
        """
        Get stored evidence metadata by ID.

        Args:
            evidence_id: Evidence ID.

        Returns:
            StoredEvidence if found, None otherwise.
        """
        self._load_index()
        return self._index.get(evidence_id)

    def read(self, evidence_id: str) -> dict[str, Any] | None:
        """
        Read evidence data from storage.

        Args:
            evidence_id: Evidence ID.

        Returns:
            Evidence data dictionary if found, None otherwise.
        """
        stored = self.get(evidence_id)
        if stored is None:
            return None

        if not stored.file_path.exists():
            logger.error(f"Evidence file not found: {stored.file_path}")
            return None

        try:
            data_bytes = stored.file_path.read_bytes()

            if stored.compressed:
                data_bytes = gzip.decompress(data_bytes)

            return json.loads(data_bytes.decode("utf-8"))
        except Exception as e:
            logger.error(f"Failed to read evidence {evidence_id}: {e}")
            return None

    def verify(self, evidence_id: str) -> bool:
        """
        Verify the integrity of stored evidence.

        Args:
            evidence_id: Evidence ID.

        Returns:
            True if integrity is verified, False otherwise.
        """
        stored = self.get(evidence_id)
        if stored is None:
            return False

        if not stored.file_path.exists():
            logger.error(f"Evidence file not found: {stored.file_path}")
            return False

        try:
            data_bytes = stored.file_path.read_bytes()
            actual_hash = self._compute_hash(data_bytes)

            if actual_hash != stored.file_hash:
                logger.error(
                    f"Hash mismatch for {evidence_id}: "
                    f"expected {stored.file_hash}, got {actual_hash}"
                )
                return False

            return True
        except Exception as e:
            logger.error(f"Failed to verify evidence {evidence_id}: {e}")
            return False

    def delete(self, evidence_id: str) -> bool:
        """
        Delete stored evidence.

        Args:
            evidence_id: Evidence ID.

        Returns:
            True if deleted, False if not found.
        """
        self._load_index()

        stored = self._index.get(evidence_id)
        if stored is None:
            return False

        # Delete file
        if stored.file_path.exists():
            stored.file_path.unlink()

        # Update index
        del self._index[evidence_id]
        self._save_index()

        logger.debug(f"Deleted evidence {evidence_id}")
        return True

    def list(
        self,
        *,
        platform: str | None = None,
        evidence_type: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> list[StoredEvidence]:
        """
        List stored evidence with optional filtering.

        Args:
            platform: Filter by platform.
            evidence_type: Filter by evidence type.
            start_date: Filter by collection date (inclusive).
            end_date: Filter by collection date (inclusive).

        Returns:
            List of matching stored evidence records.
        """
        self._load_index()

        results = list(self._index.values())

        if platform:
            results = [e for e in results if e.platform == platform]
        if evidence_type:
            results = [e for e in results if e.evidence_type == evidence_type]
        if start_date:
            results = [e for e in results if e.collected_at >= start_date]
        if end_date:
            results = [e for e in results if e.collected_at <= end_date]

        return sorted(results, key=lambda e: e.collected_at, reverse=True)

    def list_platforms(self) -> list[str]:
        """List all platforms with stored evidence."""
        self._load_index()
        return sorted(set(e.platform for e in self._index.values()))

    def list_evidence_types(self, platform: str | None = None) -> list[str]:
        """List all evidence types, optionally filtered by platform."""
        self._load_index()
        evidence = self._index.values()
        if platform:
            evidence = [e for e in evidence if e.platform == platform]
        return sorted(set(e.evidence_type for e in evidence))

    def get_statistics(self) -> dict[str, Any]:
        """Get storage statistics."""
        self._load_index()

        total_size = sum(e.file_size for e in self._index.values())
        by_platform: dict[str, int] = {}
        by_type: dict[str, int] = {}

        for evidence in self._index.values():
            by_platform[evidence.platform] = by_platform.get(evidence.platform, 0) + 1
            by_type[evidence.evidence_type] = by_type.get(evidence.evidence_type, 0) + 1

        return {
            "total_items": len(self._index),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "by_platform": by_platform,
            "by_type": by_type,
            "oldest": min(
                (e.collected_at for e in self._index.values()),
                default=None,
            ),
            "newest": max(
                (e.collected_at for e in self._index.values()),
                default=None,
            ),
        }

    def verify_all(self) -> tuple[int, int, list[str]]:
        """
        Verify integrity of all stored evidence.

        Returns:
            Tuple of (passed_count, failed_count, failed_ids).
        """
        self._load_index()

        passed = 0
        failed = 0
        failed_ids: list[str] = []

        for evidence_id in self._index:
            if self.verify(evidence_id):
                passed += 1
            else:
                failed += 1
                failed_ids.append(evidence_id)

        logger.info(f"Verification complete: {passed} passed, {failed} failed")
        return passed, failed, failed_ids

    def apply_retention(self, days: int) -> int:
        """
        Delete evidence older than the specified retention period.

        Args:
            days: Number of days to retain evidence.

        Returns:
            Number of items deleted.
        """
        self._load_index()

        from datetime import timedelta

        cutoff = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        cutoff = cutoff - timedelta(days=days)

        to_delete = [
            e.id for e in self._index.values() if e.collected_at < cutoff
        ]

        for evidence_id in to_delete:
            self.delete(evidence_id)

        logger.info(f"Retention policy applied: deleted {len(to_delete)} items")
        return len(to_delete)

    def cleanup(self, retention_days: int) -> int:
        """
        Alias for apply_retention for API compatibility.

        Args:
            retention_days: Number of days to retain evidence.

        Returns:
            Number of items deleted.
        """
        return self.apply_retention(retention_days)

    def get_by_type(
        self,
        platform: str,
        evidence_type: str,
    ) -> list[StoredEvidence]:
        """
        Get all evidence of a specific type from a platform.

        Args:
            platform: Platform name.
            evidence_type: Type of evidence.

        Returns:
            List of matching stored evidence records.
        """
        return self.list(platform=platform, evidence_type=evidence_type)

    def get_by_date_range(
        self,
        start: datetime,
        end: datetime,
        platform: str | None = None,
    ) -> list[StoredEvidence]:
        """
        Get evidence within a date range.

        Args:
            start: Start of date range (inclusive).
            end: End of date range (inclusive).
            platform: Optional platform filter.

        Returns:
            List of matching stored evidence records.
        """
        return self.list(platform=platform, start_date=start, end_date=end)

    def get_all(self) -> list[StoredEvidence]:
        """
        Get all stored evidence.

        Returns:
            List of all stored evidence records.
        """
        return self.list()

    def export_bundle(
        self,
        output_path: Path,
        *,
        evidence_ids: list[str] | None = None,
        platform: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> Path:
        """
        Export evidence to a portable bundle for air-gapped transfer.

        Args:
            output_path: Path for the output bundle.
            evidence_ids: Specific evidence IDs to export.
            platform: Filter by platform.
            start_date: Filter by collection date.
            end_date: Filter by collection date.

        Returns:
            Path to the created bundle.
        """
        self._load_index()

        # Determine what to export
        if evidence_ids:
            to_export = [self._index[eid] for eid in evidence_ids if eid in self._index]
        else:
            to_export = self.list(
                platform=platform,
                start_date=start_date,
                end_date=end_date,
            )

        if not to_export:
            raise StorageError("No evidence to export")

        # Create bundle directory
        bundle_dir = output_path.with_suffix("")
        bundle_dir.mkdir(parents=True, exist_ok=True)

        # Copy evidence files
        files_dir = bundle_dir / "files"
        files_dir.mkdir()

        manifest: list[dict[str, Any]] = []

        for evidence in to_export:
            if evidence.file_path.exists():
                dest = files_dir / evidence.file_path.name
                shutil.copy2(evidence.file_path, dest)
                manifest.append({
                    **evidence.to_dict(),
                    "bundle_path": f"files/{evidence.file_path.name}",
                })

        # Write manifest
        manifest_path = bundle_dir / "manifest.json"
        manifest_path.write_text(json.dumps({
            "version": "1.0",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "evidence_count": len(manifest),
            "evidence": manifest,
        }, indent=2))

        # Create archive
        archive_path = shutil.make_archive(
            str(bundle_dir),
            "gztar",
            bundle_dir.parent,
            bundle_dir.name,
        )

        # Clean up temp directory
        shutil.rmtree(bundle_dir)

        logger.info(f"Exported {len(manifest)} evidence items to {archive_path}")
        return Path(archive_path)

    def import_bundle(self, bundle_path: Path) -> int:
        """
        Import evidence from a bundle.

        Args:
            bundle_path: Path to the bundle archive.

        Returns:
            Number of items imported.
        """
        import tarfile

        self._ensure_dir()

        # Extract bundle
        temp_dir = self.evidence_dir / f"_import_{uuid4().hex[:8]}"
        temp_dir.mkdir()

        try:
            with tarfile.open(bundle_path, "r:gz") as tar:
                tar.extractall(temp_dir)

            # Find manifest
            manifest_path = None
            for path in temp_dir.rglob("manifest.json"):
                manifest_path = path
                break

            if not manifest_path:
                raise StorageError("Bundle does not contain a manifest")

            manifest = json.loads(manifest_path.read_text())
            bundle_root = manifest_path.parent

            imported = 0
            for item in manifest.get("evidence", []):
                bundle_file = bundle_root / item["bundle_path"]
                if not bundle_file.exists():
                    logger.warning(f"Missing file in bundle: {item['bundle_path']}")
                    continue

                # Create evidence object
                evidence = Evidence(
                    id=item["id"],
                    platform=item["platform"],
                    evidence_type=item["evidence_type"],
                    collected_at=datetime.fromisoformat(item["collected_at"]),
                    raw_data={},  # Will be read from file
                    metadata=item.get("metadata", {}),
                )

                # Read and store
                data_bytes = bundle_file.read_bytes()
                if item.get("compressed"):
                    data_bytes = gzip.decompress(data_bytes)
                evidence.raw_data = json.loads(data_bytes.decode("utf-8"))

                self.store(evidence)
                imported += 1

            logger.info(f"Imported {imported} evidence items from bundle")
            return imported

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
