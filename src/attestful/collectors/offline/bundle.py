"""
Evidence Bundle Format Definition.

Defines the structure and validation for offline evidence bundles used
in air-gapped deployments. Bundles contain:

1. manifest.json - Collection metadata and file inventory
2. checksums.json - SHA-256 hashes for integrity verification
3. signature.sig - Digital signature for authenticity
4. evidence/ - Evidence files organized by platform/type/date

Bundle Structure:
    bundle_name.tar.gz (or .zip)
    ├── manifest.json
    ├── checksums.json
    ├── signature.sig (optional)
    └── evidence/
        └── {platform}/
            └── {evidence_type}/
                └── {YYYY-MM-DD}/
                    └── {evidence_id}.json
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterator
from uuid import UUID, uuid4

from attestful.core.exceptions import ValidationError
from attestful.core.logging import get_logger

logger = get_logger(__name__)


class BundleFormat(str, Enum):
    """Supported bundle archive formats."""

    TAR_GZ = "tar.gz"  # Default, best compression
    TAR_BZ2 = "tar.bz2"  # Better compression, slower
    TAR_XZ = "tar.xz"  # Best compression, slowest
    ZIP = "zip"  # Wide compatibility
    DIRECTORY = "directory"  # Uncompressed directory (for debugging)


class BundleVersion(str, Enum):
    """Bundle format versions for compatibility."""

    V1 = "1.0"  # Initial version


# Current bundle version
BUNDLE_VERSION = BundleVersion.V1


@dataclass
class BundleMetadata:
    """
    Metadata about the bundle itself.

    Stored in the manifest for tracking and compatibility.
    """

    version: str = BUNDLE_VERSION.value
    format: str = BundleFormat.TAR_GZ.value
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = "attestful"
    attestful_version: str = "1.0.0"
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "version": self.version,
            "format": self.format,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "attestful_version": self.attestful_version,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BundleMetadata:
        """Create from dictionary."""
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        else:
            created_at = datetime.now(timezone.utc)

        return cls(
            version=data.get("version", BUNDLE_VERSION.value),
            format=data.get("format", BundleFormat.TAR_GZ.value),
            created_at=created_at,
            created_by=data.get("created_by", "attestful"),
            attestful_version=data.get("attestful_version", "1.0.0"),
            description=data.get("description", ""),
        )


@dataclass
class CollectionMetadata:
    """
    Metadata about the evidence collection run.

    Describes what was collected, when, and from what source.
    """

    collection_id: str = field(default_factory=lambda: str(uuid4()))
    organization_id: str = ""
    organization_name: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    collector_hostname: str = ""
    collector_ip: str = ""
    platforms_collected: list[str] = field(default_factory=list)
    evidence_types_collected: list[str] = field(default_factory=list)
    total_evidence_count: int = 0
    total_size_bytes: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "collection_id": self.collection_id,
            "organization_id": self.organization_id,
            "organization_name": self.organization_name,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "collector_hostname": self.collector_hostname,
            "collector_ip": self.collector_ip,
            "platforms_collected": self.platforms_collected,
            "evidence_types_collected": self.evidence_types_collected,
            "total_evidence_count": self.total_evidence_count,
            "total_size_bytes": self.total_size_bytes,
            "errors": self.errors,
            "warnings": self.warnings,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CollectionMetadata:
        """Create from dictionary."""
        started_at = data.get("started_at")
        if isinstance(started_at, str):
            started_at = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        else:
            started_at = datetime.now(timezone.utc)

        completed_at = data.get("completed_at")
        if isinstance(completed_at, str):
            completed_at = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
        else:
            completed_at = None

        return cls(
            collection_id=data.get("collection_id", str(uuid4())),
            organization_id=data.get("organization_id", ""),
            organization_name=data.get("organization_name", ""),
            started_at=started_at,
            completed_at=completed_at,
            collector_hostname=data.get("collector_hostname", ""),
            collector_ip=data.get("collector_ip", ""),
            platforms_collected=data.get("platforms_collected", []),
            evidence_types_collected=data.get("evidence_types_collected", []),
            total_evidence_count=data.get("total_evidence_count", 0),
            total_size_bytes=data.get("total_size_bytes", 0),
            errors=data.get("errors", []),
            warnings=data.get("warnings", []),
        )


@dataclass
class EvidenceFileEntry:
    """
    Entry describing a single evidence file in the bundle.

    Part of the manifest's file inventory.
    """

    file_id: str
    relative_path: str  # Path within bundle (e.g., "evidence/okta/users/2024-01-15/...")
    platform: str
    evidence_type: str
    collected_at: datetime
    size_bytes: int
    evidence_id: str | None = None  # Original evidence ID if available
    source_id: str | None = None  # Platform-specific ID
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "file_id": self.file_id,
            "relative_path": self.relative_path,
            "platform": self.platform,
            "evidence_type": self.evidence_type,
            "collected_at": self.collected_at.isoformat(),
            "size_bytes": self.size_bytes,
            "evidence_id": self.evidence_id,
            "source_id": self.source_id,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceFileEntry:
        """Create from dictionary."""
        collected_at = data.get("collected_at")
        if isinstance(collected_at, str):
            collected_at = datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
        else:
            collected_at = datetime.now(timezone.utc)

        return cls(
            file_id=data["file_id"],
            relative_path=data["relative_path"],
            platform=data["platform"],
            evidence_type=data["evidence_type"],
            collected_at=collected_at,
            size_bytes=data.get("size_bytes", 0),
            evidence_id=data.get("evidence_id"),
            source_id=data.get("source_id"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class BundleManifest:
    """
    Complete manifest for an evidence bundle.

    The manifest.json file containing all bundle metadata and file inventory.
    """

    bundle_id: str = field(default_factory=lambda: str(uuid4()))
    bundle_metadata: BundleMetadata = field(default_factory=BundleMetadata)
    collection_metadata: CollectionMetadata = field(default_factory=CollectionMetadata)
    files: list[EvidenceFileEntry] = field(default_factory=list)
    signature_info: dict[str, Any] | None = None

    @property
    def file_count(self) -> int:
        """Number of evidence files in bundle."""
        return len(self.files)

    @property
    def total_size(self) -> int:
        """Total size of all evidence files."""
        return sum(f.size_bytes for f in self.files)

    def add_file(self, entry: EvidenceFileEntry) -> None:
        """Add a file entry to the manifest."""
        self.files.append(entry)

    def get_files_by_platform(self, platform: str) -> list[EvidenceFileEntry]:
        """Get all files for a specific platform."""
        return [f for f in self.files if f.platform == platform]

    def get_files_by_type(self, evidence_type: str) -> list[EvidenceFileEntry]:
        """Get all files of a specific evidence type."""
        return [f for f in self.files if f.evidence_type == evidence_type]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "bundle_id": self.bundle_id,
            "bundle_metadata": self.bundle_metadata.to_dict(),
            "collection_metadata": self.collection_metadata.to_dict(),
            "files": [f.to_dict() for f in self.files],
            "signature_info": self.signature_info,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BundleManifest:
        """Create from dictionary."""
        return cls(
            bundle_id=data.get("bundle_id", str(uuid4())),
            bundle_metadata=BundleMetadata.from_dict(data.get("bundle_metadata", {})),
            collection_metadata=CollectionMetadata.from_dict(
                data.get("collection_metadata", {})
            ),
            files=[EvidenceFileEntry.from_dict(f) for f in data.get("files", [])],
            signature_info=data.get("signature_info"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> BundleManifest:
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))

    @classmethod
    def from_file(cls, path: Path | str) -> BundleManifest:
        """Load manifest from file."""
        path = Path(path)
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_json(f.read())

    def save(self, path: Path | str) -> None:
        """Save manifest to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())


@dataclass
class BundleChecksum:
    """
    Checksum entry for integrity verification.

    Stored in checksums.json for each file in the bundle.
    """

    relative_path: str
    algorithm: str = "sha256"
    checksum: str = ""
    size_bytes: int = 0
    verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "relative_path": self.relative_path,
            "algorithm": self.algorithm,
            "checksum": self.checksum,
            "size_bytes": self.size_bytes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BundleChecksum:
        """Create from dictionary."""
        return cls(
            relative_path=data["relative_path"],
            algorithm=data.get("algorithm", "sha256"),
            checksum=data.get("checksum", ""),
            size_bytes=data.get("size_bytes", 0),
        )


@dataclass
class BundleChecksums:
    """
    Complete checksums file for a bundle.

    Contains SHA-256 hashes for all files for integrity verification.
    """

    checksums: list[BundleChecksum] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    algorithm: str = "sha256"

    def add_checksum(self, checksum: BundleChecksum) -> None:
        """Add a checksum entry."""
        self.checksums.append(checksum)

    def get_checksum(self, relative_path: str) -> BundleChecksum | None:
        """Get checksum for a specific file."""
        for cs in self.checksums:
            if cs.relative_path == relative_path:
                return cs
        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "generated_at": self.generated_at.isoformat(),
            "algorithm": self.algorithm,
            "checksums": [c.to_dict() for c in self.checksums],
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BundleChecksums:
        """Create from dictionary."""
        generated_at = data.get("generated_at")
        if isinstance(generated_at, str):
            generated_at = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
        else:
            generated_at = datetime.now(timezone.utc)

        return cls(
            checksums=[BundleChecksum.from_dict(c) for c in data.get("checksums", [])],
            generated_at=generated_at,
            algorithm=data.get("algorithm", "sha256"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> BundleChecksums:
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))

    @classmethod
    def from_file(cls, path: Path | str) -> BundleChecksums:
        """Load checksums from file."""
        path = Path(path)
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_json(f.read())

    def save(self, path: Path | str) -> None:
        """Save checksums to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())


@dataclass
class BundleSignature:
    """
    Digital signature for bundle authenticity.

    Contains signature data and metadata about the signing key.
    """

    signature: bytes = b""
    signature_base64: str = ""
    algorithm: str = "RSA-SHA256"  # or "GPG", "ED25519"
    key_id: str = ""
    key_fingerprint: str = ""
    signer_id: str = ""
    signed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    signed_content_hash: str = ""  # Hash of what was signed

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (excluding raw signature bytes)."""
        return {
            "signature_base64": self.signature_base64,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "key_fingerprint": self.key_fingerprint,
            "signer_id": self.signer_id,
            "signed_at": self.signed_at.isoformat(),
            "signed_content_hash": self.signed_content_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BundleSignature:
        """Create from dictionary."""
        import base64

        signed_at = data.get("signed_at")
        if isinstance(signed_at, str):
            signed_at = datetime.fromisoformat(signed_at.replace("Z", "+00:00"))
        else:
            signed_at = datetime.now(timezone.utc)

        signature_base64 = data.get("signature_base64", "")
        try:
            signature = base64.b64decode(signature_base64) if signature_base64 else b""
        except Exception:
            signature = b""

        return cls(
            signature=signature,
            signature_base64=signature_base64,
            algorithm=data.get("algorithm", "RSA-SHA256"),
            key_id=data.get("key_id", ""),
            key_fingerprint=data.get("key_fingerprint", ""),
            signer_id=data.get("signer_id", ""),
            signed_at=signed_at,
            signed_content_hash=data.get("signed_content_hash", ""),
        )


@dataclass
class EvidenceBundle:
    """
    Complete evidence bundle for offline transfer.

    Represents the full bundle with manifest, checksums, signature,
    and evidence files for air-gapped deployment transfer.
    """

    manifest: BundleManifest = field(default_factory=BundleManifest)
    checksums: BundleChecksums = field(default_factory=BundleChecksums)
    signature: BundleSignature | None = None
    bundle_path: Path | None = None  # Path to bundle file or directory
    is_valid: bool = False
    validation_errors: list[str] = field(default_factory=list)

    @property
    def bundle_id(self) -> str:
        """Get bundle ID from manifest."""
        return self.manifest.bundle_id

    @property
    def is_signed(self) -> bool:
        """Check if bundle is signed."""
        return self.signature is not None and bool(self.signature.signature)

    def validate(self) -> bool:
        """
        Validate bundle structure and integrity.

        Returns:
            True if bundle is valid, False otherwise.
        """
        self.validation_errors = []

        # Check manifest exists
        if not self.manifest:
            self.validation_errors.append("Missing manifest")
            self.is_valid = False
            return False

        # Check checksums exist
        if not self.checksums:
            self.validation_errors.append("Missing checksums")
            self.is_valid = False
            return False

        # Verify manifest has required fields
        if not self.manifest.bundle_id:
            self.validation_errors.append("Manifest missing bundle_id")

        if not self.manifest.files:
            self.validation_errors.append("Manifest has no files")

        # Verify checksums exist for all manifest files
        manifest_paths = {f.relative_path for f in self.manifest.files}
        checksum_paths = {c.relative_path for c in self.checksums.checksums}

        missing_checksums = manifest_paths - checksum_paths
        if missing_checksums:
            self.validation_errors.append(
                f"Missing checksums for: {', '.join(list(missing_checksums)[:5])}"
            )

        self.is_valid = len(self.validation_errors) == 0
        return self.is_valid


# =============================================================================
# Bundle Creation Functions
# =============================================================================


def create_bundle_manifest(
    *,
    organization_id: str = "",
    organization_name: str = "",
    description: str = "",
    collector_hostname: str = "",
) -> BundleManifest:
    """
    Create a new empty bundle manifest.

    Args:
        organization_id: Organization identifier
        organization_name: Organization display name
        description: Bundle description
        collector_hostname: Hostname of collecting machine

    Returns:
        New BundleManifest instance
    """
    import socket

    hostname = collector_hostname or socket.gethostname()

    return BundleManifest(
        bundle_metadata=BundleMetadata(
            description=description,
        ),
        collection_metadata=CollectionMetadata(
            organization_id=organization_id,
            organization_name=organization_name,
            collector_hostname=hostname,
        ),
    )


def calculate_file_checksum(
    file_path: Path | str,
    algorithm: str = "sha256",
) -> BundleChecksum:
    """
    Calculate checksum for a file.

    Args:
        file_path: Path to file
        algorithm: Hash algorithm (default: sha256)

    Returns:
        BundleChecksum instance

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If algorithm not supported
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if algorithm not in ("sha256", "sha512", "sha384", "sha1", "md5"):
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    hash_func = getattr(hashlib, algorithm)()
    size = 0

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_func.update(chunk)
            size += len(chunk)

    return BundleChecksum(
        relative_path=str(file_path.name),
        algorithm=algorithm,
        checksum=hash_func.hexdigest(),
        size_bytes=size,
    )


def calculate_directory_checksums(
    directory: Path | str,
    algorithm: str = "sha256",
) -> BundleChecksums:
    """
    Calculate checksums for all files in a directory.

    Args:
        directory: Directory path
        algorithm: Hash algorithm

    Returns:
        BundleChecksums with all file checksums
    """
    directory = Path(directory)
    checksums = BundleChecksums(algorithm=algorithm)

    for file_path in directory.rglob("*"):
        if file_path.is_file():
            relative_path = str(file_path.relative_to(directory))
            checksum = calculate_file_checksum(file_path, algorithm)
            checksum.relative_path = relative_path
            checksums.add_checksum(checksum)

    return checksums


def validate_bundle_structure(bundle_path: Path | str) -> tuple[bool, list[str]]:
    """
    Validate the structure of a bundle directory or archive.

    Args:
        bundle_path: Path to bundle directory or archive file

    Returns:
        Tuple of (is_valid, list of error messages)
    """
    bundle_path = Path(bundle_path)
    errors: list[str] = []

    if bundle_path.is_dir():
        # Validate directory structure
        manifest_path = bundle_path / "manifest.json"
        checksums_path = bundle_path / "checksums.json"
        evidence_path = bundle_path / "evidence"

        if not manifest_path.exists():
            errors.append("Missing manifest.json")

        if not checksums_path.exists():
            errors.append("Missing checksums.json")

        if not evidence_path.exists():
            errors.append("Missing evidence/ directory")
        elif not evidence_path.is_dir():
            errors.append("evidence is not a directory")

    elif bundle_path.is_file():
        # Validate archive structure
        import tarfile
        import zipfile

        try:
            if bundle_path.suffix in (".gz", ".bz2", ".xz") or str(bundle_path).endswith(
                (".tar.gz", ".tar.bz2", ".tar.xz")
            ):
                with tarfile.open(bundle_path, "r:*") as tar:
                    names = tar.getnames()
                    if not any(n.endswith("manifest.json") for n in names):
                        errors.append("Missing manifest.json in archive")
                    if not any(n.endswith("checksums.json") for n in names):
                        errors.append("Missing checksums.json in archive")
                    if not any("evidence/" in n for n in names):
                        errors.append("Missing evidence/ directory in archive")

            elif bundle_path.suffix == ".zip":
                with zipfile.ZipFile(bundle_path, "r") as zf:
                    names = zf.namelist()
                    if not any(n.endswith("manifest.json") for n in names):
                        errors.append("Missing manifest.json in archive")
                    if not any(n.endswith("checksums.json") for n in names):
                        errors.append("Missing checksums.json in archive")
                    if not any("evidence/" in n for n in names):
                        errors.append("Missing evidence/ directory in archive")

            else:
                errors.append(f"Unknown archive format: {bundle_path.suffix}")

        except (tarfile.TarError, zipfile.BadZipFile) as e:
            errors.append(f"Invalid archive: {e}")

    else:
        errors.append(f"Bundle path does not exist: {bundle_path}")

    return len(errors) == 0, errors


def get_evidence_relative_path(
    platform: str,
    evidence_type: str,
    collected_at: datetime,
    evidence_id: str,
) -> str:
    """
    Generate the relative path for an evidence file within a bundle.

    Args:
        platform: Platform name (e.g., "okta", "aws")
        evidence_type: Evidence type (e.g., "users", "mfa_factors")
        collected_at: Collection timestamp
        evidence_id: Unique evidence identifier

    Returns:
        Relative path string (e.g., "evidence/okta/users/2024-01-15/abc123.json")
    """
    date_str = collected_at.strftime("%Y-%m-%d")
    return f"evidence/{platform}/{evidence_type}/{date_str}/{evidence_id}.json"
