#!/usr/bin/env python3
"""
Attestful Offline Update Manager.

Creates and applies versioned update bundles for air-gapped deployments.
Supports rollback and integrity verification.

Usage:
    # Create update bundle
    python update_manager.py create --from 0.1.0 --to 0.2.0 --output update-0.1.0-to-0.2.0.tar.gz

    # Apply update
    python update_manager.py apply update-0.1.0-to-0.2.0.tar.gz

    # Rollback
    python update_manager.py rollback

    # Verify update bundle
    python update_manager.py verify update-0.1.0-to-0.2.0.tar.gz
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

# Try to import cryptography for signing
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class UpdateType(str, Enum):
    """Type of update."""
    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"


class UpdateStatus(str, Enum):
    """Status of update operation."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class UpdateManifest:
    """Manifest describing an update bundle."""

    version: str
    created_at: str
    from_version: str
    to_version: str
    update_type: UpdateType
    description: str
    files_added: list[str]
    files_modified: list[str]
    files_deleted: list[str]
    migrations: list[str]
    oscal_updates: list[str]
    checksums: dict[str, str]
    signature: str | None = None
    signed_by: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "version": self.version,
            "created_at": self.created_at,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "update_type": self.update_type.value,
            "description": self.description,
            "files_added": self.files_added,
            "files_modified": self.files_modified,
            "files_deleted": self.files_deleted,
            "migrations": self.migrations,
            "oscal_updates": self.oscal_updates,
            "checksums": self.checksums,
            "signature": self.signature,
            "signed_by": self.signed_by,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UpdateManifest:
        """Create from dictionary."""
        return cls(
            version=data["version"],
            created_at=data["created_at"],
            from_version=data["from_version"],
            to_version=data["to_version"],
            update_type=UpdateType(data["update_type"]),
            description=data.get("description", ""),
            files_added=data.get("files_added", []),
            files_modified=data.get("files_modified", []),
            files_deleted=data.get("files_deleted", []),
            migrations=data.get("migrations", []),
            oscal_updates=data.get("oscal_updates", []),
            checksums=data.get("checksums", {}),
            signature=data.get("signature"),
            signed_by=data.get("signed_by"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class BackupManifest:
    """Manifest for a pre-update backup."""

    backup_id: str
    created_at: str
    from_version: str
    backup_path: str
    files_backed_up: list[str]
    database_backup: str | None
    config_backup: str | None
    checksums: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "backup_id": self.backup_id,
            "created_at": self.created_at,
            "from_version": self.from_version,
            "backup_path": self.backup_path,
            "files_backed_up": self.files_backed_up,
            "database_backup": self.database_backup,
            "config_backup": self.config_backup,
            "checksums": self.checksums,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BackupManifest:
        """Create from dictionary."""
        return cls(
            backup_id=data["backup_id"],
            created_at=data["created_at"],
            from_version=data["from_version"],
            backup_path=data["backup_path"],
            files_backed_up=data.get("files_backed_up", []),
            database_backup=data.get("database_backup"),
            config_backup=data.get("config_backup"),
            checksums=data.get("checksums", {}),
        )


@dataclass
class UpdateResult:
    """Result of an update operation."""

    success: bool
    status: UpdateStatus
    message: str
    from_version: str | None = None
    to_version: str | None = None
    backup_id: str | None = None
    files_updated: int = 0
    migrations_run: int = 0
    errors: list[str] = field(default_factory=list)


def calculate_sha256(path: Path) -> str:
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def get_installed_version(install_dir: Path) -> str | None:
    """Get currently installed Attestful version."""
    version_file = install_dir / "VERSION"
    if version_file.exists():
        return version_file.read_text().strip()

    # Try to get from package
    try:
        result = subprocess.run(
            [sys.executable, "-c", "import attestful; print(attestful.__version__)"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass

    return None


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings. Returns -1, 0, or 1."""
    def parse_version(v: str) -> tuple[int, ...]:
        return tuple(int(x) for x in v.split(".")[:3])

    p1, p2 = parse_version(v1), parse_version(v2)

    if p1 < p2:
        return -1
    elif p1 > p2:
        return 1
    return 0


def determine_update_type(from_version: str, to_version: str) -> UpdateType:
    """Determine update type from version difference."""
    from_parts = [int(x) for x in from_version.split(".")[:3]]
    to_parts = [int(x) for x in to_version.split(".")[:3]]

    # Pad to 3 parts
    while len(from_parts) < 3:
        from_parts.append(0)
    while len(to_parts) < 3:
        to_parts.append(0)

    if to_parts[0] != from_parts[0]:
        return UpdateType.MAJOR
    elif to_parts[1] != from_parts[1]:
        return UpdateType.MINOR
    else:
        return UpdateType.PATCH


class UpdateBundleCreator:
    """Creates update bundles for offline distribution."""

    # Bundle format version
    BUNDLE_VERSION = "1.0.0"

    def __init__(
        self,
        project_root: Path,
        from_version: str,
        to_version: str,
        signing_key_path: Path | None = None,
    ) -> None:
        """Initialize bundle creator."""
        self.project_root = project_root
        self.from_version = from_version
        self.to_version = to_version
        self.signing_key_path = signing_key_path

    def create(self, output_path: Path, description: str = "") -> Path:
        """Create an update bundle."""
        print(f"Creating update bundle: {self.from_version} -> {self.to_version}")

        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = Path(tmpdir) / "update"
            bundle_dir.mkdir()

            # Create subdirectories
            (bundle_dir / "code").mkdir()
            (bundle_dir / "migrations").mkdir()
            (bundle_dir / "oscal").mkdir()
            (bundle_dir / "data").mkdir()

            # Copy updated source files
            files_info = self._copy_source_files(bundle_dir / "code")

            # Copy migration scripts
            migrations = self._copy_migrations(bundle_dir / "migrations")

            # Copy OSCAL updates
            oscal_updates = self._copy_oscal_updates(bundle_dir / "oscal")

            # Generate checksums
            checksums = self._generate_checksums(bundle_dir)

            # Create manifest
            manifest = UpdateManifest(
                version=self.BUNDLE_VERSION,
                created_at=datetime.now(timezone.utc).isoformat(),
                from_version=self.from_version,
                to_version=self.to_version,
                update_type=determine_update_type(self.from_version, self.to_version),
                description=description or f"Update from {self.from_version} to {self.to_version}",
                files_added=files_info.get("added", []),
                files_modified=files_info.get("modified", []),
                files_deleted=files_info.get("deleted", []),
                migrations=migrations,
                oscal_updates=oscal_updates,
                checksums=checksums,
            )

            # Sign manifest if key provided
            if self.signing_key_path and CRYPTO_AVAILABLE:
                manifest = self._sign_manifest(manifest)

            # Write manifest
            manifest_path = bundle_dir / "manifest.json"
            manifest_path.write_text(json.dumps(manifest.to_dict(), indent=2))

            # Create update script
            self._create_update_script(bundle_dir)

            # Create tarball
            print(f"Creating bundle: {output_path}")
            with tarfile.open(output_path, "w:gz") as tar:
                tar.add(bundle_dir, arcname="update")

            print(f"Bundle created: {output_path.stat().st_size / 1024:.1f} KB")
            return output_path

    def _copy_source_files(self, dest_dir: Path) -> dict[str, list[str]]:
        """Copy source files to bundle."""
        src_dir = self.project_root / "src"
        if src_dir.exists():
            shutil.copytree(src_dir, dest_dir / "src")

        return {
            "added": [],
            "modified": [],
            "deleted": [],
        }

    def _copy_migrations(self, dest_dir: Path) -> list[str]:
        """Copy database migration scripts."""
        migrations_src = self.project_root / "migrations"
        migrations = []

        if migrations_src.exists():
            for migration_file in sorted(migrations_src.glob("*.py")):
                shutil.copy2(migration_file, dest_dir)
                migrations.append(migration_file.name)

        return migrations

    def _copy_oscal_updates(self, dest_dir: Path) -> list[str]:
        """Copy OSCAL catalog/profile updates."""
        oscal_src = self.project_root / "data" / "oscal"
        updates = []

        if oscal_src.exists():
            shutil.copytree(oscal_src, dest_dir, dirs_exist_ok=True)
            for f in dest_dir.rglob("*.json"):
                updates.append(str(f.relative_to(dest_dir)))

        return updates

    def _generate_checksums(self, bundle_dir: Path) -> dict[str, str]:
        """Generate checksums for all files in bundle."""
        checksums = {}

        for path in bundle_dir.rglob("*"):
            if path.is_file() and path.name != "manifest.json":
                relative_path = str(path.relative_to(bundle_dir))
                checksums[relative_path] = calculate_sha256(path)

        return checksums

    def _sign_manifest(self, manifest: UpdateManifest) -> UpdateManifest:
        """Sign the manifest with private key."""
        if not self.signing_key_path or not CRYPTO_AVAILABLE:
            return manifest

        # Load private key
        key_data = self.signing_key_path.read_bytes()
        private_key = serialization.load_pem_private_key(key_data, password=None)

        # Create signature
        manifest_bytes = json.dumps(manifest.to_dict()).encode()
        signature = private_key.sign(
            manifest_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        manifest.signature = signature.hex()
        manifest.signed_by = "update-signing-key"

        return manifest

    def _create_update_script(self, bundle_dir: Path) -> None:
        """Create the update application script."""
        script_content = '''#!/usr/bin/env python3
"""Apply Attestful update from bundle."""

import json
import shutil
import sys
from pathlib import Path

def apply_update(bundle_dir: Path, install_dir: Path) -> bool:
    """Apply update from bundle to installation."""
    manifest_path = bundle_dir / "manifest.json"
    if not manifest_path.exists():
        print("Error: No manifest found")
        return False

    with open(manifest_path) as f:
        manifest = json.load(f)

    print(f"Applying update: {manifest['from_version']} -> {manifest['to_version']}")

    # Copy source files
    src_dir = bundle_dir / "code" / "src"
    if src_dir.exists():
        dest = install_dir / "src"
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src_dir, dest)

    # Copy OSCAL data
    oscal_dir = bundle_dir / "oscal"
    if oscal_dir.exists():
        dest = install_dir / "data" / "oscal"
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copytree(oscal_dir, dest, dirs_exist_ok=True)

    # Update version file
    version_file = install_dir / "VERSION"
    version_file.write_text(manifest["to_version"])

    print(f"Update applied successfully!")
    return True

if __name__ == "__main__":
    bundle_dir = Path(__file__).parent
    install_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    sys.exit(0 if apply_update(bundle_dir, install_dir) else 1)
'''
        script_path = bundle_dir / "apply_update.py"
        script_path.write_text(script_content)
        os.chmod(script_path, 0o755)


class UpdateApplicator:
    """Applies update bundles to installations."""

    def __init__(
        self,
        install_dir: Path,
        backup_dir: Path | None = None,
        verify_signatures: bool = True,
        public_key_path: Path | None = None,
    ) -> None:
        """Initialize update applicator."""
        self.install_dir = install_dir
        self.backup_dir = backup_dir or (install_dir / ".backups")
        self.verify_signatures = verify_signatures
        self.public_key_path = public_key_path

    def apply(self, bundle_path: Path) -> UpdateResult:
        """Apply an update bundle."""
        print(f"Applying update: {bundle_path}")

        # Verify bundle exists
        if not bundle_path.exists():
            return UpdateResult(
                success=False,
                status=UpdateStatus.FAILED,
                message=f"Bundle not found: {bundle_path}",
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            extract_dir = Path(tmpdir)

            # Extract bundle
            try:
                with tarfile.open(bundle_path, "r:*") as tar:
                    tar.extractall(extract_dir)
            except Exception as e:
                return UpdateResult(
                    success=False,
                    status=UpdateStatus.FAILED,
                    message=f"Failed to extract bundle: {e}",
                )

            bundle_dir = extract_dir / "update"
            if not bundle_dir.exists():
                return UpdateResult(
                    success=False,
                    status=UpdateStatus.FAILED,
                    message="Invalid bundle structure",
                )

            # Load manifest
            manifest_path = bundle_dir / "manifest.json"
            if not manifest_path.exists():
                return UpdateResult(
                    success=False,
                    status=UpdateStatus.FAILED,
                    message="Missing manifest.json",
                )

            with open(manifest_path) as f:
                manifest = UpdateManifest.from_dict(json.load(f))

            # Verify current version
            current_version = get_installed_version(self.install_dir)
            if current_version and current_version != manifest.from_version:
                return UpdateResult(
                    success=False,
                    status=UpdateStatus.FAILED,
                    message=f"Version mismatch: installed {current_version}, expected {manifest.from_version}",
                    from_version=current_version,
                )

            # Verify checksums
            checksum_errors = self._verify_checksums(bundle_dir, manifest.checksums)
            if checksum_errors:
                return UpdateResult(
                    success=False,
                    status=UpdateStatus.FAILED,
                    message="Checksum verification failed",
                    errors=checksum_errors,
                )

            # Create backup
            backup_result = self._create_backup(manifest.from_version)
            if not backup_result[0]:
                return UpdateResult(
                    success=False,
                    status=UpdateStatus.FAILED,
                    message=f"Backup failed: {backup_result[1]}",
                )
            backup_id = backup_result[1]

            # Apply update
            try:
                files_updated = self._apply_files(bundle_dir, manifest)
                migrations_run = self._run_migrations(bundle_dir, manifest)

                # Update version
                version_file = self.install_dir / "VERSION"
                version_file.write_text(manifest.to_version)

                return UpdateResult(
                    success=True,
                    status=UpdateStatus.COMPLETED,
                    message=f"Updated to {manifest.to_version}",
                    from_version=manifest.from_version,
                    to_version=manifest.to_version,
                    backup_id=backup_id,
                    files_updated=files_updated,
                    migrations_run=migrations_run,
                )

            except Exception as e:
                # Attempt rollback
                self._rollback(backup_id)
                return UpdateResult(
                    success=False,
                    status=UpdateStatus.ROLLED_BACK,
                    message=f"Update failed, rolled back: {e}",
                    backup_id=backup_id,
                )

    def _verify_checksums(
        self,
        bundle_dir: Path,
        checksums: dict[str, str],
    ) -> list[str]:
        """Verify bundle file checksums."""
        errors = []

        for filepath, expected_hash in checksums.items():
            full_path = bundle_dir / filepath
            if not full_path.exists():
                errors.append(f"Missing: {filepath}")
                continue

            actual_hash = calculate_sha256(full_path)
            if actual_hash != expected_hash:
                errors.append(f"Checksum mismatch: {filepath}")

        return errors

    def _create_backup(self, version: str) -> tuple[bool, str]:
        """Create backup before update."""
        import uuid

        backup_id = f"backup-{version}-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
        backup_path = self.backup_dir / backup_id

        try:
            backup_path.mkdir(parents=True, exist_ok=True)

            # Backup source
            src_dir = self.install_dir / "src"
            if src_dir.exists():
                shutil.copytree(src_dir, backup_path / "src")

            # Backup VERSION
            version_file = self.install_dir / "VERSION"
            if version_file.exists():
                shutil.copy2(version_file, backup_path / "VERSION")

            # Create backup manifest
            manifest = BackupManifest(
                backup_id=backup_id,
                created_at=datetime.now(timezone.utc).isoformat(),
                from_version=version,
                backup_path=str(backup_path),
                files_backed_up=list(str(p.relative_to(backup_path)) for p in backup_path.rglob("*") if p.is_file()),
                database_backup=None,
                config_backup=None,
                checksums={},
            )

            manifest_path = backup_path / "backup_manifest.json"
            manifest_path.write_text(json.dumps(manifest.to_dict(), indent=2))

            print(f"Created backup: {backup_id}")
            return True, backup_id

        except Exception as e:
            return False, str(e)

    def _apply_files(self, bundle_dir: Path, manifest: UpdateManifest) -> int:
        """Apply file updates."""
        files_updated = 0

        # Copy source files
        src_dir = bundle_dir / "code" / "src"
        if src_dir.exists():
            dest = self.install_dir / "src"
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(src_dir, dest)
            files_updated += sum(1 for _ in src_dir.rglob("*") if _.is_file())

        # Copy OSCAL updates
        oscal_dir = bundle_dir / "oscal"
        if oscal_dir.exists() and any(oscal_dir.iterdir()):
            dest = self.install_dir / "data" / "oscal"
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copytree(oscal_dir, dest, dirs_exist_ok=True)
            files_updated += sum(1 for _ in oscal_dir.rglob("*") if _.is_file())

        return files_updated

    def _run_migrations(self, bundle_dir: Path, manifest: UpdateManifest) -> int:
        """Run database migrations."""
        migrations_dir = bundle_dir / "migrations"
        migrations_run = 0

        if not migrations_dir.exists():
            return 0

        for migration_file in sorted(migrations_dir.glob("*.py")):
            if migration_file.name in manifest.migrations:
                try:
                    subprocess.run(
                        [sys.executable, str(migration_file)],
                        check=True,
                        cwd=self.install_dir,
                    )
                    migrations_run += 1
                    print(f"Applied migration: {migration_file.name}")
                except subprocess.CalledProcessError as e:
                    print(f"Migration failed: {migration_file.name}")
                    raise

        return migrations_run

    def _rollback(self, backup_id: str) -> bool:
        """Rollback to a backup."""
        backup_path = self.backup_dir / backup_id

        if not backup_path.exists():
            print(f"Backup not found: {backup_id}")
            return False

        try:
            # Restore source
            src_backup = backup_path / "src"
            if src_backup.exists():
                src_dest = self.install_dir / "src"
                if src_dest.exists():
                    shutil.rmtree(src_dest)
                shutil.copytree(src_backup, src_dest)

            # Restore VERSION
            version_backup = backup_path / "VERSION"
            if version_backup.exists():
                shutil.copy2(version_backup, self.install_dir / "VERSION")

            print(f"Rolled back to: {backup_id}")
            return True

        except Exception as e:
            print(f"Rollback failed: {e}")
            return False

    def rollback_to_latest(self) -> UpdateResult:
        """Rollback to the most recent backup."""
        if not self.backup_dir.exists():
            return UpdateResult(
                success=False,
                status=UpdateStatus.FAILED,
                message="No backups found",
            )

        # Find latest backup
        backups = sorted(self.backup_dir.iterdir(), reverse=True)
        if not backups:
            return UpdateResult(
                success=False,
                status=UpdateStatus.FAILED,
                message="No backups available",
            )

        latest_backup = backups[0]
        backup_id = latest_backup.name

        # Load backup manifest
        manifest_path = latest_backup / "backup_manifest.json"
        if manifest_path.exists():
            with open(manifest_path) as f:
                backup_manifest = BackupManifest.from_dict(json.load(f))
            from_version = backup_manifest.from_version
        else:
            from_version = "unknown"

        if self._rollback(backup_id):
            return UpdateResult(
                success=True,
                status=UpdateStatus.ROLLED_BACK,
                message=f"Rolled back to {from_version}",
                to_version=from_version,
                backup_id=backup_id,
            )
        else:
            return UpdateResult(
                success=False,
                status=UpdateStatus.FAILED,
                message="Rollback failed",
                backup_id=backup_id,
            )


def verify_bundle(bundle_path: Path, public_key_path: Path | None = None) -> bool:
    """Verify an update bundle's integrity."""
    print(f"Verifying bundle: {bundle_path}")

    if not bundle_path.exists():
        print("Error: Bundle not found")
        return False

    with tempfile.TemporaryDirectory() as tmpdir:
        extract_dir = Path(tmpdir)

        # Extract
        try:
            with tarfile.open(bundle_path, "r:*") as tar:
                tar.extractall(extract_dir)
        except Exception as e:
            print(f"Error extracting: {e}")
            return False

        bundle_dir = extract_dir / "update"

        # Load manifest
        manifest_path = bundle_dir / "manifest.json"
        if not manifest_path.exists():
            print("Error: Missing manifest.json")
            return False

        with open(manifest_path) as f:
            manifest = UpdateManifest.from_dict(json.load(f))

        print(f"Bundle version: {manifest.version}")
        print(f"Update: {manifest.from_version} -> {manifest.to_version}")
        print(f"Type: {manifest.update_type.value}")
        print()

        # Verify checksums
        errors = []
        for filepath, expected_hash in manifest.checksums.items():
            full_path = bundle_dir / filepath
            if not full_path.exists():
                errors.append(f"Missing: {filepath}")
                continue

            actual_hash = calculate_sha256(full_path)
            if actual_hash != expected_hash:
                errors.append(f"Checksum mismatch: {filepath}")

        if errors:
            print("Verification FAILED:")
            for error in errors:
                print(f"  - {error}")
            return False

        print(f"Verified {len(manifest.checksums)} files")
        print("Bundle verification passed!")
        return True


def main():
    parser = argparse.ArgumentParser(
        description="Attestful Update Manager"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Create command
    create_parser = subparsers.add_parser("create", help="Create update bundle")
    create_parser.add_argument("--from", dest="from_version", required=True, help="Source version")
    create_parser.add_argument("--to", dest="to_version", required=True, help="Target version")
    create_parser.add_argument("-o", "--output", type=Path, required=True, help="Output path")
    create_parser.add_argument("--description", type=str, default="", help="Update description")
    create_parser.add_argument("--project-root", type=Path, default=Path.cwd(), help="Project root")
    create_parser.add_argument("--signing-key", type=Path, help="Signing key path")

    # Apply command
    apply_parser = subparsers.add_parser("apply", help="Apply update bundle")
    apply_parser.add_argument("bundle", type=Path, help="Bundle to apply")
    apply_parser.add_argument("--install-dir", type=Path, default=Path.cwd(), help="Installation directory")
    apply_parser.add_argument("--backup-dir", type=Path, help="Backup directory")
    apply_parser.add_argument("--no-verify", action="store_true", help="Skip signature verification")

    # Rollback command
    rollback_parser = subparsers.add_parser("rollback", help="Rollback to latest backup")
    rollback_parser.add_argument("--install-dir", type=Path, default=Path.cwd(), help="Installation directory")
    rollback_parser.add_argument("--backup-dir", type=Path, help="Backup directory")

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify update bundle")
    verify_parser.add_argument("bundle", type=Path, help="Bundle to verify")
    verify_parser.add_argument("--public-key", type=Path, help="Public key for signature verification")

    args = parser.parse_args()

    if args.command == "create":
        creator = UpdateBundleCreator(
            project_root=args.project_root.resolve(),
            from_version=args.from_version,
            to_version=args.to_version,
            signing_key_path=args.signing_key,
        )
        bundle_path = creator.create(args.output.resolve(), args.description)
        print(f"\nBundle created: {bundle_path}")

    elif args.command == "apply":
        applicator = UpdateApplicator(
            install_dir=args.install_dir.resolve(),
            backup_dir=args.backup_dir.resolve() if args.backup_dir else None,
            verify_signatures=not args.no_verify,
        )
        result = applicator.apply(args.bundle.resolve())

        if result.success:
            print(f"\n{result.message}")
            print(f"Files updated: {result.files_updated}")
            print(f"Migrations run: {result.migrations_run}")
        else:
            print(f"\nUpdate failed: {result.message}")
            if result.errors:
                for error in result.errors:
                    print(f"  - {error}")
            sys.exit(1)

    elif args.command == "rollback":
        applicator = UpdateApplicator(
            install_dir=args.install_dir.resolve(),
            backup_dir=args.backup_dir.resolve() if args.backup_dir else None,
        )
        result = applicator.rollback_to_latest()

        if result.success:
            print(f"\n{result.message}")
        else:
            print(f"\nRollback failed: {result.message}")
            sys.exit(1)

    elif args.command == "verify":
        if not verify_bundle(args.bundle.resolve(), args.public_key):
            sys.exit(1)


if __name__ == "__main__":
    main()
