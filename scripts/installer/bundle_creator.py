#!/usr/bin/env python3
"""
Attestful Bundled Installer Creator.

Creates self-contained installation bundles that include all Python
dependencies as wheel files for offline/air-gapped installation.

Usage:
    python bundle_creator.py create --output bundle.tar.gz
    python bundle_creator.py verify bundle.tar.gz
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class BundleConfig:
    """Configuration for bundle creation."""

    # Output settings
    output_path: Path = Path("attestful-bundle.tar.gz")
    compression: str = "gz"  # gz, bz2, xz, or none

    # Python settings
    python_version: str = f"{sys.version_info.major}.{sys.version_info.minor}"
    platform_tag: str = ""

    # Content settings
    include_oscal_catalogs: bool = True
    include_sample_data: bool = False
    include_docs: bool = True

    # Source settings
    project_root: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent)

    def __post_init__(self) -> None:
        if not self.platform_tag:
            self.platform_tag = get_platform_tag()


@dataclass
class BundleManifest:
    """Manifest describing bundle contents."""

    version: str
    created_at: str
    python_version: str
    platform: str
    platform_tag: str
    attestful_version: str
    wheel_count: int
    total_size: int
    checksums: dict[str, str]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "version": self.version,
            "created_at": self.created_at,
            "python_version": self.python_version,
            "platform": self.platform,
            "platform_tag": self.platform_tag,
            "attestful_version": self.attestful_version,
            "wheel_count": self.wheel_count,
            "total_size": self.total_size,
            "checksums": self.checksums,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BundleManifest:
        """Create from dictionary."""
        return cls(
            version=data["version"],
            created_at=data["created_at"],
            python_version=data["python_version"],
            platform=data["platform"],
            platform_tag=data["platform_tag"],
            attestful_version=data["attestful_version"],
            wheel_count=data["wheel_count"],
            total_size=data["total_size"],
            checksums=data["checksums"],
            metadata=data.get("metadata", {}),
        )


def get_platform_tag() -> str:
    """Get platform tag for wheel compatibility."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "darwin":
        # macOS uses special tags
        version = platform.mac_ver()[0]
        major, minor = version.split(".")[:2]
        return f"macosx_{major}_{minor}_{machine}"
    elif system == "linux":
        # Linux uses manylinux tags
        return f"manylinux_2_17_{machine}"
    elif system == "windows":
        if machine in ("amd64", "x86_64"):
            return "win_amd64"
        return f"win_{machine}"

    return f"{system}_{machine}"


def calculate_sha256(path: Path) -> str:
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def get_attestful_version(project_root: Path) -> str:
    """Get Attestful version from pyproject.toml."""
    pyproject = project_root / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text()
        for line in content.split("\n"):
            if line.strip().startswith("version"):
                # Parse version = "x.x.x"
                parts = line.split("=", 1)
                if len(parts) == 2:
                    version = parts[1].strip().strip('"').strip("'")
                    return version
    return "0.1.0"


def download_wheels(
    project_root: Path,
    output_dir: Path,
    python_version: str,
) -> list[Path]:
    """Download wheel files for all dependencies."""
    print(f"Downloading wheels to {output_dir}...")

    # Create pip download command
    cmd = [
        sys.executable, "-m", "pip", "download",
        "--dest", str(output_dir),
        "--python-version", python_version,
        "-r", str(project_root / "requirements.txt") if (project_root / "requirements.txt").exists() else ".",
    ]

    # If using pyproject.toml, download the package itself
    if (project_root / "pyproject.toml").exists():
        cmd = [
            sys.executable, "-m", "pip", "download",
            "--dest", str(output_dir),
            str(project_root),
        ]

    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, cwd=project_root)
    except subprocess.CalledProcessError as e:
        print(f"Warning: pip download had issues: {e.stderr}")
        # Try alternative approach - export requirements and download
        try:
            # Export requirements from poetry if available
            poetry_cmd = ["poetry", "export", "-f", "requirements.txt", "--without-hashes"]
            result = subprocess.run(
                poetry_cmd, capture_output=True, text=True, cwd=project_root
            )
            if result.returncode == 0:
                req_file = output_dir / "requirements.txt"
                req_file.write_text(result.stdout)

                # Download from requirements
                pip_cmd = [
                    sys.executable, "-m", "pip", "download",
                    "--dest", str(output_dir),
                    "-r", str(req_file),
                ]
                subprocess.run(pip_cmd, check=True, cwd=project_root)
        except Exception as ex:
            print(f"Warning: Failed to export/download: {ex}")

    # Also build attestful wheel
    try:
        build_cmd = [sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(output_dir), str(project_root)]
        subprocess.run(build_cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Warning: Failed to build attestful wheel: {e.stderr}")

    return list(output_dir.glob("*.whl"))


def create_install_script() -> str:
    """Create the installation script content."""
    return '''#!/usr/bin/env python3
"""
Attestful Offline Installer.

Installs Attestful from bundled wheel files without network access.

Usage:
    python install.py [--prefix PREFIX] [--user] [--help]
"""

import argparse
import json
import os
import platform
import subprocess
import sys
from pathlib import Path


def get_python_version():
    """Get current Python version string."""
    return f"{sys.version_info.major}.{sys.version_info.minor}"


def check_python_version(required_version: str) -> bool:
    """Check if Python version meets requirements."""
    current = get_python_version()
    req_major, req_minor = map(int, required_version.split("."))
    cur_major, cur_minor = sys.version_info.major, sys.version_info.minor

    if cur_major != req_major:
        return False
    return cur_minor >= req_minor


def verify_checksums(wheels_dir: Path, checksums: dict[str, str]) -> list[str]:
    """Verify wheel file checksums."""
    import hashlib
    errors = []

    for filename, expected_hash in checksums.items():
        filepath = wheels_dir / filename
        if not filepath.exists():
            errors.append(f"Missing file: {filename}")
            continue

        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)

        actual_hash = sha256.hexdigest()
        if actual_hash != expected_hash:
            errors.append(f"Checksum mismatch for {filename}")

    return errors


def install_wheels(wheels_dir: Path, user: bool = False, prefix: str | None = None) -> bool:
    """Install all wheel files."""
    wheels = list(wheels_dir.glob("*.whl"))

    if not wheels:
        print("Error: No wheel files found")
        return False

    print(f"Installing {len(wheels)} packages...")

    # Build pip install command
    cmd = [sys.executable, "-m", "pip", "install", "--no-index", "--find-links", str(wheels_dir)]

    if user:
        cmd.append("--user")
    elif prefix:
        cmd.extend(["--prefix", prefix])

    # Install attestful (which will pull in dependencies from wheels_dir)
    attestful_wheels = [w for w in wheels if "attestful" in w.name.lower()]
    if attestful_wheels:
        cmd.append(str(attestful_wheels[0]))
    else:
        # Install all wheels
        cmd.extend(str(w) for w in wheels)

    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("Installation completed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Installation failed: {e.stderr}")
        return False


def init_attestful() -> bool:
    """Initialize Attestful after installation."""
    try:
        # Run attestful configure init
        result = subprocess.run(
            [sys.executable, "-m", "attestful", "configure", "init"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print("Attestful initialized successfully!")
            return True
        else:
            print(f"Warning: Initialization had issues: {result.stderr}")
            return False
    except Exception as e:
        print(f"Warning: Could not initialize: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Install Attestful from bundled wheels"
    )
    parser.add_argument(
        "--user",
        action="store_true",
        help="Install to user site-packages",
    )
    parser.add_argument(
        "--prefix",
        type=str,
        help="Install prefix path",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip checksum verification",
    )
    parser.add_argument(
        "--no-init",
        action="store_true",
        help="Skip Attestful initialization",
    )

    args = parser.parse_args()

    # Determine bundle directory
    script_dir = Path(__file__).parent.resolve()

    # Load manifest
    manifest_path = script_dir / "manifest.json"
    if not manifest_path.exists():
        print("Error: manifest.json not found")
        sys.exit(1)

    with open(manifest_path) as f:
        manifest = json.load(f)

    print(f"Attestful Offline Installer v{manifest['version']}")
    print(f"Built for Python {manifest['python_version']} on {manifest['platform']}")
    print()

    # Check Python version
    if not check_python_version(manifest["python_version"]):
        print(f"Error: Python {manifest['python_version']}+ required")
        print(f"Current version: {get_python_version()}")
        sys.exit(1)

    # Verify checksums
    wheels_dir = script_dir / "wheels"
    if not args.no_verify:
        print("Verifying package integrity...")
        errors = verify_checksums(wheels_dir, manifest.get("checksums", {}))
        if errors:
            print("Integrity check failed:")
            for error in errors:
                print(f"  - {error}")
            sys.exit(1)
        print("All packages verified!")
        print()

    # Install
    if not install_wheels(wheels_dir, user=args.user, prefix=args.prefix):
        sys.exit(1)

    # Initialize
    if not args.no_init:
        print()
        print("Initializing Attestful...")
        init_attestful()

    print()
    print("Installation complete!")
    print("Run 'attestful --help' to get started.")


if __name__ == "__main__":
    main()
'''


def create_readme() -> str:
    """Create README content for bundle."""
    return '''# Attestful Offline Installation Bundle

This bundle contains everything needed to install Attestful without
network access.

## Contents

- `install.py` - Installation script
- `manifest.json` - Bundle manifest with checksums
- `wheels/` - Python wheel packages
- `data/` - OSCAL catalogs and profiles (optional)
- `docs/` - Documentation (optional)

## Requirements

- Python 3.11 or higher
- pip (included with Python)

## Installation

### Quick Install (User)

```bash
python install.py --user
```

### System Install (requires sudo)

```bash
sudo python install.py
```

### Custom Prefix

```bash
python install.py --prefix /opt/attestful
```

## Options

- `--user` - Install to user site-packages
- `--prefix PATH` - Install to custom location
- `--no-verify` - Skip checksum verification
- `--no-init` - Skip post-install initialization

## Verification

The installer verifies all package checksums before installation.
To skip verification (not recommended):

```bash
python install.py --no-verify
```

## Post-Installation

After installation, initialize Attestful:

```bash
attestful configure init
```

## Troubleshooting

### Python version mismatch

This bundle was built for a specific Python version. If you see
version errors, you may need a bundle built for your Python version.

### Permission errors

Use `--user` for user installation or `sudo` for system installation.

### Missing dependencies

Ensure all wheel files in the `wheels/` directory are intact.
Re-download the bundle if files are corrupted.

## Support

For issues, visit: https://github.com/clay-good/attestful/issues
'''


class BundleCreator:
    """Creates offline installation bundles."""

    # Current bundle format version
    BUNDLE_VERSION = "1.0.0"

    def __init__(self, config: BundleConfig) -> None:
        """Initialize bundle creator."""
        self.config = config

    def create(self) -> Path:
        """Create the installation bundle."""
        print(f"Creating Attestful bundle...")
        print(f"  Python version: {self.config.python_version}")
        print(f"  Platform: {self.config.platform_tag}")
        print()

        with tempfile.TemporaryDirectory() as tmpdir:
            bundle_dir = Path(tmpdir) / "attestful-bundle"
            bundle_dir.mkdir()

            # Create subdirectories
            wheels_dir = bundle_dir / "wheels"
            wheels_dir.mkdir()

            # Download wheels
            wheel_files = download_wheels(
                self.config.project_root,
                wheels_dir,
                self.config.python_version,
            )
            print(f"Downloaded {len(wheel_files)} wheel files")

            # Calculate checksums
            checksums = {}
            total_size = 0
            for wheel_file in wheel_files:
                checksums[wheel_file.name] = calculate_sha256(wheel_file)
                total_size += wheel_file.stat().st_size

            # Copy OSCAL data if requested
            if self.config.include_oscal_catalogs:
                oscal_src = self.config.project_root / "data" / "oscal"
                if oscal_src.exists():
                    oscal_dst = bundle_dir / "data" / "oscal"
                    shutil.copytree(oscal_src, oscal_dst)
                    print("Included OSCAL catalogs")

            # Copy docs if requested
            if self.config.include_docs:
                docs_src = self.config.project_root / "docs"
                if docs_src.exists():
                    docs_dst = bundle_dir / "docs"
                    shutil.copytree(docs_src, docs_dst)
                    print("Included documentation")

            # Create manifest
            manifest = BundleManifest(
                version=self.BUNDLE_VERSION,
                created_at=datetime.now(timezone.utc).isoformat(),
                python_version=self.config.python_version,
                platform=platform.system(),
                platform_tag=self.config.platform_tag,
                attestful_version=get_attestful_version(self.config.project_root),
                wheel_count=len(wheel_files),
                total_size=total_size,
                checksums=checksums,
                metadata={
                    "include_oscal": self.config.include_oscal_catalogs,
                    "include_docs": self.config.include_docs,
                },
            )

            manifest_path = bundle_dir / "manifest.json"
            manifest_path.write_text(json.dumps(manifest.to_dict(), indent=2))

            # Create install script
            install_script = bundle_dir / "install.py"
            install_script.write_text(create_install_script())
            os.chmod(install_script, 0o755)

            # Create README
            readme = bundle_dir / "README.md"
            readme.write_text(create_readme())

            # Create tarball
            output_path = self.config.output_path
            compression = self.config.compression

            if compression == "none":
                mode = "w"
                if not str(output_path).endswith(".tar"):
                    output_path = Path(str(output_path).rsplit(".", 1)[0] + ".tar")
            else:
                mode = f"w:{compression}"

            print(f"Creating bundle: {output_path}")
            with tarfile.open(output_path, mode) as tar:
                tar.add(bundle_dir, arcname="attestful-bundle")

            bundle_size = output_path.stat().st_size
            print(f"Bundle created: {bundle_size / 1024 / 1024:.1f} MB")

            return output_path


def verify_bundle(bundle_path: Path) -> bool:
    """Verify a bundle's integrity."""
    print(f"Verifying bundle: {bundle_path}")

    if not bundle_path.exists():
        print("Error: Bundle file not found")
        return False

    with tempfile.TemporaryDirectory() as tmpdir:
        extract_dir = Path(tmpdir)

        # Extract bundle
        try:
            with tarfile.open(bundle_path, "r:*") as tar:
                tar.extractall(extract_dir)
        except Exception as e:
            print(f"Error extracting bundle: {e}")
            return False

        bundle_dir = extract_dir / "attestful-bundle"
        if not bundle_dir.exists():
            print("Error: Invalid bundle structure")
            return False

        # Load manifest
        manifest_path = bundle_dir / "manifest.json"
        if not manifest_path.exists():
            print("Error: Missing manifest.json")
            return False

        with open(manifest_path) as f:
            manifest_data = json.load(f)
            manifest = BundleManifest.from_dict(manifest_data)

        print(f"Bundle version: {manifest.version}")
        print(f"Attestful version: {manifest.attestful_version}")
        print(f"Python version: {manifest.python_version}")
        print(f"Platform: {manifest.platform}")
        print(f"Wheel count: {manifest.wheel_count}")
        print()

        # Verify checksums
        wheels_dir = bundle_dir / "wheels"
        errors = []

        for filename, expected_hash in manifest.checksums.items():
            filepath = wheels_dir / filename
            if not filepath.exists():
                errors.append(f"Missing: {filename}")
                continue

            actual_hash = calculate_sha256(filepath)
            if actual_hash != expected_hash:
                errors.append(f"Checksum mismatch: {filename}")

        if errors:
            print("Verification FAILED:")
            for error in errors:
                print(f"  - {error}")
            return False

        print(f"All {len(manifest.checksums)} packages verified!")
        return True


def main():
    parser = argparse.ArgumentParser(
        description="Attestful Bundle Creator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Create command
    create_parser = subparsers.add_parser("create", help="Create installation bundle")
    create_parser.add_argument(
        "-o", "--output",
        type=Path,
        default=Path("attestful-bundle.tar.gz"),
        help="Output bundle path",
    )
    create_parser.add_argument(
        "--compression",
        choices=["gz", "bz2", "xz", "none"],
        default="gz",
        help="Compression format",
    )
    create_parser.add_argument(
        "--python-version",
        default=f"{sys.version_info.major}.{sys.version_info.minor}",
        help="Target Python version",
    )
    create_parser.add_argument(
        "--no-oscal",
        action="store_true",
        help="Exclude OSCAL catalogs",
    )
    create_parser.add_argument(
        "--no-docs",
        action="store_true",
        help="Exclude documentation",
    )
    create_parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).parent.parent.parent,
        help="Project root directory",
    )

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify bundle integrity")
    verify_parser.add_argument("bundle", type=Path, help="Bundle file to verify")

    args = parser.parse_args()

    if args.command == "create":
        config = BundleConfig(
            output_path=args.output,
            compression=args.compression,
            python_version=args.python_version,
            include_oscal_catalogs=not args.no_oscal,
            include_docs=not args.no_docs,
            project_root=args.project_root.resolve(),
        )
        creator = BundleCreator(config)
        bundle_path = creator.create()
        print(f"\nBundle created: {bundle_path}")

    elif args.command == "verify":
        if verify_bundle(args.bundle):
            print("\nBundle verification passed!")
        else:
            print("\nBundle verification failed!")
            sys.exit(1)


if __name__ == "__main__":
    main()
