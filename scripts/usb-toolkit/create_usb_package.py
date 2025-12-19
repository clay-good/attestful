#!/usr/bin/env python3
"""
Attestful USB Deployment Toolkit Creator.

Creates a complete USB-based deployment package for air-gapped installations.
Includes installation bundles for multiple platforms, documentation, and
verification tools.

Usage:
    python create_usb_package.py --output /path/to/usb --platforms linux,darwin,windows
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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class USBPackageConfig:
    """Configuration for USB package creation."""

    output_dir: Path
    platforms: list[str] = field(default_factory=lambda: ["linux", "darwin", "windows"])
    python_versions: list[str] = field(default_factory=lambda: ["3.11", "3.12"])
    include_docker: bool = True
    include_docs: bool = True
    include_oscal_data: bool = True
    project_root: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent)


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
                parts = line.split("=", 1)
                if len(parts) == 2:
                    return parts[1].strip().strip('"').strip("'")
    return "0.1.0"


def create_checksums_file(directory: Path, output_file: Path) -> dict[str, str]:
    """Create checksums file for all files in directory."""
    checksums = {}

    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.name != "CHECKSUMS.sha256":
            relative_path = path.relative_to(directory)
            checksums[str(relative_path)] = calculate_sha256(path)

    # Write checksums file
    with open(output_file, "w") as f:
        for filepath, checksum in sorted(checksums.items()):
            f.write(f"{checksum}  {filepath}\n")

    return checksums


def create_autorun_script() -> str:
    """Create cross-platform autorun script."""
    return '''#!/usr/bin/env bash
#
# Attestful USB Installation Launcher
#
# This script automatically detects the platform and launches
# the appropriate installer.

set -e

# Determine script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Detect platform
detect_platform() {
    case "$(uname -s)" in
        Linux*)     echo "linux" ;;
        Darwin*)    echo "darwin" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *)          echo "unknown" ;;
    esac
}

# Main
main() {
    echo "=========================================="
    echo "  Attestful USB Installation Launcher"
    echo "=========================================="
    echo ""

    PLATFORM=$(detect_platform)
    echo "Detected platform: $PLATFORM"

    case "$PLATFORM" in
        linux|darwin)
            if [ -f "$SCRIPT_DIR/install/$PLATFORM/install.sh" ]; then
                exec "$SCRIPT_DIR/install/$PLATFORM/install.sh" "$@"
            else
                echo "Error: Installer not found for $PLATFORM"
                exit 1
            fi
            ;;
        windows)
            echo "On Windows, please run install\\\\windows\\\\install.bat"
            ;;
        *)
            echo "Error: Unknown platform"
            echo "Please manually run the appropriate installer from the install/ directory"
            exit 1
            ;;
    esac
}

main "$@"
'''


def create_windows_installer() -> str:
    """Create Windows batch installer."""
    return '''@echo off
REM Attestful Windows Installer
REM
REM Run as Administrator for system-wide installation
REM Run as user for user-local installation

setlocal enabledelayedexpansion

echo ==========================================
echo   Attestful Windows Installer
echo ==========================================
echo.

REM Detect Python
set PYTHON_CMD=
for %%p in (python3.12 python3.11 python3 python) do (
    where %%p >nul 2>&1
    if !errorlevel! equ 0 (
        set PYTHON_CMD=%%p
        goto :found_python
    )
)

echo Error: Python 3.11+ not found
echo Please install Python from https://python.org
pause
exit /b 1

:found_python
echo Found Python: %PYTHON_CMD%

REM Get script directory
set SCRIPT_DIR=%~dp0

REM Check for bundle
set BUNDLE_DIR=%SCRIPT_DIR%bundle

if not exist "%BUNDLE_DIR%" (
    echo Error: Bundle directory not found
    pause
    exit /b 1
)

REM Run Python installer
echo.
echo Running installer...
%PYTHON_CMD% "%BUNDLE_DIR%\\install.py" --user %*

if !errorlevel! neq 0 (
    echo.
    echo Installation failed
    pause
    exit /b 1
)

echo.
echo Installation complete!
echo Run 'attestful --help' to get started.
pause
'''


def create_linux_installer() -> str:
    """Create Linux shell installer."""
    return '''#!/usr/bin/env bash
#
# Attestful Linux Installer
#
# Usage:
#   ./install.sh [--user|--prefix PATH]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="$SCRIPT_DIR/bundle"

echo "=========================================="
echo "  Attestful Linux Installer"
echo "=========================================="
echo ""

# Detect Python
PYTHON_CMD=""
for cmd in python3.12 python3.11 python3; do
    if command -v "$cmd" &> /dev/null; then
        version=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        major=$(echo "$version" | cut -d. -f1)
        minor=$(echo "$version" | cut -d. -f2)
        if [ "$major" -eq 3 ] && [ "$minor" -ge 11 ]; then
            PYTHON_CMD="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo "Error: Python 3.11+ not found"
    echo "Please install Python 3.11 or higher"
    exit 1
fi

echo "Using Python: $PYTHON_CMD ($("$PYTHON_CMD" --version))"

# Check bundle
if [ ! -d "$BUNDLE_DIR" ]; then
    echo "Error: Bundle directory not found"
    exit 1
fi

# Run Python installer
echo ""
"$PYTHON_CMD" "$BUNDLE_DIR/install.py" "$@"

echo ""
echo "Installation complete!"
echo "Run 'attestful --help' to get started."
'''


def create_macos_installer() -> str:
    """Create macOS shell installer."""
    return '''#!/usr/bin/env bash
#
# Attestful macOS Installer
#
# Usage:
#   ./install.sh [--user|--prefix PATH]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="$SCRIPT_DIR/bundle"

echo "=========================================="
echo "  Attestful macOS Installer"
echo "=========================================="
echo ""

# Detect Python (prefer Homebrew, then system)
PYTHON_CMD=""
for cmd in /opt/homebrew/bin/python3.12 /opt/homebrew/bin/python3.11 \
           /usr/local/bin/python3.12 /usr/local/bin/python3.11 \
           python3.12 python3.11 python3; do
    if command -v "$cmd" &> /dev/null; then
        version=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
        major=$(echo "$version" | cut -d. -f1)
        minor=$(echo "$version" | cut -d. -f2)
        if [ "$major" -eq 3 ] && [ "$minor" -ge 11 ]; then
            PYTHON_CMD="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo "Error: Python 3.11+ not found"
    echo ""
    echo "Install Python using Homebrew:"
    echo "  brew install python@3.11"
    exit 1
fi

echo "Using Python: $PYTHON_CMD ($("$PYTHON_CMD" --version))"

# Check bundle
if [ ! -d "$BUNDLE_DIR" ]; then
    echo "Error: Bundle directory not found"
    exit 1
fi

# Run Python installer
echo ""
"$PYTHON_CMD" "$BUNDLE_DIR/install.py" "$@"

echo ""
echo "Installation complete!"
echo "Run 'attestful --help' to get started."
'''


def create_verification_script() -> str:
    """Create package verification script."""
    return '''#!/usr/bin/env python3
"""
Attestful USB Package Verification Tool.

Verifies the integrity of all files in the USB package.
"""

import hashlib
import sys
from pathlib import Path


def verify_checksums(base_dir: Path) -> bool:
    """Verify all checksums in the package."""
    checksums_file = base_dir / "CHECKSUMS.sha256"

    if not checksums_file.exists():
        print("Error: CHECKSUMS.sha256 not found")
        return False

    errors = []
    verified = 0

    with open(checksums_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split("  ", 1)
            if len(parts) != 2:
                continue

            expected_hash, filepath = parts
            full_path = base_dir / filepath

            if not full_path.exists():
                errors.append(f"Missing: {filepath}")
                continue

            sha256 = hashlib.sha256()
            with open(full_path, "rb") as file:
                for chunk in iter(lambda: file.read(8192), b""):
                    sha256.update(chunk)

            if sha256.hexdigest() != expected_hash:
                errors.append(f"Checksum mismatch: {filepath}")
            else:
                verified += 1

    print(f"Verified: {verified} files")

    if errors:
        print(f"\\nErrors: {len(errors)}")
        for error in errors:
            print(f"  - {error}")
        return False

    print("\\nAll files verified successfully!")
    return True


def main():
    base_dir = Path(__file__).parent.resolve()
    print("Attestful USB Package Verification")
    print("=" * 40)
    print(f"Package directory: {base_dir}")
    print()

    if not verify_checksums(base_dir):
        sys.exit(1)


if __name__ == "__main__":
    main()
'''


class USBPackageCreator:
    """Creates USB deployment packages."""

    def __init__(self, config: USBPackageConfig) -> None:
        """Initialize USB package creator."""
        self.config = config

    def create(self) -> Path:
        """Create the USB deployment package."""
        print("Creating Attestful USB Deployment Package")
        print("=" * 50)
        print()

        output_dir = self.config.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)

        # Create directory structure
        self._create_directory_structure(output_dir)

        # Create autorun script
        autorun_path = output_dir / "autorun.sh"
        autorun_path.write_text(create_autorun_script())
        os.chmod(autorun_path, 0o755)
        print("Created: autorun.sh")

        # Create platform-specific installers
        self._create_platform_installers(output_dir)

        # Copy documentation
        if self.config.include_docs:
            self._copy_documentation(output_dir)

        # Copy OSCAL data
        if self.config.include_oscal_data:
            self._copy_oscal_data(output_dir)

        # Copy Docker images if requested
        if self.config.include_docker:
            self._copy_docker_files(output_dir)

        # Create verification script
        verify_script = output_dir / "verify.py"
        verify_script.write_text(create_verification_script())
        os.chmod(verify_script, 0o755)
        print("Created: verify.py")

        # Create manifest
        self._create_manifest(output_dir)

        # Create README
        self._create_readme(output_dir)

        # Generate checksums (must be last)
        checksums_file = output_dir / "CHECKSUMS.sha256"
        checksums = create_checksums_file(output_dir, checksums_file)
        print(f"Created: CHECKSUMS.sha256 ({len(checksums)} files)")

        print()
        print(f"USB package created: {output_dir}")
        return output_dir

    def _create_directory_structure(self, output_dir: Path) -> None:
        """Create directory structure."""
        directories = [
            "install/linux/bundle",
            "install/darwin/bundle",
            "install/windows/bundle",
            "data/oscal",
            "docker",
            "docs",
        ]

        for dir_path in directories:
            (output_dir / dir_path).mkdir(parents=True, exist_ok=True)

    def _create_platform_installers(self, output_dir: Path) -> None:
        """Create platform-specific installers."""
        # Linux
        linux_dir = output_dir / "install" / "linux"
        linux_installer = linux_dir / "install.sh"
        linux_installer.write_text(create_linux_installer())
        os.chmod(linux_installer, 0o755)
        print("Created: install/linux/install.sh")

        # macOS (darwin)
        darwin_dir = output_dir / "install" / "darwin"
        darwin_installer = darwin_dir / "install.sh"
        darwin_installer.write_text(create_macos_installer())
        os.chmod(darwin_installer, 0o755)
        print("Created: install/darwin/install.sh")

        # Windows
        windows_dir = output_dir / "install" / "windows"
        windows_installer = windows_dir / "install.bat"
        windows_installer.write_text(create_windows_installer())
        print("Created: install/windows/install.bat")

    def _copy_documentation(self, output_dir: Path) -> None:
        """Copy documentation files."""
        docs_src = self.config.project_root / "docs"
        docs_dst = output_dir / "docs"

        if docs_src.exists():
            shutil.copytree(docs_src, docs_dst, dirs_exist_ok=True)
            print("Copied: documentation")

        # Also copy README
        readme_src = self.config.project_root / "README.md"
        if readme_src.exists():
            shutil.copy2(readme_src, output_dir / "docs" / "README.md")

    def _copy_oscal_data(self, output_dir: Path) -> None:
        """Copy OSCAL catalogs and profiles."""
        oscal_src = self.config.project_root / "data" / "oscal"
        oscal_dst = output_dir / "data" / "oscal"

        if oscal_src.exists():
            shutil.copytree(oscal_src, oscal_dst, dirs_exist_ok=True)
            print("Copied: OSCAL data")

    def _copy_docker_files(self, output_dir: Path) -> None:
        """Copy Docker configuration files."""
        docker_src = self.config.project_root / "docker"
        docker_dst = output_dir / "docker"

        if docker_src.exists():
            shutil.copytree(docker_src, docker_dst, dirs_exist_ok=True)
            print("Copied: Docker configuration")

    def _create_manifest(self, output_dir: Path) -> None:
        """Create package manifest."""
        manifest = {
            "version": "1.0.0",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "attestful_version": get_attestful_version(self.config.project_root),
            "platforms": self.config.platforms,
            "python_versions": self.config.python_versions,
            "contents": {
                "installers": True,
                "documentation": self.config.include_docs,
                "oscal_data": self.config.include_oscal_data,
                "docker": self.config.include_docker,
            },
        }

        manifest_path = output_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))
        print("Created: manifest.json")

    def _create_readme(self, output_dir: Path) -> None:
        """Create USB package README."""
        readme_content = f'''# Attestful USB Deployment Package

This USB package contains everything needed to install Attestful
in an air-gapped environment.

## Contents

- `autorun.sh` - Cross-platform installation launcher
- `verify.py` - Package integrity verification tool
- `install/` - Platform-specific installers
  - `linux/` - Linux installer and bundles
  - `darwin/` - macOS installer and bundles
  - `windows/` - Windows installer and bundles
- `data/` - OSCAL catalogs and compliance data
- `docker/` - Docker configuration files
- `docs/` - Documentation

## Quick Start

### Linux/macOS

```bash
./autorun.sh --user
```

### Windows

Run `install\\windows\\install.bat` as Administrator.

## Verification

Before installation, verify package integrity:

```bash
python3 verify.py
```

## Manual Installation

If the autorun script doesn't work:

1. Navigate to the appropriate platform directory
2. Run the installer script
3. Follow the prompts

## Docker Deployment

For Docker-based deployment:

```bash
cd docker
docker compose -f docker-compose.yml -f docker-compose.airgap.yml up -d
```

## Created

{datetime.now(timezone.utc).isoformat()}

## Version

Attestful {get_attestful_version(self.config.project_root)}
'''

        readme_path = output_dir / "README.md"
        readme_path.write_text(readme_content)
        print("Created: README.md")


def main():
    parser = argparse.ArgumentParser(
        description="Create Attestful USB deployment package"
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        required=True,
        help="Output directory for USB package",
    )
    parser.add_argument(
        "--platforms",
        type=str,
        default="linux,darwin,windows",
        help="Platforms to include (comma-separated)",
    )
    parser.add_argument(
        "--python-versions",
        type=str,
        default="3.11,3.12",
        help="Python versions to support (comma-separated)",
    )
    parser.add_argument(
        "--no-docker",
        action="store_true",
        help="Exclude Docker files",
    )
    parser.add_argument(
        "--no-docs",
        action="store_true",
        help="Exclude documentation",
    )
    parser.add_argument(
        "--no-oscal",
        action="store_true",
        help="Exclude OSCAL data",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).parent.parent.parent,
        help="Project root directory",
    )

    args = parser.parse_args()

    config = USBPackageConfig(
        output_dir=args.output.resolve(),
        platforms=args.platforms.split(","),
        python_versions=args.python_versions.split(","),
        include_docker=not args.no_docker,
        include_docs=not args.no_docs,
        include_oscal_data=not args.no_oscal,
        project_root=args.project_root.resolve(),
    )

    creator = USBPackageCreator(config)
    creator.create()


if __name__ == "__main__":
    main()
