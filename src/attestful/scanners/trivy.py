"""
Trivy scanner wrapper for container and IaC vulnerability scanning.

Migrated from Compliy (Step 4.2.10 of instructions.txt).
"""

import json
import subprocess
from typing import Any

from attestful.core.logging import get_logger

logger = get_logger(__name__)


class TrivyScanner:
    """Wrapper for Trivy vulnerability scanner."""

    def __init__(self, trivy_path: str = "trivy", skip_install_check: bool = False):
        """
        Initialize Trivy scanner.

        Args:
            trivy_path: Path to trivy executable (default: "trivy" from PATH)
            skip_install_check: Skip checking if Trivy is installed (for testing)
        """
        self.trivy_path = trivy_path
        if not skip_install_check:
            self._check_trivy_installed()

    def _check_trivy_installed(self) -> None:
        """Check if Trivy is installed and accessible."""
        try:
            result = subprocess.run(
                [self.trivy_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                raise RuntimeError(f"Trivy not found at {self.trivy_path}")
            logger.info(f"Trivy version: {result.stdout.strip()}")
        except FileNotFoundError:
            raise RuntimeError(
                "Trivy not found. Please install Trivy: https://aquasecurity.github.io/trivy/"
            ) from None
        except subprocess.TimeoutExpired:
            raise RuntimeError("Trivy version check timed out") from None

    def scan_image(
        self,
        image: str,
        severity: list[str] | None = None,
        timeout: int = 300,
    ) -> dict[str, Any]:
        """
        Scan a container image for vulnerabilities.

        Args:
            image: Container image name (e.g., "python:3.9-alpine")
            severity: List of severities to include (e.g., ["CRITICAL", "HIGH"])
            timeout: Scan timeout in seconds (default: 300)

        Returns:
            Dict containing scan results in Trivy JSON format

        Raises:
            RuntimeError: If scan fails
        """
        cmd = [
            self.trivy_path,
            "image",
            "--format",
            "json",
            "--quiet",
        ]

        if severity:
            cmd.extend(["--severity", ",".join(severity)])

        cmd.append(image)

        logger.info(f"Scanning image: {image}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode != 0:
                error_msg = result.stderr or result.stdout
                raise RuntimeError(f"Trivy scan failed: {error_msg}")

            scan_results = json.loads(result.stdout)
            logger.info(f"Scan completed for image: {image}")
            return scan_results

        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Trivy scan timed out after {timeout} seconds") from None
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse Trivy output: {e}") from e

    def scan_filesystem(
        self,
        path: str,
        severity: list[str] | None = None,
        timeout: int = 300,
    ) -> dict[str, Any]:
        """
        Scan a filesystem path for vulnerabilities.

        Args:
            path: Filesystem path to scan
            severity: List of severities to include
            timeout: Scan timeout in seconds

        Returns:
            Dict containing scan results in Trivy JSON format

        Raises:
            RuntimeError: If scan fails
        """
        cmd = [
            self.trivy_path,
            "fs",
            "--format",
            "json",
            "--quiet",
        ]

        if severity:
            cmd.extend(["--severity", ",".join(severity)])

        cmd.append(path)

        logger.info(f"Scanning filesystem: {path}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode != 0:
                error_msg = result.stderr or result.stdout
                raise RuntimeError(f"Trivy scan failed: {error_msg}")

            scan_results = json.loads(result.stdout)
            logger.info(f"Scan completed for path: {path}")
            return scan_results

        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Trivy scan timed out after {timeout} seconds") from None
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse Trivy output: {e}") from e

    def scan_config(
        self,
        path: str,
        severity: list[str] | None = None,
        timeout: int = 300,
    ) -> dict[str, Any]:
        """
        Scan IaC configuration files for misconfigurations.

        Args:
            path: Path to IaC files (Terraform, CloudFormation, K8s, etc.)
            severity: List of severities to include
            timeout: Scan timeout in seconds

        Returns:
            Dict containing scan results in Trivy JSON format

        Raises:
            RuntimeError: If scan fails
        """
        cmd = [
            self.trivy_path,
            "config",
            "--format",
            "json",
            "--quiet",
        ]

        if severity:
            cmd.extend(["--severity", ",".join(severity)])

        cmd.append(path)

        logger.info(f"Scanning IaC config: {path}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode != 0:
                error_msg = result.stderr or result.stdout
                raise RuntimeError(f"Trivy scan failed: {error_msg}")

            scan_results = json.loads(result.stdout)
            logger.info(f"Scan completed for config: {path}")
            return scan_results

        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Trivy scan timed out after {timeout} seconds") from None
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse Trivy output: {e}") from e

    def get_version(self) -> str:
        """
        Get Trivy version.

        Returns:
            Trivy version string
        """
        try:
            result = subprocess.run(
                [self.trivy_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout.strip()
        except Exception as e:
            logger.error(f"Failed to get Trivy version: {e}")
            return "unknown"
