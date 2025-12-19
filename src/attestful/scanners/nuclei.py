"""
Nuclei scanner wrapper for web application vulnerability scanning.
"""

import json
import subprocess
from typing import Any

from attestful.core.logging import get_logger

logger = get_logger(__name__)


class NucleiScanner:
    """Wrapper for Nuclei vulnerability scanner."""

    def __init__(self, nuclei_path: str = "nuclei", skip_install_check: bool = False):
        """
        Initialize Nuclei scanner.

        Args:
            nuclei_path: Path to nuclei executable (default: "nuclei" from PATH)
            skip_install_check: Skip checking if Nuclei is installed (for testing)
        """
        self.nuclei_path = nuclei_path
        if not skip_install_check:
            self._check_nuclei_installed()

    def _check_nuclei_installed(self) -> None:
        """Check if Nuclei is installed and accessible."""
        try:
            result = subprocess.run(
                [self.nuclei_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                raise RuntimeError(f"Nuclei not found at {self.nuclei_path}")
            logger.info(f"Nuclei version: {result.stdout.strip()}")
        except FileNotFoundError:
            raise RuntimeError(
                "Nuclei not found. Please install Nuclei: https://github.com/projectdiscovery/nuclei"
            ) from None
        except subprocess.TimeoutExpired:
            raise RuntimeError("Nuclei version check timed out") from None

    def scan_target(
        self,
        target: str,
        templates: list[str] | None = None,
        severity: list[str] | None = None,
        tags: list[str] | None = None,
        timeout: int = 600,
    ) -> list[dict[str, Any]]:
        """
        Scan a target URL for vulnerabilities.

        Args:
            target: Target URL (e.g., "https://example.com")
            templates: List of template paths or IDs to use
            severity: List of severities to include (e.g., ["critical", "high"])
            tags: List of tags to filter templates (e.g., ["cve", "owasp"])
            timeout: Scan timeout in seconds (default: 600)

        Returns:
            List of vulnerability dictionaries in Nuclei JSON format

        Raises:
            RuntimeError: If scan fails
        """
        cmd = [
            self.nuclei_path,
            "-target",
            target,
            "-json",
            "-silent",
        ]

        if templates:
            for template in templates:
                cmd.extend(["-t", template])

        if severity:
            cmd.extend(["-severity", ",".join(severity)])

        if tags:
            cmd.extend(["-tags", ",".join(tags)])

        logger.info(f"Scanning target: {target}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            # Nuclei outputs one JSON object per line
            vulnerabilities = []
            if result.stdout:
                for line in result.stdout.strip().split("\n"):
                    if line:
                        try:
                            vuln = json.loads(line)
                            vulnerabilities.append(vuln)
                        except json.JSONDecodeError:
                            logger.warning(f"Failed to parse Nuclei output line: {line}")

            logger.info(
                f"Scan completed for target: {target}, found {len(vulnerabilities)} vulnerabilities"
            )
            return vulnerabilities

        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Nuclei scan timed out after {timeout} seconds") from None

    def scan_targets(
        self,
        targets: list[str],
        templates: list[str] | None = None,
        severity: list[str] | None = None,
        tags: list[str] | None = None,
        timeout: int = 600,
    ) -> list[dict[str, Any]]:
        """
        Scan multiple targets for vulnerabilities.

        Args:
            targets: List of target URLs
            templates: List of template paths or IDs to use
            severity: List of severities to include
            tags: List of tags to filter templates
            timeout: Scan timeout in seconds

        Returns:
            List of vulnerability dictionaries

        Raises:
            RuntimeError: If scan fails
        """
        cmd = [
            self.nuclei_path,
            "-json",
            "-silent",
        ]

        # Add targets
        for target in targets:
            cmd.extend(["-target", target])

        if templates:
            for template in templates:
                cmd.extend(["-t", template])

        if severity:
            cmd.extend(["-severity", ",".join(severity)])

        if tags:
            cmd.extend(["-tags", ",".join(tags)])

        logger.info(f"Scanning {len(targets)} targets")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            vulnerabilities = []
            if result.stdout:
                for line in result.stdout.strip().split("\n"):
                    if line:
                        try:
                            vuln = json.loads(line)
                            vulnerabilities.append(vuln)
                        except json.JSONDecodeError:
                            logger.warning(f"Failed to parse Nuclei output line: {line}")

            logger.info(f"Scan completed, found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities

        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Nuclei scan timed out after {timeout} seconds") from None

    def update_templates(self) -> bool:
        """
        Update Nuclei templates to the latest version.

        Returns:
            True if update successful, False otherwise
        """
        try:
            result = subprocess.run(
                [self.nuclei_path, "-update-templates"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode == 0:
                logger.info("Nuclei templates updated successfully")
                return True
            else:
                logger.error(f"Failed to update Nuclei templates: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Failed to update Nuclei templates: {e}")
            return False

    def list_templates(self, tags: list[str] | None = None) -> list[str]:
        """
        List available Nuclei templates.

        Args:
            tags: Optional list of tags to filter templates

        Returns:
            List of template IDs
        """
        cmd = [self.nuclei_path, "-tl"]

        if tags:
            cmd.extend(["-tags", ",".join(tags)])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                templates = [line.strip() for line in result.stdout.split("\n") if line.strip()]
                return templates
            else:
                logger.error(f"Failed to list templates: {result.stderr}")
                return []
        except Exception as e:
            logger.error(f"Failed to list templates: {e}")
            return []

    def get_version(self) -> str:
        """
        Get Nuclei version.

        Returns:
            Nuclei version string
        """
        try:
            result = subprocess.run(
                [self.nuclei_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout.strip()
        except Exception as e:
            logger.error(f"Failed to get Nuclei version: {e}")
            return "unknown"
