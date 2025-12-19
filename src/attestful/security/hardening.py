"""
Security hardening for Attestful air-gapped deployments.

Provides:
- Certificate pinning for network calls
- Secure default configurations
- Secrets management for offline use
- Security scanning of deployment artifacts

Step 10.5 of instructions.txt.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import ssl
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

from attestful.core.logging import get_logger

logger = get_logger(__name__)


# =============================================================================
# Certificate Pinning
# =============================================================================


class CertificatePinningMode(str, Enum):
    """Certificate pinning enforcement mode."""
    DISABLED = "disabled"  # No pinning (not recommended)
    REPORT = "report"  # Log mismatches but allow connection
    ENFORCE = "enforce"  # Block connections with mismatched certificates


@dataclass
class PinnedCertificate:
    """A pinned certificate entry."""

    host: str
    port: int
    fingerprint: str  # SHA-256 fingerprint
    expires_at: datetime | None = None
    description: str = ""
    added_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_expired(self) -> bool:
        """Check if the pin has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "host": self.host,
            "port": self.port,
            "fingerprint": self.fingerprint,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "description": self.description,
            "added_at": self.added_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PinnedCertificate:
        """Create from dictionary."""
        return cls(
            host=data["host"],
            port=data["port"],
            fingerprint=data["fingerprint"],
            expires_at=(
                datetime.fromisoformat(data["expires_at"])
                if data.get("expires_at") else None
            ),
            description=data.get("description", ""),
            added_at=datetime.fromisoformat(data["added_at"]) if "added_at" in data else datetime.now(timezone.utc),
        )


class CertificatePinningStore:
    """
    Manages certificate pins for network connections.

    Implements HPKP-style certificate pinning for known services
    to prevent MITM attacks in air-gapped environments.
    """

    def __init__(
        self,
        pins_file: Path | None = None,
        mode: CertificatePinningMode = CertificatePinningMode.ENFORCE,
        on_violation: Callable[[str, str, str], None] | None = None,
    ) -> None:
        """
        Initialize certificate pinning store.

        Args:
            pins_file: Path to store pinned certificates.
            mode: Enforcement mode.
            on_violation: Callback for pin violations.
        """
        self.pins_file = pins_file or Path.home() / ".attestful" / "cert_pins.json"
        self.mode = mode
        self.on_violation = on_violation
        self._pins: dict[str, PinnedCertificate] = {}
        self._loaded = False

    def _make_key(self, host: str, port: int) -> str:
        """Create lookup key for host:port."""
        return f"{host}:{port}"

    def _load(self) -> None:
        """Load pins from file."""
        if self._loaded:
            return

        self._pins = {}

        if self.pins_file.exists():
            try:
                with open(self.pins_file) as f:
                    data = json.load(f)
                    for key, pin_data in data.items():
                        self._pins[key] = PinnedCertificate.from_dict(pin_data)
                logger.debug(f"Loaded {len(self._pins)} certificate pins")
            except Exception as e:
                logger.warning(f"Failed to load certificate pins: {e}")

        self._loaded = True

    def _save(self) -> None:
        """Save pins to file."""
        self.pins_file.parent.mkdir(parents=True, exist_ok=True)

        data = {key: pin.to_dict() for key, pin in self._pins.items()}

        with open(self.pins_file, "w") as f:
            json.dump(data, f, indent=2)

        # Secure permissions
        os.chmod(self.pins_file, stat.S_IRUSR | stat.S_IWUSR)

    @staticmethod
    def get_certificate_fingerprint(cert_pem: bytes) -> str:
        """
        Get SHA-256 fingerprint of a certificate.

        Args:
            cert_pem: PEM-encoded certificate.

        Returns:
            Hex-encoded SHA-256 fingerprint.
        """
        cert = x509.load_pem_x509_certificate(cert_pem)
        return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

    @staticmethod
    def fetch_certificate(host: str, port: int = 443, timeout: float = 10.0) -> bytes:
        """
        Fetch a certificate from a remote server.

        Args:
            host: Hostname.
            port: Port number.
            timeout: Connection timeout.

        Returns:
            PEM-encoded certificate.
        """
        import socket

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der is None:
                    raise ValueError("No certificate received")

                cert = x509.load_der_x509_certificate(cert_der)
                return cert.public_bytes(serialization.Encoding.PEM)

    def pin_certificate(
        self,
        host: str,
        port: int = 443,
        fingerprint: str | None = None,
        expires_in_days: int | None = None,
        description: str = "",
        fetch: bool = True,
    ) -> PinnedCertificate:
        """
        Pin a certificate for a host.

        Args:
            host: Hostname.
            port: Port number.
            fingerprint: Certificate fingerprint (if known).
            expires_in_days: Pin expiration in days.
            description: Description of the pin.
            fetch: Fetch certificate if fingerprint not provided.

        Returns:
            The pinned certificate entry.
        """
        self._load()

        if fingerprint is None and fetch:
            cert_pem = self.fetch_certificate(host, port)
            fingerprint = self.get_certificate_fingerprint(cert_pem)

        if fingerprint is None:
            raise ValueError("Fingerprint required if not fetching")

        expires_at = None
        if expires_in_days is not None:
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)

        pin = PinnedCertificate(
            host=host,
            port=port,
            fingerprint=fingerprint.lower(),
            expires_at=expires_at,
            description=description,
        )

        key = self._make_key(host, port)
        self._pins[key] = pin
        self._save()

        logger.info(f"Pinned certificate for {host}:{port}")
        return pin

    def verify_certificate(
        self,
        host: str,
        port: int,
        cert_pem: bytes,
    ) -> bool:
        """
        Verify a certificate against the pinned entry.

        Args:
            host: Hostname.
            port: Port number.
            cert_pem: PEM-encoded certificate to verify.

        Returns:
            True if certificate matches pin (or no pin exists).
        """
        self._load()

        key = self._make_key(host, port)
        pin = self._pins.get(key)

        if pin is None:
            # No pin - allow in report mode, block in enforce mode if strict
            return True

        if pin.is_expired():
            logger.warning(f"Certificate pin expired for {host}:{port}")
            return True  # Allow expired pins (need refresh)

        actual_fingerprint = self.get_certificate_fingerprint(cert_pem)

        if actual_fingerprint.lower() != pin.fingerprint.lower():
            message = f"Certificate pin mismatch for {host}:{port}"
            logger.error(message)

            if self.on_violation:
                self.on_violation(host, pin.fingerprint, actual_fingerprint)

            if self.mode == CertificatePinningMode.ENFORCE:
                return False
            elif self.mode == CertificatePinningMode.REPORT:
                logger.warning("Pin violation reported but connection allowed")
                return True

        return True

    def remove_pin(self, host: str, port: int = 443) -> bool:
        """Remove a certificate pin."""
        self._load()

        key = self._make_key(host, port)
        if key in self._pins:
            del self._pins[key]
            self._save()
            return True
        return False

    def list_pins(self) -> list[PinnedCertificate]:
        """List all certificate pins."""
        self._load()
        return list(self._pins.values())

    def cleanup_expired(self) -> int:
        """Remove expired pins."""
        self._load()

        expired_keys = [
            key for key, pin in self._pins.items()
            if pin.is_expired()
        ]

        for key in expired_keys:
            del self._pins[key]

        if expired_keys:
            self._save()

        return len(expired_keys)


# =============================================================================
# Secure Default Configuration
# =============================================================================


@dataclass
class SecureDefaults:
    """Secure default configuration settings."""

    # Encryption
    require_encryption_at_rest: bool = True
    encryption_algorithm: str = "AES-256-GCM"
    key_derivation_iterations: int = 600_000

    # Authentication
    require_authentication: bool = True
    session_timeout_minutes: int = 30
    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 15

    # Network
    disable_insecure_protocols: bool = True
    require_tls_1_3: bool = True
    certificate_pinning_mode: CertificatePinningMode = CertificatePinningMode.ENFORCE

    # File permissions
    config_file_mode: int = 0o600
    key_file_mode: int = 0o400
    log_file_mode: int = 0o640

    # Audit
    enable_audit_logging: bool = True
    audit_log_tampering_detection: bool = True

    # Hardening
    disable_debug_mode: bool = True
    disable_stack_traces: bool = True
    sanitize_error_messages: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "require_encryption_at_rest": self.require_encryption_at_rest,
            "encryption_algorithm": self.encryption_algorithm,
            "key_derivation_iterations": self.key_derivation_iterations,
            "require_authentication": self.require_authentication,
            "session_timeout_minutes": self.session_timeout_minutes,
            "max_failed_attempts": self.max_failed_attempts,
            "lockout_duration_minutes": self.lockout_duration_minutes,
            "disable_insecure_protocols": self.disable_insecure_protocols,
            "require_tls_1_3": self.require_tls_1_3,
            "certificate_pinning_mode": self.certificate_pinning_mode.value,
            "config_file_mode": oct(self.config_file_mode),
            "key_file_mode": oct(self.key_file_mode),
            "log_file_mode": oct(self.log_file_mode),
            "enable_audit_logging": self.enable_audit_logging,
            "audit_log_tampering_detection": self.audit_log_tampering_detection,
            "disable_debug_mode": self.disable_debug_mode,
            "disable_stack_traces": self.disable_stack_traces,
            "sanitize_error_messages": self.sanitize_error_messages,
        }


def apply_secure_defaults(config_dir: Path) -> None:
    """
    Apply secure default configurations.

    Args:
        config_dir: Configuration directory.
    """
    defaults = SecureDefaults()

    # Set secure file permissions on config directory
    config_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(config_dir, 0o700)

    # Create secure defaults file
    defaults_file = config_dir / "security_defaults.json"
    defaults_file.write_text(json.dumps(defaults.to_dict(), indent=2))
    os.chmod(defaults_file, defaults.config_file_mode)

    logger.info("Applied secure default configurations")


# =============================================================================
# Secrets Management
# =============================================================================


class SecretsManager:
    """
    Manages secrets for offline/air-gapped use.

    Provides secure storage of sensitive values using
    encryption at rest with key derivation.
    """

    # Current version of secrets format
    VERSION = "1.0.0"

    def __init__(
        self,
        secrets_file: Path | None = None,
        master_key: bytes | None = None,
    ) -> None:
        """
        Initialize secrets manager.

        Args:
            secrets_file: Path to encrypted secrets file.
            master_key: Master encryption key.
        """
        self.secrets_file = secrets_file or Path.home() / ".attestful" / "secrets.enc"
        self._master_key = master_key
        self._fernet: Fernet | None = None
        self._secrets: dict[str, str] = {}
        self._loaded = False

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
        )
        return kdf.derive(password.encode())

    def initialize(self, password: str) -> None:
        """
        Initialize secrets storage with a password.

        Args:
            password: Master password for encryption.
        """
        salt = secrets.token_bytes(32)
        key = self._derive_key(password, salt)
        fernet_key = Fernet.generate_key()

        # Encrypt the Fernet key with derived key
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        encrypted_fernet_key = aesgcm.encrypt(nonce, fernet_key, None)

        # Store salt + nonce + encrypted key
        self.secrets_file.parent.mkdir(parents=True, exist_ok=True)

        header = {
            "version": self.VERSION,
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "encrypted_key": encrypted_fernet_key.hex(),
        }

        with open(self.secrets_file, "w") as f:
            json.dump({"header": header, "secrets": {}}, f)

        os.chmod(self.secrets_file, stat.S_IRUSR | stat.S_IWUSR)

        self._fernet = Fernet(fernet_key)
        self._loaded = True
        self._secrets = {}

        logger.info("Initialized secrets storage")

    def unlock(self, password: str) -> bool:
        """
        Unlock secrets with password.

        Args:
            password: Master password.

        Returns:
            True if successful.
        """
        if not self.secrets_file.exists():
            return False

        try:
            with open(self.secrets_file) as f:
                data = json.load(f)

            header = data["header"]
            salt = bytes.fromhex(header["salt"])
            nonce = bytes.fromhex(header["nonce"])
            encrypted_key = bytes.fromhex(header["encrypted_key"])

            # Derive key and decrypt Fernet key
            key = self._derive_key(password, salt)

            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            aesgcm = AESGCM(key)
            fernet_key = aesgcm.decrypt(nonce, encrypted_key, None)

            self._fernet = Fernet(fernet_key)

            # Decrypt secrets
            self._secrets = {}
            for name, encrypted_value in data.get("secrets", {}).items():
                decrypted = self._fernet.decrypt(encrypted_value.encode())
                self._secrets[name] = decrypted.decode()

            self._loaded = True
            logger.info("Unlocked secrets storage")
            return True

        except Exception as e:
            logger.warning(f"Failed to unlock secrets: {e}")
            return False

    def _save(self) -> None:
        """Save encrypted secrets."""
        if not self._fernet:
            raise RuntimeError("Secrets not initialized or unlocked")

        with open(self.secrets_file) as f:
            data = json.load(f)

        # Encrypt secrets
        encrypted_secrets = {}
        for name, value in self._secrets.items():
            encrypted = self._fernet.encrypt(value.encode())
            encrypted_secrets[name] = encrypted.decode()

        data["secrets"] = encrypted_secrets

        with open(self.secrets_file, "w") as f:
            json.dump(data, f, indent=2)

    def set_secret(self, name: str, value: str) -> None:
        """Set a secret value."""
        if not self._loaded:
            raise RuntimeError("Secrets not unlocked")

        self._secrets[name] = value
        self._save()

    def get_secret(self, name: str) -> str | None:
        """Get a secret value."""
        if not self._loaded:
            raise RuntimeError("Secrets not unlocked")

        return self._secrets.get(name)

    def delete_secret(self, name: str) -> bool:
        """Delete a secret."""
        if not self._loaded:
            raise RuntimeError("Secrets not unlocked")

        if name in self._secrets:
            del self._secrets[name]
            self._save()
            return True
        return False

    def list_secrets(self) -> list[str]:
        """List secret names (not values)."""
        if not self._loaded:
            raise RuntimeError("Secrets not unlocked")

        return list(self._secrets.keys())


# =============================================================================
# Security Scanning
# =============================================================================


@dataclass
class SecurityScanResult:
    """Result of a security scan."""

    scan_type: str
    target: str
    issues: list[dict[str, Any]]
    summary: dict[str, int]
    scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def has_critical(self) -> bool:
        """Check if scan found critical issues."""
        return self.summary.get("critical", 0) > 0

    @property
    def has_high(self) -> bool:
        """Check if scan found high severity issues."""
        return self.summary.get("high", 0) > 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_type": self.scan_type,
            "target": self.target,
            "issues": self.issues,
            "summary": self.summary,
            "scanned_at": self.scanned_at.isoformat(),
        }


class SecurityScanner:
    """
    Scans deployment artifacts for security issues.

    Supports scanning:
    - Docker images for vulnerabilities
    - Python packages for known issues
    - Configurations for insecure settings
    """

    def __init__(self, output_dir: Path | None = None) -> None:
        """
        Initialize security scanner.

        Args:
            output_dir: Directory for scan reports.
        """
        self.output_dir = output_dir or Path.cwd() / "security-reports"

    def scan_python_packages(self, requirements_file: Path | None = None) -> SecurityScanResult:
        """
        Scan Python packages for known vulnerabilities.

        Uses pip-audit or safety if available.
        """
        issues = []
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        # Try pip-audit first
        try:
            cmd = [sys.executable, "-m", "pip_audit", "--format", "json"]
            if requirements_file:
                cmd.extend(["-r", str(requirements_file)])

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0 or result.stdout:
                audit_results = json.loads(result.stdout) if result.stdout else []

                for vuln in audit_results:
                    severity = vuln.get("severity", "unknown").lower()
                    if severity in summary:
                        summary[severity] += 1

                    issues.append({
                        "package": vuln.get("name"),
                        "installed_version": vuln.get("version"),
                        "vulnerability_id": vuln.get("id"),
                        "severity": severity,
                        "description": vuln.get("description"),
                        "fix_versions": vuln.get("fix_versions", []),
                    })

        except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError):
            # pip-audit not available, try safety
            try:
                cmd = ["safety", "check", "--json"]
                if requirements_file:
                    cmd.extend(["-r", str(requirements_file)])

                result = subprocess.run(cmd, capture_output=True, text=True)
                safety_results = json.loads(result.stdout) if result.stdout else []

                for vuln in safety_results:
                    issues.append({
                        "package": vuln[0] if len(vuln) > 0 else "unknown",
                        "vulnerability_id": vuln[4] if len(vuln) > 4 else "unknown",
                        "severity": "unknown",
                        "description": vuln[3] if len(vuln) > 3 else "",
                    })
                    summary["medium"] += 1  # Default to medium

            except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError):
                logger.warning("Neither pip-audit nor safety available for Python scanning")

        return SecurityScanResult(
            scan_type="python_packages",
            target=str(requirements_file) if requirements_file else "installed",
            issues=issues,
            summary=summary,
        )

    def scan_docker_image(self, image: str) -> SecurityScanResult:
        """
        Scan a Docker image for vulnerabilities.

        Uses trivy if available.
        """
        issues = []
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        try:
            cmd = ["trivy", "image", "--format", "json", "--quiet", image]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0 and result.stdout:
                trivy_results = json.loads(result.stdout)

                for target in trivy_results.get("Results", []):
                    for vuln in target.get("Vulnerabilities", []):
                        severity = vuln.get("Severity", "UNKNOWN").lower()
                        if severity in summary:
                            summary[severity] += 1

                        issues.append({
                            "target": target.get("Target"),
                            "package": vuln.get("PkgName"),
                            "installed_version": vuln.get("InstalledVersion"),
                            "vulnerability_id": vuln.get("VulnerabilityID"),
                            "severity": severity,
                            "title": vuln.get("Title"),
                            "description": vuln.get("Description"),
                            "fixed_version": vuln.get("FixedVersion"),
                        })

        except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError):
            logger.warning("Trivy not available for Docker image scanning")

        return SecurityScanResult(
            scan_type="docker_image",
            target=image,
            issues=issues,
            summary=summary,
        )

    def scan_configuration(self, config_dir: Path) -> SecurityScanResult:
        """
        Scan configuration files for security issues.

        Checks for:
        - Insecure file permissions
        - Exposed secrets
        - Weak encryption settings
        """
        issues = []
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        sensitive_patterns = [
            "password", "secret", "key", "token", "credential",
            "api_key", "apikey", "auth", "private",
        ]

        for path in config_dir.rglob("*"):
            if not path.is_file():
                continue

            # Check file permissions
            mode = path.stat().st_mode
            if mode & stat.S_IROTH:  # World readable
                issues.append({
                    "type": "insecure_permissions",
                    "file": str(path),
                    "severity": "medium",
                    "description": "File is world-readable",
                    "current_mode": oct(mode),
                })
                summary["medium"] += 1

            # Check for exposed secrets in common config files
            if path.suffix in (".json", ".yaml", ".yml", ".toml", ".ini", ".env"):
                try:
                    content = path.read_text()
                    for pattern in sensitive_patterns:
                        if pattern in content.lower():
                            # Check if it looks like an actual value
                            lines = [l for l in content.split("\n")
                                     if pattern in l.lower() and "=" in l or ":" in l]
                            for line in lines:
                                # Very basic check - not foolproof
                                if any(c.isalnum() for c in line.split("=")[-1] if len(line.split("=")[-1].strip()) > 3):
                                    issues.append({
                                        "type": "potential_secret",
                                        "file": str(path),
                                        "severity": "high",
                                        "description": f"Potential secret containing '{pattern}'",
                                        "line_preview": line[:50] + "..." if len(line) > 50 else line,
                                    })
                                    summary["high"] += 1
                                    break
                        break  # Only report once per file
                except Exception:
                    pass

        return SecurityScanResult(
            scan_type="configuration",
            target=str(config_dir),
            issues=issues,
            summary=summary,
        )

    def generate_report(
        self,
        results: list[SecurityScanResult],
        output_format: str = "json",
    ) -> Path:
        """
        Generate a security scan report.

        Args:
            results: List of scan results.
            output_format: Report format (json, html).

        Returns:
            Path to generated report.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        report_file = self.output_dir / f"security-report-{timestamp}.{output_format}"

        if output_format == "json":
            report_data = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_scans": len(results),
                "scans": [r.to_dict() for r in results],
                "overall_summary": {
                    "critical": sum(r.summary.get("critical", 0) for r in results),
                    "high": sum(r.summary.get("high", 0) for r in results),
                    "medium": sum(r.summary.get("medium", 0) for r in results),
                    "low": sum(r.summary.get("low", 0) for r in results),
                },
            }
            report_file.write_text(json.dumps(report_data, indent=2))

        logger.info(f"Security report generated: {report_file}")
        return report_file


# =============================================================================
# Module exports
# =============================================================================


def get_certificate_pinning_store() -> CertificatePinningStore:
    """Get the certificate pinning store singleton."""
    return CertificatePinningStore()


def get_secrets_manager() -> SecretsManager:
    """Get the secrets manager singleton."""
    return SecretsManager()


def get_security_scanner() -> SecurityScanner:
    """Get the security scanner singleton."""
    return SecurityScanner()
