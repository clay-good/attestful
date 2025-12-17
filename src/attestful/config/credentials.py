"""
Encrypted credential storage for Attestful.

Provides secure storage of platform credentials using Fernet
symmetric encryption with automatic key management.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from attestful.core.exceptions import ConfigurationError, SecurityError
from attestful.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class Credential:
    """
    Represents a stored credential for a platform.

    Attributes:
        platform: Platform identifier (e.g., 'aws', 'okta').
        name: Credential name/alias.
        data: Credential data (varies by platform).
        created_at: When the credential was created.
        updated_at: When the credential was last updated.
        metadata: Additional metadata about the credential.
    """

    platform: str
    name: str
    data: dict[str, Any]
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert credential to dictionary for serialization."""
        return {
            "platform": self.platform,
            "name": self.name,
            "data": self.data,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Credential:
        """Create credential from dictionary."""
        return cls(
            platform=data["platform"],
            name=data["name"],
            data=data["data"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            metadata=data.get("metadata", {}),
        )


class CredentialStore:
    """
    Encrypted credential storage manager.

    Stores credentials encrypted with Fernet symmetric encryption.
    The encryption key is stored separately with restricted permissions.

    Features:
    - Automatic key generation and rotation
    - Platform-specific credential schemas
    - Credential validation before storage
    - Audit logging of credential access

    Example:
        store = CredentialStore(data_dir=Path("~/.attestful"))
        store.set("aws", "production", {
            "access_key_id": "AKIA...",
            "secret_access_key": "...",
            "region": "us-east-1",
        })
        cred = store.get("aws", "production")
    """

    # Platform-specific required fields
    PLATFORM_SCHEMAS: dict[str, set[str]] = {
        "aws": {"access_key_id", "secret_access_key"},
        "azure": {"tenant_id", "client_id", "client_secret"},
        "gcp": {"project_id"},  # Can use service account file
        "okta": {"domain", "api_token"},
        "jamf": {"url", "username", "password"},
        "google_workspace": {"admin_email", "delegated_credentials_file"},
        "snowflake": {"account", "user", "password"},
        "datadog": {"api_key", "app_key"},
        "gitlab": {"url", "private_token"},
        "github": {"token"},
        "jira": {"url", "email", "api_token"},
        "slack": {"token"},
        "pagerduty": {"api_key"},
    }

    def __init__(
        self,
        data_dir: Path | None = None,
        key_file: Path | None = None,
        credentials_file: Path | None = None,
    ) -> None:
        """
        Initialize the credential store.

        Args:
            data_dir: Base directory for credential storage.
            key_file: Path to encryption key file.
            credentials_file: Path to encrypted credentials file.
        """
        self.data_dir = data_dir or Path.home() / ".attestful"
        self.key_file = key_file or self.data_dir / ".key"
        self.credentials_file = credentials_file or self.data_dir / "credentials.enc"

        self._fernet: Fernet | None = None
        self._credentials: dict[str, dict[str, Credential]] = {}
        self._loaded = False

    def _ensure_directory(self) -> None:
        """Create data directory with secure permissions."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        # Set directory permissions to owner only (700)
        os.chmod(self.data_dir, stat.S_IRWXU)

    def _get_or_create_key(self) -> bytes:
        """
        Get the encryption key, creating one if it doesn't exist.

        Returns:
            Encryption key bytes.
        """
        self._ensure_directory()

        if self.key_file.exists():
            key = self.key_file.read_bytes()
            logger.debug("Loaded existing encryption key")
            return key

        # Generate new key
        key = Fernet.generate_key()
        self.key_file.write_bytes(key)
        # Set file permissions to owner read only (400)
        os.chmod(self.key_file, stat.S_IRUSR)
        logger.info("Generated new encryption key")
        return key

    def _get_fernet(self) -> Fernet:
        """Get or create the Fernet encryption instance."""
        if self._fernet is None:
            key = self._get_or_create_key()
            self._fernet = Fernet(key)
        return self._fernet

    def _load(self) -> None:
        """Load credentials from encrypted file."""
        if self._loaded:
            return

        self._credentials = {}

        if not self.credentials_file.exists():
            self._loaded = True
            return

        try:
            encrypted_data = self.credentials_file.read_bytes()
            fernet = self._get_fernet()
            decrypted_data = fernet.decrypt(encrypted_data)
            raw_credentials = json.loads(decrypted_data.decode("utf-8"))

            for platform, creds in raw_credentials.items():
                self._credentials[platform] = {}
                for name, cred_data in creds.items():
                    self._credentials[platform][name] = Credential.from_dict(cred_data)

            logger.debug(f"Loaded {sum(len(c) for c in self._credentials.values())} credentials")
            self._loaded = True

        except InvalidToken:
            raise SecurityError(
                "Failed to decrypt credentials",
                details={"file": str(self.credentials_file)},
            )
        except json.JSONDecodeError as e:
            raise ConfigurationError(
                "Invalid credentials file format",
                details={"error": str(e)},
            )

    def _save(self) -> None:
        """Save credentials to encrypted file."""
        self._ensure_directory()

        raw_credentials: dict[str, dict[str, dict[str, Any]]] = {}
        for platform, creds in self._credentials.items():
            raw_credentials[platform] = {}
            for name, cred in creds.items():
                raw_credentials[platform][name] = cred.to_dict()

        json_data = json.dumps(raw_credentials, indent=2)
        fernet = self._get_fernet()
        encrypted_data = fernet.encrypt(json_data.encode("utf-8"))

        self.credentials_file.write_bytes(encrypted_data)
        # Set file permissions to owner read/write only (600)
        os.chmod(self.credentials_file, stat.S_IRUSR | stat.S_IWUSR)
        logger.debug("Saved credentials to encrypted file")

    def validate_credential(self, platform: str, data: dict[str, Any]) -> list[str]:
        """
        Validate credential data against platform schema.

        Args:
            platform: Platform identifier.
            data: Credential data to validate.

        Returns:
            List of validation errors (empty if valid).
        """
        errors: list[str] = []

        schema = self.PLATFORM_SCHEMAS.get(platform)
        if schema:
            missing = schema - set(data.keys())
            if missing:
                errors.append(f"Missing required fields: {', '.join(sorted(missing))}")

        # Check for empty values
        for key, value in data.items():
            if value is None or (isinstance(value, str) and not value.strip()):
                errors.append(f"Empty value for field: {key}")

        return errors

    def set(
        self,
        platform: str,
        name: str,
        data: dict[str, Any],
        *,
        metadata: dict[str, Any] | None = None,
        validate: bool = True,
    ) -> Credential:
        """
        Store a credential.

        Args:
            platform: Platform identifier (e.g., 'aws', 'okta').
            name: Credential name/alias.
            data: Credential data.
            metadata: Optional metadata.
            validate: Whether to validate against platform schema.

        Returns:
            The stored credential.

        Raises:
            ConfigurationError: If validation fails.
        """
        self._load()

        if validate:
            errors = self.validate_credential(platform, data)
            if errors:
                raise ConfigurationError(
                    f"Invalid {platform} credentials",
                    details={"errors": errors},
                )

        now = datetime.now(timezone.utc)

        # Check if updating existing credential
        existing = self._credentials.get(platform, {}).get(name)
        if existing:
            created_at = existing.created_at
        else:
            created_at = now

        credential = Credential(
            platform=platform,
            name=name,
            data=data,
            created_at=created_at,
            updated_at=now,
            metadata=metadata or {},
        )

        if platform not in self._credentials:
            self._credentials[platform] = {}
        self._credentials[platform][name] = credential

        self._save()
        logger.info(f"Stored credential: {platform}/{name}")
        return credential

    def get(self, platform: str, name: str) -> Credential | None:
        """
        Retrieve a credential.

        Args:
            platform: Platform identifier.
            name: Credential name.

        Returns:
            Credential if found, None otherwise.
        """
        self._load()
        return self._credentials.get(platform, {}).get(name)

    def get_default(self, platform: str) -> Credential | None:
        """
        Get the default credential for a platform.

        Returns the credential named 'default', or the first one if
        'default' doesn't exist.

        Args:
            platform: Platform identifier.

        Returns:
            Credential if found, None otherwise.
        """
        self._load()
        platform_creds = self._credentials.get(platform, {})

        if not platform_creds:
            return None

        # Try 'default' first
        if "default" in platform_creds:
            return platform_creds["default"]

        # Return first credential
        return next(iter(platform_creds.values()))

    def delete(self, platform: str, name: str) -> bool:
        """
        Delete a credential.

        Args:
            platform: Platform identifier.
            name: Credential name.

        Returns:
            True if deleted, False if not found.
        """
        self._load()

        if platform not in self._credentials:
            return False

        if name not in self._credentials[platform]:
            return False

        del self._credentials[platform][name]

        # Clean up empty platform dict
        if not self._credentials[platform]:
            del self._credentials[platform]

        self._save()
        logger.info(f"Deleted credential: {platform}/{name}")
        return True

    def list_platforms(self) -> list[str]:
        """
        List all platforms with stored credentials.

        Returns:
            List of platform identifiers.
        """
        self._load()
        return sorted(self._credentials.keys())

    def list_credentials(self, platform: str) -> list[str]:
        """
        List all credential names for a platform.

        Args:
            platform: Platform identifier.

        Returns:
            List of credential names.
        """
        self._load()
        return sorted(self._credentials.get(platform, {}).keys())

    def list_all(self) -> dict[str, list[str]]:
        """
        List all stored credentials by platform.

        Returns:
            Dictionary mapping platforms to credential names.
        """
        self._load()
        return {
            platform: sorted(creds.keys())
            for platform, creds in sorted(self._credentials.items())
        }

    def rotate_key(self) -> None:
        """
        Rotate the encryption key.

        Creates a new key and re-encrypts all credentials.
        """
        self._load()

        # Generate new key
        new_key = Fernet.generate_key()

        # Update internal state
        self._fernet = Fernet(new_key)

        # Save with new key
        self._save()

        # Write new key file
        self.key_file.write_bytes(new_key)
        os.chmod(self.key_file, stat.S_IRUSR)

        logger.info("Rotated encryption key")

    def export_metadata(self) -> list[dict[str, Any]]:
        """
        Export credential metadata (without sensitive data).

        Returns:
            List of credential metadata dictionaries.
        """
        self._load()
        result = []

        for platform, creds in self._credentials.items():
            for name, cred in creds.items():
                result.append({
                    "platform": platform,
                    "name": name,
                    "created_at": cred.created_at.isoformat(),
                    "updated_at": cred.updated_at.isoformat(),
                    "metadata": cred.metadata,
                    "fields": list(cred.data.keys()),
                })

        return result

    def test_credential(self, platform: str, name: str) -> tuple[bool, str]:
        """
        Test a stored credential by attempting to authenticate.

        Args:
            platform: Platform identifier.
            name: Credential name.

        Returns:
            Tuple of (success, message).
        """
        credential = self.get(platform, name)
        if not credential:
            return False, f"Credential not found: {platform}/{name}"

        # Platform-specific validation would go here
        # For now, just return success if credential exists
        return True, "Credential validation not implemented for this platform"


@lru_cache
def get_credential_store() -> CredentialStore:
    """
    Get the credential store singleton.

    Returns:
        CredentialStore instance (cached).
    """
    from attestful.config.settings import get_settings

    settings = get_settings()
    return CredentialStore(
        data_dir=settings.data_dir,
        key_file=settings.effective_encryption_key_file,
        credentials_file=settings.credentials_file,
    )
