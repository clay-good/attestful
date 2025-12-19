"""
Audit logging with tamper detection for Attestful.

Provides:
- Structured audit log entries
- Checksum chain for tamper detection
- Persistent audit storage
- Sensitive data masking

Step 8.1.8 and 11.4.4 of instructions.txt.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from attestful.core.logging import get_logger

logger = get_logger(__name__)


# =============================================================================
# Audit Actions
# =============================================================================


class AuditAction(str, Enum):
    """Types of auditable actions."""

    # Authentication
    USER_LOGIN = "user:login"
    USER_LOGOUT = "user:logout"
    USER_LOGIN_FAILED = "user:login_failed"

    # Scans
    SCAN_STARTED = "scan:started"
    SCAN_COMPLETED = "scan:completed"
    SCAN_FAILED = "scan:failed"
    SCAN_DELETED = "scan:deleted"

    # Evidence collection
    COLLECTION_STARTED = "collection:started"
    COLLECTION_COMPLETED = "collection:completed"
    COLLECTION_FAILED = "collection:failed"

    # Credentials
    CREDENTIAL_ACCESSED = "credential:accessed"
    CREDENTIAL_STORED = "credential:stored"
    CREDENTIAL_DELETED = "credential:deleted"

    # Configuration
    CONFIG_CHANGED = "config:changed"
    CONFIG_EXPORTED = "config:exported"
    CONFIG_IMPORTED = "config:imported"

    # Users
    USER_CREATED = "user:created"
    USER_UPDATED = "user:updated"
    USER_DELETED = "user:deleted"
    ROLE_CHANGED = "role:changed"

    # Permissions
    PERMISSION_CHECK = "permission:check"
    PERMISSION_GRANTED = "permission:granted"
    PERMISSION_REVOKED = "permission:revoked"

    # Reports
    REPORT_GENERATED = "report:generated"
    REPORT_EXPORTED = "report:exported"

    # Remediation
    REMEDIATION_STARTED = "remediation:started"
    REMEDIATION_COMPLETED = "remediation:completed"
    REMEDIATION_FAILED = "remediation:failed"
    REMEDIATION_ROLLED_BACK = "remediation:rolled_back"

    # OSCAL
    OSCAL_IMPORTED = "oscal:imported"
    OSCAL_EXPORTED = "oscal:exported"
    SSP_GENERATED = "ssp:generated"


# =============================================================================
# Sensitive Data Patterns
# =============================================================================


# Patterns to mask in audit logs
SENSITIVE_PATTERNS = [
    (re.compile(r"(password|secret|token|key|credential)['\"]?\s*[:=]\s*['\"]?([^'\"}\s]+)", re.I), r"\1=***REDACTED***"),
    (re.compile(r"(AKIA[0-9A-Z]{16})"), r"***AWS_KEY***"),
    (re.compile(r"([a-zA-Z0-9+/]{40})"), r"***POSSIBLE_SECRET***"),
]

# Keys that should always be masked
SENSITIVE_KEYS = {"password", "secret", "token", "key", "api_key", "access_key", "secret_key", "credential", "value"}


def mask_sensitive_data(data: dict[str, Any]) -> dict[str, Any]:
    """
    Mask sensitive data in a dictionary.

    Args:
        data: Dictionary to mask.

    Returns:
        Masked copy of the dictionary.
    """
    result = {}

    for key, value in data.items():
        key_lower = key.lower()

        if key_lower in SENSITIVE_KEYS:
            result[key] = "***REDACTED***"
        elif isinstance(value, dict):
            result[key] = mask_sensitive_data(value)
        elif isinstance(value, str):
            masked = value
            for pattern, replacement in SENSITIVE_PATTERNS:
                masked = pattern.sub(replacement, masked)
            result[key] = masked
        else:
            result[key] = value

    return result


# =============================================================================
# Audit Entry
# =============================================================================


@dataclass
class AuditEntry:
    """A single audit log entry with integrity verification."""

    timestamp: datetime
    action: AuditAction
    user: str
    details: dict[str, Any]
    checksum: str = ""
    previous_hash: str = ""

    def compute_checksum(self, previous_hash: str = "") -> str:
        """
        Compute SHA-256 checksum for this entry.

        Args:
            previous_hash: Hash of the previous entry (for chain).

        Returns:
            Hex-encoded SHA-256 hash.
        """
        data = {
            "timestamp": self.timestamp.isoformat(),
            "action": self.action.value if isinstance(self.action, AuditAction) else self.action,
            "user": self.user,
            "details": self.details,
            "previous_hash": previous_hash,
        }
        json_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(json_str.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "action": self.action.value if isinstance(self.action, AuditAction) else self.action,
            "user": self.user,
            "details": self.details,
            "checksum": self.checksum,
            "previous_hash": self.previous_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEntry:
        """Create from dictionary."""
        action_value = data["action"]
        try:
            action = AuditAction(action_value)
        except ValueError:
            action = action_value  # type: ignore

        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            action=action,
            user=data["user"],
            details=data.get("details", {}),
            checksum=data.get("checksum", ""),
            previous_hash=data.get("previous_hash", ""),
        )


# =============================================================================
# Audit Log
# =============================================================================


class AuditLog:
    """
    Persistent audit log with tamper detection.

    Uses a checksum chain where each entry's hash includes
    the previous entry's hash, enabling detection of any
    modifications or deletions.
    """

    VERSION = "1.0.0"

    def __init__(self, log_path: Path | None = None) -> None:
        """
        Initialize audit log.

        Args:
            log_path: Path to the audit log file.
        """
        self.log_path = log_path or Path.home() / ".attestful" / "audit.log"
        self._entries: list[AuditEntry] = []
        self._loaded = False

    def _load(self) -> None:
        """Load entries from file."""
        if self._loaded:
            return

        self._entries = []

        if self.log_path.exists():
            try:
                with open(self.log_path) as f:
                    data = json.load(f)

                for entry_data in data.get("entries", []):
                    self._entries.append(AuditEntry.from_dict(entry_data))

                logger.debug(f"Loaded {len(self._entries)} audit log entries")
            except Exception as e:
                logger.warning(f"Failed to load audit log: {e}")

        self._loaded = True

    def _save(self) -> None:
        """Save entries to file."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "version": self.VERSION,
            "entries": [e.to_dict() for e in self._entries],
        }

        with open(self.log_path, "w") as f:
            json.dump(data, f, indent=2)

        # Secure permissions (owner read/write only)
        os.chmod(self.log_path, stat.S_IRUSR | stat.S_IWUSR)

    def log(
        self,
        action: AuditAction,
        user: str,
        details: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """
        Log an auditable action.

        Args:
            action: The action being logged.
            user: The user performing the action.
            details: Additional details about the action.

        Returns:
            The created audit entry.
        """
        self._load()

        # Mask sensitive data in details
        masked_details = mask_sensitive_data(details or {})

        # Get previous hash for chain
        previous_hash = ""
        if self._entries:
            previous_hash = self._entries[-1].checksum

        # Create entry
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            action=action,
            user=user,
            details=masked_details,
            previous_hash=previous_hash,
        )

        # Compute checksum including previous hash
        entry.checksum = entry.compute_checksum(previous_hash)

        self._entries.append(entry)
        self._save()

        logger.debug(f"Audit: {action.value} by {user}")
        return entry

    def get_entries(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        action: AuditAction | None = None,
        user: str | None = None,
        limit: int | None = None,
    ) -> list[AuditEntry]:
        """
        Get audit log entries with optional filtering.

        Args:
            start_date: Filter entries after this date.
            end_date: Filter entries before this date.
            action: Filter by action type.
            user: Filter by user.
            limit: Maximum number of entries to return.

        Returns:
            List of matching audit entries.
        """
        self._load()

        results = self._entries.copy()

        if start_date:
            results = [e for e in results if e.timestamp >= start_date]

        if end_date:
            results = [e for e in results if e.timestamp <= end_date]

        if action:
            results = [e for e in results if e.action == action]

        if user:
            results = [e for e in results if e.user == user]

        if limit:
            results = results[-limit:]

        return results

    def verify_integrity(self) -> tuple[bool, list[str]]:
        """
        Verify the integrity of the audit log chain.

        Returns:
            Tuple of (is_valid, list of error messages).
        """
        self._load()

        if not self._entries:
            return True, []

        errors = []

        for i, entry in enumerate(self._entries):
            # Get expected previous hash
            expected_previous = ""
            if i > 0:
                expected_previous = self._entries[i - 1].checksum

            # Verify previous hash matches
            if entry.previous_hash != expected_previous:
                errors.append(
                    f"Entry {i}: previous_hash mismatch. "
                    f"Expected {expected_previous[:16]}..., got {entry.previous_hash[:16]}..."
                )

            # Recompute checksum
            computed = entry.compute_checksum(expected_previous)
            if computed != entry.checksum:
                errors.append(
                    f"Entry {i}: checksum mismatch. "
                    f"Expected {computed[:16]}..., got {entry.checksum[:16]}..."
                )

        return len(errors) == 0, errors

    def get_entry_count(self) -> int:
        """Get total number of entries."""
        self._load()
        return len(self._entries)


# =============================================================================
# Verification Function
# =============================================================================


def verify_audit_chain(audit_log: AuditLog) -> bool:
    """
    Verify the integrity of an audit log chain.

    Args:
        audit_log: The audit log to verify.

    Returns:
        True if the chain is valid.
    """
    is_valid, errors = audit_log.verify_integrity()

    if not is_valid:
        for error in errors:
            logger.error(f"Audit chain verification failed: {error}")

    return is_valid


# =============================================================================
# Module Exports
# =============================================================================


__all__ = [
    "AuditAction",
    "AuditEntry",
    "AuditLog",
    "mask_sensitive_data",
    "verify_audit_chain",
]
