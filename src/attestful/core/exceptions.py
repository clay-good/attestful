"""
Attestful exception hierarchy.

All Attestful exceptions inherit from AttestfulError, making it easy to catch
all attestful-related exceptions while still allowing specific handling.
"""

from __future__ import annotations

from typing import Any


class AttestfulError(Exception):
    """Base exception for all Attestful errors."""

    def __init__(
        self,
        message: str,
        *,
        details: dict[str, Any] | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.cause = cause

    def __str__(self) -> str:
        if self.cause:
            return f"{self.message} (caused by: {self.cause})"
        return self.message

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.message!r}, details={self.details!r})"


# =============================================================================
# Configuration Errors
# =============================================================================


class ConfigurationError(AttestfulError):
    """Error in configuration or settings."""

    pass


class CredentialError(ConfigurationError):
    """Error with credentials (missing, invalid, expired)."""

    def __init__(
        self,
        message: str,
        *,
        platform: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.platform = platform


# =============================================================================
# OSCAL Errors
# =============================================================================


class OSCALError(AttestfulError):
    """Base error for OSCAL-related operations."""

    pass


class CatalogError(OSCALError):
    """Error loading or parsing an OSCAL catalog."""

    def __init__(
        self,
        message: str,
        *,
        catalog_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.catalog_id = catalog_id


class ProfileError(OSCALError):
    """Error loading or resolving an OSCAL profile."""

    def __init__(
        self,
        message: str,
        *,
        profile_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.profile_id = profile_id


class SSPError(OSCALError):
    """Error generating or validating an SSP."""

    pass


class AssessmentError(OSCALError):
    """Error with assessment operations."""

    pass


# =============================================================================
# Collection Errors
# =============================================================================


class CollectionError(AttestfulError):
    """Base error for collection operations."""

    def __init__(
        self,
        message: str,
        *,
        platform: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.platform = platform


class ResourceCollectionError(CollectionError):
    """Error collecting resources for compliance checking."""

    def __init__(
        self,
        message: str,
        *,
        resource_type: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.resource_type = resource_type


class EvidenceCollectionError(CollectionError):
    """Error collecting evidence for proof gathering."""

    def __init__(
        self,
        message: str,
        *,
        evidence_type: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.evidence_type = evidence_type


class RateLimitError(CollectionError):
    """Rate limit exceeded during collection."""

    def __init__(
        self,
        message: str,
        *,
        retry_after: int | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class AuthenticationError(CollectionError):
    """Authentication failed during collection."""

    pass


# =============================================================================
# Evaluation Errors
# =============================================================================


class EvaluationError(AttestfulError):
    """Error evaluating a compliance check."""

    def __init__(
        self,
        message: str,
        *,
        check_id: str | None = None,
        resource_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.check_id = check_id
        self.resource_id = resource_id


class ConditionError(EvaluationError):
    """Error parsing or executing a check condition."""

    pass


# =============================================================================
# Storage Errors
# =============================================================================


class StorageError(AttestfulError):
    """Base error for storage operations."""

    pass


class DatabaseError(StorageError):
    """Error with database operations."""

    pass


class EvidenceStorageError(StorageError):
    """Error storing or retrieving evidence files."""

    def __init__(
        self,
        message: str,
        *,
        file_path: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.file_path = file_path


class IntegrityError(StorageError):
    """Evidence or data integrity check failed."""

    def __init__(
        self,
        message: str,
        *,
        expected_hash: str | None = None,
        actual_hash: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash


# =============================================================================
# Validation Errors
# =============================================================================


class ValidationError(AttestfulError):
    """Data validation error."""

    def __init__(
        self,
        message: str,
        *,
        field: str | None = None,
        value: Any = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.field = field
        self.value = value


# =============================================================================
# Remediation Errors
# =============================================================================


class RemediationError(AttestfulError):
    """Error during remediation."""

    def __init__(
        self,
        message: str,
        *,
        action_id: str | None = None,
        resource_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.action_id = action_id
        self.resource_id = resource_id


class RollbackError(RemediationError):
    """Error rolling back a remediation action."""

    pass


# =============================================================================
# Security Errors
# =============================================================================


class SecurityError(AttestfulError):
    """Base error for security-related operations."""

    pass


class EncryptionError(SecurityError):
    """Error with encryption or decryption operations."""

    pass


class KeyError(SecurityError):
    """Error with cryptographic keys."""

    pass
