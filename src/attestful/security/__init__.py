"""
Security module for Attestful.

Provides RBAC, encryption, audit logging, and security
hardening for enterprise deployments.
"""

from attestful.security.audit import (
    AuditAction,
    AuditEntry,
    AuditLog,
    mask_sensitive_data,
    verify_audit_chain,
)
from attestful.security.certificates import CertificateManager
from attestful.security.hardening import (
    CertificatePinningMode,
    CertificatePinningStore,
    PinnedCertificate,
    SecureDefaults,
    SecretsManager,
    SecurityScanResult,
    SecurityScanner,
    apply_secure_defaults,
    get_certificate_pinning_store,
    get_secrets_manager,
    get_security_scanner,
)
from attestful.security.offline_auth import (
    AuthStatus,
    CachedAuthResult,
    OfflineAuthCache,
    OfflineCredentialValidator,
    TokenRefreshManager,
    TokenType,
    ValidationResult,
    get_offline_auth_cache,
    reset_offline_auth_cache,
)
from attestful.security.rbac import (
    Permission,
    RBACManager,
    RBACUser,
    Role,
    ROLE_PERMISSIONS,
    check_permission,
)

__all__ = [
    # Audit
    "AuditAction",
    "AuditEntry",
    "AuditLog",
    "mask_sensitive_data",
    "verify_audit_chain",
    # Certificates
    "CertificateManager",
    # Offline Auth
    "AuthStatus",
    "CachedAuthResult",
    "OfflineAuthCache",
    "OfflineCredentialValidator",
    "TokenRefreshManager",
    "TokenType",
    "ValidationResult",
    "get_offline_auth_cache",
    "reset_offline_auth_cache",
    # Security Hardening
    "CertificatePinningMode",
    "CertificatePinningStore",
    "PinnedCertificate",
    "SecureDefaults",
    "SecretsManager",
    "SecurityScanResult",
    "SecurityScanner",
    "apply_secure_defaults",
    "get_certificate_pinning_store",
    "get_secrets_manager",
    "get_security_scanner",
    # RBAC
    "Permission",
    "RBACManager",
    "RBACUser",
    "Role",
    "ROLE_PERMISSIONS",
    "check_permission",
]
