"""
Security module for Attestful.

Provides RBAC, encryption, audit logging, and security
hardening for enterprise deployments.

Migrated from Compliy (Step 4.2.13 of instructions.txt).
"""

from attestful.security.certificates import CertificateManager

__all__ = [
    "CertificateManager",
]
