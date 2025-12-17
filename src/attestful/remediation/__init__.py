"""
Automated remediation for Attestful.

Provides automated fixes for common compliance issues
with dry-run support and rollback capabilities.
"""

from attestful.remediation.base import (
    RemediationAction,
    RemediationEngine,
    RemediationPlan,
    RemediationResult,
    RemediationStatus,
    RiskLevel,
)
from attestful.remediation.aws import (
    REMEDIATION_REGISTRY,
    BlockS3PublicAccessAction,
    EnableCloudTrailLogValidationAction,
    EnableKMSKeyRotationAction,
    EnableS3BucketEncryptionAction,
    EnableS3BucketVersioningAction,
    RemoveOpenSSHAccessAction,
    UpdateIAMPasswordPolicyAction,
    get_remediation_action,
)

__all__ = [
    # Base classes
    "RemediationAction",
    "RemediationEngine",
    "RemediationPlan",
    "RemediationResult",
    "RemediationStatus",
    "RiskLevel",
    # AWS actions
    "BlockS3PublicAccessAction",
    "EnableCloudTrailLogValidationAction",
    "EnableKMSKeyRotationAction",
    "EnableS3BucketEncryptionAction",
    "EnableS3BucketVersioningAction",
    "RemoveOpenSSHAccessAction",
    "UpdateIAMPasswordPolicyAction",
    # Registry
    "REMEDIATION_REGISTRY",
    "get_remediation_action",
]
