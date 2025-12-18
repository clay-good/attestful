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
from attestful.remediation.azure import (
    AZURE_REMEDIATION_REGISTRY,
    BlockStoragePublicAccessAction,
    EnableKeyVaultPurgeProtectionAction,
    EnableKeyVaultSoftDeleteAction,
    EnableSQLAuditingAction,
    EnableSQLThreatDetectionAction,
    EnableStorageSoftDeleteAction,
    RemoveNSGOpenRDPAction,
    RemoveNSGOpenSSHAction,
    get_azure_remediation_action,
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
    # AWS Registry
    "REMEDIATION_REGISTRY",
    "get_remediation_action",
    # Azure actions
    "BlockStoragePublicAccessAction",
    "EnableKeyVaultPurgeProtectionAction",
    "EnableKeyVaultSoftDeleteAction",
    "EnableSQLAuditingAction",
    "EnableSQLThreatDetectionAction",
    "EnableStorageSoftDeleteAction",
    "RemoveNSGOpenRDPAction",
    "RemoveNSGOpenSSHAction",
    # Azure Registry
    "AZURE_REMEDIATION_REGISTRY",
    "get_azure_remediation_action",
]
