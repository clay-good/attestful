"""
Automated remediation for Attestful.

Provides automated fixes for common compliance issues
with dry-run support and rollback capabilities.

Supports:
- AWS remediation (S3, KMS, CloudTrail, IAM, EC2)
- Azure remediation (Storage, Key Vault, SQL, NSG)
- GCP remediation (Storage, Firewall, OS Login, Compute)
- Kubernetes remediation (Security Context, Resource Limits, Network Policies, RBAC)
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
from attestful.remediation.gcp import (
    GCP_REMEDIATION_REGISTRY,
    EnableComputeInstanceShieldedVMAction,
    EnableOSLoginAction,
    EnableStorageBucketUniformAccessAction,
    EnableStorageBucketVersioningAction,
    RemovePublicRDPAccessAction,
    RemovePublicSSHAccessAction,
    get_gcp_remediation_action,
)
from attestful.remediation.kubernetes import (
    K8S_REMEDIATION_REGISTRY,
    AddResourceLimitsAction,
    CreateDefaultDenyNetworkPolicyAction,
    EnablePodSecurityContextAction,
    RemoveClusterAdminBindingAction,
    get_k8s_remediation_action,
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
    # GCP actions
    "EnableStorageBucketVersioningAction",
    "EnableStorageBucketUniformAccessAction",
    "RemovePublicSSHAccessAction",
    "RemovePublicRDPAccessAction",
    "EnableOSLoginAction",
    "EnableComputeInstanceShieldedVMAction",
    # GCP Registry
    "GCP_REMEDIATION_REGISTRY",
    "get_gcp_remediation_action",
    # Kubernetes actions
    "EnablePodSecurityContextAction",
    "AddResourceLimitsAction",
    "CreateDefaultDenyNetworkPolicyAction",
    "RemoveClusterAdminBindingAction",
    # Kubernetes Registry
    "K8S_REMEDIATION_REGISTRY",
    "get_k8s_remediation_action",
]
