"""
Azure-specific remediation actions for SOC 2 compliance.

Provides automated fixes for common Azure compliance issues including:
- Storage account encryption and soft delete
- Key Vault purge protection
- SQL database auditing and encryption
- Network security group hardening
"""

from __future__ import annotations

import asyncio
from typing import Any

from attestful.core.logging import get_logger
from attestful.remediation.base import (
    RemediationAction,
    RemediationResult,
    RemediationStatus,
    RiskLevel,
)

logger = get_logger(__name__)


def _get_azure_credentials():
    """Get Azure credentials with lazy import."""
    from azure.identity import DefaultAzureCredential

    return DefaultAzureCredential()


def _get_storage_client(subscription_id: str):
    """Get Azure Storage Management client."""
    from azure.mgmt.storage import StorageManagementClient

    return StorageManagementClient(_get_azure_credentials(), subscription_id)


def _get_keyvault_client(subscription_id: str):
    """Get Azure Key Vault Management client."""
    from azure.mgmt.keyvault import KeyVaultManagementClient

    return KeyVaultManagementClient(_get_azure_credentials(), subscription_id)


def _get_sql_client(subscription_id: str):
    """Get Azure SQL Management client."""
    from azure.mgmt.sql import SqlManagementClient

    return SqlManagementClient(_get_azure_credentials(), subscription_id)


def _get_network_client(subscription_id: str):
    """Get Azure Network Management client."""
    from azure.mgmt.network import NetworkManagementClient

    return NetworkManagementClient(_get_azure_credentials(), subscription_id)


# =============================================================================
# Storage Account Remediation Actions
# =============================================================================


class BlockStoragePublicAccessAction(RemediationAction):
    """Disable public access on an Azure Storage Account (SOC 2 CC6.6)."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        subscription_id: str,
        resource_group: str,
        storage_account_name: str,
        dry_run: bool = False,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="storage_account",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.storage_account_name = storage_account_name

    async def validate(self) -> tuple[bool, str]:
        """Validate that storage account can be modified."""
        try:
            from azure.core.exceptions import ResourceNotFoundError

            client = _get_storage_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            await loop.run_in_executor(
                None,
                lambda: client.storage_accounts.get_properties(
                    self.resource_group,
                    self.storage_account_name,
                ),
            )

            return True, "Storage account is accessible and can be modified"

        except ResourceNotFoundError:
            return False, f"Storage account '{self.storage_account_name}' not found"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    async def execute(self) -> RemediationResult:
        """Disable public blob access on the storage account."""
        changes_made = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would disable public access on storage account {self.storage_account_name}",
                    changes_made=["Disable public blob access"],
                )

            from azure.core.exceptions import HttpResponseError
            from azure.mgmt.storage.models import StorageAccountUpdateParameters

            client = _get_storage_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            # Get current settings for rollback
            current = await loop.run_in_executor(
                None,
                lambda: client.storage_accounts.get_properties(
                    self.resource_group,
                    self.storage_account_name,
                ),
            )

            self.rollback_data = {
                "storage_account_name": self.storage_account_name,
                "resource_group": self.resource_group,
                "previous_public_access": current.allow_blob_public_access,
            }

            # Disable public blob access
            update_params = StorageAccountUpdateParameters(
                allow_blob_public_access=False,
            )

            await loop.run_in_executor(
                None,
                lambda: client.storage_accounts.update(
                    self.resource_group,
                    self.storage_account_name,
                    update_params,
                ),
            )

            changes_made.append(f"Disabled public blob access on storage account {self.storage_account_name}")

            logger.info(
                "azure_storage_public_access_blocked",
                extra={
                    "storage_account": self.storage_account_name,
                    "action_id": self.action_id,
                },
            )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully disabled public access on storage account {self.storage_account_name}",
                changes_made=changes_made,
            )

        except Exception as e:
            error_code = "Unknown"
            if hasattr(e, 'error') and e.error:
                error_code = e.error.code
            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to disable public access: {error_code}",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback public access changes."""
        if not self.rollback_data:
            return True

        try:
            from azure.mgmt.storage.models import StorageAccountUpdateParameters

            client = _get_storage_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            previous = self.rollback_data.get("previous_public_access", True)

            update_params = StorageAccountUpdateParameters(
                allow_blob_public_access=previous,
            )

            await loop.run_in_executor(
                None,
                lambda: client.storage_accounts.update(
                    self.resource_group,
                    self.storage_account_name,
                    update_params,
                ),
            )

            logger.info(
                "azure_storage_public_access_rolled_back",
                extra={
                    "storage_account": self.storage_account_name,
                    "action_id": self.action_id,
                },
            )

            return True

        except Exception as e:
            logger.error(
                "azure_storage_public_access_rollback_failed",
                extra={
                    "storage_account": self.storage_account_name,
                    "error": str(e),
                },
            )
            return False

    def get_description(self) -> str:
        """Get description of this remediation."""
        return f"Disable public blob access on Azure storage account '{self.storage_account_name}'"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level - medium because it may break public access patterns."""
        return RiskLevel.MEDIUM


class EnableStorageSoftDeleteAction(RemediationAction):
    """Enable blob soft delete on an Azure Storage Account (SOC 2 CC7.3)."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        subscription_id: str,
        resource_group: str,
        storage_account_name: str,
        retention_days: int = 30,
        dry_run: bool = False,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="storage_account",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.storage_account_name = storage_account_name
        self.retention_days = retention_days

    async def validate(self) -> tuple[bool, str]:
        """Validate that blob service properties can be updated."""
        try:
            from azure.core.exceptions import ResourceNotFoundError

            client = _get_storage_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            await loop.run_in_executor(
                None,
                lambda: client.storage_accounts.get_properties(
                    self.resource_group,
                    self.storage_account_name,
                ),
            )

            return True, "Storage account is accessible"

        except ResourceNotFoundError:
            return False, f"Storage account '{self.storage_account_name}' not found"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    async def execute(self) -> RemediationResult:
        """Enable blob soft delete on the storage account."""
        changes_made = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would enable blob soft delete with {self.retention_days} days retention on {self.storage_account_name}",
                    changes_made=[f"Enable blob soft delete ({self.retention_days} days)"],
                )

            from azure.mgmt.storage.models import (
                BlobServiceProperties,
                DeleteRetentionPolicy,
            )

            client = _get_storage_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            # Get current blob service properties for rollback
            try:
                current = await loop.run_in_executor(
                    None,
                    lambda: client.blob_services.get_service_properties(
                        self.resource_group,
                        self.storage_account_name,
                    ),
                )
                self.rollback_data = {
                    "storage_account_name": self.storage_account_name,
                    "resource_group": self.resource_group,
                    "previous_enabled": current.delete_retention_policy.enabled if current.delete_retention_policy else False,
                    "previous_days": current.delete_retention_policy.days if current.delete_retention_policy else 0,
                }
            except Exception:
                self.rollback_data = {
                    "storage_account_name": self.storage_account_name,
                    "resource_group": self.resource_group,
                    "previous_enabled": False,
                    "previous_days": 0,
                }

            # Enable soft delete
            properties = BlobServiceProperties(
                delete_retention_policy=DeleteRetentionPolicy(
                    enabled=True,
                    days=self.retention_days,
                ),
            )

            await loop.run_in_executor(
                None,
                lambda: client.blob_services.set_service_properties(
                    self.resource_group,
                    self.storage_account_name,
                    properties,
                ),
            )

            changes_made.append(
                f"Enabled blob soft delete with {self.retention_days} days retention on {self.storage_account_name}"
            )

            logger.info(
                "azure_storage_soft_delete_enabled",
                extra={
                    "storage_account": self.storage_account_name,
                    "retention_days": self.retention_days,
                    "action_id": self.action_id,
                },
            )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully enabled blob soft delete on storage account {self.storage_account_name}",
                changes_made=changes_made,
            )

        except Exception as e:
            error_code = "Unknown"
            if hasattr(e, 'error') and e.error:
                error_code = e.error.code
            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to enable soft delete: {error_code}",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback soft delete changes."""
        if not self.rollback_data:
            return True

        try:
            from azure.mgmt.storage.models import (
                BlobServiceProperties,
                DeleteRetentionPolicy,
            )

            client = _get_storage_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            previous_enabled = self.rollback_data.get("previous_enabled", False)
            previous_days = self.rollback_data.get("previous_days", 7)

            properties = BlobServiceProperties(
                delete_retention_policy=DeleteRetentionPolicy(
                    enabled=previous_enabled,
                    days=previous_days if previous_enabled else None,
                ),
            )

            await loop.run_in_executor(
                None,
                lambda: client.blob_services.set_service_properties(
                    self.resource_group,
                    self.storage_account_name,
                    properties,
                ),
            )

            logger.info(
                "azure_storage_soft_delete_rolled_back",
                extra={
                    "storage_account": self.storage_account_name,
                    "action_id": self.action_id,
                },
            )

            return True

        except Exception as e:
            logger.error(
                "azure_storage_soft_delete_rollback_failed",
                extra={
                    "storage_account": self.storage_account_name,
                    "error": str(e),
                },
            )
            return False

    def get_description(self) -> str:
        """Get description of this remediation."""
        return f"Enable blob soft delete with {self.retention_days} days retention on storage account '{self.storage_account_name}'"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level."""
        return RiskLevel.LOW


# =============================================================================
# Key Vault Remediation Actions
# =============================================================================


class EnableKeyVaultPurgeProtectionAction(RemediationAction):
    """Enable purge protection on an Azure Key Vault (SOC 2 CC6.1)."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        subscription_id: str,
        resource_group: str,
        vault_name: str,
        dry_run: bool = False,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="key_vault",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.vault_name = vault_name

    async def validate(self) -> tuple[bool, str]:
        """Validate that Key Vault can be modified."""
        try:
            from azure.core.exceptions import ResourceNotFoundError

            client = _get_keyvault_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            vault = await loop.run_in_executor(
                None,
                lambda: client.vaults.get(
                    self.resource_group,
                    self.vault_name,
                ),
            )

            # Check if soft delete is enabled (required for purge protection)
            if not vault.properties.enable_soft_delete:
                return False, "Soft delete must be enabled before enabling purge protection"

            # Check if purge protection is already enabled (cannot be disabled once enabled)
            if vault.properties.enable_purge_protection:
                return False, "Purge protection is already enabled"

            return True, "Key Vault is accessible and purge protection can be enabled"

        except ResourceNotFoundError:
            return False, f"Key Vault '{self.vault_name}' not found"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    async def execute(self) -> RemediationResult:
        """Enable purge protection on the Key Vault."""
        changes_made = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would enable purge protection on Key Vault {self.vault_name}",
                    changes_made=["Enable purge protection (irreversible)"],
                )

            from azure.mgmt.keyvault.models import VaultPatchParameters, VaultPatchProperties

            client = _get_keyvault_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            # Note: Purge protection cannot be disabled once enabled, so no rollback data needed
            self.rollback_data = {
                "vault_name": self.vault_name,
                "resource_group": self.resource_group,
                "note": "Purge protection cannot be disabled once enabled",
            }

            # Enable purge protection
            update_params = VaultPatchParameters(
                properties=VaultPatchProperties(
                    enable_purge_protection=True,
                ),
            )

            await loop.run_in_executor(
                None,
                lambda: client.vaults.update(
                    self.resource_group,
                    self.vault_name,
                    update_params,
                ),
            )

            changes_made.append(f"Enabled purge protection on Key Vault {self.vault_name} (irreversible)")

            logger.info(
                "azure_keyvault_purge_protection_enabled",
                extra={
                    "vault_name": self.vault_name,
                    "action_id": self.action_id,
                },
            )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully enabled purge protection on Key Vault {self.vault_name}",
                changes_made=changes_made,
            )

        except Exception as e:
            error_code = "Unknown"
            if hasattr(e, 'error') and e.error:
                error_code = e.error.code
            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to enable purge protection: {error_code}",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback is not possible for purge protection."""
        logger.warning(
            "azure_keyvault_purge_protection_rollback_not_possible",
            extra={
                "vault_name": self.vault_name,
                "action_id": self.action_id,
                "reason": "Purge protection cannot be disabled once enabled",
            },
        )
        return False

    def get_description(self) -> str:
        """Get description of this remediation."""
        return f"Enable purge protection on Key Vault '{self.vault_name}' (WARNING: This action is irreversible)"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level - high because it's irreversible."""
        return RiskLevel.HIGH


class EnableKeyVaultSoftDeleteAction(RemediationAction):
    """Enable soft delete on an Azure Key Vault (SOC 2 CC6.1)."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        subscription_id: str,
        resource_group: str,
        vault_name: str,
        retention_days: int = 90,
        dry_run: bool = False,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="key_vault",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.vault_name = vault_name
        self.retention_days = retention_days

    async def validate(self) -> tuple[bool, str]:
        """Validate that Key Vault can be modified."""
        try:
            from azure.core.exceptions import ResourceNotFoundError

            client = _get_keyvault_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            vault = await loop.run_in_executor(
                None,
                lambda: client.vaults.get(
                    self.resource_group,
                    self.vault_name,
                ),
            )

            # Note: As of 2020, soft delete is enabled by default and cannot be disabled for new vaults
            if vault.properties.enable_soft_delete:
                return False, "Soft delete is already enabled"

            return True, "Key Vault is accessible and soft delete can be enabled"

        except ResourceNotFoundError:
            return False, f"Key Vault '{self.vault_name}' not found"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    async def execute(self) -> RemediationResult:
        """Enable soft delete on the Key Vault."""
        changes_made = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would enable soft delete with {self.retention_days} days retention on Key Vault {self.vault_name}",
                    changes_made=[f"Enable soft delete ({self.retention_days} days)"],
                )

            from azure.mgmt.keyvault.models import VaultPatchParameters, VaultPatchProperties

            client = _get_keyvault_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            # Note: Soft delete cannot be disabled once enabled on newer vaults
            self.rollback_data = {
                "vault_name": self.vault_name,
                "resource_group": self.resource_group,
                "note": "Soft delete cannot be disabled on most vaults",
            }

            # Enable soft delete
            update_params = VaultPatchParameters(
                properties=VaultPatchProperties(
                    enable_soft_delete=True,
                    soft_delete_retention_in_days=self.retention_days,
                ),
            )

            await loop.run_in_executor(
                None,
                lambda: client.vaults.update(
                    self.resource_group,
                    self.vault_name,
                    update_params,
                ),
            )

            changes_made.append(
                f"Enabled soft delete with {self.retention_days} days retention on Key Vault {self.vault_name}"
            )

            logger.info(
                "azure_keyvault_soft_delete_enabled",
                extra={
                    "vault_name": self.vault_name,
                    "retention_days": self.retention_days,
                    "action_id": self.action_id,
                },
            )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully enabled soft delete on Key Vault {self.vault_name}",
                changes_made=changes_made,
            )

        except Exception as e:
            error_code = "Unknown"
            if hasattr(e, 'error') and e.error:
                error_code = e.error.code
            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to enable soft delete: {error_code}",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback is not possible for soft delete on most vaults."""
        logger.warning(
            "azure_keyvault_soft_delete_rollback_not_possible",
            extra={
                "vault_name": self.vault_name,
                "action_id": self.action_id,
            },
        )
        return False

    def get_description(self) -> str:
        """Get description of this remediation."""
        return f"Enable soft delete with {self.retention_days} days retention on Key Vault '{self.vault_name}'"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level - medium because it may not be reversible."""
        return RiskLevel.MEDIUM


# =============================================================================
# SQL Database Remediation Actions
# =============================================================================


class EnableSQLAuditingAction(RemediationAction):
    """Enable auditing on an Azure SQL Server (SOC 2 CC7.2)."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        subscription_id: str,
        resource_group: str,
        server_name: str,
        storage_account_id: str,
        retention_days: int = 90,
        dry_run: bool = False,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="sql_server",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.server_name = server_name
        self.storage_account_id = storage_account_id
        self.retention_days = retention_days

    async def validate(self) -> tuple[bool, str]:
        """Validate that SQL Server can be modified."""
        try:
            from azure.core.exceptions import ResourceNotFoundError

            client = _get_sql_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            await loop.run_in_executor(
                None,
                lambda: client.servers.get(
                    self.resource_group,
                    self.server_name,
                ),
            )

            if not self.storage_account_id:
                return False, "Storage account ID is required for auditing"

            return True, "SQL Server is accessible and auditing can be enabled"

        except ResourceNotFoundError:
            return False, f"SQL Server '{self.server_name}' not found"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    async def execute(self) -> RemediationResult:
        """Enable auditing on the SQL Server."""
        changes_made = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would enable auditing on SQL Server {self.server_name}",
                    changes_made=[f"Enable blob auditing with {self.retention_days} days retention"],
                )

            from azure.mgmt.sql.models import (
                BlobAuditingPolicyState,
                ServerBlobAuditingPolicy,
            )

            client = _get_sql_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            # Get current auditing settings for rollback
            try:
                current = await loop.run_in_executor(
                    None,
                    lambda: client.server_blob_auditing_policies.get(
                        self.resource_group,
                        self.server_name,
                    ),
                )
                self.rollback_data = {
                    "server_name": self.server_name,
                    "resource_group": self.resource_group,
                    "previous_state": current.state.value if current.state else "Disabled",
                    "previous_storage_account_id": current.storage_account_resource_id,
                    "previous_retention_days": current.retention_days,
                }
            except Exception:
                self.rollback_data = {
                    "server_name": self.server_name,
                    "resource_group": self.resource_group,
                    "previous_state": "Disabled",
                }

            # Enable auditing
            policy = ServerBlobAuditingPolicy(
                state=BlobAuditingPolicyState.ENABLED,
                storage_account_resource_id=self.storage_account_id,
                retention_days=self.retention_days,
                is_storage_secondary_key_in_use=False,
            )

            await loop.run_in_executor(
                None,
                lambda: client.server_blob_auditing_policies.create_or_update(
                    self.resource_group,
                    self.server_name,
                    policy,
                ),
            )

            changes_made.append(
                f"Enabled blob auditing with {self.retention_days} days retention on SQL Server {self.server_name}"
            )

            logger.info(
                "azure_sql_auditing_enabled",
                extra={
                    "server_name": self.server_name,
                    "retention_days": self.retention_days,
                    "action_id": self.action_id,
                },
            )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully enabled auditing on SQL Server {self.server_name}",
                changes_made=changes_made,
            )

        except Exception as e:
            error_code = "Unknown"
            if hasattr(e, 'error') and e.error:
                error_code = e.error.code
            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to enable auditing: {error_code}",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback auditing changes."""
        if not self.rollback_data:
            return True

        try:
            from azure.mgmt.sql.models import (
                BlobAuditingPolicyState,
                ServerBlobAuditingPolicy,
            )

            client = _get_sql_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            previous_state = self.rollback_data.get("previous_state", "Disabled")

            if previous_state == "Disabled":
                policy = ServerBlobAuditingPolicy(
                    state=BlobAuditingPolicyState.DISABLED,
                )
            else:
                policy = ServerBlobAuditingPolicy(
                    state=BlobAuditingPolicyState.ENABLED,
                    storage_account_resource_id=self.rollback_data.get("previous_storage_account_id"),
                    retention_days=self.rollback_data.get("previous_retention_days", 90),
                )

            await loop.run_in_executor(
                None,
                lambda: client.server_blob_auditing_policies.create_or_update(
                    self.resource_group,
                    self.server_name,
                    policy,
                ),
            )

            logger.info(
                "azure_sql_auditing_rolled_back",
                extra={
                    "server_name": self.server_name,
                    "action_id": self.action_id,
                },
            )

            return True

        except Exception as e:
            logger.error(
                "azure_sql_auditing_rollback_failed",
                extra={
                    "server_name": self.server_name,
                    "error": str(e),
                },
            )
            return False

    def get_description(self) -> str:
        """Get description of this remediation."""
        return f"Enable blob auditing with {self.retention_days} days retention on SQL Server '{self.server_name}'"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level."""
        return RiskLevel.LOW


class EnableSQLThreatDetectionAction(RemediationAction):
    """Enable Advanced Threat Protection on an Azure SQL Server (SOC 2 CC7.2)."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        subscription_id: str,
        resource_group: str,
        server_name: str,
        email_addresses: list[str] | None = None,
        dry_run: bool = False,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="sql_server",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.server_name = server_name
        self.email_addresses = email_addresses or []

    async def validate(self) -> tuple[bool, str]:
        """Validate that SQL Server can be modified."""
        try:
            from azure.core.exceptions import ResourceNotFoundError

            client = _get_sql_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            await loop.run_in_executor(
                None,
                lambda: client.servers.get(
                    self.resource_group,
                    self.server_name,
                ),
            )

            return True, "SQL Server is accessible and threat detection can be enabled"

        except ResourceNotFoundError:
            return False, f"SQL Server '{self.server_name}' not found"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    async def execute(self) -> RemediationResult:
        """Enable Advanced Threat Protection on the SQL Server."""
        changes_made = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would enable Advanced Threat Protection on SQL Server {self.server_name}",
                    changes_made=["Enable Advanced Threat Protection"],
                )

            from azure.mgmt.sql.models import (
                SecurityAlertPolicyState,
                ServerSecurityAlertPolicy,
            )

            client = _get_sql_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            # Get current settings for rollback
            try:
                current = await loop.run_in_executor(
                    None,
                    lambda: client.server_security_alert_policies.get(
                        self.resource_group,
                        self.server_name,
                    ),
                )
                self.rollback_data = {
                    "server_name": self.server_name,
                    "resource_group": self.resource_group,
                    "previous_state": current.state.value if current.state else "Disabled",
                    "previous_email_addresses": current.email_addresses,
                }
            except Exception:
                self.rollback_data = {
                    "server_name": self.server_name,
                    "resource_group": self.resource_group,
                    "previous_state": "Disabled",
                }

            # Enable threat detection
            policy = ServerSecurityAlertPolicy(
                state=SecurityAlertPolicyState.ENABLED,
                email_addresses=self.email_addresses,
                email_account_admins=True,
            )

            await loop.run_in_executor(
                None,
                lambda: client.server_security_alert_policies.create_or_update(
                    self.resource_group,
                    self.server_name,
                    policy,
                ),
            )

            changes_made.append(f"Enabled Advanced Threat Protection on SQL Server {self.server_name}")

            logger.info(
                "azure_sql_threat_detection_enabled",
                extra={
                    "server_name": self.server_name,
                    "action_id": self.action_id,
                },
            )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully enabled Advanced Threat Protection on SQL Server {self.server_name}",
                changes_made=changes_made,
            )

        except Exception as e:
            error_code = "Unknown"
            if hasattr(e, 'error') and e.error:
                error_code = e.error.code
            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to enable threat detection: {error_code}",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback threat detection changes."""
        if not self.rollback_data:
            return True

        try:
            from azure.mgmt.sql.models import (
                SecurityAlertPolicyState,
                ServerSecurityAlertPolicy,
            )

            client = _get_sql_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            previous_state = self.rollback_data.get("previous_state", "Disabled")

            if previous_state == "Disabled":
                policy = ServerSecurityAlertPolicy(
                    state=SecurityAlertPolicyState.DISABLED,
                )
            else:
                policy = ServerSecurityAlertPolicy(
                    state=SecurityAlertPolicyState.ENABLED,
                    email_addresses=self.rollback_data.get("previous_email_addresses", []),
                )

            await loop.run_in_executor(
                None,
                lambda: client.server_security_alert_policies.create_or_update(
                    self.resource_group,
                    self.server_name,
                    policy,
                ),
            )

            logger.info(
                "azure_sql_threat_detection_rolled_back",
                extra={
                    "server_name": self.server_name,
                    "action_id": self.action_id,
                },
            )

            return True

        except Exception as e:
            logger.error(
                "azure_sql_threat_detection_rollback_failed",
                extra={
                    "server_name": self.server_name,
                    "error": str(e),
                },
            )
            return False

    def get_description(self) -> str:
        """Get description of this remediation."""
        return f"Enable Advanced Threat Protection on SQL Server '{self.server_name}'"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level."""
        return RiskLevel.LOW


# =============================================================================
# Network Security Group Remediation Actions
# =============================================================================


class RemoveNSGOpenSSHAction(RemediationAction):
    """Remove unrestricted SSH access from Network Security Group (SOC 2 CC6.3)."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        subscription_id: str,
        resource_group: str,
        nsg_name: str,
        dry_run: bool = False,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="network_security_group",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.nsg_name = nsg_name

    async def validate(self) -> tuple[bool, str]:
        """Validate that NSG can be modified."""
        try:
            from azure.core.exceptions import ResourceNotFoundError

            client = _get_network_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            await loop.run_in_executor(
                None,
                lambda: client.network_security_groups.get(
                    self.resource_group,
                    self.nsg_name,
                ),
            )

            return True, "Network Security Group is accessible"

        except ResourceNotFoundError:
            return False, f"Network Security Group '{self.nsg_name}' not found"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    async def execute(self) -> RemediationResult:
        """Remove unrestricted SSH access rules from NSG."""
        changes_made = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would remove unrestricted SSH rules from NSG {self.nsg_name}",
                    changes_made=["Remove rules allowing SSH from 0.0.0.0/0 or *"],
                )

            client = _get_network_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            # Get current NSG
            nsg = await loop.run_in_executor(
                None,
                lambda: client.network_security_groups.get(
                    self.resource_group,
                    self.nsg_name,
                ),
            )

            self.rollback_data = {
                "nsg_name": self.nsg_name,
                "resource_group": self.resource_group,
                "removed_rules": [],
            }

            # Find and remove rules that allow SSH from anywhere
            rules_to_remove = []
            for rule in nsg.security_rules or []:
                if (
                    rule.direction == "Inbound"
                    and rule.access == "Allow"
                    and (rule.destination_port_range == "22" or "22" in (rule.destination_port_ranges or []))
                    and (
                        rule.source_address_prefix in ["*", "0.0.0.0/0", "Internet"]
                        or "0.0.0.0/0" in (rule.source_address_prefixes or [])
                        or "*" in (rule.source_address_prefixes or [])
                    )
                ):
                    rules_to_remove.append(rule.name)
                    # Store for rollback
                    self.rollback_data["removed_rules"].append({
                        "name": rule.name,
                        "priority": rule.priority,
                        "direction": rule.direction,
                        "access": rule.access,
                        "protocol": rule.protocol,
                        "source_address_prefix": rule.source_address_prefix,
                        "destination_address_prefix": rule.destination_address_prefix,
                        "source_port_range": rule.source_port_range,
                        "destination_port_range": rule.destination_port_range,
                    })

            if not rules_to_remove:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message="No unrestricted SSH access rules found",
                    changes_made=[],
                )

            # Delete the rules
            for rule_name in rules_to_remove:
                await loop.run_in_executor(
                    None,
                    lambda rn=rule_name: client.security_rules.begin_delete(
                        self.resource_group,
                        self.nsg_name,
                        rn,
                    ).result(),
                )
                changes_made.append(f"Removed rule '{rule_name}' allowing SSH from anywhere")

            logger.info(
                "azure_nsg_ssh_rules_removed",
                extra={
                    "nsg_name": self.nsg_name,
                    "rules_removed": rules_to_remove,
                    "action_id": self.action_id,
                },
            )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully removed {len(rules_to_remove)} unrestricted SSH rule(s) from NSG {self.nsg_name}",
                changes_made=changes_made,
            )

        except Exception as e:
            error_code = "Unknown"
            if hasattr(e, 'error') and e.error:
                error_code = e.error.code
            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to remove SSH rules: {error_code}",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback - re-create removed SSH rules."""
        if not self.rollback_data or not self.rollback_data.get("removed_rules"):
            return True

        try:
            from azure.mgmt.network.models import SecurityRule

            client = _get_network_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            for rule_data in self.rollback_data["removed_rules"]:
                rule = SecurityRule(
                    name=rule_data["name"],
                    priority=rule_data["priority"],
                    direction=rule_data["direction"],
                    access=rule_data["access"],
                    protocol=rule_data["protocol"],
                    source_address_prefix=rule_data["source_address_prefix"],
                    destination_address_prefix=rule_data["destination_address_prefix"],
                    source_port_range=rule_data["source_port_range"],
                    destination_port_range=rule_data["destination_port_range"],
                )

                await loop.run_in_executor(
                    None,
                    lambda r=rule: client.security_rules.begin_create_or_update(
                        self.resource_group,
                        self.nsg_name,
                        r.name,
                        r,
                    ).result(),
                )

            logger.info(
                "azure_nsg_ssh_rules_rolled_back",
                extra={
                    "nsg_name": self.nsg_name,
                    "action_id": self.action_id,
                },
            )

            return True

        except Exception as e:
            logger.error(
                "azure_nsg_ssh_rollback_failed",
                extra={
                    "nsg_name": self.nsg_name,
                    "error": str(e),
                },
            )
            return False

    def get_description(self) -> str:
        """Get description of this remediation."""
        return f"Remove unrestricted SSH access (0.0.0.0/0 or *) from Network Security Group '{self.nsg_name}'"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level - high because it may block legitimate access."""
        return RiskLevel.HIGH


class RemoveNSGOpenRDPAction(RemediationAction):
    """Remove unrestricted RDP access from Network Security Group (SOC 2 CC6.3)."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        subscription_id: str,
        resource_group: str,
        nsg_name: str,
        dry_run: bool = False,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="network_security_group",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.nsg_name = nsg_name

    async def validate(self) -> tuple[bool, str]:
        """Validate that NSG can be modified."""
        try:
            from azure.core.exceptions import ResourceNotFoundError

            client = _get_network_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            await loop.run_in_executor(
                None,
                lambda: client.network_security_groups.get(
                    self.resource_group,
                    self.nsg_name,
                ),
            )

            return True, "Network Security Group is accessible"

        except ResourceNotFoundError:
            return False, f"Network Security Group '{self.nsg_name}' not found"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    async def execute(self) -> RemediationResult:
        """Remove unrestricted RDP access rules from NSG."""
        changes_made = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would remove unrestricted RDP rules from NSG {self.nsg_name}",
                    changes_made=["Remove rules allowing RDP from 0.0.0.0/0 or *"],
                )

            client = _get_network_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            # Get current NSG
            nsg = await loop.run_in_executor(
                None,
                lambda: client.network_security_groups.get(
                    self.resource_group,
                    self.nsg_name,
                ),
            )

            self.rollback_data = {
                "nsg_name": self.nsg_name,
                "resource_group": self.resource_group,
                "removed_rules": [],
            }

            # Find and remove rules that allow RDP from anywhere
            rules_to_remove = []
            for rule in nsg.security_rules or []:
                if (
                    rule.direction == "Inbound"
                    and rule.access == "Allow"
                    and (rule.destination_port_range == "3389" or "3389" in (rule.destination_port_ranges or []))
                    and (
                        rule.source_address_prefix in ["*", "0.0.0.0/0", "Internet"]
                        or "0.0.0.0/0" in (rule.source_address_prefixes or [])
                        or "*" in (rule.source_address_prefixes or [])
                    )
                ):
                    rules_to_remove.append(rule.name)
                    self.rollback_data["removed_rules"].append({
                        "name": rule.name,
                        "priority": rule.priority,
                        "direction": rule.direction,
                        "access": rule.access,
                        "protocol": rule.protocol,
                        "source_address_prefix": rule.source_address_prefix,
                        "destination_address_prefix": rule.destination_address_prefix,
                        "source_port_range": rule.source_port_range,
                        "destination_port_range": rule.destination_port_range,
                    })

            if not rules_to_remove:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message="No unrestricted RDP access rules found",
                    changes_made=[],
                )

            # Delete the rules
            for rule_name in rules_to_remove:
                await loop.run_in_executor(
                    None,
                    lambda rn=rule_name: client.security_rules.begin_delete(
                        self.resource_group,
                        self.nsg_name,
                        rn,
                    ).result(),
                )
                changes_made.append(f"Removed rule '{rule_name}' allowing RDP from anywhere")

            logger.info(
                "azure_nsg_rdp_rules_removed",
                extra={
                    "nsg_name": self.nsg_name,
                    "rules_removed": rules_to_remove,
                    "action_id": self.action_id,
                },
            )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully removed {len(rules_to_remove)} unrestricted RDP rule(s) from NSG {self.nsg_name}",
                changes_made=changes_made,
            )

        except Exception as e:
            error_code = "Unknown"
            if hasattr(e, 'error') and e.error:
                error_code = e.error.code
            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to remove RDP rules: {error_code}",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback - re-create removed RDP rules."""
        if not self.rollback_data or not self.rollback_data.get("removed_rules"):
            return True

        try:
            from azure.mgmt.network.models import SecurityRule

            client = _get_network_client(self.subscription_id)
            loop = asyncio.get_event_loop()

            for rule_data in self.rollback_data["removed_rules"]:
                rule = SecurityRule(
                    name=rule_data["name"],
                    priority=rule_data["priority"],
                    direction=rule_data["direction"],
                    access=rule_data["access"],
                    protocol=rule_data["protocol"],
                    source_address_prefix=rule_data["source_address_prefix"],
                    destination_address_prefix=rule_data["destination_address_prefix"],
                    source_port_range=rule_data["source_port_range"],
                    destination_port_range=rule_data["destination_port_range"],
                )

                await loop.run_in_executor(
                    None,
                    lambda r=rule: client.security_rules.begin_create_or_update(
                        self.resource_group,
                        self.nsg_name,
                        r.name,
                        r,
                    ).result(),
                )

            logger.info(
                "azure_nsg_rdp_rules_rolled_back",
                extra={
                    "nsg_name": self.nsg_name,
                    "action_id": self.action_id,
                },
            )

            return True

        except Exception as e:
            logger.error(
                "azure_nsg_rdp_rollback_failed",
                extra={
                    "nsg_name": self.nsg_name,
                    "error": str(e),
                },
            )
            return False

    def get_description(self) -> str:
        """Get description of this remediation."""
        return f"Remove unrestricted RDP access (0.0.0.0/0 or *) from Network Security Group '{self.nsg_name}'"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level - high because it may block legitimate access."""
        return RiskLevel.HIGH


# =============================================================================
# Remediation Action Registry
# =============================================================================


# Map check IDs to remediation action classes
AZURE_REMEDIATION_REGISTRY: dict[str, type[RemediationAction]] = {
    # Storage account remediations
    "soc2-cc6.6-azure-storage-public-access-disabled": BlockStoragePublicAccessAction,
    "soc2-cc7.3-azure-storage-soft-delete": EnableStorageSoftDeleteAction,
    # Key Vault remediations
    "soc2-cc6.1-azure-keyvault-purge-protection": EnableKeyVaultPurgeProtectionAction,
    "soc2-cc6.1-azure-keyvault-soft-delete": EnableKeyVaultSoftDeleteAction,
    # SQL remediations
    "soc2-cc7.2-azure-sql-auditing": EnableSQLAuditingAction,
    "soc2-cc7.2-azure-sql-threat-detection": EnableSQLThreatDetectionAction,
    # NSG remediations
    "soc2-cc6.3-azure-nsg-no-public-ssh": RemoveNSGOpenSSHAction,
    "soc2-cc6.3-azure-nsg-no-public-rdp": RemoveNSGOpenRDPAction,
}


def get_azure_remediation_action(
    check_id: str,
    resource_id: str,
    resource_data: dict[str, Any],
    subscription_id: str,
    resource_group: str | None = None,
    dry_run: bool = False,
    **kwargs: Any,
) -> RemediationAction | None:
    """
    Get a remediation action for a failed Azure check.

    Args:
        check_id: ID of the failed compliance check
        resource_id: ID of the resource to remediate
        resource_data: Current resource data
        subscription_id: Azure subscription ID
        resource_group: Azure resource group name
        dry_run: If True, only simulate remediation
        **kwargs: Additional arguments for specific action types

    Returns:
        RemediationAction instance or None if no remediation available
    """
    action_class = AZURE_REMEDIATION_REGISTRY.get(check_id)

    if not action_class:
        return None

    # Extract resource group from resource data if not provided
    if not resource_group:
        resource_group = resource_data.get("resource_group") or resource_data.get("metadata", {}).get("resource_group")

    if not resource_group:
        logger.warning(
            "azure_remediation_missing_resource_group",
            extra={"check_id": check_id, "resource_id": resource_id},
        )
        return None

    # Handle specific action types
    if action_class == BlockStoragePublicAccessAction:
        storage_account_name = resource_data.get("name") or kwargs.get("storage_account_name") or resource_id
        return action_class(
            check_id=check_id,
            resource_id=resource_id,
            resource_data=resource_data,
            subscription_id=subscription_id,
            resource_group=resource_group,
            storage_account_name=storage_account_name,
            dry_run=dry_run,
        )

    if action_class == EnableStorageSoftDeleteAction:
        storage_account_name = resource_data.get("name") or kwargs.get("storage_account_name") or resource_id
        return action_class(
            check_id=check_id,
            resource_id=resource_id,
            resource_data=resource_data,
            subscription_id=subscription_id,
            resource_group=resource_group,
            storage_account_name=storage_account_name,
            retention_days=kwargs.get("retention_days", 30),
            dry_run=dry_run,
        )

    if action_class in (EnableKeyVaultPurgeProtectionAction, EnableKeyVaultSoftDeleteAction):
        vault_name = resource_data.get("name") or kwargs.get("vault_name") or resource_id
        if action_class == EnableKeyVaultSoftDeleteAction:
            return action_class(
                check_id=check_id,
                resource_id=resource_id,
                resource_data=resource_data,
                subscription_id=subscription_id,
                resource_group=resource_group,
                vault_name=vault_name,
                retention_days=kwargs.get("retention_days", 90),
                dry_run=dry_run,
            )
        return action_class(
            check_id=check_id,
            resource_id=resource_id,
            resource_data=resource_data,
            subscription_id=subscription_id,
            resource_group=resource_group,
            vault_name=vault_name,
            dry_run=dry_run,
        )

    if action_class == EnableSQLAuditingAction:
        server_name = resource_data.get("name") or kwargs.get("server_name") or resource_id
        storage_account_id = kwargs.get("storage_account_id")
        if not storage_account_id:
            logger.warning(
                "azure_sql_auditing_missing_storage_account",
                extra={"check_id": check_id, "server_name": server_name},
            )
            return None
        return action_class(
            check_id=check_id,
            resource_id=resource_id,
            resource_data=resource_data,
            subscription_id=subscription_id,
            resource_group=resource_group,
            server_name=server_name,
            storage_account_id=storage_account_id,
            retention_days=kwargs.get("retention_days", 90),
            dry_run=dry_run,
        )

    if action_class == EnableSQLThreatDetectionAction:
        server_name = resource_data.get("name") or kwargs.get("server_name") or resource_id
        return action_class(
            check_id=check_id,
            resource_id=resource_id,
            resource_data=resource_data,
            subscription_id=subscription_id,
            resource_group=resource_group,
            server_name=server_name,
            email_addresses=kwargs.get("email_addresses"),
            dry_run=dry_run,
        )

    if action_class in (RemoveNSGOpenSSHAction, RemoveNSGOpenRDPAction):
        nsg_name = resource_data.get("name") or kwargs.get("nsg_name") or resource_id
        return action_class(
            check_id=check_id,
            resource_id=resource_id,
            resource_data=resource_data,
            subscription_id=subscription_id,
            resource_group=resource_group,
            nsg_name=nsg_name,
            dry_run=dry_run,
        )

    return None
