"""
Unit tests for Azure remediation module.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from attestful.remediation.base import (
    RemediationEngine,
    RemediationPlan,
    RemediationResult,
    RemediationStatus,
    RiskLevel,
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


# =============================================================================
# Test Storage Account Remediation Actions
# =============================================================================


class TestBlockStoragePublicAccessAction:
    """Tests for BlockStoragePublicAccessAction."""

    def test_create_action(self):
        """Test creating storage public access action."""
        action = BlockStoragePublicAccessAction(
            check_id="soc2-cc6.6-azure-storage-public-access-disabled",
            resource_id="/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/myaccount",
            resource_data={"name": "myaccount"},
            subscription_id="sub-123",
            resource_group="rg",
            storage_account_name="myaccount",
            dry_run=True,
        )

        assert action.check_id == "soc2-cc6.6-azure-storage-public-access-disabled"
        assert action.storage_account_name == "myaccount"
        assert action.subscription_id == "sub-123"
        assert action.resource_group == "rg"
        assert action.dry_run is True

    def test_get_description(self):
        """Test getting action description."""
        action = BlockStoragePublicAccessAction(
            check_id="soc2-cc6.6-azure-storage-public-access-disabled",
            resource_id="myaccount",
            resource_data={"name": "myaccount"},
            subscription_id="sub-123",
            resource_group="rg",
            storage_account_name="myaccount",
        )

        description = action.get_description()

        assert "myaccount" in description
        assert "public" in description.lower()

    def test_get_risk_level(self):
        """Test that blocking public access is MEDIUM risk."""
        action = BlockStoragePublicAccessAction(
            check_id="soc2-cc6.6-azure-storage-public-access-disabled",
            resource_id="myaccount",
            resource_data={"name": "myaccount"},
            subscription_id="sub-123",
            resource_group="rg",
            storage_account_name="myaccount",
        )

        assert action.get_risk_level() == RiskLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_execute_dry_run(self):
        """Test dry-run execution."""
        action = BlockStoragePublicAccessAction(
            check_id="soc2-cc6.6-azure-storage-public-access-disabled",
            resource_id="myaccount",
            resource_data={"name": "myaccount"},
            subscription_id="sub-123",
            resource_group="rg",
            storage_account_name="myaccount",
            dry_run=True,
        )

        result = await action.execute()

        assert result.status == RemediationStatus.SUCCESS
        assert result.dry_run is True
        assert "[DRY RUN]" in result.message


class TestEnableStorageSoftDeleteAction:
    """Tests for EnableStorageSoftDeleteAction."""

    def test_create_action(self):
        """Test creating storage soft delete action."""
        action = EnableStorageSoftDeleteAction(
            check_id="soc2-cc7.3-azure-storage-soft-delete",
            resource_id="myaccount",
            resource_data={"name": "myaccount"},
            subscription_id="sub-123",
            resource_group="rg",
            storage_account_name="myaccount",
            retention_days=30,
        )

        assert action.storage_account_name == "myaccount"
        assert action.retention_days == 30

    def test_get_risk_level(self):
        """Test that enabling soft delete is LOW risk."""
        action = EnableStorageSoftDeleteAction(
            check_id="soc2-cc7.3-azure-storage-soft-delete",
            resource_id="myaccount",
            resource_data={"name": "myaccount"},
            subscription_id="sub-123",
            resource_group="rg",
            storage_account_name="myaccount",
        )

        assert action.get_risk_level() == RiskLevel.LOW

    def test_get_description(self):
        """Test getting action description."""
        action = EnableStorageSoftDeleteAction(
            check_id="soc2-cc7.3-azure-storage-soft-delete",
            resource_id="myaccount",
            resource_data={"name": "myaccount"},
            subscription_id="sub-123",
            resource_group="rg",
            storage_account_name="myaccount",
            retention_days=30,
        )

        description = action.get_description()

        assert "myaccount" in description
        assert "30" in description
        assert "soft delete" in description.lower()

    @pytest.mark.asyncio
    async def test_execute_dry_run(self):
        """Test dry-run execution."""
        action = EnableStorageSoftDeleteAction(
            check_id="soc2-cc7.3-azure-storage-soft-delete",
            resource_id="myaccount",
            resource_data={"name": "myaccount"},
            subscription_id="sub-123",
            resource_group="rg",
            storage_account_name="myaccount",
            retention_days=30,
            dry_run=True,
        )

        result = await action.execute()

        assert result.status == RemediationStatus.SUCCESS
        assert result.dry_run is True
        assert "[DRY RUN]" in result.message
        assert "30" in result.message


# =============================================================================
# Test Key Vault Remediation Actions
# =============================================================================


class TestEnableKeyVaultPurgeProtectionAction:
    """Tests for EnableKeyVaultPurgeProtectionAction."""

    def test_create_action(self):
        """Test creating purge protection action."""
        action = EnableKeyVaultPurgeProtectionAction(
            check_id="soc2-cc6.1-azure-keyvault-purge-protection",
            resource_id="myvault",
            resource_data={"name": "myvault"},
            subscription_id="sub-123",
            resource_group="rg",
            vault_name="myvault",
        )

        assert action.vault_name == "myvault"

    def test_get_risk_level(self):
        """Test that enabling purge protection is HIGH risk (irreversible)."""
        action = EnableKeyVaultPurgeProtectionAction(
            check_id="soc2-cc6.1-azure-keyvault-purge-protection",
            resource_id="myvault",
            resource_data={"name": "myvault"},
            subscription_id="sub-123",
            resource_group="rg",
            vault_name="myvault",
        )

        assert action.get_risk_level() == RiskLevel.HIGH

    def test_get_description(self):
        """Test getting action description."""
        action = EnableKeyVaultPurgeProtectionAction(
            check_id="soc2-cc6.1-azure-keyvault-purge-protection",
            resource_id="myvault",
            resource_data={"name": "myvault"},
            subscription_id="sub-123",
            resource_group="rg",
            vault_name="myvault",
        )

        description = action.get_description()

        assert "myvault" in description
        assert "purge protection" in description.lower()
        assert "irreversible" in description.lower()

    @pytest.mark.asyncio
    async def test_execute_dry_run(self):
        """Test dry-run execution."""
        action = EnableKeyVaultPurgeProtectionAction(
            check_id="soc2-cc6.1-azure-keyvault-purge-protection",
            resource_id="myvault",
            resource_data={"name": "myvault"},
            subscription_id="sub-123",
            resource_group="rg",
            vault_name="myvault",
            dry_run=True,
        )

        result = await action.execute()

        assert result.status == RemediationStatus.SUCCESS
        assert "[DRY RUN]" in result.message

    @pytest.mark.asyncio
    async def test_rollback_not_possible(self):
        """Test that rollback returns False (not possible)."""
        action = EnableKeyVaultPurgeProtectionAction(
            check_id="soc2-cc6.1-azure-keyvault-purge-protection",
            resource_id="myvault",
            resource_data={"name": "myvault"},
            subscription_id="sub-123",
            resource_group="rg",
            vault_name="myvault",
        )

        # With rollback data set
        action.rollback_data = {"note": "Cannot rollback"}

        result = await action.rollback()

        # Rollback should return False because purge protection cannot be disabled
        assert result is False


class TestEnableKeyVaultSoftDeleteAction:
    """Tests for EnableKeyVaultSoftDeleteAction."""

    def test_create_action(self):
        """Test creating soft delete action."""
        action = EnableKeyVaultSoftDeleteAction(
            check_id="soc2-cc6.1-azure-keyvault-soft-delete",
            resource_id="myvault",
            resource_data={"name": "myvault"},
            subscription_id="sub-123",
            resource_group="rg",
            vault_name="myvault",
            retention_days=90,
        )

        assert action.vault_name == "myvault"
        assert action.retention_days == 90

    def test_get_risk_level(self):
        """Test that enabling soft delete is MEDIUM risk."""
        action = EnableKeyVaultSoftDeleteAction(
            check_id="soc2-cc6.1-azure-keyvault-soft-delete",
            resource_id="myvault",
            resource_data={"name": "myvault"},
            subscription_id="sub-123",
            resource_group="rg",
            vault_name="myvault",
        )

        assert action.get_risk_level() == RiskLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_execute_dry_run(self):
        """Test dry-run execution."""
        action = EnableKeyVaultSoftDeleteAction(
            check_id="soc2-cc6.1-azure-keyvault-soft-delete",
            resource_id="myvault",
            resource_data={"name": "myvault"},
            subscription_id="sub-123",
            resource_group="rg",
            vault_name="myvault",
            retention_days=90,
            dry_run=True,
        )

        result = await action.execute()

        assert result.status == RemediationStatus.SUCCESS
        assert "[DRY RUN]" in result.message
        assert "90" in result.message


# =============================================================================
# Test SQL Remediation Actions
# =============================================================================


class TestEnableSQLAuditingAction:
    """Tests for EnableSQLAuditingAction."""

    def test_create_action(self):
        """Test creating SQL auditing action."""
        action = EnableSQLAuditingAction(
            check_id="soc2-cc7.2-azure-sql-auditing",
            resource_id="myserver",
            resource_data={"name": "myserver"},
            subscription_id="sub-123",
            resource_group="rg",
            server_name="myserver",
            storage_account_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/logs",
            retention_days=90,
        )

        assert action.server_name == "myserver"
        assert action.retention_days == 90
        assert action.storage_account_id is not None

    def test_get_risk_level(self):
        """Test that enabling auditing is LOW risk."""
        action = EnableSQLAuditingAction(
            check_id="soc2-cc7.2-azure-sql-auditing",
            resource_id="myserver",
            resource_data={"name": "myserver"},
            subscription_id="sub-123",
            resource_group="rg",
            server_name="myserver",
            storage_account_id="storage-id",
        )

        assert action.get_risk_level() == RiskLevel.LOW

    def test_get_description(self):
        """Test getting action description."""
        action = EnableSQLAuditingAction(
            check_id="soc2-cc7.2-azure-sql-auditing",
            resource_id="myserver",
            resource_data={"name": "myserver"},
            subscription_id="sub-123",
            resource_group="rg",
            server_name="myserver",
            storage_account_id="storage-id",
            retention_days=90,
        )

        description = action.get_description()

        assert "myserver" in description
        assert "auditing" in description.lower()
        assert "90" in description

    @pytest.mark.asyncio
    async def test_execute_dry_run(self):
        """Test dry-run execution."""
        action = EnableSQLAuditingAction(
            check_id="soc2-cc7.2-azure-sql-auditing",
            resource_id="myserver",
            resource_data={"name": "myserver"},
            subscription_id="sub-123",
            resource_group="rg",
            server_name="myserver",
            storage_account_id="storage-id",
            dry_run=True,
        )

        result = await action.execute()

        assert result.status == RemediationStatus.SUCCESS
        assert "[DRY RUN]" in result.message


class TestEnableSQLThreatDetectionAction:
    """Tests for EnableSQLThreatDetectionAction."""

    def test_create_action(self):
        """Test creating threat detection action."""
        action = EnableSQLThreatDetectionAction(
            check_id="soc2-cc7.2-azure-sql-threat-detection",
            resource_id="myserver",
            resource_data={"name": "myserver"},
            subscription_id="sub-123",
            resource_group="rg",
            server_name="myserver",
            email_addresses=["security@example.com"],
        )

        assert action.server_name == "myserver"
        assert "security@example.com" in action.email_addresses

    def test_get_risk_level(self):
        """Test that enabling threat detection is LOW risk."""
        action = EnableSQLThreatDetectionAction(
            check_id="soc2-cc7.2-azure-sql-threat-detection",
            resource_id="myserver",
            resource_data={"name": "myserver"},
            subscription_id="sub-123",
            resource_group="rg",
            server_name="myserver",
        )

        assert action.get_risk_level() == RiskLevel.LOW

    @pytest.mark.asyncio
    async def test_execute_dry_run(self):
        """Test dry-run execution."""
        action = EnableSQLThreatDetectionAction(
            check_id="soc2-cc7.2-azure-sql-threat-detection",
            resource_id="myserver",
            resource_data={"name": "myserver"},
            subscription_id="sub-123",
            resource_group="rg",
            server_name="myserver",
            dry_run=True,
        )

        result = await action.execute()

        assert result.status == RemediationStatus.SUCCESS
        assert "[DRY RUN]" in result.message


# =============================================================================
# Test NSG Remediation Actions
# =============================================================================


class TestRemoveNSGOpenSSHAction:
    """Tests for RemoveNSGOpenSSHAction."""

    def test_create_action(self):
        """Test creating NSG SSH removal action."""
        action = RemoveNSGOpenSSHAction(
            check_id="soc2-cc6.3-azure-nsg-no-public-ssh",
            resource_id="my-nsg",
            resource_data={"name": "my-nsg"},
            subscription_id="sub-123",
            resource_group="rg",
            nsg_name="my-nsg",
        )

        assert action.nsg_name == "my-nsg"

    def test_get_risk_level(self):
        """Test that removing SSH access is HIGH risk."""
        action = RemoveNSGOpenSSHAction(
            check_id="soc2-cc6.3-azure-nsg-no-public-ssh",
            resource_id="my-nsg",
            resource_data={"name": "my-nsg"},
            subscription_id="sub-123",
            resource_group="rg",
            nsg_name="my-nsg",
        )

        assert action.get_risk_level() == RiskLevel.HIGH

    def test_get_description(self):
        """Test getting action description."""
        action = RemoveNSGOpenSSHAction(
            check_id="soc2-cc6.3-azure-nsg-no-public-ssh",
            resource_id="my-nsg",
            resource_data={"name": "my-nsg"},
            subscription_id="sub-123",
            resource_group="rg",
            nsg_name="my-nsg",
        )

        description = action.get_description()

        assert "my-nsg" in description
        assert "SSH" in description

    @pytest.mark.asyncio
    async def test_execute_dry_run(self):
        """Test dry-run execution."""
        action = RemoveNSGOpenSSHAction(
            check_id="soc2-cc6.3-azure-nsg-no-public-ssh",
            resource_id="my-nsg",
            resource_data={"name": "my-nsg"},
            subscription_id="sub-123",
            resource_group="rg",
            nsg_name="my-nsg",
            dry_run=True,
        )

        result = await action.execute()

        assert result.status == RemediationStatus.SUCCESS
        assert "[DRY RUN]" in result.message


class TestRemoveNSGOpenRDPAction:
    """Tests for RemoveNSGOpenRDPAction."""

    def test_create_action(self):
        """Test creating NSG RDP removal action."""
        action = RemoveNSGOpenRDPAction(
            check_id="soc2-cc6.3-azure-nsg-no-public-rdp",
            resource_id="my-nsg",
            resource_data={"name": "my-nsg"},
            subscription_id="sub-123",
            resource_group="rg",
            nsg_name="my-nsg",
        )

        assert action.nsg_name == "my-nsg"

    def test_get_risk_level(self):
        """Test that removing RDP access is HIGH risk."""
        action = RemoveNSGOpenRDPAction(
            check_id="soc2-cc6.3-azure-nsg-no-public-rdp",
            resource_id="my-nsg",
            resource_data={"name": "my-nsg"},
            subscription_id="sub-123",
            resource_group="rg",
            nsg_name="my-nsg",
        )

        assert action.get_risk_level() == RiskLevel.HIGH

    def test_get_description(self):
        """Test getting action description."""
        action = RemoveNSGOpenRDPAction(
            check_id="soc2-cc6.3-azure-nsg-no-public-rdp",
            resource_id="my-nsg",
            resource_data={"name": "my-nsg"},
            subscription_id="sub-123",
            resource_group="rg",
            nsg_name="my-nsg",
        )

        description = action.get_description()

        assert "my-nsg" in description
        assert "RDP" in description

    @pytest.mark.asyncio
    async def test_execute_dry_run(self):
        """Test dry-run execution."""
        action = RemoveNSGOpenRDPAction(
            check_id="soc2-cc6.3-azure-nsg-no-public-rdp",
            resource_id="my-nsg",
            resource_data={"name": "my-nsg"},
            subscription_id="sub-123",
            resource_group="rg",
            nsg_name="my-nsg",
            dry_run=True,
        )

        result = await action.execute()

        assert result.status == RemediationStatus.SUCCESS
        assert "[DRY RUN]" in result.message


# =============================================================================
# Test Azure Remediation Registry
# =============================================================================


class TestAzureRemediationRegistry:
    """Tests for Azure remediation action registry."""

    def test_registry_has_storage_actions(self):
        """Test that registry contains storage account actions."""
        assert "soc2-cc6.6-azure-storage-public-access-disabled" in AZURE_REMEDIATION_REGISTRY
        assert "soc2-cc7.3-azure-storage-soft-delete" in AZURE_REMEDIATION_REGISTRY

    def test_registry_has_keyvault_actions(self):
        """Test that registry contains Key Vault actions."""
        assert "soc2-cc6.1-azure-keyvault-purge-protection" in AZURE_REMEDIATION_REGISTRY
        assert "soc2-cc6.1-azure-keyvault-soft-delete" in AZURE_REMEDIATION_REGISTRY

    def test_registry_has_sql_actions(self):
        """Test that registry contains SQL actions."""
        assert "soc2-cc7.2-azure-sql-auditing" in AZURE_REMEDIATION_REGISTRY
        assert "soc2-cc7.2-azure-sql-threat-detection" in AZURE_REMEDIATION_REGISTRY

    def test_registry_has_nsg_actions(self):
        """Test that registry contains NSG actions."""
        assert "soc2-cc6.3-azure-nsg-no-public-ssh" in AZURE_REMEDIATION_REGISTRY
        assert "soc2-cc6.3-azure-nsg-no-public-rdp" in AZURE_REMEDIATION_REGISTRY


# =============================================================================
# Test get_azure_remediation_action Factory Function
# =============================================================================


class TestGetAzureRemediationAction:
    """Tests for get_azure_remediation_action factory function."""

    def test_get_storage_public_access_action(self):
        """Test getting storage public access action."""
        action = get_azure_remediation_action(
            check_id="soc2-cc6.6-azure-storage-public-access-disabled",
            resource_id="myaccount",
            resource_data={"name": "myaccount", "resource_group": "rg"},
            subscription_id="sub-123",
            dry_run=True,
        )

        assert action is not None
        assert isinstance(action, BlockStoragePublicAccessAction)
        assert action.storage_account_name == "myaccount"
        assert action.dry_run is True

    def test_get_storage_soft_delete_action(self):
        """Test getting storage soft delete action with custom retention."""
        action = get_azure_remediation_action(
            check_id="soc2-cc7.3-azure-storage-soft-delete",
            resource_id="myaccount",
            resource_data={"name": "myaccount", "resource_group": "rg"},
            subscription_id="sub-123",
            retention_days=14,
        )

        assert action is not None
        assert isinstance(action, EnableStorageSoftDeleteAction)
        assert action.retention_days == 14

    def test_get_keyvault_purge_protection_action(self):
        """Test getting Key Vault purge protection action."""
        action = get_azure_remediation_action(
            check_id="soc2-cc6.1-azure-keyvault-purge-protection",
            resource_id="myvault",
            resource_data={"name": "myvault", "resource_group": "rg"},
            subscription_id="sub-123",
        )

        assert action is not None
        assert isinstance(action, EnableKeyVaultPurgeProtectionAction)
        assert action.vault_name == "myvault"

    def test_get_keyvault_soft_delete_action(self):
        """Test getting Key Vault soft delete action."""
        action = get_azure_remediation_action(
            check_id="soc2-cc6.1-azure-keyvault-soft-delete",
            resource_id="myvault",
            resource_data={"name": "myvault", "resource_group": "rg"},
            subscription_id="sub-123",
            retention_days=60,
        )

        assert action is not None
        assert isinstance(action, EnableKeyVaultSoftDeleteAction)
        assert action.retention_days == 60

    def test_get_sql_auditing_action(self):
        """Test getting SQL auditing action."""
        action = get_azure_remediation_action(
            check_id="soc2-cc7.2-azure-sql-auditing",
            resource_id="myserver",
            resource_data={"name": "myserver", "resource_group": "rg"},
            subscription_id="sub-123",
            storage_account_id="storage-id",
            retention_days=120,
        )

        assert action is not None
        assert isinstance(action, EnableSQLAuditingAction)
        assert action.retention_days == 120

    def test_get_sql_auditing_action_without_storage_returns_none(self):
        """Test that SQL auditing action requires storage account ID."""
        action = get_azure_remediation_action(
            check_id="soc2-cc7.2-azure-sql-auditing",
            resource_id="myserver",
            resource_data={"name": "myserver", "resource_group": "rg"},
            subscription_id="sub-123",
            # No storage_account_id provided
        )

        assert action is None

    def test_get_sql_threat_detection_action(self):
        """Test getting SQL threat detection action."""
        action = get_azure_remediation_action(
            check_id="soc2-cc7.2-azure-sql-threat-detection",
            resource_id="myserver",
            resource_data={"name": "myserver", "resource_group": "rg"},
            subscription_id="sub-123",
            email_addresses=["admin@example.com"],
        )

        assert action is not None
        assert isinstance(action, EnableSQLThreatDetectionAction)
        assert "admin@example.com" in action.email_addresses

    def test_get_nsg_ssh_action(self):
        """Test getting NSG SSH removal action."""
        action = get_azure_remediation_action(
            check_id="soc2-cc6.3-azure-nsg-no-public-ssh",
            resource_id="my-nsg",
            resource_data={"name": "my-nsg", "resource_group": "rg"},
            subscription_id="sub-123",
        )

        assert action is not None
        assert isinstance(action, RemoveNSGOpenSSHAction)

    def test_get_nsg_rdp_action(self):
        """Test getting NSG RDP removal action."""
        action = get_azure_remediation_action(
            check_id="soc2-cc6.3-azure-nsg-no-public-rdp",
            resource_id="my-nsg",
            resource_data={"name": "my-nsg", "resource_group": "rg"},
            subscription_id="sub-123",
        )

        assert action is not None
        assert isinstance(action, RemoveNSGOpenRDPAction)

    def test_get_unknown_action_returns_none(self):
        """Test that unknown check ID returns None."""
        action = get_azure_remediation_action(
            check_id="unknown-check-id",
            resource_id="resource",
            resource_data={},
            subscription_id="sub-123",
        )

        assert action is None

    def test_missing_resource_group_returns_none(self):
        """Test that missing resource group returns None."""
        action = get_azure_remediation_action(
            check_id="soc2-cc6.6-azure-storage-public-access-disabled",
            resource_id="myaccount",
            resource_data={"name": "myaccount"},  # No resource_group
            subscription_id="sub-123",
        )

        assert action is None

    def test_resource_group_from_metadata(self):
        """Test that resource group can be extracted from metadata."""
        action = get_azure_remediation_action(
            check_id="soc2-cc6.6-azure-storage-public-access-disabled",
            resource_id="myaccount",
            resource_data={
                "name": "myaccount",
                "metadata": {"resource_group": "my-rg"},
            },
            subscription_id="sub-123",
        )

        assert action is not None
        assert action.resource_group == "my-rg"


# =============================================================================
# Test Risk Level Handling
# =============================================================================


class TestAzureRiskLevels:
    """Tests for Azure action risk levels."""

    def test_low_risk_actions(self):
        """Test that certain actions are LOW risk."""
        low_risk_actions = [
            EnableStorageSoftDeleteAction(
                check_id="soc2-cc7.3-azure-storage-soft-delete",
                resource_id="myaccount",
                resource_data={},
                subscription_id="sub",
                resource_group="rg",
                storage_account_name="myaccount",
            ),
            EnableSQLAuditingAction(
                check_id="soc2-cc7.2-azure-sql-auditing",
                resource_id="myserver",
                resource_data={},
                subscription_id="sub",
                resource_group="rg",
                server_name="myserver",
                storage_account_id="storage-id",
            ),
            EnableSQLThreatDetectionAction(
                check_id="soc2-cc7.2-azure-sql-threat-detection",
                resource_id="myserver",
                resource_data={},
                subscription_id="sub",
                resource_group="rg",
                server_name="myserver",
            ),
        ]

        for action in low_risk_actions:
            assert action.get_risk_level() == RiskLevel.LOW

    def test_medium_risk_actions(self):
        """Test that certain actions are MEDIUM risk."""
        medium_risk_actions = [
            BlockStoragePublicAccessAction(
                check_id="soc2-cc6.6-azure-storage-public-access-disabled",
                resource_id="myaccount",
                resource_data={},
                subscription_id="sub",
                resource_group="rg",
                storage_account_name="myaccount",
            ),
            EnableKeyVaultSoftDeleteAction(
                check_id="soc2-cc6.1-azure-keyvault-soft-delete",
                resource_id="myvault",
                resource_data={},
                subscription_id="sub",
                resource_group="rg",
                vault_name="myvault",
            ),
        ]

        for action in medium_risk_actions:
            assert action.get_risk_level() == RiskLevel.MEDIUM

    def test_high_risk_actions(self):
        """Test that certain actions are HIGH risk."""
        high_risk_actions = [
            EnableKeyVaultPurgeProtectionAction(
                check_id="soc2-cc6.1-azure-keyvault-purge-protection",
                resource_id="myvault",
                resource_data={},
                subscription_id="sub",
                resource_group="rg",
                vault_name="myvault",
            ),
            RemoveNSGOpenSSHAction(
                check_id="soc2-cc6.3-azure-nsg-no-public-ssh",
                resource_id="my-nsg",
                resource_data={},
                subscription_id="sub",
                resource_group="rg",
                nsg_name="my-nsg",
            ),
            RemoveNSGOpenRDPAction(
                check_id="soc2-cc6.3-azure-nsg-no-public-rdp",
                resource_id="my-nsg",
                resource_data={},
                subscription_id="sub",
                resource_group="rg",
                nsg_name="my-nsg",
            ),
        ]

        for action in high_risk_actions:
            assert action.get_risk_level() == RiskLevel.HIGH


# =============================================================================
# Test Integration with RemediationEngine
# =============================================================================


class TestAzureRemediationWithEngine:
    """Tests for Azure actions with the RemediationEngine."""

    @pytest.mark.asyncio
    async def test_execute_azure_action_dry_run(self):
        """Test executing Azure action in dry-run mode."""
        engine = RemediationEngine(require_approval=False)

        action = EnableStorageSoftDeleteAction(
            check_id="soc2-cc7.3-azure-storage-soft-delete",
            resource_id="myaccount",
            resource_data={"name": "myaccount"},
            subscription_id="sub-123",
            resource_group="rg",
            storage_account_name="myaccount",
            dry_run=True,
        )

        # Mock validation to skip Azure API call
        async def mock_validate():
            return (True, "Mock validation passed")
        action.validate = mock_validate

        result = await engine.execute_action(action, auto_approve=True)

        assert result.status == RemediationStatus.SUCCESS
        assert result.dry_run is True

    @pytest.mark.asyncio
    async def test_high_risk_azure_action_skipped(self):
        """Test that high-risk Azure actions are skipped with low max_risk_level."""
        engine = RemediationEngine(
            require_approval=False,
            max_risk_level=RiskLevel.LOW,
        )

        action = RemoveNSGOpenSSHAction(
            check_id="soc2-cc6.3-azure-nsg-no-public-ssh",
            resource_id="my-nsg",
            resource_data={"name": "my-nsg"},
            subscription_id="sub-123",
            resource_group="rg",
            nsg_name="my-nsg",
            dry_run=True,
        )

        result = await engine.execute_action(action, auto_approve=False)

        assert result.status == RemediationStatus.SKIPPED
        assert "exceeds maximum" in result.message

    @pytest.mark.asyncio
    async def test_plan_with_azure_actions(self):
        """Test creating and summarizing a plan with Azure actions."""
        plan = RemediationPlan()

        # Add LOW risk action
        plan.add_action(
            EnableStorageSoftDeleteAction(
                check_id="soc2-cc7.3-azure-storage-soft-delete",
                resource_id="account1",
                resource_data={},
                subscription_id="sub",
                resource_group="rg",
                storage_account_name="account1",
            )
        )

        # Add MEDIUM risk action
        plan.add_action(
            BlockStoragePublicAccessAction(
                check_id="soc2-cc6.6-azure-storage-public-access-disabled",
                resource_id="account2",
                resource_data={},
                subscription_id="sub",
                resource_group="rg",
                storage_account_name="account2",
            )
        )

        # Add HIGH risk action
        plan.add_action(
            RemoveNSGOpenSSHAction(
                check_id="soc2-cc6.3-azure-nsg-no-public-ssh",
                resource_id="nsg1",
                resource_data={},
                subscription_id="sub",
                resource_group="rg",
                nsg_name="nsg1",
            )
        )

        summary = plan.get_summary()

        assert summary["total_actions"] == 3
        assert summary["by_risk_level"]["low"] == 1
        assert summary["by_risk_level"]["medium"] == 1
        assert summary["by_risk_level"]["high"] == 1
