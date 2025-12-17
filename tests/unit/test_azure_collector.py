"""
Unit tests for Azure collector.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from attestful.core.models import CollectionResult, Evidence, Resource


# Mock the Azure SDK before importing the collector
@pytest.fixture(autouse=True)
def mock_azure_sdk():
    """Mock Azure SDK modules."""
    mock_modules = {
        "azure.identity": MagicMock(),
        "azure.mgmt.compute": MagicMock(),
        "azure.mgmt.network": MagicMock(),
        "azure.mgmt.resource": MagicMock(),
        "azure.mgmt.storage": MagicMock(),
        "azure.mgmt.keyvault": MagicMock(),
        "azure.mgmt.sql": MagicMock(),
        "azure.mgmt.monitor": MagicMock(),
        "azure.core.exceptions": MagicMock(),
    }

    with patch.dict("sys.modules", mock_modules):
        # Set AZURE_SDK_AVAILABLE to True
        import attestful.collectors.cloud.azure as azure_module

        azure_module.AZURE_SDK_AVAILABLE = True
        azure_module.AzureError = Exception
        azure_module.ClientAuthenticationError = Exception
        azure_module.HttpResponseError = Exception

        yield


class TestAzureCollectorConfig:
    """Tests for AzureCollectorConfig."""

    def test_default_config(self, mock_azure_sdk):
        """Test default configuration values."""
        from attestful.collectors.cloud.azure import AzureCollectorConfig

        config = AzureCollectorConfig()

        assert config.tenant_id is None
        assert config.client_id is None
        assert config.client_secret is None
        assert config.subscription_id is None
        assert config.use_managed_identity is False
        assert config.subscription_ids == []
        assert config.resource_groups == []
        assert config.max_retries == 3
        assert config.timeout == 30

    def test_custom_config(self, mock_azure_sdk):
        """Test custom configuration values."""
        from attestful.collectors.cloud.azure import AzureCollectorConfig

        config = AzureCollectorConfig(
            tenant_id="test-tenant",
            client_id="test-client",
            client_secret="test-secret",
            subscription_id="test-sub-1",
            subscription_ids=["test-sub-1", "test-sub-2"],
            resource_groups=["rg-1", "rg-2"],
            use_managed_identity=False,
            max_retries=5,
            timeout=60,
        )

        assert config.tenant_id == "test-tenant"
        assert config.client_id == "test-client"
        assert config.client_secret == "test-secret"
        assert config.subscription_id == "test-sub-1"
        assert config.subscription_ids == ["test-sub-1", "test-sub-2"]
        assert config.resource_groups == ["rg-1", "rg-2"]
        assert config.max_retries == 5
        assert config.timeout == 60

    def test_managed_identity_config(self, mock_azure_sdk):
        """Test managed identity configuration."""
        from attestful.collectors.cloud.azure import AzureCollectorConfig

        config = AzureCollectorConfig(
            use_managed_identity=True,
            subscription_id="test-sub",
        )

        assert config.use_managed_identity is True
        assert config.subscription_id == "test-sub"


class TestAzureCollector:
    """Tests for AzureCollector."""

    def test_init_with_config(self, mock_azure_sdk):
        """Test initialization with configuration."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        config = AzureCollectorConfig(
            tenant_id="test-tenant",
            client_id="test-client",
            client_secret="test-secret",
            subscription_ids=["sub-1"],
        )

        collector = AzureCollector(config=config)

        assert collector.config == config
        assert collector.PLATFORM == "azure"

    def test_init_without_config(self, mock_azure_sdk):
        """Test initialization without configuration."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        collector = AzureCollector()

        assert isinstance(collector.config, AzureCollectorConfig)

    def test_supported_resource_types(self, mock_azure_sdk):
        """Test supported resource types."""
        from attestful.collectors.cloud.azure import AzureCollector

        collector = AzureCollector()

        assert "virtual_machine" in collector.SUPPORTED_RESOURCE_TYPES
        assert "network_security_group" in collector.SUPPORTED_RESOURCE_TYPES
        assert "virtual_network" in collector.SUPPORTED_RESOURCE_TYPES
        assert "storage_account" in collector.SUPPORTED_RESOURCE_TYPES
        assert "key_vault" in collector.SUPPORTED_RESOURCE_TYPES
        assert "sql_server" in collector.SUPPORTED_RESOURCE_TYPES
        assert "sql_database" in collector.SUPPORTED_RESOURCE_TYPES
        assert "disk" in collector.SUPPORTED_RESOURCE_TYPES
        assert "public_ip" in collector.SUPPORTED_RESOURCE_TYPES
        assert "load_balancer" in collector.SUPPORTED_RESOURCE_TYPES
        assert len(collector.SUPPORTED_RESOURCE_TYPES) == 10

    def test_supported_evidence_types(self, mock_azure_sdk):
        """Test supported evidence types."""
        from attestful.collectors.cloud.azure import AzureCollector

        collector = AzureCollector()

        assert "subscription_info" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "security_center_status" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "policy_assignments" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "role_assignments" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "activity_log" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "diagnostic_settings" in collector.SUPPORTED_EVIDENCE_TYPES
        assert len(collector.SUPPORTED_EVIDENCE_TYPES) == 6


class TestAzureCredentials:
    """Tests for Azure credential handling."""

    def test_service_principal_credential(self, mock_azure_sdk):
        """Test service principal credential creation."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        config = AzureCollectorConfig(
            tenant_id="test-tenant",
            client_id="test-client",
            client_secret="test-secret",
        )

        collector = AzureCollector(config=config)

        with patch(
            "attestful.collectors.cloud.azure.ClientSecretCredential"
        ) as mock_cred:
            credential = collector._get_credential()
            mock_cred.assert_called_once_with(
                tenant_id="test-tenant",
                client_id="test-client",
                client_secret="test-secret",
            )

    def test_managed_identity_credential(self, mock_azure_sdk):
        """Test managed identity credential creation."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        config = AzureCollectorConfig(use_managed_identity=True)

        collector = AzureCollector(config=config)

        with patch(
            "attestful.collectors.cloud.azure.ManagedIdentityCredential"
        ) as mock_cred:
            credential = collector._get_credential()
            mock_cred.assert_called_once()

    def test_default_credential(self, mock_azure_sdk):
        """Test default credential chain."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        config = AzureCollectorConfig()

        collector = AzureCollector(config=config)

        with patch(
            "attestful.collectors.cloud.azure.DefaultAzureCredential"
        ) as mock_cred:
            credential = collector._get_credential()
            mock_cred.assert_called_once()


class TestSubscriptionDiscovery:
    """Tests for subscription discovery."""

    def test_explicit_subscription_ids(self, mock_azure_sdk):
        """Test using explicit subscription IDs."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        config = AzureCollectorConfig(subscription_ids=["sub-1", "sub-2"])

        collector = AzureCollector(config=config)
        subscription_ids = collector._get_subscription_ids()

        assert subscription_ids == ["sub-1", "sub-2"]

    def test_single_subscription_id(self, mock_azure_sdk):
        """Test using single subscription ID."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        config = AzureCollectorConfig(subscription_id="sub-1")

        collector = AzureCollector(config=config)
        subscription_ids = collector._get_subscription_ids()

        assert subscription_ids == ["sub-1"]


class TestResourceCollection:
    """Tests for resource collection."""

    def test_collect_virtual_machines(self, mock_azure_sdk):
        """Test collecting virtual machines."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        # Create mock VM
        mock_vm = MagicMock()
        mock_vm.id = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1"
        mock_vm.name = "vm-1"
        mock_vm.location = "eastus"
        mock_vm.as_dict.return_value = {
            "id": mock_vm.id,
            "name": "vm-1",
            "location": "eastus",
            "hardware_profile": {"vm_size": "Standard_DS2_v2"},
        }

        config = AzureCollectorConfig(subscription_ids=["sub-1"])
        collector = AzureCollector(config=config)

        with patch.object(collector, "_get_compute_client") as mock_client:
            mock_compute = MagicMock()
            mock_compute.virtual_machines.list_all.return_value = [mock_vm]
            mock_client.return_value = mock_compute

            resources = collector.collect_resources(resource_types=["virtual_machine"])

            assert len(resources) == 1
            assert resources[0].type == "virtual_machine"
            assert resources[0].provider == "azure"
            assert resources[0].region == "eastus"
            assert resources[0].name == "vm-1"
            assert resources[0].raw_data["subscription_id"] == "sub-1"
            assert resources[0].raw_data["resource_group"] == "rg-1"

    def test_collect_network_security_groups(self, mock_azure_sdk):
        """Test collecting NSGs."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        mock_nsg = MagicMock()
        mock_nsg.id = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkSecurityGroups/nsg-1"
        mock_nsg.name = "nsg-1"
        mock_nsg.location = "westus"
        mock_nsg.as_dict.return_value = {
            "id": mock_nsg.id,
            "name": "nsg-1",
            "location": "westus",
            "security_rules": [],
        }

        config = AzureCollectorConfig(subscription_ids=["sub-1"])
        collector = AzureCollector(config=config)

        with patch.object(collector, "_get_network_client") as mock_client:
            mock_network = MagicMock()
            mock_network.network_security_groups.list_all.return_value = [mock_nsg]
            mock_client.return_value = mock_network

            resources = collector.collect_resources(
                resource_types=["network_security_group"]
            )

            assert len(resources) == 1
            assert resources[0].type == "network_security_group"
            assert resources[0].name == "nsg-1"

    def test_collect_storage_accounts(self, mock_azure_sdk):
        """Test collecting storage accounts."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        mock_storage = MagicMock()
        mock_storage.id = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/storage1"
        mock_storage.name = "storage1"
        mock_storage.location = "eastus2"
        mock_storage.as_dict.return_value = {
            "id": mock_storage.id,
            "name": "storage1",
            "location": "eastus2",
            "sku": {"name": "Standard_LRS"},
        }

        config = AzureCollectorConfig(subscription_ids=["sub-1"])
        collector = AzureCollector(config=config)

        with patch.object(collector, "_get_storage_client") as mock_client:
            mock_storage_client = MagicMock()
            mock_storage_client.storage_accounts.list.return_value = [mock_storage]
            mock_storage_client.storage_accounts.get_properties.side_effect = Exception(
                "Not found"
            )
            mock_client.return_value = mock_storage_client

            resources = collector.collect_resources(resource_types=["storage_account"])

            assert len(resources) == 1
            assert resources[0].type == "storage_account"
            assert resources[0].name == "storage1"

    def test_collect_key_vaults(self, mock_azure_sdk):
        """Test collecting Key Vaults."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        mock_vault = MagicMock()
        mock_vault.id = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/vault1"
        mock_vault.name = "vault1"
        mock_vault.location = "centralus"
        mock_vault.as_dict.return_value = {
            "id": mock_vault.id,
            "name": "vault1",
            "location": "centralus",
        }

        config = AzureCollectorConfig(subscription_ids=["sub-1"])
        collector = AzureCollector(config=config)

        with patch.object(collector, "_get_keyvault_client") as mock_client:
            mock_kv = MagicMock()
            mock_kv.vaults.list.return_value = [mock_vault]
            mock_client.return_value = mock_kv

            resources = collector.collect_resources(resource_types=["key_vault"])

            assert len(resources) == 1
            assert resources[0].type == "key_vault"
            assert resources[0].name == "vault1"

    def test_collect_sql_servers(self, mock_azure_sdk):
        """Test collecting SQL servers."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        mock_server = MagicMock()
        mock_server.id = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Sql/servers/sqlserver1"
        mock_server.name = "sqlserver1"
        mock_server.location = "northeurope"
        mock_server.as_dict.return_value = {
            "id": mock_server.id,
            "name": "sqlserver1",
            "location": "northeurope",
        }

        config = AzureCollectorConfig(subscription_ids=["sub-1"])
        collector = AzureCollector(config=config)

        with patch.object(collector, "_get_sql_client") as mock_client:
            mock_sql = MagicMock()
            mock_sql.servers.list.return_value = [mock_server]
            mock_client.return_value = mock_sql

            resources = collector.collect_resources(resource_types=["sql_server"])

            assert len(resources) == 1
            assert resources[0].type == "sql_server"
            assert resources[0].name == "sqlserver1"

    def test_collect_multiple_resource_types(self, mock_azure_sdk):
        """Test collecting multiple resource types."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        mock_vm = MagicMock()
        mock_vm.id = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1"
        mock_vm.name = "vm-1"
        mock_vm.location = "eastus"
        mock_vm.as_dict.return_value = {"id": mock_vm.id, "name": "vm-1"}

        mock_nsg = MagicMock()
        mock_nsg.id = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/networkSecurityGroups/nsg-1"
        mock_nsg.name = "nsg-1"
        mock_nsg.location = "eastus"
        mock_nsg.as_dict.return_value = {"id": mock_nsg.id, "name": "nsg-1"}

        config = AzureCollectorConfig(subscription_ids=["sub-1"])
        collector = AzureCollector(config=config)

        with (
            patch.object(collector, "_get_compute_client") as mock_compute,
            patch.object(collector, "_get_network_client") as mock_network,
        ):
            mock_compute_client = MagicMock()
            mock_compute_client.virtual_machines.list_all.return_value = [mock_vm]
            mock_compute.return_value = mock_compute_client

            mock_network_client = MagicMock()
            mock_network_client.network_security_groups.list_all.return_value = [
                mock_nsg
            ]
            mock_network.return_value = mock_network_client

            resources = collector.collect_resources(
                resource_types=["virtual_machine", "network_security_group"]
            )

            assert len(resources) == 2
            types = {r.type for r in resources}
            assert types == {"virtual_machine", "network_security_group"}

    def test_collect_unknown_resource_type(self, mock_azure_sdk):
        """Test handling unknown resource types."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        config = AzureCollectorConfig(subscription_ids=["sub-1"])
        collector = AzureCollector(config=config)

        resources = collector.collect_resources(resource_types=["unknown_type"])

        assert len(resources) == 0


class TestEvidenceCollection:
    """Tests for evidence collection."""

    def test_collect_subscription_info(self, mock_azure_sdk):
        """Test collecting subscription info."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        mock_sub = MagicMock()
        mock_sub.as_dict.return_value = {
            "subscription_id": "sub-1",
            "display_name": "Test Subscription",
            "state": "Enabled",
        }

        config = AzureCollectorConfig(subscription_ids=["sub-1"])
        collector = AzureCollector(config=config)

        with (
            patch.object(collector, "_get_credential") as mock_cred,
            patch("attestful.collectors.cloud.azure.SubscriptionClient") as mock_client,
        ):
            mock_sub_client = MagicMock()
            mock_sub_client.subscriptions.list.return_value = [mock_sub]
            mock_client.return_value = mock_sub_client

            result = collector.collect_evidence(evidence_types=["subscription_info"])

            assert isinstance(result, CollectionResult)
            assert result.platform == "azure"
            assert len(result.evidence) == 1
            assert result.evidence[0].evidence_type == "subscription_info"
            assert "subscriptions" in result.evidence[0].raw_data

    def test_collect_policy_assignments(self, mock_azure_sdk):
        """Test collecting policy assignments."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        config = AzureCollectorConfig(subscription_ids=["sub-1"])
        collector = AzureCollector(config=config)

        # Mock ImportError for azure.mgmt.resource.policy
        with patch.object(collector, "_rate_limit"):
            with patch.dict("sys.modules", {"azure.mgmt.resource.policy": None}):
                # This should handle the import error gracefully
                result = collector.collect_evidence(evidence_types=["policy_assignments"])

                assert isinstance(result, CollectionResult)
                assert result.platform == "azure"

    def test_collect_multiple_evidence_types(self, mock_azure_sdk):
        """Test collecting multiple evidence types."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        mock_sub = MagicMock()
        mock_sub.as_dict.return_value = {"subscription_id": "sub-1"}

        config = AzureCollectorConfig(subscription_ids=["sub-1"])
        collector = AzureCollector(config=config)

        with (
            patch.object(collector, "_get_credential") as mock_cred,
            patch("attestful.collectors.cloud.azure.SubscriptionClient") as mock_client,
            patch.object(collector, "_get_monitor_client") as mock_monitor,
        ):
            mock_sub_client = MagicMock()
            mock_sub_client.subscriptions.list.return_value = [mock_sub]
            mock_client.return_value = mock_sub_client

            mock_monitor_client = MagicMock()
            mock_monitor_client.subscription_diagnostic_settings.list.return_value = []
            mock_monitor.return_value = mock_monitor_client

            result = collector.collect_evidence(
                evidence_types=["subscription_info", "diagnostic_settings"]
            )

            assert isinstance(result, CollectionResult)
            assert len(result.evidence) == 2
            types = {e.evidence_type for e in result.evidence}
            assert "subscription_info" in types
            assert "diagnostic_settings" in types

    def test_collect_unknown_evidence_type(self, mock_azure_sdk):
        """Test handling unknown evidence types."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        config = AzureCollectorConfig(subscription_ids=["sub-1"])
        collector = AzureCollector(config=config)

        result = collector.collect_evidence(evidence_types=["unknown_type"])

        assert isinstance(result, CollectionResult)
        assert len(result.evidence) == 0


class TestAzureCollectorIntegration:
    """Integration tests for Azure collector."""

    def test_full_collection_workflow(self, mock_azure_sdk):
        """Test full collection workflow."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        mock_vm = MagicMock()
        mock_vm.id = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1"
        mock_vm.name = "vm-1"
        mock_vm.location = "eastus"
        mock_vm.as_dict.return_value = {"id": mock_vm.id, "name": "vm-1"}

        mock_sub = MagicMock()
        mock_sub.as_dict.return_value = {"subscription_id": "sub-1"}

        config = AzureCollectorConfig(
            tenant_id="test-tenant",
            client_id="test-client",
            client_secret="test-secret",
            subscription_ids=["sub-1"],
        )
        collector = AzureCollector(config=config)

        with (
            patch.object(collector, "_get_credential") as mock_cred,
            patch.object(collector, "_get_compute_client") as mock_compute,
            patch("attestful.collectors.cloud.azure.SubscriptionClient") as mock_sub_client,
        ):
            mock_compute_client = MagicMock()
            mock_compute_client.virtual_machines.list_all.return_value = [mock_vm]
            mock_compute.return_value = mock_compute_client

            mock_subscription_client = MagicMock()
            mock_subscription_client.subscriptions.list.return_value = [mock_sub]
            mock_sub_client.return_value = mock_subscription_client

            # Collect resources
            resources = collector.collect_resources(resource_types=["virtual_machine"])
            assert len(resources) == 1

            # Collect evidence
            evidence = collector.collect_evidence(evidence_types=["subscription_info"])
            assert len(evidence.evidence) == 1

    def test_error_handling_during_collection(self, mock_azure_sdk):
        """Test error handling during collection."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        config = AzureCollectorConfig(subscription_ids=["sub-1"])
        collector = AzureCollector(config=config)

        with patch.object(collector, "_get_compute_client") as mock_compute:
            mock_compute_client = MagicMock()
            mock_compute_client.virtual_machines.list_all.side_effect = Exception(
                "API Error"
            )
            mock_compute.return_value = mock_compute_client

            # Should not raise, just log error and return empty
            resources = collector.collect_resources(resource_types=["virtual_machine"])
            assert len(resources) == 0

    def test_multiple_subscriptions(self, mock_azure_sdk):
        """Test collecting from multiple subscriptions."""
        from attestful.collectors.cloud.azure import (
            AzureCollector,
            AzureCollectorConfig,
        )

        mock_vm1 = MagicMock()
        mock_vm1.id = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1"
        mock_vm1.name = "vm-1"
        mock_vm1.location = "eastus"
        mock_vm1.as_dict.return_value = {"id": mock_vm1.id, "name": "vm-1"}

        mock_vm2 = MagicMock()
        mock_vm2.id = "/subscriptions/sub-2/resourceGroups/rg-2/providers/Microsoft.Compute/virtualMachines/vm-2"
        mock_vm2.name = "vm-2"
        mock_vm2.location = "westus"
        mock_vm2.as_dict.return_value = {"id": mock_vm2.id, "name": "vm-2"}

        config = AzureCollectorConfig(subscription_ids=["sub-1", "sub-2"])
        collector = AzureCollector(config=config)

        call_count = 0

        def mock_compute_client(sub_id):
            nonlocal call_count
            mock_client = MagicMock()
            if sub_id == "sub-1":
                mock_client.virtual_machines.list_all.return_value = [mock_vm1]
            else:
                mock_client.virtual_machines.list_all.return_value = [mock_vm2]
            call_count += 1
            return mock_client

        with patch.object(
            collector, "_get_compute_client", side_effect=mock_compute_client
        ):
            resources = collector.collect_resources(resource_types=["virtual_machine"])

            assert len(resources) == 2
            assert call_count == 2
            names = {r.name for r in resources}
            assert names == {"vm-1", "vm-2"}


class TestAzureCollectorSdkNotAvailable:
    """Tests for when Azure SDK is not available."""

    def test_raises_error_without_sdk(self):
        """Test that collector raises error when SDK is not available."""
        import attestful.collectors.cloud.azure as azure_module

        # Temporarily set SDK as unavailable
        original_value = azure_module.AZURE_SDK_AVAILABLE
        azure_module.AZURE_SDK_AVAILABLE = False

        try:
            from attestful.collectors.cloud.azure import AzureCollector
            from attestful.core.exceptions import ConfigurationError

            with pytest.raises(ConfigurationError) as exc_info:
                AzureCollector()

            assert "Azure SDK not installed" in str(exc_info.value)
        finally:
            azure_module.AZURE_SDK_AVAILABLE = original_value
