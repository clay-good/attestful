"""
Azure collector for Attestful.

Dual-mode collector supporting both resource collection (for compliance checks)
and evidence collection (for audit documentation).

Requires azure-identity and azure-mgmt-* packages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator

from attestful.collectors.base import BaseCollector
from attestful.core.exceptions import CollectionError, ConfigurationError
from attestful.core.logging import get_logger
from attestful.core.models import CollectionResult, Evidence, Resource

logger = get_logger(__name__)

# Optional Azure SDK imports
try:
    from azure.identity import (
        ClientSecretCredential,
        DefaultAzureCredential,
        ManagedIdentityCredential,
    )
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.keyvault import KeyVaultManagementClient
    from azure.mgmt.sql import SqlManagementClient
    from azure.mgmt.monitor import MonitorManagementClient
    from azure.core.exceptions import (
        AzureError,
        ClientAuthenticationError,
        HttpResponseError,
    )

    AZURE_SDK_AVAILABLE = True
except ImportError:
    AZURE_SDK_AVAILABLE = False
    AzureError = Exception
    ClientAuthenticationError = Exception
    HttpResponseError = Exception


@dataclass
class AzureCollectorConfig:
    """Configuration for Azure collector."""

    # Authentication options
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    subscription_id: str | None = None
    use_managed_identity: bool = False

    # Scanning scope
    subscription_ids: list[str] = field(default_factory=list)
    resource_groups: list[str] = field(default_factory=list)

    # Rate limiting
    max_retries: int = 3
    timeout: int = 30


class AzureCollector(BaseCollector):
    """
    Azure collector for infrastructure resources and compliance evidence.

    Supports dual-mode operation:
    - Resource mode: Collects Azure resources for compliance checking
    - Evidence mode: Collects Azure configuration evidence for audits

    Resource Types:
    - virtual_machine: Azure VMs
    - network_security_group: NSGs
    - virtual_network: VNets
    - storage_account: Storage accounts
    - key_vault: Key Vaults
    - sql_server: SQL servers
    - sql_database: SQL databases
    - disk: Managed disks
    - public_ip: Public IP addresses
    - load_balancer: Load balancers

    Evidence Types:
    - subscription_info: Subscription details
    - security_center_status: Defender for Cloud status
    - policy_assignments: Azure Policy assignments
    - role_assignments: RBAC role assignments
    - activity_log: Activity log summary
    - diagnostic_settings: Diagnostic settings status

    Example:
        collector = AzureCollector(
            config=AzureCollectorConfig(
                tenant_id="...",
                client_id="...",
                client_secret="...",
                subscription_ids=["..."],
            )
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["virtual_machine", "storage_account"]
        )

        # Collect evidence for audits
        result = collector.collect_evidence(
            evidence_types=["security_center_status", "policy_assignments"]
        )
    """

    PLATFORM = "azure"
    SUPPORTED_RESOURCE_TYPES = [
        "virtual_machine",
        "network_security_group",
        "virtual_network",
        "storage_account",
        "key_vault",
        "sql_server",
        "sql_database",
        "disk",
        "public_ip",
        "load_balancer",
    ]
    SUPPORTED_EVIDENCE_TYPES = [
        "subscription_info",
        "security_center_status",
        "policy_assignments",
        "role_assignments",
        "activity_log",
        "diagnostic_settings",
    ]

    def __init__(
        self,
        config: AzureCollectorConfig | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize Azure collector.

        Args:
            config: Azure collector configuration.
            **kwargs: Additional arguments passed to BaseCollector.
        """
        if not AZURE_SDK_AVAILABLE:
            raise ConfigurationError(
                "Azure SDK not installed. Install with: pip install azure-identity azure-mgmt-resource "
                "azure-mgmt-compute azure-mgmt-network azure-mgmt-storage azure-mgmt-keyvault "
                "azure-mgmt-sql azure-mgmt-monitor"
            )

        super().__init__(**kwargs)
        self.config = config or AzureCollectorConfig()
        self._credential: Any = None
        self._subscription_ids: list[str] | None = None

    def _get_credential(self) -> Any:
        """Get Azure credential for authentication."""
        if self._credential is None:
            if self.config.use_managed_identity:
                self._credential = ManagedIdentityCredential()
                logger.info("Using managed identity authentication")
            elif self.config.client_id and self.config.client_secret and self.config.tenant_id:
                self._credential = ClientSecretCredential(
                    tenant_id=self.config.tenant_id,
                    client_id=self.config.client_id,
                    client_secret=self.config.client_secret,
                )
                logger.info("Using service principal authentication")
            else:
                self._credential = DefaultAzureCredential()
                logger.info("Using default Azure credential chain")

        return self._credential

    def _get_subscription_ids(self) -> list[str]:
        """Get subscription IDs to scan."""
        if self._subscription_ids is not None:
            return self._subscription_ids

        if self.config.subscription_ids:
            self._subscription_ids = self.config.subscription_ids
            return self._subscription_ids

        if self.config.subscription_id:
            self._subscription_ids = [self.config.subscription_id]
            return self._subscription_ids

        # Discover all subscriptions
        credential = self._get_credential()
        subscription_client = SubscriptionClient(credential)

        self._subscription_ids = []
        for sub in subscription_client.subscriptions.list():
            if sub.state == "Enabled":
                self._subscription_ids.append(sub.subscription_id)

        logger.info(f"Discovered {len(self._subscription_ids)} Azure subscriptions")
        return self._subscription_ids

    def _get_resource_client(self, subscription_id: str) -> Any:
        """Get Resource Management client."""
        credential = self._get_credential()
        return ResourceManagementClient(credential, subscription_id)

    def _get_compute_client(self, subscription_id: str) -> Any:
        """Get Compute Management client."""
        credential = self._get_credential()
        return ComputeManagementClient(credential, subscription_id)

    def _get_network_client(self, subscription_id: str) -> Any:
        """Get Network Management client."""
        credential = self._get_credential()
        return NetworkManagementClient(credential, subscription_id)

    def _get_storage_client(self, subscription_id: str) -> Any:
        """Get Storage Management client."""
        credential = self._get_credential()
        return StorageManagementClient(credential, subscription_id)

    def _get_keyvault_client(self, subscription_id: str) -> Any:
        """Get Key Vault Management client."""
        credential = self._get_credential()
        return KeyVaultManagementClient(credential, subscription_id)

    def _get_sql_client(self, subscription_id: str) -> Any:
        """Get SQL Management client."""
        credential = self._get_credential()
        return SqlManagementClient(credential, subscription_id)

    def _get_monitor_client(self, subscription_id: str) -> Any:
        """Get Monitor Management client."""
        credential = self._get_credential()
        return MonitorManagementClient(credential, subscription_id)

    def validate_credentials(self) -> bool:
        """Validate Azure credentials."""
        try:
            credential = self._get_credential()
            subscription_client = SubscriptionClient(credential)

            # Try to list subscriptions to validate credentials
            subscriptions = list(subscription_client.subscriptions.list())
            if subscriptions:
                logger.info(f"Validated Azure credentials, found {len(subscriptions)} subscription(s)")
                return True
            else:
                logger.warning("No Azure subscriptions accessible")
                return False
        except ClientAuthenticationError as e:
            logger.error(f"Azure authentication failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Azure credential validation failed: {e}")
            return False

    # =========================================================================
    # Resource Collection Methods
    # =========================================================================

    def collect_resources(
        self,
        *,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """
        Collect Azure resources.

        Args:
            resource_types: List of resource types to collect.

        Returns:
            List of collected resources.
        """
        types_to_collect = resource_types or self.SUPPORTED_RESOURCE_TYPES
        resources: list[Resource] = []

        for resource_type in types_to_collect:
            if resource_type not in self.SUPPORTED_RESOURCE_TYPES:
                logger.warning(f"Unknown resource type: {resource_type}")
                continue

            collector_method = getattr(self, f"_collect_{resource_type}", None)
            if collector_method is None:
                logger.warning(f"No collector for resource type: {resource_type}")
                continue

            try:
                collected = list(collector_method())
                resources.extend(collected)
                logger.debug(f"Collected {len(collected)} {resource_type} resources")
            except Exception as e:
                logger.error(f"Failed to collect {resource_type}: {e}")

        return resources

    def _collect_virtual_machine(self) -> Iterator[Resource]:
        """Collect Azure VMs."""
        for subscription_id in self._get_subscription_ids():
            self._rate_limit()
            compute_client = self._get_compute_client(subscription_id)

            try:
                for vm in compute_client.virtual_machines.list_all():
                    vm_data = vm.as_dict()

                    # Extract resource group and location
                    resource_group = vm.id.split("/")[4] if vm.id else "unknown"
                    location = vm.location or "unknown"

                    yield Resource(
                        id=vm.id,
                        type="virtual_machine",
                        provider="azure",
                        region=location,
                        name=vm.name,
                        raw_data={
                            **vm_data,
                            "subscription_id": subscription_id,
                            "resource_group": resource_group,
                        },
                    )
            except HttpResponseError as e:
                logger.error(f"Failed to collect VMs in subscription {subscription_id}: {e}")

    def _collect_network_security_group(self) -> Iterator[Resource]:
        """Collect Network Security Groups."""
        for subscription_id in self._get_subscription_ids():
            self._rate_limit()
            network_client = self._get_network_client(subscription_id)

            try:
                for nsg in network_client.network_security_groups.list_all():
                    nsg_data = nsg.as_dict()
                    resource_group = nsg.id.split("/")[4] if nsg.id else "unknown"

                    yield Resource(
                        id=nsg.id,
                        type="network_security_group",
                        provider="azure",
                        region=nsg.location or "unknown",
                        name=nsg.name,
                        raw_data={
                            **nsg_data,
                            "subscription_id": subscription_id,
                            "resource_group": resource_group,
                        },
                    )
            except HttpResponseError as e:
                logger.error(f"Failed to collect NSGs in subscription {subscription_id}: {e}")

    def _collect_virtual_network(self) -> Iterator[Resource]:
        """Collect Virtual Networks."""
        for subscription_id in self._get_subscription_ids():
            self._rate_limit()
            network_client = self._get_network_client(subscription_id)

            try:
                for vnet in network_client.virtual_networks.list_all():
                    vnet_data = vnet.as_dict()
                    resource_group = vnet.id.split("/")[4] if vnet.id else "unknown"

                    yield Resource(
                        id=vnet.id,
                        type="virtual_network",
                        provider="azure",
                        region=vnet.location or "unknown",
                        name=vnet.name,
                        raw_data={
                            **vnet_data,
                            "subscription_id": subscription_id,
                            "resource_group": resource_group,
                        },
                    )
            except HttpResponseError as e:
                logger.error(f"Failed to collect VNets in subscription {subscription_id}: {e}")

    def _collect_storage_account(self) -> Iterator[Resource]:
        """Collect Storage Accounts."""
        for subscription_id in self._get_subscription_ids():
            self._rate_limit()
            storage_client = self._get_storage_client(subscription_id)

            try:
                for account in storage_client.storage_accounts.list():
                    account_data = account.as_dict()
                    resource_group = account.id.split("/")[4] if account.id else "unknown"

                    # Get additional properties
                    try:
                        props = storage_client.storage_accounts.get_properties(
                            resource_group, account.name
                        )
                        account_data["properties"] = props.as_dict()
                    except HttpResponseError:
                        pass

                    yield Resource(
                        id=account.id,
                        type="storage_account",
                        provider="azure",
                        region=account.location or "unknown",
                        name=account.name,
                        raw_data={
                            **account_data,
                            "subscription_id": subscription_id,
                            "resource_group": resource_group,
                        },
                    )
            except HttpResponseError as e:
                logger.error(f"Failed to collect storage accounts in subscription {subscription_id}: {e}")

    def _collect_key_vault(self) -> Iterator[Resource]:
        """Collect Key Vaults."""
        for subscription_id in self._get_subscription_ids():
            self._rate_limit()
            kv_client = self._get_keyvault_client(subscription_id)

            try:
                for vault in kv_client.vaults.list():
                    vault_data = vault.as_dict()
                    resource_group = vault.id.split("/")[4] if vault.id else "unknown"

                    yield Resource(
                        id=vault.id,
                        type="key_vault",
                        provider="azure",
                        region=vault.location or "unknown",
                        name=vault.name,
                        raw_data={
                            **vault_data,
                            "subscription_id": subscription_id,
                            "resource_group": resource_group,
                        },
                    )
            except HttpResponseError as e:
                logger.error(f"Failed to collect Key Vaults in subscription {subscription_id}: {e}")

    def _collect_sql_server(self) -> Iterator[Resource]:
        """Collect SQL Servers."""
        for subscription_id in self._get_subscription_ids():
            self._rate_limit()
            sql_client = self._get_sql_client(subscription_id)

            try:
                for server in sql_client.servers.list():
                    server_data = server.as_dict()
                    resource_group = server.id.split("/")[4] if server.id else "unknown"

                    yield Resource(
                        id=server.id,
                        type="sql_server",
                        provider="azure",
                        region=server.location or "unknown",
                        name=server.name,
                        raw_data={
                            **server_data,
                            "subscription_id": subscription_id,
                            "resource_group": resource_group,
                        },
                    )
            except HttpResponseError as e:
                logger.error(f"Failed to collect SQL servers in subscription {subscription_id}: {e}")

    def _collect_sql_database(self) -> Iterator[Resource]:
        """Collect SQL Databases."""
        for subscription_id in self._get_subscription_ids():
            self._rate_limit()
            sql_client = self._get_sql_client(subscription_id)

            try:
                for server in sql_client.servers.list():
                    resource_group = server.id.split("/")[4] if server.id else "unknown"

                    try:
                        for db in sql_client.databases.list_by_server(resource_group, server.name):
                            # Skip system databases
                            if db.name in ["master", "model", "msdb", "tempdb"]:
                                continue

                            db_data = db.as_dict()

                            yield Resource(
                                id=db.id,
                                type="sql_database",
                                provider="azure",
                                region=db.location or server.location or "unknown",
                                name=db.name,
                                raw_data={
                                    **db_data,
                                    "subscription_id": subscription_id,
                                    "resource_group": resource_group,
                                    "server_name": server.name,
                                },
                            )
                    except HttpResponseError as e:
                        logger.warning(f"Failed to list databases for server {server.name}: {e}")
            except HttpResponseError as e:
                logger.error(f"Failed to collect SQL databases in subscription {subscription_id}: {e}")

    def _collect_disk(self) -> Iterator[Resource]:
        """Collect Managed Disks."""
        for subscription_id in self._get_subscription_ids():
            self._rate_limit()
            compute_client = self._get_compute_client(subscription_id)

            try:
                for disk in compute_client.disks.list():
                    disk_data = disk.as_dict()
                    resource_group = disk.id.split("/")[4] if disk.id else "unknown"

                    yield Resource(
                        id=disk.id,
                        type="disk",
                        provider="azure",
                        region=disk.location or "unknown",
                        name=disk.name,
                        raw_data={
                            **disk_data,
                            "subscription_id": subscription_id,
                            "resource_group": resource_group,
                        },
                    )
            except HttpResponseError as e:
                logger.error(f"Failed to collect disks in subscription {subscription_id}: {e}")

    def _collect_public_ip(self) -> Iterator[Resource]:
        """Collect Public IP Addresses."""
        for subscription_id in self._get_subscription_ids():
            self._rate_limit()
            network_client = self._get_network_client(subscription_id)

            try:
                for pip in network_client.public_ip_addresses.list_all():
                    pip_data = pip.as_dict()
                    resource_group = pip.id.split("/")[4] if pip.id else "unknown"

                    yield Resource(
                        id=pip.id,
                        type="public_ip",
                        provider="azure",
                        region=pip.location or "unknown",
                        name=pip.name,
                        raw_data={
                            **pip_data,
                            "subscription_id": subscription_id,
                            "resource_group": resource_group,
                        },
                    )
            except HttpResponseError as e:
                logger.error(f"Failed to collect public IPs in subscription {subscription_id}: {e}")

    def _collect_load_balancer(self) -> Iterator[Resource]:
        """Collect Load Balancers."""
        for subscription_id in self._get_subscription_ids():
            self._rate_limit()
            network_client = self._get_network_client(subscription_id)

            try:
                for lb in network_client.load_balancers.list_all():
                    lb_data = lb.as_dict()
                    resource_group = lb.id.split("/")[4] if lb.id else "unknown"

                    yield Resource(
                        id=lb.id,
                        type="load_balancer",
                        provider="azure",
                        region=lb.location or "unknown",
                        name=lb.name,
                        raw_data={
                            **lb_data,
                            "subscription_id": subscription_id,
                            "resource_group": resource_group,
                        },
                    )
            except HttpResponseError as e:
                logger.error(f"Failed to collect load balancers in subscription {subscription_id}: {e}")

    # =========================================================================
    # Evidence Collection Methods
    # =========================================================================

    def collect_evidence(
        self,
        *,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """
        Collect Azure evidence for compliance audits.

        Args:
            evidence_types: List of evidence types to collect.

        Returns:
            CollectionResult with collected evidence.
        """
        types_to_collect = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        result = CollectionResult(platform=self.PLATFORM)

        for evidence_type in types_to_collect:
            if evidence_type not in self.SUPPORTED_EVIDENCE_TYPES:
                logger.warning(f"Unknown evidence type: {evidence_type}")
                continue

            collector_method = getattr(self, f"_evidence_{evidence_type}", None)
            if collector_method is None:
                logger.warning(f"No collector for evidence type: {evidence_type}")
                continue

            try:
                evidence = collector_method()
                if evidence:
                    result.add_evidence(evidence)
                    logger.debug(f"Collected {evidence_type} evidence")
            except Exception as e:
                error_msg = f"Failed to collect {evidence_type}: {e}"
                logger.error(error_msg)
                result.add_error(error_msg)

        result.complete()
        return result

    def _evidence_subscription_info(self) -> Evidence:
        """Collect subscription information."""
        self._rate_limit()
        credential = self._get_credential()
        subscription_client = SubscriptionClient(credential)

        subscriptions = []
        for sub in subscription_client.subscriptions.list():
            sub_data = sub.as_dict()
            subscriptions.append(sub_data)

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="subscription_info",
            raw_data={"subscriptions": subscriptions},
            metadata={"source": "SubscriptionClient.subscriptions.list"},
        )

    def _evidence_security_center_status(self) -> Evidence:
        """Collect Microsoft Defender for Cloud status."""
        # Note: Requires azure-mgmt-security package
        security_status: list[dict[str, Any]] = []

        for subscription_id in self._get_subscription_ids():
            self._rate_limit()

            try:
                from azure.mgmt.security import SecurityCenter

                credential = self._get_credential()
                security_client = SecurityCenter(credential, subscription_id, "")

                # Get auto provisioning settings
                try:
                    auto_provision = list(security_client.auto_provisioning_settings.list())
                    security_status.append({
                        "subscription_id": subscription_id,
                        "auto_provisioning": [ap.as_dict() for ap in auto_provision],
                    })
                except Exception as e:
                    logger.warning(f"Failed to get auto provisioning settings: {e}")
                    security_status.append({
                        "subscription_id": subscription_id,
                        "error": str(e),
                    })
            except ImportError:
                logger.warning("azure-mgmt-security not installed, skipping security center status")
                return Evidence(
                    platform=self.PLATFORM,
                    evidence_type="security_center_status",
                    raw_data={"error": "azure-mgmt-security not installed"},
                    metadata={"source": "SecurityCenter"},
                )
            except Exception as e:
                logger.error(f"Failed to collect security center status: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="security_center_status",
            raw_data={"security_status": security_status},
            metadata={"source": "SecurityCenter"},
        )

    def _evidence_policy_assignments(self) -> Evidence:
        """Collect Azure Policy assignments."""
        policy_assignments: list[dict[str, Any]] = []

        for subscription_id in self._get_subscription_ids():
            self._rate_limit()

            try:
                from azure.mgmt.resource.policy import PolicyClient

                credential = self._get_credential()
                policy_client = PolicyClient(credential, subscription_id)

                for assignment in policy_client.policy_assignments.list():
                    assignment_data = assignment.as_dict()
                    assignment_data["subscription_id"] = subscription_id
                    policy_assignments.append(assignment_data)
            except ImportError:
                logger.warning("azure-mgmt-resource[policy] not available")
                return Evidence(
                    platform=self.PLATFORM,
                    evidence_type="policy_assignments",
                    raw_data={"error": "Policy client not available"},
                    metadata={"source": "PolicyClient"},
                )
            except HttpResponseError as e:
                logger.error(f"Failed to list policy assignments in subscription {subscription_id}: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="policy_assignments",
            raw_data={"assignments": policy_assignments},
            metadata={"source": "PolicyClient.policy_assignments.list"},
        )

    def _evidence_role_assignments(self) -> Evidence:
        """Collect RBAC role assignments."""
        role_assignments: list[dict[str, Any]] = []

        for subscription_id in self._get_subscription_ids():
            self._rate_limit()

            try:
                from azure.mgmt.authorization import AuthorizationManagementClient

                credential = self._get_credential()
                auth_client = AuthorizationManagementClient(credential, subscription_id)

                for assignment in auth_client.role_assignments.list_for_subscription():
                    assignment_data = assignment.as_dict()
                    assignment_data["subscription_id"] = subscription_id
                    role_assignments.append(assignment_data)
            except ImportError:
                logger.warning("azure-mgmt-authorization not available")
                return Evidence(
                    platform=self.PLATFORM,
                    evidence_type="role_assignments",
                    raw_data={"error": "Authorization client not available"},
                    metadata={"source": "AuthorizationManagementClient"},
                )
            except HttpResponseError as e:
                logger.error(f"Failed to list role assignments in subscription {subscription_id}: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="role_assignments",
            raw_data={"assignments": role_assignments},
            metadata={"source": "AuthorizationManagementClient.role_assignments.list_for_subscription"},
        )

    def _evidence_activity_log(self) -> Evidence:
        """Collect activity log summary."""
        activity_logs: list[dict[str, Any]] = []

        # Get logs from last 7 days
        from datetime import timedelta

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=7)

        for subscription_id in self._get_subscription_ids():
            self._rate_limit()

            try:
                monitor_client = self._get_monitor_client(subscription_id)

                # Filter for important events
                filter_str = (
                    f"eventTimestamp ge '{start_time.isoformat()}' "
                    f"and eventTimestamp le '{end_time.isoformat()}' "
                    "and level eq 'Critical' or level eq 'Error' or level eq 'Warning'"
                )

                events = []
                try:
                    for event in monitor_client.activity_logs.list(filter=filter_str):
                        event_data = event.as_dict()
                        events.append({
                            "event_timestamp": event_data.get("event_timestamp"),
                            "level": event_data.get("level"),
                            "operation_name": event_data.get("operation_name", {}).get("value"),
                            "status": event_data.get("status", {}).get("value"),
                            "caller": event_data.get("caller"),
                        })
                        if len(events) >= 100:  # Limit to 100 events per subscription
                            break
                except HttpResponseError:
                    pass

                activity_logs.append({
                    "subscription_id": subscription_id,
                    "event_count": len(events),
                    "events": events,
                })
            except HttpResponseError as e:
                logger.error(f"Failed to get activity logs in subscription {subscription_id}: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="activity_log",
            raw_data={
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "logs": activity_logs,
            },
            metadata={"source": "MonitorManagementClient.activity_logs.list"},
        )

    def _evidence_diagnostic_settings(self) -> Evidence:
        """Collect diagnostic settings status."""
        diagnostic_settings: list[dict[str, Any]] = []

        for subscription_id in self._get_subscription_ids():
            self._rate_limit()

            try:
                monitor_client = self._get_monitor_client(subscription_id)

                # Check subscription-level diagnostic settings
                try:
                    settings = list(
                        monitor_client.subscription_diagnostic_settings.list(subscription_id)
                    )
                    diagnostic_settings.append({
                        "subscription_id": subscription_id,
                        "settings": [s.as_dict() for s in settings],
                    })
                except HttpResponseError as e:
                    diagnostic_settings.append({
                        "subscription_id": subscription_id,
                        "error": str(e),
                    })
            except HttpResponseError as e:
                logger.error(f"Failed to get diagnostic settings in subscription {subscription_id}: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="diagnostic_settings",
            raw_data={"settings": diagnostic_settings},
            metadata={"source": "MonitorManagementClient.subscription_diagnostic_settings.list"},
        )
