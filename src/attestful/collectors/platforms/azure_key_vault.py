"""
Azure Key Vault collector.

Collects secrets management evidence from Azure Key Vault for
compliance verification and audit purposes.

Supports:
- Secret, key, and certificate inventory collection
- Access policy and RBAC assignment collection
- Diagnostic log collection for access auditing
- Key rotation and expiration tracking
- Managed identity authentication
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from attestful.collectors.base import (
    BaseCollector,
    CollectorMetadata,
    CollectorMode,
    register_collector,
)
from attestful.core.exceptions import (
    AuthenticationError,
    CollectionError,
    ConfigurationError,
)
from attestful.core.models import CollectionResult, Evidence


# Evidence types for Azure Key Vault
AZURE_KEY_VAULT_EVIDENCE_TYPES = [
    "vault_list",
    "vault_config",
    "secret_list",
    "secret_metadata",
    "key_list",
    "key_metadata",
    "certificate_list",
    "certificate_metadata",
    "access_policies",
    "rbac_assignments",
    "diagnostic_settings",
    "audit_logs",
    "network_config",
    "compliance_status",
]


@dataclass
class AzureKeyVaultConfig:
    """Azure Key Vault collector configuration."""

    # Authentication options
    # Option 1: Service principal
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None

    # Option 2: Managed identity
    use_managed_identity: bool = False

    # Option 3: Azure CLI
    use_cli_auth: bool = False

    # Subscription filtering
    subscription_ids: list[str] | None = None

    # Collection options
    include_secrets: bool = True
    include_keys: bool = True
    include_certificates: bool = True
    include_audit_logs: bool = True
    audit_logs_days: int = 30

    # Compliance thresholds
    key_expiry_warning_days: int = 30
    secret_age_threshold_days: int = 90
    certificate_expiry_warning_days: int = 30


@register_collector()
class AzureKeyVaultCollector(BaseCollector):
    """
    Azure Key Vault collector.

    Collects secrets management evidence including:
    - Key Vault inventory and configuration
    - Secrets, keys, and certificates metadata
    - Access policies and RBAC assignments
    - Diagnostic settings and audit logs
    - Network security configuration
    - Compliance status

    Evidence Types:
        - vault_list: List of Key Vaults with metadata
        - vault_config: Detailed vault configuration
        - secret_list: List of secrets with metadata
        - secret_metadata: Detailed secret properties
        - key_list: List of cryptographic keys
        - key_metadata: Detailed key properties and rotation
        - certificate_list: List of certificates
        - certificate_metadata: Certificate details and expiration
        - access_policies: Vault access policies
        - rbac_assignments: RBAC role assignments
        - diagnostic_settings: Logging configuration
        - audit_logs: Access and operation logs
        - network_config: Network rules and private endpoints
        - compliance_status: Overall compliance assessment

    Control Mappings:
        - NIST CSF: PR.AA, PR.DS
        - SOC 2: CC6.1, CC6.7
        - NIST 800-53: IA-5, SC-12, SC-28
        - ISO 27001: A.5.17, A.8.24
    """

    metadata = CollectorMetadata(
        name="Azure Key Vault",
        platform="azure_key_vault",
        description="Azure Key Vault secrets management collector",
        mode=CollectorMode.EVIDENCE,
        evidence_types=AZURE_KEY_VAULT_EVIDENCE_TYPES,
        requires_credentials=True,
        version="1.0.0",
    )

    def __init__(
        self,
        *,
        config: AzureKeyVaultConfig | None = None,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        use_managed_identity: bool = False,
        use_cli_auth: bool = False,
        subscription_ids: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize Azure Key Vault collector.

        Args:
            config: Pre-configured AzureKeyVaultConfig object
            tenant_id: Azure AD tenant ID
            client_id: Service principal client ID
            client_secret: Service principal client secret
            use_managed_identity: Use managed identity authentication
            use_cli_auth: Use Azure CLI authentication
            subscription_ids: List of subscription IDs to collect from
            **kwargs: Additional arguments for BaseCollector
        """
        super().__init__(**kwargs)

        if config:
            self.config = config
        else:
            self.config = AzureKeyVaultConfig(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
                use_managed_identity=use_managed_identity,
                use_cli_auth=use_cli_auth,
                subscription_ids=subscription_ids,
            )

        self._credential: Any = None
        self._mgmt_client: Any = None
        self._keyvault_clients: dict[str, Any] = {}

    def _get_credential(self) -> Any:
        """Get Azure credential object."""
        if self._credential is None:
            try:
                from azure.identity import (
                    ClientSecretCredential,
                    DefaultAzureCredential,
                    ManagedIdentityCredential,
                    AzureCliCredential,
                )
            except ImportError:
                raise ConfigurationError(
                    "azure-identity is required for Azure Key Vault collection. "
                    "Install with: pip install azure-identity"
                )

            if self.config.use_managed_identity:
                self._credential = ManagedIdentityCredential()
            elif self.config.use_cli_auth:
                self._credential = AzureCliCredential()
            elif self.config.client_id and self.config.client_secret:
                self._credential = ClientSecretCredential(
                    tenant_id=self.config.tenant_id,
                    client_id=self.config.client_id,
                    client_secret=self.config.client_secret,
                )
            else:
                self._credential = DefaultAzureCredential()

        return self._credential

    def _get_mgmt_client(self, subscription_id: str) -> Any:
        """Get Key Vault management client."""
        try:
            from azure.mgmt.keyvault import KeyVaultManagementClient
        except ImportError:
            raise ConfigurationError(
                "azure-mgmt-keyvault is required. "
                "Install with: pip install azure-mgmt-keyvault"
            )

        return KeyVaultManagementClient(
            credential=self._get_credential(),
            subscription_id=subscription_id,
        )

    def _get_keyvault_client(self, vault_url: str) -> Any:
        """Get Key Vault data plane client."""
        if vault_url not in self._keyvault_clients:
            try:
                from azure.keyvault.secrets import SecretClient
            except ImportError:
                raise ConfigurationError(
                    "azure-keyvault-secrets is required. "
                    "Install with: pip install azure-keyvault-secrets"
                )

            self._keyvault_clients[vault_url] = SecretClient(
                vault_url=vault_url,
                credential=self._get_credential(),
            )

        return self._keyvault_clients[vault_url]

    def _get_subscriptions(self) -> list[dict]:
        """Get list of subscriptions."""
        if self.config.subscription_ids:
            return [{"id": sub_id} for sub_id in self.config.subscription_ids]

        try:
            from azure.mgmt.resource import SubscriptionClient
        except ImportError:
            raise ConfigurationError(
                "azure-mgmt-resource is required. "
                "Install with: pip install azure-mgmt-resource"
            )

        client = SubscriptionClient(credential=self._get_credential())
        return list(client.subscriptions.list())

    def validate_credentials(self) -> bool:
        """Validate Azure credentials."""
        try:
            credential = self._get_credential()
            # Try to get a token to validate
            credential.get_token("https://management.azure.com/.default")
            self.logger.info("Azure authentication successful")
            return True
        except Exception as e:
            self.logger.error(f"Azure authentication failed: {e}")
            raise AuthenticationError(
                f"Failed to authenticate with Azure: {e}",
                provider="azure_key_vault",
            )

    # =========================================================================
    # Evidence Collection
    # =========================================================================

    def collect_evidence(
        self,
        *,
        evidence_types: list[str] | None = None,
        since: datetime | None = None,
        filters: dict[str, Any] | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> CollectionResult:
        """
        Collect Azure Key Vault evidence.

        Args:
            evidence_types: Types of evidence to collect (None = all)
            since: Only collect evidence after this time
            filters: Additional filters
            progress_callback: Progress callback(current, total)

        Returns:
            CollectionResult with collected evidence
        """
        self.logger.info("Starting Azure Key Vault evidence collection")

        types_to_collect = evidence_types or AZURE_KEY_VAULT_EVIDENCE_TYPES
        subscriptions = self._get_subscriptions()
        total_steps = len(types_to_collect) * len(subscriptions)
        current_step = 0

        all_evidence: list[Evidence] = []
        errors: list[str] = []

        for subscription in subscriptions:
            sub_id = (
                subscription.subscription_id
                if hasattr(subscription, "subscription_id")
                else subscription.get("id", subscription)
            )
            self.logger.info(f"Collecting from subscription: {sub_id}")

            for evidence_type in types_to_collect:
                if progress_callback:
                    progress_callback(current_step, total_steps)
                current_step += 1

                try:
                    evidence_items = self._collect_evidence_type(
                        evidence_type, sub_id, since, filters
                    )
                    all_evidence.extend(evidence_items)
                    self.logger.debug(
                        f"Collected {len(evidence_items)} {evidence_type} items "
                        f"from {sub_id}"
                    )
                except Exception as e:
                    error_msg = f"Failed to collect {evidence_type} from {sub_id}: {e}"
                    self.logger.warning(error_msg)
                    errors.append(error_msg)

        if progress_callback:
            progress_callback(total_steps, total_steps)

        self.logger.info(
            f"Collected {len(all_evidence)} Azure Key Vault evidence items"
        )

        return CollectionResult(
            success=len(errors) == 0,
            evidence=all_evidence,
            errors=errors,
            metadata={
                "platform": "azure_key_vault",
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "subscriptions": [
                    s.subscription_id if hasattr(s, "subscription_id") else s
                    for s in subscriptions
                ],
                "evidence_types": types_to_collect,
            },
        )

    def _collect_evidence_type(
        self,
        evidence_type: str,
        subscription_id: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect evidence of a specific type."""
        collectors = {
            "vault_list": self._collect_vault_list,
            "vault_config": self._collect_vault_config,
            "secret_list": self._collect_secret_list,
            "secret_metadata": self._collect_secret_metadata,
            "key_list": self._collect_key_list,
            "key_metadata": self._collect_key_metadata,
            "certificate_list": self._collect_certificate_list,
            "certificate_metadata": self._collect_certificate_metadata,
            "access_policies": self._collect_access_policies,
            "rbac_assignments": self._collect_rbac_assignments,
            "diagnostic_settings": self._collect_diagnostic_settings,
            "audit_logs": self._collect_audit_logs,
            "network_config": self._collect_network_config,
            "compliance_status": self._collect_compliance_status,
        }

        collector = collectors.get(evidence_type)
        if not collector:
            self.logger.warning(f"Unknown evidence type: {evidence_type}")
            return []

        return self._with_retry(
            lambda: collector(subscription_id, since, filters),
            f"collect_{evidence_type}",
        )

    def _list_vaults(self, subscription_id: str) -> list[Any]:
        """List all Key Vaults in a subscription."""
        client = self._get_mgmt_client(subscription_id)
        return list(client.vaults.list_by_subscription())

    def _collect_vault_list(
        self,
        subscription_id: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect Key Vault list evidence."""
        vaults = self._list_vaults(subscription_id)

        vault_summary = []
        for vault in vaults:
            vault_summary.append({
                "name": vault.name,
                "id": vault.id,
                "location": vault.location,
                "sku": vault.properties.sku.name if vault.properties.sku else None,
                "soft_delete_enabled": vault.properties.enable_soft_delete,
                "purge_protection_enabled": vault.properties.enable_purge_protection,
                "rbac_enabled": vault.properties.enable_rbac_authorization,
            })

        return [
            self._create_evidence(
                evidence_type="vault_list",
                raw_data={"vaults": [v.as_dict() for v in vaults]},
                source_id=f"azure_key_vault_{subscription_id}",
                metadata={
                    "subscription_id": subscription_id,
                    "total_vaults": len(vaults),
                    "soft_delete_enabled_count": sum(
                        1 for v in vaults
                        if v.properties.enable_soft_delete
                    ),
                    "purge_protection_enabled_count": sum(
                        1 for v in vaults
                        if v.properties.enable_purge_protection
                    ),
                    "rbac_enabled_count": sum(
                        1 for v in vaults
                        if v.properties.enable_rbac_authorization
                    ),
                    "summary": vault_summary,
                },
            )
        ]

    def _collect_vault_config(
        self,
        subscription_id: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect detailed vault configuration evidence."""
        vaults = self._list_vaults(subscription_id)
        evidence_items = []

        for vault in vaults:
            props = vault.properties

            evidence_items.append(
                self._create_evidence(
                    evidence_type="vault_config",
                    raw_data=vault.as_dict(),
                    source_id=vault.name,
                    metadata={
                        "subscription_id": subscription_id,
                        "vault_name": vault.name,
                        "vault_uri": props.vault_uri,
                        "location": vault.location,
                        "sku": props.sku.name if props.sku else None,
                        "tenant_id": props.tenant_id,
                        "soft_delete_enabled": props.enable_soft_delete,
                        "soft_delete_retention_days": props.soft_delete_retention_in_days,
                        "purge_protection_enabled": props.enable_purge_protection,
                        "rbac_enabled": props.enable_rbac_authorization,
                        "enabled_for_deployment": props.enabled_for_deployment,
                        "enabled_for_disk_encryption": props.enabled_for_disk_encryption,
                        "enabled_for_template_deployment": props.enabled_for_template_deployment,
                        "access_policy_count": (
                            len(props.access_policies) if props.access_policies else 0
                        ),
                    },
                )
            )

        return evidence_items

    def _collect_secret_list(
        self,
        subscription_id: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect secret list evidence."""
        if not self.config.include_secrets:
            return []

        vaults = self._list_vaults(subscription_id)
        evidence_items = []

        for vault in vaults:
            vault_url = vault.properties.vault_uri

            try:
                from azure.keyvault.secrets import SecretClient

                client = SecretClient(
                    vault_url=vault_url,
                    credential=self._get_credential(),
                )
                secrets = list(client.list_properties_of_secrets())

                secret_summary = []
                for secret in secrets:
                    secret_summary.append({
                        "name": secret.name,
                        "enabled": secret.enabled,
                        "created_on": (
                            secret.created_on.isoformat()
                            if secret.created_on
                            else None
                        ),
                        "updated_on": (
                            secret.updated_on.isoformat()
                            if secret.updated_on
                            else None
                        ),
                        "expires_on": (
                            secret.expires_on.isoformat()
                            if secret.expires_on
                            else None
                        ),
                        "content_type": secret.content_type,
                    })

                evidence_items.append(
                    self._create_evidence(
                        evidence_type="secret_list",
                        raw_data={
                            "vault_name": vault.name,
                            "secrets": [
                                {
                                    "name": s.name,
                                    "id": s.id,
                                    "enabled": s.enabled,
                                    "created_on": s.created_on.isoformat() if s.created_on else None,
                                    "updated_on": s.updated_on.isoformat() if s.updated_on else None,
                                    "expires_on": s.expires_on.isoformat() if s.expires_on else None,
                                }
                                for s in secrets
                            ],
                        },
                        source_id=vault.name,
                        metadata={
                            "subscription_id": subscription_id,
                            "vault_name": vault.name,
                            "total_secrets": len(secrets),
                            "enabled_secrets": sum(1 for s in secrets if s.enabled),
                            "expiring_soon": sum(
                                1 for s in secrets
                                if s.expires_on and s.expires_on < datetime.now(timezone.utc) + timedelta(days=30)
                            ),
                            "summary": secret_summary,
                        },
                    )
                )

            except Exception as e:
                self.logger.warning(f"Failed to list secrets from {vault.name}: {e}")

        return evidence_items

    def _collect_secret_metadata(
        self,
        subscription_id: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect detailed secret metadata evidence."""
        if not self.config.include_secrets:
            return []

        vaults = self._list_vaults(subscription_id)
        evidence_items = []

        for vault in vaults:
            vault_url = vault.properties.vault_uri

            try:
                from azure.keyvault.secrets import SecretClient

                client = SecretClient(
                    vault_url=vault_url,
                    credential=self._get_credential(),
                )

                for secret_props in client.list_properties_of_secrets():
                    # Get all versions
                    versions = list(
                        client.list_properties_of_secret_versions(secret_props.name)
                    )

                    # Calculate age
                    age_days = None
                    if secret_props.created_on:
                        age_days = (
                            datetime.now(timezone.utc) - secret_props.created_on
                        ).days

                    evidence_items.append(
                        self._create_evidence(
                            evidence_type="secret_metadata",
                            raw_data={
                                "vault_name": vault.name,
                                "secret_name": secret_props.name,
                                "secret_id": secret_props.id,
                                "properties": {
                                    "enabled": secret_props.enabled,
                                    "created_on": secret_props.created_on.isoformat() if secret_props.created_on else None,
                                    "updated_on": secret_props.updated_on.isoformat() if secret_props.updated_on else None,
                                    "expires_on": secret_props.expires_on.isoformat() if secret_props.expires_on else None,
                                    "not_before": secret_props.not_before.isoformat() if secret_props.not_before else None,
                                    "content_type": secret_props.content_type,
                                    "tags": secret_props.tags,
                                },
                                "version_count": len(versions),
                            },
                            source_id=f"{vault.name}/{secret_props.name}",
                            metadata={
                                "subscription_id": subscription_id,
                                "vault_name": vault.name,
                                "secret_name": secret_props.name,
                                "enabled": secret_props.enabled,
                                "version_count": len(versions),
                                "age_days": age_days,
                                "has_expiration": secret_props.expires_on is not None,
                                "is_expired": (
                                    secret_props.expires_on is not None
                                    and secret_props.expires_on < datetime.now(timezone.utc)
                                ),
                            },
                        )
                    )

            except Exception as e:
                self.logger.warning(f"Failed to get secret metadata from {vault.name}: {e}")

        return evidence_items

    def _collect_key_list(
        self,
        subscription_id: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect cryptographic key list evidence."""
        if not self.config.include_keys:
            return []

        vaults = self._list_vaults(subscription_id)
        evidence_items = []

        for vault in vaults:
            vault_url = vault.properties.vault_uri

            try:
                from azure.keyvault.keys import KeyClient

                client = KeyClient(
                    vault_url=vault_url,
                    credential=self._get_credential(),
                )
                keys = list(client.list_properties_of_keys())

                key_summary = []
                for key in keys:
                    key_summary.append({
                        "name": key.name,
                        "enabled": key.enabled,
                        "key_type": key.key_type.value if key.key_type else None,
                        "created_on": key.created_on.isoformat() if key.created_on else None,
                        "expires_on": key.expires_on.isoformat() if key.expires_on else None,
                    })

                evidence_items.append(
                    self._create_evidence(
                        evidence_type="key_list",
                        raw_data={
                            "vault_name": vault.name,
                            "keys": [
                                {
                                    "name": k.name,
                                    "id": k.id,
                                    "enabled": k.enabled,
                                    "key_type": k.key_type.value if k.key_type else None,
                                }
                                for k in keys
                            ],
                        },
                        source_id=vault.name,
                        metadata={
                            "subscription_id": subscription_id,
                            "vault_name": vault.name,
                            "total_keys": len(keys),
                            "enabled_keys": sum(1 for k in keys if k.enabled),
                            "summary": key_summary,
                        },
                    )
                )

            except Exception as e:
                self.logger.warning(f"Failed to list keys from {vault.name}: {e}")

        return evidence_items

    def _collect_key_metadata(
        self,
        subscription_id: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect detailed key metadata evidence."""
        if not self.config.include_keys:
            return []

        vaults = self._list_vaults(subscription_id)
        evidence_items = []

        for vault in vaults:
            vault_url = vault.properties.vault_uri

            try:
                from azure.keyvault.keys import KeyClient

                client = KeyClient(
                    vault_url=vault_url,
                    credential=self._get_credential(),
                )

                for key_props in client.list_properties_of_keys():
                    # Get key details
                    try:
                        key = client.get_key(key_props.name)
                    except Exception:
                        continue

                    # Get versions
                    versions = list(
                        client.list_properties_of_key_versions(key_props.name)
                    )

                    evidence_items.append(
                        self._create_evidence(
                            evidence_type="key_metadata",
                            raw_data={
                                "vault_name": vault.name,
                                "key_name": key.name,
                                "key_id": key.id,
                                "key_type": key.key_type.value if key.key_type else None,
                                "key_size": key.key.n.bit_length() if hasattr(key.key, 'n') and key.key.n else None,
                                "key_operations": [op.value for op in (key.key_operations or [])],
                                "properties": {
                                    "enabled": key.properties.enabled,
                                    "created_on": key.properties.created_on.isoformat() if key.properties.created_on else None,
                                    "updated_on": key.properties.updated_on.isoformat() if key.properties.updated_on else None,
                                    "expires_on": key.properties.expires_on.isoformat() if key.properties.expires_on else None,
                                    "exportable": key.properties.exportable,
                                    "release_policy": key.properties.release_policy is not None,
                                },
                                "version_count": len(versions),
                            },
                            source_id=f"{vault.name}/{key.name}",
                            metadata={
                                "subscription_id": subscription_id,
                                "vault_name": vault.name,
                                "key_name": key.name,
                                "key_type": key.key_type.value if key.key_type else None,
                                "enabled": key.properties.enabled,
                                "version_count": len(versions),
                                "has_expiration": key.properties.expires_on is not None,
                                "is_expired": (
                                    key.properties.expires_on is not None
                                    and key.properties.expires_on < datetime.now(timezone.utc)
                                ),
                                "expiring_soon": (
                                    key.properties.expires_on is not None
                                    and key.properties.expires_on < datetime.now(timezone.utc) + timedelta(days=self.config.key_expiry_warning_days)
                                ),
                            },
                        )
                    )

            except Exception as e:
                self.logger.warning(f"Failed to get key metadata from {vault.name}: {e}")

        return evidence_items

    def _collect_certificate_list(
        self,
        subscription_id: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect certificate list evidence."""
        if not self.config.include_certificates:
            return []

        vaults = self._list_vaults(subscription_id)
        evidence_items = []

        for vault in vaults:
            vault_url = vault.properties.vault_uri

            try:
                from azure.keyvault.certificates import CertificateClient

                client = CertificateClient(
                    vault_url=vault_url,
                    credential=self._get_credential(),
                )
                certs = list(client.list_properties_of_certificates())

                cert_summary = []
                for cert in certs:
                    cert_summary.append({
                        "name": cert.name,
                        "enabled": cert.enabled,
                        "created_on": cert.created_on.isoformat() if cert.created_on else None,
                        "expires_on": cert.expires_on.isoformat() if cert.expires_on else None,
                    })

                evidence_items.append(
                    self._create_evidence(
                        evidence_type="certificate_list",
                        raw_data={
                            "vault_name": vault.name,
                            "certificates": [
                                {
                                    "name": c.name,
                                    "id": c.id,
                                    "enabled": c.enabled,
                                }
                                for c in certs
                            ],
                        },
                        source_id=vault.name,
                        metadata={
                            "subscription_id": subscription_id,
                            "vault_name": vault.name,
                            "total_certificates": len(certs),
                            "enabled_certificates": sum(1 for c in certs if c.enabled),
                            "summary": cert_summary,
                        },
                    )
                )

            except Exception as e:
                self.logger.warning(f"Failed to list certificates from {vault.name}: {e}")

        return evidence_items

    def _collect_certificate_metadata(
        self,
        subscription_id: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect detailed certificate metadata evidence."""
        if not self.config.include_certificates:
            return []

        vaults = self._list_vaults(subscription_id)
        evidence_items = []

        for vault in vaults:
            vault_url = vault.properties.vault_uri

            try:
                from azure.keyvault.certificates import CertificateClient

                client = CertificateClient(
                    vault_url=vault_url,
                    credential=self._get_credential(),
                )

                for cert_props in client.list_properties_of_certificates():
                    try:
                        cert = client.get_certificate(cert_props.name)
                    except Exception:
                        continue

                    policy = cert.policy

                    evidence_items.append(
                        self._create_evidence(
                            evidence_type="certificate_metadata",
                            raw_data={
                                "vault_name": vault.name,
                                "certificate_name": cert.name,
                                "certificate_id": cert.id,
                                "properties": {
                                    "enabled": cert.properties.enabled,
                                    "created_on": cert.properties.created_on.isoformat() if cert.properties.created_on else None,
                                    "updated_on": cert.properties.updated_on.isoformat() if cert.properties.updated_on else None,
                                    "expires_on": cert.properties.expires_on.isoformat() if cert.properties.expires_on else None,
                                },
                                "policy": {
                                    "issuer_name": policy.issuer_name if policy else None,
                                    "subject": policy.subject if policy else None,
                                    "key_type": policy.key_type.value if policy and policy.key_type else None,
                                    "key_size": policy.key_size if policy else None,
                                    "exportable": policy.exportable if policy else None,
                                    "validity_in_months": policy.validity_in_months if policy else None,
                                } if policy else None,
                            },
                            source_id=f"{vault.name}/{cert.name}",
                            metadata={
                                "subscription_id": subscription_id,
                                "vault_name": vault.name,
                                "certificate_name": cert.name,
                                "enabled": cert.properties.enabled,
                                "has_expiration": cert.properties.expires_on is not None,
                                "is_expired": (
                                    cert.properties.expires_on is not None
                                    and cert.properties.expires_on < datetime.now(timezone.utc)
                                ),
                                "expiring_soon": (
                                    cert.properties.expires_on is not None
                                    and cert.properties.expires_on < datetime.now(timezone.utc) + timedelta(days=self.config.certificate_expiry_warning_days)
                                ),
                            },
                        )
                    )

            except Exception as e:
                self.logger.warning(f"Failed to get certificate metadata from {vault.name}: {e}")

        return evidence_items

    def _collect_access_policies(
        self,
        subscription_id: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect access policy evidence."""
        vaults = self._list_vaults(subscription_id)
        evidence_items = []

        for vault in vaults:
            policies = vault.properties.access_policies or []

            policy_summary = []
            for policy in policies:
                policy_summary.append({
                    "tenant_id": policy.tenant_id,
                    "object_id": policy.object_id,
                    "secret_permissions": [p.value for p in (policy.permissions.secrets or [])],
                    "key_permissions": [p.value for p in (policy.permissions.keys or [])],
                    "certificate_permissions": [p.value for p in (policy.permissions.certificates or [])],
                    "storage_permissions": [p.value for p in (policy.permissions.storage or [])] if policy.permissions.storage else [],
                })

            evidence_items.append(
                self._create_evidence(
                    evidence_type="access_policies",
                    raw_data={
                        "vault_name": vault.name,
                        "policies": [p.as_dict() for p in policies],
                    },
                    source_id=vault.name,
                    metadata={
                        "subscription_id": subscription_id,
                        "vault_name": vault.name,
                        "rbac_enabled": vault.properties.enable_rbac_authorization,
                        "policy_count": len(policies),
                        "summary": policy_summary,
                    },
                )
            )

        return evidence_items

    def _collect_rbac_assignments(
        self,
        subscription_id: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect RBAC role assignment evidence."""
        try:
            from azure.mgmt.authorization import AuthorizationManagementClient
        except ImportError:
            self.logger.warning("azure-mgmt-authorization not installed, skipping RBAC")
            return []

        vaults = self._list_vaults(subscription_id)
        evidence_items = []

        auth_client = AuthorizationManagementClient(
            credential=self._get_credential(),
            subscription_id=subscription_id,
        )

        for vault in vaults:
            try:
                # Get role assignments scoped to this vault
                assignments = list(
                    auth_client.role_assignments.list_for_scope(vault.id)
                )

                assignment_summary = []
                for assignment in assignments:
                    assignment_summary.append({
                        "principal_id": assignment.principal_id,
                        "principal_type": assignment.principal_type,
                        "role_definition_id": assignment.role_definition_id,
                        "scope": assignment.scope,
                    })

                evidence_items.append(
                    self._create_evidence(
                        evidence_type="rbac_assignments",
                        raw_data={
                            "vault_name": vault.name,
                            "assignments": [a.as_dict() for a in assignments],
                        },
                        source_id=vault.name,
                        metadata={
                            "subscription_id": subscription_id,
                            "vault_name": vault.name,
                            "assignment_count": len(assignments),
                            "summary": assignment_summary,
                        },
                    )
                )

            except Exception as e:
                self.logger.warning(f"Failed to get RBAC for {vault.name}: {e}")

        return evidence_items

    def _collect_diagnostic_settings(
        self,
        subscription_id: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect diagnostic settings evidence."""
        try:
            from azure.mgmt.monitor import MonitorManagementClient
        except ImportError:
            self.logger.warning("azure-mgmt-monitor not installed, skipping diagnostics")
            return []

        vaults = self._list_vaults(subscription_id)
        evidence_items = []

        monitor_client = MonitorManagementClient(
            credential=self._get_credential(),
            subscription_id=subscription_id,
        )

        for vault in vaults:
            try:
                settings = list(
                    monitor_client.diagnostic_settings.list(vault.id)
                )

                settings_summary = []
                for setting in settings:
                    settings_summary.append({
                        "name": setting.name,
                        "storage_account_id": setting.storage_account_id,
                        "workspace_id": setting.workspace_id,
                        "event_hub_authorization_rule_id": setting.event_hub_authorization_rule_id,
                    })

                evidence_items.append(
                    self._create_evidence(
                        evidence_type="diagnostic_settings",
                        raw_data={
                            "vault_name": vault.name,
                            "settings": [s.as_dict() for s in settings],
                        },
                        source_id=vault.name,
                        metadata={
                            "subscription_id": subscription_id,
                            "vault_name": vault.name,
                            "has_diagnostics": len(settings) > 0,
                            "settings_count": len(settings),
                            "logs_enabled": any(
                                any(log.enabled for log in (s.logs or []))
                                for s in settings
                            ),
                            "summary": settings_summary,
                        },
                    )
                )

            except Exception as e:
                self.logger.warning(f"Failed to get diagnostics for {vault.name}: {e}")

        return evidence_items

    def _collect_audit_logs(
        self,
        subscription_id: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect audit log evidence."""
        if not self.config.include_audit_logs:
            return []

        try:
            from azure.mgmt.monitor import MonitorManagementClient
        except ImportError:
            self.logger.warning("azure-mgmt-monitor not installed, skipping audit logs")
            return []

        vaults = self._list_vaults(subscription_id)
        evidence_items = []

        monitor_client = MonitorManagementClient(
            credential=self._get_credential(),
            subscription_id=subscription_id,
        )

        end_time = datetime.now(timezone.utc)
        start_time = since or (
            end_time - timedelta(days=self.config.audit_logs_days)
        )

        for vault in vaults:
            try:
                # Query activity logs for this vault
                filter_str = (
                    f"eventTimestamp ge '{start_time.isoformat()}' and "
                    f"eventTimestamp le '{end_time.isoformat()}' and "
                    f"resourceUri eq '{vault.id}'"
                )

                logs = list(
                    monitor_client.activity_logs.list(filter=filter_str)
                )

                # Summarize by operation
                operation_summary: dict[str, int] = {}
                for log in logs:
                    op_name = log.operation_name.value if log.operation_name else "Unknown"
                    operation_summary[op_name] = operation_summary.get(op_name, 0) + 1

                evidence_items.append(
                    self._create_evidence(
                        evidence_type="audit_logs",
                        raw_data={
                            "vault_name": vault.name,
                            "logs": [log.as_dict() for log in logs[:1000]],  # Limit
                        },
                        source_id=vault.name,
                        metadata={
                            "subscription_id": subscription_id,
                            "vault_name": vault.name,
                            "total_events": len(logs),
                            "start_time": start_time.isoformat(),
                            "end_time": end_time.isoformat(),
                            "operation_summary": operation_summary,
                        },
                    )
                )

            except Exception as e:
                self.logger.warning(f"Failed to get audit logs for {vault.name}: {e}")

        return evidence_items

    def _collect_network_config(
        self,
        subscription_id: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect network configuration evidence."""
        vaults = self._list_vaults(subscription_id)
        evidence_items = []

        for vault in vaults:
            props = vault.properties
            network_acls = props.network_acls

            evidence_items.append(
                self._create_evidence(
                    evidence_type="network_config",
                    raw_data={
                        "vault_name": vault.name,
                        "network_acls": network_acls.as_dict() if network_acls else None,
                        "private_endpoint_connections": [
                            pe.as_dict() for pe in (props.private_endpoint_connections or [])
                        ],
                    },
                    source_id=vault.name,
                    metadata={
                        "subscription_id": subscription_id,
                        "vault_name": vault.name,
                        "default_action": (
                            network_acls.default_action.value
                            if network_acls and network_acls.default_action
                            else "Allow"
                        ),
                        "bypass": (
                            network_acls.bypass.value
                            if network_acls and network_acls.bypass
                            else None
                        ),
                        "ip_rules_count": (
                            len(network_acls.ip_rules)
                            if network_acls and network_acls.ip_rules
                            else 0
                        ),
                        "vnet_rules_count": (
                            len(network_acls.virtual_network_rules)
                            if network_acls and network_acls.virtual_network_rules
                            else 0
                        ),
                        "private_endpoints_count": len(
                            props.private_endpoint_connections or []
                        ),
                        "public_access_enabled": (
                            not network_acls
                            or network_acls.default_action.value == "Allow"
                            if network_acls and network_acls.default_action
                            else True
                        ),
                    },
                )
            )

        return evidence_items

    def _collect_compliance_status(
        self,
        subscription_id: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect overall compliance status."""
        vaults = self._list_vaults(subscription_id)

        compliant_vaults = []
        non_compliant_vaults = []
        issues_by_vault: dict[str, list[str]] = {}

        for vault in vaults:
            props = vault.properties
            issues = []

            # Check soft delete
            if not props.enable_soft_delete:
                issues.append("Soft delete not enabled")

            # Check purge protection
            if not props.enable_purge_protection:
                issues.append("Purge protection not enabled")

            # Check network access
            network_acls = props.network_acls
            if not network_acls or (
                network_acls.default_action
                and network_acls.default_action.value == "Allow"
            ):
                issues.append("Public network access allowed")

            # Check for private endpoints
            if not props.private_endpoint_connections:
                issues.append("No private endpoint connections")

            if issues:
                non_compliant_vaults.append(vault.name)
                issues_by_vault[vault.name] = issues
            else:
                compliant_vaults.append(vault.name)

        compliance_score = (
            len(compliant_vaults) / len(vaults) * 100 if vaults else 100
        )

        return [
            self._create_evidence(
                evidence_type="compliance_status",
                raw_data={
                    "compliant_vaults": compliant_vaults,
                    "non_compliant_vaults": non_compliant_vaults,
                    "issues_by_vault": issues_by_vault,
                },
                source_id=f"azure_key_vault_compliance_{subscription_id}",
                metadata={
                    "subscription_id": subscription_id,
                    "total_vaults": len(vaults),
                    "compliant_count": len(compliant_vaults),
                    "non_compliant_count": len(non_compliant_vaults),
                    "compliance_score": round(compliance_score, 2),
                },
            )
        ]
