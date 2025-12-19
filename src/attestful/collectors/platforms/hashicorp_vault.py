"""
HashiCorp Vault collector.

Collects secrets management evidence from HashiCorp Vault for
compliance verification and audit purposes.

Supports:
- Secrets engine inventory and configuration collection
- Authentication method and policy collection
- Audit log collection for access tracking
- Token and lease management collection
- AppRole or Kubernetes authentication
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import urljoin

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


# Evidence types for HashiCorp Vault
HASHICORP_VAULT_EVIDENCE_TYPES = [
    "vault_status",
    "secrets_engines",
    "secrets_engine_config",
    "auth_methods",
    "auth_method_config",
    "policies",
    "policy_details",
    "audit_devices",
    "audit_logs",
    "tokens",
    "leases",
    "namespaces",
    "mounts",
    "health",
    "compliance_status",
]


@dataclass
class HashiCorpVaultConfig:
    """HashiCorp Vault collector configuration."""

    # Connection
    vault_addr: str | None = None
    vault_namespace: str | None = None

    # Authentication options
    # Option 1: Token
    vault_token: str | None = None

    # Option 2: AppRole
    role_id: str | None = None
    secret_id: str | None = None

    # Option 3: Kubernetes
    kubernetes_role: str | None = None
    kubernetes_jwt_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token"

    # Option 4: LDAP
    ldap_username: str | None = None
    ldap_password: str | None = None

    # TLS options
    tls_verify: bool = True
    tls_ca_cert: str | None = None
    tls_client_cert: str | None = None
    tls_client_key: str | None = None

    # Collection options
    include_audit_logs: bool = True
    audit_logs_days: int = 30
    include_lease_details: bool = True

    # Namespaces to collect from (Enterprise feature)
    namespaces: list[str] | None = None


@register_collector()
class HashiCorpVaultCollector(BaseCollector):
    """
    HashiCorp Vault collector.

    Collects secrets management evidence including:
    - Vault status and health information
    - Secrets engines and their configurations
    - Authentication methods and configurations
    - Policies and access controls
    - Audit devices and logs
    - Tokens and leases

    Evidence Types:
        - vault_status: Overall Vault status and seal state
        - secrets_engines: List of mounted secrets engines
        - secrets_engine_config: Configuration for each engine
        - auth_methods: List of enabled auth methods
        - auth_method_config: Configuration for each auth method
        - policies: List of all policies
        - policy_details: Policy content and rules
        - audit_devices: Configured audit devices
        - audit_logs: Audit log entries
        - tokens: Token accessor information
        - leases: Active lease information
        - namespaces: Namespace hierarchy (Enterprise)
        - mounts: All mount points
        - health: Vault health status
        - compliance_status: Overall compliance assessment

    Control Mappings:
        - NIST CSF: PR.AA, PR.DS
        - SOC 2: CC6.1, CC6.7
        - NIST 800-53: IA-5, SC-12, SC-28
        - ISO 27001: A.5.17, A.8.24
    """

    metadata = CollectorMetadata(
        name="HashiCorp Vault",
        platform="hashicorp_vault",
        description="HashiCorp Vault secrets management collector",
        mode=CollectorMode.EVIDENCE,
        evidence_types=HASHICORP_VAULT_EVIDENCE_TYPES,
        requires_credentials=True,
        version="1.0.0",
    )

    def __init__(
        self,
        *,
        config: HashiCorpVaultConfig | None = None,
        vault_addr: str | None = None,
        vault_token: str | None = None,
        role_id: str | None = None,
        secret_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize HashiCorp Vault collector.

        Args:
            config: Pre-configured HashiCorpVaultConfig object
            vault_addr: Vault server address (e.g., https://vault.example.com:8200)
            vault_token: Vault authentication token
            role_id: AppRole role ID
            secret_id: AppRole secret ID
            **kwargs: Additional arguments for BaseCollector
        """
        super().__init__(**kwargs)

        if config:
            self.config = config
        else:
            self.config = HashiCorpVaultConfig(
                vault_addr=vault_addr or os.environ.get("VAULT_ADDR"),
                vault_token=vault_token or os.environ.get("VAULT_TOKEN"),
                role_id=role_id,
                secret_id=secret_id,
            )

        self._token: str | None = self.config.vault_token
        self._session: Any = None

    def _get_session(self) -> Any:
        """Get or create requests session."""
        if self._session is None:
            try:
                import requests
            except ImportError:
                raise ConfigurationError(
                    "requests is required for HashiCorp Vault collection"
                )

            self._session = requests.Session()

            # Configure TLS
            if not self.config.tls_verify:
                self._session.verify = False
            elif self.config.tls_ca_cert:
                self._session.verify = self.config.tls_ca_cert

            if self.config.tls_client_cert and self.config.tls_client_key:
                self._session.cert = (
                    self.config.tls_client_cert,
                    self.config.tls_client_key,
                )

        return self._session

    def _authenticate(self) -> str:
        """Authenticate with Vault and get a token."""
        if self._token:
            return self._token

        if self.config.role_id and self.config.secret_id:
            # AppRole authentication
            return self._auth_approle()
        elif self.config.kubernetes_role:
            # Kubernetes authentication
            return self._auth_kubernetes()
        elif self.config.ldap_username and self.config.ldap_password:
            # LDAP authentication
            return self._auth_ldap()
        else:
            raise ConfigurationError(
                "No authentication method configured. "
                "Provide vault_token, role_id/secret_id, kubernetes_role, "
                "or ldap_username/ldap_password"
            )

    def _auth_approle(self) -> str:
        """Authenticate using AppRole."""
        url = urljoin(self.config.vault_addr, "/v1/auth/approle/login")
        response = self._get_session().post(
            url,
            json={
                "role_id": self.config.role_id,
                "secret_id": self.config.secret_id,
            },
        )

        if response.status_code != 200:
            raise AuthenticationError(
                f"AppRole authentication failed: {response.text}",
                provider="hashicorp_vault",
            )

        data = response.json()
        self._token = data["auth"]["client_token"]
        return self._token

    def _auth_kubernetes(self) -> str:
        """Authenticate using Kubernetes service account."""
        # Read JWT from service account
        try:
            with open(self.config.kubernetes_jwt_path) as f:
                jwt = f.read().strip()
        except FileNotFoundError:
            raise ConfigurationError(
                f"Kubernetes JWT not found at {self.config.kubernetes_jwt_path}"
            )

        url = urljoin(self.config.vault_addr, "/v1/auth/kubernetes/login")
        response = self._get_session().post(
            url,
            json={
                "role": self.config.kubernetes_role,
                "jwt": jwt,
            },
        )

        if response.status_code != 200:
            raise AuthenticationError(
                f"Kubernetes authentication failed: {response.text}",
                provider="hashicorp_vault",
            )

        data = response.json()
        self._token = data["auth"]["client_token"]
        return self._token

    def _auth_ldap(self) -> str:
        """Authenticate using LDAP."""
        url = urljoin(
            self.config.vault_addr,
            f"/v1/auth/ldap/login/{self.config.ldap_username}",
        )
        response = self._get_session().post(
            url,
            json={"password": self.config.ldap_password},
        )

        if response.status_code != 200:
            raise AuthenticationError(
                f"LDAP authentication failed: {response.text}",
                provider="hashicorp_vault",
            )

        data = response.json()
        self._token = data["auth"]["client_token"]
        return self._token

    def _make_request(
        self,
        method: str,
        path: str,
        *,
        data: dict[str, Any] | None = None,
        namespace: str | None = None,
    ) -> dict[str, Any]:
        """
        Make authenticated request to Vault API.

        Args:
            method: HTTP method
            path: API path (e.g., /v1/sys/health)
            data: Request body
            namespace: Vault namespace (Enterprise)

        Returns:
            Response data

        Raises:
            CollectionError: If request fails
        """
        token = self._authenticate()
        url = urljoin(self.config.vault_addr, path)

        headers = {"X-Vault-Token": token}
        if namespace or self.config.vault_namespace:
            headers["X-Vault-Namespace"] = namespace or self.config.vault_namespace

        session = self._get_session()

        if method.upper() == "GET":
            response = session.get(url, headers=headers, timeout=self.timeout)
        elif method.upper() == "POST":
            response = session.post(
                url, headers=headers, json=data, timeout=self.timeout
            )
        elif method.upper() == "PUT":
            response = session.put(
                url, headers=headers, json=data, timeout=self.timeout
            )
        elif method.upper() == "DELETE":
            response = session.delete(url, headers=headers, timeout=self.timeout)
        elif method.upper() == "LIST":
            response = session.request(
                "LIST", url, headers=headers, timeout=self.timeout
            )
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        if response.status_code == 403:
            raise AuthenticationError(
                f"Access denied: {response.text}",
                provider="hashicorp_vault",
            )

        if response.status_code == 404:
            return {}

        if response.status_code >= 400:
            raise CollectionError(
                f"Vault API error {response.status_code}: {response.text}",
                platform="hashicorp_vault",
            )

        if response.status_code == 204:
            return {}

        return response.json()

    def validate_credentials(self) -> bool:
        """Validate Vault credentials."""
        try:
            token = self._authenticate()
            # Verify token by looking it up
            response = self._make_request("GET", "/v1/auth/token/lookup-self")
            self.logger.info(
                f"Authenticated to Vault (policies: {response.get('data', {}).get('policies', [])})"
            )
            return True
        except Exception as e:
            self.logger.error(f"Vault authentication failed: {e}")
            raise AuthenticationError(
                f"Failed to authenticate with Vault: {e}",
                provider="hashicorp_vault",
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
        Collect HashiCorp Vault evidence.

        Args:
            evidence_types: Types of evidence to collect (None = all)
            since: Only collect evidence after this time
            filters: Additional filters
            progress_callback: Progress callback(current, total)

        Returns:
            CollectionResult with collected evidence
        """
        self.logger.info("Starting HashiCorp Vault evidence collection")

        types_to_collect = evidence_types or HASHICORP_VAULT_EVIDENCE_TYPES
        namespaces = self.config.namespaces or [None]  # None = root namespace
        total_steps = len(types_to_collect) * len(namespaces)
        current_step = 0

        all_evidence: list[Evidence] = []
        errors: list[str] = []

        for namespace in namespaces:
            ns_label = namespace or "root"
            self.logger.info(f"Collecting from namespace: {ns_label}")

            for evidence_type in types_to_collect:
                if progress_callback:
                    progress_callback(current_step, total_steps)
                current_step += 1

                try:
                    evidence_items = self._collect_evidence_type(
                        evidence_type, namespace, since, filters
                    )
                    all_evidence.extend(evidence_items)
                    self.logger.debug(
                        f"Collected {len(evidence_items)} {evidence_type} items "
                        f"from {ns_label}"
                    )
                except Exception as e:
                    error_msg = f"Failed to collect {evidence_type} from {ns_label}: {e}"
                    self.logger.warning(error_msg)
                    errors.append(error_msg)

        if progress_callback:
            progress_callback(total_steps, total_steps)

        self.logger.info(
            f"Collected {len(all_evidence)} HashiCorp Vault evidence items"
        )

        return CollectionResult(
            success=len(errors) == 0,
            evidence=all_evidence,
            errors=errors,
            metadata={
                "platform": "hashicorp_vault",
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "vault_addr": self.config.vault_addr,
                "namespaces": namespaces,
                "evidence_types": types_to_collect,
            },
        )

    def _collect_evidence_type(
        self,
        evidence_type: str,
        namespace: str | None,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect evidence of a specific type."""
        collectors = {
            "vault_status": self._collect_vault_status,
            "secrets_engines": self._collect_secrets_engines,
            "secrets_engine_config": self._collect_secrets_engine_config,
            "auth_methods": self._collect_auth_methods,
            "auth_method_config": self._collect_auth_method_config,
            "policies": self._collect_policies,
            "policy_details": self._collect_policy_details,
            "audit_devices": self._collect_audit_devices,
            "audit_logs": self._collect_audit_logs,
            "tokens": self._collect_tokens,
            "leases": self._collect_leases,
            "namespaces": self._collect_namespaces,
            "mounts": self._collect_mounts,
            "health": self._collect_health,
            "compliance_status": self._collect_compliance_status,
        }

        collector = collectors.get(evidence_type)
        if not collector:
            self.logger.warning(f"Unknown evidence type: {evidence_type}")
            return []

        return self._with_retry(
            lambda: collector(namespace, since, filters),
            f"collect_{evidence_type}",
        )

    def _collect_vault_status(
        self,
        namespace: str | None,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect Vault status evidence."""
        # Get seal status
        response = self._make_request("GET", "/v1/sys/seal-status", namespace=namespace)

        return [
            self._create_evidence(
                evidence_type="vault_status",
                raw_data=response,
                source_id="vault_status",
                metadata={
                    "namespace": namespace,
                    "sealed": response.get("sealed", True),
                    "initialized": response.get("initialized", False),
                    "cluster_name": response.get("cluster_name"),
                    "version": response.get("version"),
                    "recovery_seal": response.get("recovery_seal", False),
                    "storage_type": response.get("storage_type"),
                },
            )
        ]

    def _collect_health(
        self,
        namespace: str | None,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect Vault health evidence."""
        # Health endpoint doesn't require authentication
        session = self._get_session()
        url = urljoin(self.config.vault_addr, "/v1/sys/health")

        response = session.get(url, timeout=self.timeout)
        data = response.json() if response.status_code < 500 else {}

        return [
            self._create_evidence(
                evidence_type="health",
                raw_data=data,
                source_id="vault_health",
                metadata={
                    "namespace": namespace,
                    "initialized": data.get("initialized", False),
                    "sealed": data.get("sealed", True),
                    "standby": data.get("standby", False),
                    "performance_standby": data.get("performance_standby", False),
                    "replication_performance_mode": data.get(
                        "replication_performance_mode"
                    ),
                    "replication_dr_mode": data.get("replication_dr_mode"),
                    "server_time_utc": data.get("server_time_utc"),
                    "version": data.get("version"),
                    "cluster_name": data.get("cluster_name"),
                },
            )
        ]

    def _collect_secrets_engines(
        self,
        namespace: str | None,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect secrets engines evidence."""
        response = self._make_request("GET", "/v1/sys/mounts", namespace=namespace)
        mounts = response.get("data", response)

        engine_summary = []
        for path, config in mounts.items():
            engine_summary.append({
                "path": path,
                "type": config.get("type"),
                "description": config.get("description"),
                "accessor": config.get("accessor"),
                "local": config.get("local", False),
                "seal_wrap": config.get("seal_wrap", False),
            })

        return [
            self._create_evidence(
                evidence_type="secrets_engines",
                raw_data=mounts,
                source_id="vault_secrets_engines",
                metadata={
                    "namespace": namespace,
                    "total_engines": len(mounts),
                    "engine_types": list(set(m.get("type") for m in mounts.values())),
                    "summary": engine_summary,
                },
            )
        ]

    def _collect_secrets_engine_config(
        self,
        namespace: str | None,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect detailed secrets engine configuration evidence."""
        response = self._make_request("GET", "/v1/sys/mounts", namespace=namespace)
        mounts = response.get("data", response)
        evidence_items = []

        for path, config in mounts.items():
            # Get tune configuration
            tune_path = f"/v1/sys/mounts/{path.rstrip('/')}/tune"
            try:
                tune = self._make_request("GET", tune_path, namespace=namespace)
                tune_data = tune.get("data", tune)
            except Exception:
                tune_data = {}

            evidence_items.append(
                self._create_evidence(
                    evidence_type="secrets_engine_config",
                    raw_data={
                        "path": path,
                        "config": config,
                        "tune": tune_data,
                    },
                    source_id=path.rstrip("/"),
                    metadata={
                        "namespace": namespace,
                        "path": path,
                        "type": config.get("type"),
                        "description": config.get("description"),
                        "default_lease_ttl": tune_data.get("default_lease_ttl"),
                        "max_lease_ttl": tune_data.get("max_lease_ttl"),
                        "force_no_cache": tune_data.get("force_no_cache", False),
                    },
                )
            )

        return evidence_items

    def _collect_auth_methods(
        self,
        namespace: str | None,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect authentication methods evidence."""
        response = self._make_request("GET", "/v1/sys/auth", namespace=namespace)
        auth_methods = response.get("data", response)

        method_summary = []
        for path, config in auth_methods.items():
            method_summary.append({
                "path": path,
                "type": config.get("type"),
                "description": config.get("description"),
                "accessor": config.get("accessor"),
                "local": config.get("local", False),
            })

        return [
            self._create_evidence(
                evidence_type="auth_methods",
                raw_data=auth_methods,
                source_id="vault_auth_methods",
                metadata={
                    "namespace": namespace,
                    "total_methods": len(auth_methods),
                    "method_types": list(
                        set(m.get("type") for m in auth_methods.values())
                    ),
                    "summary": method_summary,
                },
            )
        ]

    def _collect_auth_method_config(
        self,
        namespace: str | None,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect detailed auth method configuration evidence."""
        response = self._make_request("GET", "/v1/sys/auth", namespace=namespace)
        auth_methods = response.get("data", response)
        evidence_items = []

        for path, config in auth_methods.items():
            # Get tune configuration
            tune_path = f"/v1/sys/auth/{path.rstrip('/')}/tune"
            try:
                tune = self._make_request("GET", tune_path, namespace=namespace)
                tune_data = tune.get("data", tune)
            except Exception:
                tune_data = {}

            evidence_items.append(
                self._create_evidence(
                    evidence_type="auth_method_config",
                    raw_data={
                        "path": path,
                        "config": config,
                        "tune": tune_data,
                    },
                    source_id=f"auth/{path.rstrip('/')}",
                    metadata={
                        "namespace": namespace,
                        "path": path,
                        "type": config.get("type"),
                        "description": config.get("description"),
                        "default_lease_ttl": tune_data.get("default_lease_ttl"),
                        "max_lease_ttl": tune_data.get("max_lease_ttl"),
                        "token_type": tune_data.get("token_type"),
                    },
                )
            )

        return evidence_items

    def _collect_policies(
        self,
        namespace: str | None,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect policies evidence."""
        response = self._make_request("LIST", "/v1/sys/policies/acl", namespace=namespace)
        policies = response.get("data", {}).get("keys", [])

        return [
            self._create_evidence(
                evidence_type="policies",
                raw_data={"policies": policies},
                source_id="vault_policies",
                metadata={
                    "namespace": namespace,
                    "total_policies": len(policies),
                    "policy_names": policies,
                },
            )
        ]

    def _collect_policy_details(
        self,
        namespace: str | None,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect detailed policy content evidence."""
        response = self._make_request("LIST", "/v1/sys/policies/acl", namespace=namespace)
        policies = response.get("data", {}).get("keys", [])
        evidence_items = []

        for policy_name in policies:
            try:
                policy_response = self._make_request(
                    "GET",
                    f"/v1/sys/policies/acl/{policy_name}",
                    namespace=namespace,
                )
                policy_data = policy_response.get("data", policy_response)

                # Parse policy to extract paths
                policy_text = policy_data.get("policy", "")
                paths = self._extract_policy_paths(policy_text)

                evidence_items.append(
                    self._create_evidence(
                        evidence_type="policy_details",
                        raw_data={
                            "name": policy_name,
                            "policy": policy_text,
                        },
                        source_id=f"policy/{policy_name}",
                        metadata={
                            "namespace": namespace,
                            "policy_name": policy_name,
                            "path_count": len(paths),
                            "paths": paths[:20],  # Limit for metadata
                            "has_sudo": "sudo" in policy_text.lower(),
                            "has_deny": "deny" in policy_text.lower(),
                        },
                    )
                )

            except Exception as e:
                self.logger.warning(f"Failed to get policy {policy_name}: {e}")

        return evidence_items

    def _extract_policy_paths(self, policy_text: str) -> list[str]:
        """Extract paths from policy HCL text."""
        paths = []
        lines = policy_text.split("\n")
        for line in lines:
            line = line.strip()
            if line.startswith("path"):
                # Extract path from: path "secret/*" {
                parts = line.split('"')
                if len(parts) >= 2:
                    paths.append(parts[1])
        return paths

    def _collect_audit_devices(
        self,
        namespace: str | None,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect audit device evidence."""
        response = self._make_request("GET", "/v1/sys/audit", namespace=namespace)
        audit_devices = response.get("data", response)

        device_summary = []
        for path, config in audit_devices.items():
            device_summary.append({
                "path": path,
                "type": config.get("type"),
                "description": config.get("description"),
                "local": config.get("local", False),
            })

        return [
            self._create_evidence(
                evidence_type="audit_devices",
                raw_data=audit_devices,
                source_id="vault_audit_devices",
                metadata={
                    "namespace": namespace,
                    "total_devices": len(audit_devices),
                    "device_types": list(
                        set(d.get("type") for d in audit_devices.values())
                    ),
                    "has_file_audit": any(
                        d.get("type") == "file" for d in audit_devices.values()
                    ),
                    "has_syslog_audit": any(
                        d.get("type") == "syslog" for d in audit_devices.values()
                    ),
                    "summary": device_summary,
                },
            )
        ]

    def _collect_audit_logs(
        self,
        namespace: str | None,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect audit log evidence (if accessible)."""
        if not self.config.include_audit_logs:
            return []

        # Note: Vault doesn't expose audit logs via API by default
        # This collects audit device configuration instead
        # Actual log access would require external log aggregation

        response = self._make_request("GET", "/v1/sys/audit", namespace=namespace)
        audit_devices = response.get("data", response)

        return [
            self._create_evidence(
                evidence_type="audit_logs",
                raw_data={
                    "audit_devices": audit_devices,
                    "note": "Audit logs are not directly accessible via API. "
                    "Check configured audit devices for log destinations.",
                },
                source_id="vault_audit_logs",
                metadata={
                    "namespace": namespace,
                    "audit_enabled": len(audit_devices) > 0,
                    "device_count": len(audit_devices),
                    "log_destinations": [
                        d.get("options", {}).get("file_path")
                        or d.get("options", {}).get("facility", "syslog")
                        for d in audit_devices.values()
                    ],
                },
            )
        ]

    def _collect_tokens(
        self,
        namespace: str | None,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect token accessor evidence."""
        response = self._make_request("LIST", "/v1/auth/token/accessors", namespace=namespace)
        accessors = response.get("data", {}).get("keys", [])

        # Get details for a sample of accessors (limited to avoid performance issues)
        token_details = []
        for accessor in accessors[:50]:  # Limit
            try:
                details = self._make_request(
                    "POST",
                    "/v1/auth/token/lookup-accessor",
                    data={"accessor": accessor},
                    namespace=namespace,
                )
                token_data = details.get("data", {})
                token_details.append({
                    "accessor": accessor,
                    "display_name": token_data.get("display_name"),
                    "policies": token_data.get("policies", []),
                    "ttl": token_data.get("ttl"),
                    "renewable": token_data.get("renewable", False),
                    "orphan": token_data.get("orphan", False),
                    "creation_time": token_data.get("creation_time"),
                    "expire_time": token_data.get("expire_time"),
                })
            except Exception:
                continue

        return [
            self._create_evidence(
                evidence_type="tokens",
                raw_data={
                    "total_accessors": len(accessors),
                    "sampled_tokens": token_details,
                },
                source_id="vault_tokens",
                metadata={
                    "namespace": namespace,
                    "total_tokens": len(accessors),
                    "sampled_count": len(token_details),
                    "orphan_tokens": sum(1 for t in token_details if t.get("orphan")),
                    "non_renewable": sum(
                        1 for t in token_details if not t.get("renewable")
                    ),
                },
            )
        ]

    def _collect_leases(
        self,
        namespace: str | None,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect lease information evidence."""
        if not self.config.include_lease_details:
            return []

        # List leases by prefix
        lease_prefixes = []
        try:
            response = self._make_request("LIST", "/v1/sys/leases/lookup", namespace=namespace)
            lease_prefixes = response.get("data", {}).get("keys", [])
        except Exception:
            pass

        # Count leases per prefix
        lease_counts = {}
        for prefix in lease_prefixes:
            try:
                response = self._make_request(
                    "LIST",
                    f"/v1/sys/leases/lookup/{prefix}",
                    namespace=namespace,
                )
                keys = response.get("data", {}).get("keys", [])
                lease_counts[prefix] = len(keys)
            except Exception:
                lease_counts[prefix] = 0

        return [
            self._create_evidence(
                evidence_type="leases",
                raw_data={
                    "lease_prefixes": lease_prefixes,
                    "lease_counts": lease_counts,
                },
                source_id="vault_leases",
                metadata={
                    "namespace": namespace,
                    "total_prefixes": len(lease_prefixes),
                    "total_leases": sum(lease_counts.values()),
                    "leases_by_prefix": lease_counts,
                },
            )
        ]

    def _collect_namespaces(
        self,
        namespace: str | None,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect namespace evidence (Enterprise feature)."""
        try:
            response = self._make_request("LIST", "/v1/sys/namespaces", namespace=namespace)
            namespaces = response.get("data", {}).get("keys", [])
        except Exception:
            # Namespaces not available (OSS or insufficient permissions)
            return [
                self._create_evidence(
                    evidence_type="namespaces",
                    raw_data={"namespaces_available": False},
                    source_id="vault_namespaces",
                    metadata={
                        "namespace": namespace,
                        "enterprise_feature": True,
                        "available": False,
                    },
                )
            ]

        return [
            self._create_evidence(
                evidence_type="namespaces",
                raw_data={"namespaces": namespaces},
                source_id="vault_namespaces",
                metadata={
                    "namespace": namespace,
                    "enterprise_feature": True,
                    "available": True,
                    "total_namespaces": len(namespaces),
                    "namespace_names": namespaces,
                },
            )
        ]

    def _collect_mounts(
        self,
        namespace: str | None,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect all mount points evidence."""
        # Get secrets engines
        secrets = self._make_request("GET", "/v1/sys/mounts", namespace=namespace)
        secrets_mounts = secrets.get("data", secrets)

        # Get auth methods
        auth = self._make_request("GET", "/v1/sys/auth", namespace=namespace)
        auth_mounts = auth.get("data", auth)

        return [
            self._create_evidence(
                evidence_type="mounts",
                raw_data={
                    "secrets_engines": secrets_mounts,
                    "auth_methods": auth_mounts,
                },
                source_id="vault_mounts",
                metadata={
                    "namespace": namespace,
                    "secrets_engine_count": len(secrets_mounts),
                    "auth_method_count": len(auth_mounts),
                    "total_mounts": len(secrets_mounts) + len(auth_mounts),
                },
            )
        ]

    def _collect_compliance_status(
        self,
        namespace: str | None,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect overall compliance status."""
        issues = []

        # Check seal status
        try:
            status = self._make_request("GET", "/v1/sys/seal-status", namespace=namespace)
            if status.get("sealed"):
                issues.append("Vault is sealed")
        except Exception:
            issues.append("Unable to check seal status")

        # Check audit devices
        try:
            audit = self._make_request("GET", "/v1/sys/audit", namespace=namespace)
            audit_devices = audit.get("data", audit)
            if not audit_devices:
                issues.append("No audit devices configured")
        except Exception:
            issues.append("Unable to check audit devices")

        # Check auth methods
        try:
            auth = self._make_request("GET", "/v1/sys/auth", namespace=namespace)
            auth_methods = auth.get("data", auth)

            # Check for root token auth only
            if len(auth_methods) == 1 and "token/" in auth_methods:
                issues.append("Only token auth enabled - no additional auth methods")
        except Exception:
            issues.append("Unable to check auth methods")

        # Check policies
        try:
            policies = self._make_request("LIST", "/v1/sys/policies/acl", namespace=namespace)
            policy_list = policies.get("data", {}).get("keys", [])

            # Check for default policy only
            if policy_list == ["default", "root"]:
                issues.append("Only default policies exist - no custom policies")
        except Exception:
            issues.append("Unable to check policies")

        compliance_score = max(0, 100 - (len(issues) * 20))

        return [
            self._create_evidence(
                evidence_type="compliance_status",
                raw_data={
                    "issues": issues,
                    "checks_performed": [
                        "seal_status",
                        "audit_devices",
                        "auth_methods",
                        "policies",
                    ],
                },
                source_id="vault_compliance",
                metadata={
                    "namespace": namespace,
                    "issue_count": len(issues),
                    "issues": issues,
                    "compliance_score": compliance_score,
                    "compliant": len(issues) == 0,
                },
            )
        ]
