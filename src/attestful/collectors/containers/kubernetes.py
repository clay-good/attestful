"""
Kubernetes collector for Attestful.

Dual-mode collector supporting both resource collection (for compliance checks)
and evidence collection (for audit documentation).

Requires kubernetes package.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterator

from attestful.collectors.base import BaseCollector, CollectorMetadata, CollectorMode
from attestful.core.exceptions import (
    AuthenticationError,
    CollectionError,
    ConfigurationError,
)
from attestful.core.logging import get_logger
from attestful.core.models import CollectionResult, Evidence, Resource

logger = get_logger(__name__)

# Optional Kubernetes SDK import
try:
    from kubernetes import client, config
    from kubernetes.client.exceptions import ApiException
    from kubernetes.config.config_exception import ConfigException

    K8S_SDK_AVAILABLE = True
except ImportError:
    K8S_SDK_AVAILABLE = False
    ApiException = Exception  # type: ignore
    ConfigException = Exception  # type: ignore


@dataclass
class KubernetesCollectorConfig:
    """Configuration for Kubernetes collector."""

    # Authentication options
    kubeconfig_path: str | None = None  # Path to kubeconfig file
    context: str | None = None  # Kubernetes context to use
    in_cluster: bool = False  # Use in-cluster config (for running inside k8s)

    # API server direct connection (alternative to kubeconfig)
    api_server: str | None = None
    api_token: str | None = None
    ca_cert_path: str | None = None
    skip_tls_verify: bool = False

    # Scanning scope
    namespaces: list[str] = field(default_factory=list)  # Empty = all namespaces
    exclude_namespaces: list[str] = field(
        default_factory=lambda: ["kube-system", "kube-public", "kube-node-lease"]
    )
    label_selectors: dict[str, str] = field(default_factory=dict)

    # Rate limiting
    max_retries: int = 3
    timeout: int = 30


class KubernetesCollector(BaseCollector):
    """
    Kubernetes collector for container resources and compliance evidence.

    Supports dual-mode operation:
    - Resource mode: Collects Kubernetes resources for compliance checking
    - Evidence mode: Collects cluster configuration evidence for audits

    Resource Types:
    - pod: Running pods
    - deployment: Deployment configurations
    - service: Service definitions
    - configmap: ConfigMaps
    - secret: Secret metadata (not values)
    - namespace: Namespace configurations
    - networkpolicy: Network policies
    - serviceaccount: Service accounts
    - role: RBAC roles
    - rolebinding: RBAC role bindings
    - clusterrole: Cluster-wide RBAC roles
    - clusterrolebinding: Cluster-wide role bindings
    - persistentvolume: Persistent volumes
    - persistentvolumeclaim: PVC configurations
    - ingress: Ingress resources
    - node: Cluster nodes

    Evidence Types:
    - cluster_info: Cluster metadata and version
    - rbac_config: RBAC configuration summary
    - network_policies: Network policy evidence
    - pod_security: Pod security configurations
    - secrets_inventory: Secrets metadata inventory
    - resource_quotas: Resource quota evidence
    - limit_ranges: Limit range configurations
    - admission_controllers: Admission controller info

    Example:
        collector = KubernetesCollector(
            config=KubernetesCollectorConfig(
                namespaces=["production", "staging"],
            )
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["pod", "deployment", "networkpolicy"]
        )

        # Collect evidence for audits
        result = collector.collect_evidence(
            evidence_types=["rbac_config", "pod_security"]
        )
    """

    PLATFORM = "kubernetes"
    SUPPORTED_RESOURCE_TYPES = [
        "pod",
        "deployment",
        "daemonset",
        "statefulset",
        "replicaset",
        "service",
        "configmap",
        "secret",
        "namespace",
        "networkpolicy",
        "serviceaccount",
        "role",
        "rolebinding",
        "clusterrole",
        "clusterrolebinding",
        "persistentvolume",
        "persistentvolumeclaim",
        "ingress",
        "node",
        "cronjob",
        "job",
    ]
    SUPPORTED_EVIDENCE_TYPES = [
        "cluster_info",
        "rbac_config",
        "network_policies",
        "pod_security",
        "secrets_inventory",
        "resource_quotas",
        "limit_ranges",
        "admission_controllers",
    ]

    metadata = CollectorMetadata(
        name="KubernetesCollector",
        platform="kubernetes",
        description="Kubernetes cluster resource and evidence collector",
        mode=CollectorMode.BOTH,
        resource_types=SUPPORTED_RESOURCE_TYPES,
        evidence_types=SUPPORTED_EVIDENCE_TYPES,
        requires_credentials=True,
        version="1.0.0",
    )

    def __init__(
        self,
        config: KubernetesCollectorConfig | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize Kubernetes collector.

        Args:
            config: Kubernetes collector configuration.
            **kwargs: Additional arguments passed to BaseCollector.
        """
        if not K8S_SDK_AVAILABLE:
            raise ConfigurationError(
                "Kubernetes SDK not installed. Install with: pip install kubernetes"
            )

        super().__init__(**kwargs)
        self.config = config or KubernetesCollectorConfig()
        self._api_client: client.ApiClient | None = None
        self._core_v1: client.CoreV1Api | None = None
        self._apps_v1: client.AppsV1Api | None = None
        self._batch_v1: client.BatchV1Api | None = None
        self._networking_v1: client.NetworkingV1Api | None = None
        self._rbac_v1: client.RbacAuthorizationV1Api | None = None
        self._version_api: client.VersionApi | None = None

    def _configure_client(self) -> None:
        """Configure the Kubernetes API client."""
        if self._api_client is not None:
            return

        try:
            if self.config.in_cluster:
                # Running inside Kubernetes cluster
                config.load_incluster_config()
                self._api_client = client.ApiClient()
            elif self.config.api_server and self.config.api_token:
                # Direct API server connection
                configuration = client.Configuration()
                configuration.host = self.config.api_server
                configuration.api_key = {"authorization": f"Bearer {self.config.api_token}"}

                if self.config.skip_tls_verify:
                    configuration.verify_ssl = False
                elif self.config.ca_cert_path:
                    configuration.ssl_ca_cert = self.config.ca_cert_path

                self._api_client = client.ApiClient(configuration)
            else:
                # Use kubeconfig file
                config.load_kube_config(
                    config_file=self.config.kubeconfig_path,
                    context=self.config.context,
                )
                self._api_client = client.ApiClient()

            # Initialize API clients
            self._core_v1 = client.CoreV1Api(self._api_client)
            self._apps_v1 = client.AppsV1Api(self._api_client)
            self._batch_v1 = client.BatchV1Api(self._api_client)
            self._networking_v1 = client.NetworkingV1Api(self._api_client)
            self._rbac_v1 = client.RbacAuthorizationV1Api(self._api_client)
            self._version_api = client.VersionApi(self._api_client)

        except ConfigException as e:
            raise AuthenticationError(
                f"Failed to configure Kubernetes client: {e}",
                platform="kubernetes",
            )

    def validate_credentials(self) -> bool:
        """
        Validate Kubernetes credentials by attempting to list namespaces.

        Returns:
            True if credentials are valid.

        Raises:
            AuthenticationError: If authentication fails.
        """
        try:
            self._configure_client()
            # Try to get cluster version as a simple auth check
            self._version_api.get_code()
            return True

        except ApiException as e:
            if e.status == 401:
                raise AuthenticationError(
                    "Kubernetes authentication failed: Invalid credentials",
                    platform="kubernetes",
                )
            elif e.status == 403:
                raise AuthenticationError(
                    "Kubernetes authentication failed: Insufficient permissions",
                    platform="kubernetes",
                )
            raise AuthenticationError(
                f"Kubernetes authentication failed: {e}",
                platform="kubernetes",
            )
        except Exception as e:
            raise AuthenticationError(
                f"Kubernetes connection failed: {e}",
                platform="kubernetes",
            )

    def _get_namespaces(self) -> list[str]:
        """Get list of namespaces to scan."""
        if self.config.namespaces:
            return self.config.namespaces

        try:
            ns_list = self._core_v1.list_namespace()
            namespaces = [
                ns.metadata.name
                for ns in ns_list.items
                if ns.metadata.name not in self.config.exclude_namespaces
            ]
            return namespaces
        except ApiException as e:
            self.logger.warning(f"Failed to list namespaces: {e}")
            return ["default"]

    def _label_selector_string(self) -> str:
        """Build label selector string from config."""
        if not self.config.label_selectors:
            return ""
        return ",".join(f"{k}={v}" for k, v in self.config.label_selectors.items())

    # =========================================================================
    # Resource Collection
    # =========================================================================

    def collect_resources(
        self,
        *,
        resource_types: list[str] | None = None,
        regions: list[str] | None = None,  # Not used for k8s, kept for interface
        filters: dict[str, Any] | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> list[Resource]:
        """
        Collect Kubernetes resources for compliance checking.

        Args:
            resource_types: Specific resource types to collect (None = all).
            regions: Not used for Kubernetes.
            filters: Additional filters (namespace, label_selector).
            progress_callback: Optional callback(current, total) for progress.

        Returns:
            List of collected Resource objects.
        """
        self._configure_client()

        types_to_collect = resource_types or self.SUPPORTED_RESOURCE_TYPES
        resources: list[Resource] = []
        filters = filters or {}

        # Override namespaces from filters if provided
        namespaces = filters.get("namespaces") or self._get_namespaces()
        label_selector = filters.get("label_selector") or self._label_selector_string()

        total_types = len(types_to_collect)

        for i, resource_type in enumerate(types_to_collect):
            if progress_callback:
                progress_callback(i, total_types)

            try:
                collected = self._collect_resource_type(
                    resource_type, namespaces, label_selector
                )
                resources.extend(collected)
                self.logger.debug(
                    f"Collected {len(collected)} {resource_type} resources"
                )
            except ApiException as e:
                self.logger.warning(
                    f"Failed to collect {resource_type}: {e.reason}"
                )
            except Exception as e:
                self.logger.warning(f"Error collecting {resource_type}: {e}")

        if progress_callback:
            progress_callback(total_types, total_types)

        self.logger.info(f"Collected {len(resources)} Kubernetes resources")
        return resources

    def _collect_resource_type(
        self,
        resource_type: str,
        namespaces: list[str],
        label_selector: str,
    ) -> list[Resource]:
        """Collect resources of a specific type."""
        collectors = {
            "pod": self._collect_pods,
            "deployment": self._collect_deployments,
            "daemonset": self._collect_daemonsets,
            "statefulset": self._collect_statefulsets,
            "replicaset": self._collect_replicasets,
            "service": self._collect_services,
            "configmap": self._collect_configmaps,
            "secret": self._collect_secrets,
            "namespace": self._collect_namespaces,
            "networkpolicy": self._collect_network_policies,
            "serviceaccount": self._collect_service_accounts,
            "role": self._collect_roles,
            "rolebinding": self._collect_role_bindings,
            "clusterrole": self._collect_cluster_roles,
            "clusterrolebinding": self._collect_cluster_role_bindings,
            "persistentvolume": self._collect_persistent_volumes,
            "persistentvolumeclaim": self._collect_pvcs,
            "ingress": self._collect_ingresses,
            "node": self._collect_nodes,
            "cronjob": self._collect_cronjobs,
            "job": self._collect_jobs,
        }

        collector_fn = collectors.get(resource_type)
        if not collector_fn:
            self.logger.warning(f"Unknown resource type: {resource_type}")
            return []

        return list(collector_fn(namespaces, label_selector))

    def _collect_pods(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect pod resources."""
        for ns in namespaces:
            self._rate_limit()
            pods = self._core_v1.list_namespaced_pod(
                namespace=ns, label_selector=label_selector
            )
            for pod in pods.items:
                yield self._create_resource(
                    resource_id=f"{ns}/{pod.metadata.name}",
                    resource_type="pod",
                    raw_data=self._sanitize_k8s_object(pod),
                    region=ns,
                    name=pod.metadata.name,
                    tags=pod.metadata.labels or {},
                    metadata={
                        "namespace": ns,
                        "phase": pod.status.phase,
                        "node": pod.spec.node_name,
                        "host_network": pod.spec.host_network or False,
                        "host_pid": pod.spec.host_pid or False,
                        "host_ipc": pod.spec.host_ipc or False,
                        "service_account": pod.spec.service_account_name,
                        "containers": [c.name for c in pod.spec.containers],
                        "security_context": self._extract_security_context(pod.spec),
                    },
                )

    def _collect_deployments(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect deployment resources."""
        for ns in namespaces:
            self._rate_limit()
            deployments = self._apps_v1.list_namespaced_deployment(
                namespace=ns, label_selector=label_selector
            )
            for deploy in deployments.items:
                yield self._create_resource(
                    resource_id=f"{ns}/{deploy.metadata.name}",
                    resource_type="deployment",
                    raw_data=self._sanitize_k8s_object(deploy),
                    region=ns,
                    name=deploy.metadata.name,
                    tags=deploy.metadata.labels or {},
                    metadata={
                        "namespace": ns,
                        "replicas": deploy.spec.replicas,
                        "ready_replicas": deploy.status.ready_replicas or 0,
                        "strategy": deploy.spec.strategy.type if deploy.spec.strategy else None,
                        "service_account": deploy.spec.template.spec.service_account_name,
                        "containers": [
                            c.name for c in deploy.spec.template.spec.containers
                        ],
                        "security_context": self._extract_security_context(
                            deploy.spec.template.spec
                        ),
                    },
                )

    def _collect_daemonsets(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect daemonset resources."""
        for ns in namespaces:
            self._rate_limit()
            daemonsets = self._apps_v1.list_namespaced_daemon_set(
                namespace=ns, label_selector=label_selector
            )
            for ds in daemonsets.items:
                yield self._create_resource(
                    resource_id=f"{ns}/{ds.metadata.name}",
                    resource_type="daemonset",
                    raw_data=self._sanitize_k8s_object(ds),
                    region=ns,
                    name=ds.metadata.name,
                    tags=ds.metadata.labels or {},
                    metadata={
                        "namespace": ns,
                        "desired": ds.status.desired_number_scheduled,
                        "current": ds.status.current_number_scheduled,
                        "ready": ds.status.number_ready,
                        "service_account": ds.spec.template.spec.service_account_name,
                    },
                )

    def _collect_statefulsets(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect statefulset resources."""
        for ns in namespaces:
            self._rate_limit()
            statefulsets = self._apps_v1.list_namespaced_stateful_set(
                namespace=ns, label_selector=label_selector
            )
            for sts in statefulsets.items:
                yield self._create_resource(
                    resource_id=f"{ns}/{sts.metadata.name}",
                    resource_type="statefulset",
                    raw_data=self._sanitize_k8s_object(sts),
                    region=ns,
                    name=sts.metadata.name,
                    tags=sts.metadata.labels or {},
                    metadata={
                        "namespace": ns,
                        "replicas": sts.spec.replicas,
                        "ready_replicas": sts.status.ready_replicas or 0,
                        "service_account": sts.spec.template.spec.service_account_name,
                    },
                )

    def _collect_replicasets(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect replicaset resources."""
        for ns in namespaces:
            self._rate_limit()
            replicasets = self._apps_v1.list_namespaced_replica_set(
                namespace=ns, label_selector=label_selector
            )
            for rs in replicasets.items:
                yield self._create_resource(
                    resource_id=f"{ns}/{rs.metadata.name}",
                    resource_type="replicaset",
                    raw_data=self._sanitize_k8s_object(rs),
                    region=ns,
                    name=rs.metadata.name,
                    tags=rs.metadata.labels or {},
                    metadata={
                        "namespace": ns,
                        "replicas": rs.spec.replicas,
                        "ready_replicas": rs.status.ready_replicas or 0,
                    },
                )

    def _collect_services(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect service resources."""
        for ns in namespaces:
            self._rate_limit()
            services = self._core_v1.list_namespaced_service(
                namespace=ns, label_selector=label_selector
            )
            for svc in services.items:
                yield self._create_resource(
                    resource_id=f"{ns}/{svc.metadata.name}",
                    resource_type="service",
                    raw_data=self._sanitize_k8s_object(svc),
                    region=ns,
                    name=svc.metadata.name,
                    tags=svc.metadata.labels or {},
                    metadata={
                        "namespace": ns,
                        "type": svc.spec.type,
                        "cluster_ip": svc.spec.cluster_ip,
                        "external_ips": svc.spec.external_i_ps or [],
                        "ports": [
                            {"port": p.port, "protocol": p.protocol, "target_port": str(p.target_port)}
                            for p in (svc.spec.ports or [])
                        ],
                    },
                )

    def _collect_configmaps(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect configmap resources."""
        for ns in namespaces:
            self._rate_limit()
            configmaps = self._core_v1.list_namespaced_config_map(
                namespace=ns, label_selector=label_selector
            )
            for cm in configmaps.items:
                yield self._create_resource(
                    resource_id=f"{ns}/{cm.metadata.name}",
                    resource_type="configmap",
                    raw_data=self._sanitize_k8s_object(cm),
                    region=ns,
                    name=cm.metadata.name,
                    tags=cm.metadata.labels or {},
                    metadata={
                        "namespace": ns,
                        "data_keys": list(cm.data.keys()) if cm.data else [],
                    },
                )

    def _collect_secrets(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect secret resources (metadata only, not values)."""
        for ns in namespaces:
            self._rate_limit()
            secrets = self._core_v1.list_namespaced_secret(
                namespace=ns, label_selector=label_selector
            )
            for secret in secrets.items:
                # Only collect metadata, never the actual secret data
                yield self._create_resource(
                    resource_id=f"{ns}/{secret.metadata.name}",
                    resource_type="secret",
                    raw_data={
                        "metadata": {
                            "name": secret.metadata.name,
                            "namespace": ns,
                            "labels": secret.metadata.labels,
                            "annotations": secret.metadata.annotations,
                            "creation_timestamp": str(secret.metadata.creation_timestamp),
                        },
                        "type": secret.type,
                        "data_keys": list(secret.data.keys()) if secret.data else [],
                    },
                    region=ns,
                    name=secret.metadata.name,
                    tags=secret.metadata.labels or {},
                    metadata={
                        "namespace": ns,
                        "type": secret.type,
                        "data_keys": list(secret.data.keys()) if secret.data else [],
                    },
                )

    def _collect_namespaces(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect namespace resources."""
        self._rate_limit()
        ns_list = self._core_v1.list_namespace(label_selector=label_selector)
        for ns in ns_list.items:
            yield self._create_resource(
                resource_id=ns.metadata.name,
                resource_type="namespace",
                raw_data=self._sanitize_k8s_object(ns),
                name=ns.metadata.name,
                tags=ns.metadata.labels or {},
                metadata={
                    "phase": ns.status.phase,
                    "annotations": ns.metadata.annotations or {},
                },
            )

    def _collect_network_policies(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect network policy resources."""
        for ns in namespaces:
            self._rate_limit()
            policies = self._networking_v1.list_namespaced_network_policy(
                namespace=ns, label_selector=label_selector
            )
            for policy in policies.items:
                yield self._create_resource(
                    resource_id=f"{ns}/{policy.metadata.name}",
                    resource_type="networkpolicy",
                    raw_data=self._sanitize_k8s_object(policy),
                    region=ns,
                    name=policy.metadata.name,
                    tags=policy.metadata.labels or {},
                    metadata={
                        "namespace": ns,
                        "pod_selector": policy.spec.pod_selector.match_labels
                        if policy.spec.pod_selector else {},
                        "policy_types": policy.spec.policy_types or [],
                        "has_ingress": bool(policy.spec.ingress),
                        "has_egress": bool(policy.spec.egress),
                    },
                )

    def _collect_service_accounts(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect service account resources."""
        for ns in namespaces:
            self._rate_limit()
            accounts = self._core_v1.list_namespaced_service_account(
                namespace=ns, label_selector=label_selector
            )
            for sa in accounts.items:
                yield self._create_resource(
                    resource_id=f"{ns}/{sa.metadata.name}",
                    resource_type="serviceaccount",
                    raw_data=self._sanitize_k8s_object(sa),
                    region=ns,
                    name=sa.metadata.name,
                    tags=sa.metadata.labels or {},
                    metadata={
                        "namespace": ns,
                        "automount_service_account_token": sa.automount_service_account_token,
                        "secrets": [s.name for s in (sa.secrets or [])],
                        "image_pull_secrets": [
                            s.name for s in (sa.image_pull_secrets or [])
                        ],
                    },
                )

    def _collect_roles(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect role resources."""
        for ns in namespaces:
            self._rate_limit()
            roles = self._rbac_v1.list_namespaced_role(
                namespace=ns, label_selector=label_selector
            )
            for role in roles.items:
                yield self._create_resource(
                    resource_id=f"{ns}/{role.metadata.name}",
                    resource_type="role",
                    raw_data=self._sanitize_k8s_object(role),
                    region=ns,
                    name=role.metadata.name,
                    tags=role.metadata.labels or {},
                    metadata={
                        "namespace": ns,
                        "rules_count": len(role.rules) if role.rules else 0,
                        "rules": [
                            {
                                "api_groups": r.api_groups,
                                "resources": r.resources,
                                "verbs": r.verbs,
                            }
                            for r in (role.rules or [])
                        ],
                    },
                )

    def _collect_role_bindings(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect role binding resources."""
        for ns in namespaces:
            self._rate_limit()
            bindings = self._rbac_v1.list_namespaced_role_binding(
                namespace=ns, label_selector=label_selector
            )
            for binding in bindings.items:
                yield self._create_resource(
                    resource_id=f"{ns}/{binding.metadata.name}",
                    resource_type="rolebinding",
                    raw_data=self._sanitize_k8s_object(binding),
                    region=ns,
                    name=binding.metadata.name,
                    tags=binding.metadata.labels or {},
                    metadata={
                        "namespace": ns,
                        "role_ref": {
                            "kind": binding.role_ref.kind,
                            "name": binding.role_ref.name,
                        },
                        "subjects": [
                            {
                                "kind": s.kind,
                                "name": s.name,
                                "namespace": getattr(s, "namespace", None),
                            }
                            for s in (binding.subjects or [])
                        ],
                    },
                )

    def _collect_cluster_roles(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect cluster role resources."""
        self._rate_limit()
        roles = self._rbac_v1.list_cluster_role(label_selector=label_selector)
        for role in roles.items:
            yield self._create_resource(
                resource_id=role.metadata.name,
                resource_type="clusterrole",
                raw_data=self._sanitize_k8s_object(role),
                name=role.metadata.name,
                tags=role.metadata.labels or {},
                metadata={
                    "rules_count": len(role.rules) if role.rules else 0,
                    "aggregation_rule": bool(role.aggregation_rule),
                },
            )

    def _collect_cluster_role_bindings(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect cluster role binding resources."""
        self._rate_limit()
        bindings = self._rbac_v1.list_cluster_role_binding(label_selector=label_selector)
        for binding in bindings.items:
            yield self._create_resource(
                resource_id=binding.metadata.name,
                resource_type="clusterrolebinding",
                raw_data=self._sanitize_k8s_object(binding),
                name=binding.metadata.name,
                tags=binding.metadata.labels or {},
                metadata={
                    "role_ref": {
                        "kind": binding.role_ref.kind,
                        "name": binding.role_ref.name,
                    },
                    "subjects_count": len(binding.subjects) if binding.subjects else 0,
                },
            )

    def _collect_persistent_volumes(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect persistent volume resources."""
        self._rate_limit()
        pvs = self._core_v1.list_persistent_volume(label_selector=label_selector)
        for pv in pvs.items:
            yield self._create_resource(
                resource_id=pv.metadata.name,
                resource_type="persistentvolume",
                raw_data=self._sanitize_k8s_object(pv),
                name=pv.metadata.name,
                tags=pv.metadata.labels or {},
                metadata={
                    "capacity": pv.spec.capacity,
                    "access_modes": pv.spec.access_modes,
                    "reclaim_policy": pv.spec.persistent_volume_reclaim_policy,
                    "storage_class": pv.spec.storage_class_name,
                    "phase": pv.status.phase,
                },
            )

    def _collect_pvcs(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect persistent volume claim resources."""
        for ns in namespaces:
            self._rate_limit()
            pvcs = self._core_v1.list_namespaced_persistent_volume_claim(
                namespace=ns, label_selector=label_selector
            )
            for pvc in pvcs.items:
                yield self._create_resource(
                    resource_id=f"{ns}/{pvc.metadata.name}",
                    resource_type="persistentvolumeclaim",
                    raw_data=self._sanitize_k8s_object(pvc),
                    region=ns,
                    name=pvc.metadata.name,
                    tags=pvc.metadata.labels or {},
                    metadata={
                        "namespace": ns,
                        "access_modes": pvc.spec.access_modes,
                        "storage_class": pvc.spec.storage_class_name,
                        "volume_name": pvc.spec.volume_name,
                        "phase": pvc.status.phase,
                    },
                )

    def _collect_ingresses(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect ingress resources."""
        for ns in namespaces:
            self._rate_limit()
            ingresses = self._networking_v1.list_namespaced_ingress(
                namespace=ns, label_selector=label_selector
            )
            for ing in ingresses.items:
                yield self._create_resource(
                    resource_id=f"{ns}/{ing.metadata.name}",
                    resource_type="ingress",
                    raw_data=self._sanitize_k8s_object(ing),
                    region=ns,
                    name=ing.metadata.name,
                    tags=ing.metadata.labels or {},
                    metadata={
                        "namespace": ns,
                        "ingress_class": ing.spec.ingress_class_name,
                        "tls": bool(ing.spec.tls),
                        "rules_count": len(ing.spec.rules) if ing.spec.rules else 0,
                        "hosts": [
                            r.host for r in (ing.spec.rules or []) if r.host
                        ],
                    },
                )

    def _collect_nodes(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect node resources."""
        self._rate_limit()
        nodes = self._core_v1.list_node(label_selector=label_selector)
        for node in nodes.items:
            conditions = {
                c.type: c.status for c in (node.status.conditions or [])
            }
            yield self._create_resource(
                resource_id=node.metadata.name,
                resource_type="node",
                raw_data=self._sanitize_k8s_object(node),
                name=node.metadata.name,
                tags=node.metadata.labels or {},
                metadata={
                    "os_image": node.status.node_info.os_image if node.status.node_info else None,
                    "kernel_version": node.status.node_info.kernel_version if node.status.node_info else None,
                    "container_runtime": node.status.node_info.container_runtime_version if node.status.node_info else None,
                    "kubelet_version": node.status.node_info.kubelet_version if node.status.node_info else None,
                    "ready": conditions.get("Ready") == "True",
                    "taints": [
                        {"key": t.key, "effect": t.effect}
                        for t in (node.spec.taints or [])
                    ],
                },
            )

    def _collect_cronjobs(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect cronjob resources."""
        for ns in namespaces:
            self._rate_limit()
            cronjobs = self._batch_v1.list_namespaced_cron_job(
                namespace=ns, label_selector=label_selector
            )
            for cj in cronjobs.items:
                yield self._create_resource(
                    resource_id=f"{ns}/{cj.metadata.name}",
                    resource_type="cronjob",
                    raw_data=self._sanitize_k8s_object(cj),
                    region=ns,
                    name=cj.metadata.name,
                    tags=cj.metadata.labels or {},
                    metadata={
                        "namespace": ns,
                        "schedule": cj.spec.schedule,
                        "suspend": cj.spec.suspend,
                        "concurrency_policy": cj.spec.concurrency_policy,
                    },
                )

    def _collect_jobs(
        self, namespaces: list[str], label_selector: str
    ) -> Iterator[Resource]:
        """Collect job resources."""
        for ns in namespaces:
            self._rate_limit()
            jobs = self._batch_v1.list_namespaced_job(
                namespace=ns, label_selector=label_selector
            )
            for job in jobs.items:
                yield self._create_resource(
                    resource_id=f"{ns}/{job.metadata.name}",
                    resource_type="job",
                    raw_data=self._sanitize_k8s_object(job),
                    region=ns,
                    name=job.metadata.name,
                    tags=job.metadata.labels or {},
                    metadata={
                        "namespace": ns,
                        "completions": job.spec.completions,
                        "parallelism": job.spec.parallelism,
                        "active": job.status.active or 0,
                        "succeeded": job.status.succeeded or 0,
                        "failed": job.status.failed or 0,
                    },
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
        Collect Kubernetes evidence for compliance audits.

        Args:
            evidence_types: Specific evidence types to collect (None = all).
            since: Not used for Kubernetes evidence.
            filters: Additional filters.
            progress_callback: Optional callback(current, total) for progress.

        Returns:
            CollectionResult with collected evidence.
        """
        self._configure_client()

        types_to_collect = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        evidence_list: list[Evidence] = []
        errors: list[str] = []

        total_types = len(types_to_collect)

        for i, evidence_type in enumerate(types_to_collect):
            if progress_callback:
                progress_callback(i, total_types)

            try:
                collected = self._collect_evidence_type(evidence_type)
                evidence_list.extend(collected)
                self.logger.debug(f"Collected {evidence_type} evidence")
            except ApiException as e:
                error_msg = f"Failed to collect {evidence_type}: {e.reason}"
                self.logger.warning(error_msg)
                errors.append(error_msg)
            except Exception as e:
                error_msg = f"Error collecting {evidence_type}: {e}"
                self.logger.warning(error_msg)
                errors.append(error_msg)

        if progress_callback:
            progress_callback(total_types, total_types)

        self.logger.info(f"Collected {len(evidence_list)} evidence items")

        return CollectionResult(
            evidence_items=evidence_list,
            platform="kubernetes",
            errors=errors,
            success=len(errors) == 0,
            partial=len(errors) > 0 and len(evidence_list) > 0,
            evidence_types_collected=types_to_collect,
            completed_at=datetime.now(timezone.utc),
        )

    def _collect_evidence_type(self, evidence_type: str) -> list[Evidence]:
        """Collect a specific evidence type."""
        collectors = {
            "cluster_info": self._collect_cluster_info_evidence,
            "rbac_config": self._collect_rbac_evidence,
            "network_policies": self._collect_network_policy_evidence,
            "pod_security": self._collect_pod_security_evidence,
            "secrets_inventory": self._collect_secrets_inventory_evidence,
            "resource_quotas": self._collect_resource_quota_evidence,
            "limit_ranges": self._collect_limit_range_evidence,
            "admission_controllers": self._collect_admission_controller_evidence,
        }

        collector_fn = collectors.get(evidence_type)
        if not collector_fn:
            self.logger.warning(f"Unknown evidence type: {evidence_type}")
            return []

        return collector_fn()

    def _collect_cluster_info_evidence(self) -> list[Evidence]:
        """Collect cluster information evidence."""
        self._rate_limit()
        version_info = self._version_api.get_code()

        self._rate_limit()
        nodes = self._core_v1.list_node()

        self._rate_limit()
        namespaces = self._core_v1.list_namespace()

        return [
            self._create_evidence(
                evidence_type="cluster_info",
                raw_data={
                    "version": {
                        "major": version_info.major,
                        "minor": version_info.minor,
                        "git_version": version_info.git_version,
                        "platform": version_info.platform,
                    },
                    "nodes": {
                        "count": len(nodes.items),
                        "summary": [
                            {
                                "name": n.metadata.name,
                                "ready": any(
                                    c.type == "Ready" and c.status == "True"
                                    for c in (n.status.conditions or [])
                                ),
                            }
                            for n in nodes.items
                        ],
                    },
                    "namespaces": {
                        "count": len(namespaces.items),
                        "names": [ns.metadata.name for ns in namespaces.items],
                    },
                },
                source_id="cluster",
                metadata={"collected_at": datetime.now(timezone.utc).isoformat()},
            )
        ]

    def _collect_rbac_evidence(self) -> list[Evidence]:
        """Collect RBAC configuration evidence."""
        evidence: list[Evidence] = []

        # Collect cluster roles
        self._rate_limit()
        cluster_roles = self._rbac_v1.list_cluster_role()

        # Collect cluster role bindings
        self._rate_limit()
        cluster_bindings = self._rbac_v1.list_cluster_role_binding()

        evidence.append(
            self._create_evidence(
                evidence_type="rbac_config",
                raw_data={
                    "cluster_roles": {
                        "count": len(cluster_roles.items),
                        "names": [r.metadata.name for r in cluster_roles.items],
                        "with_wildcards": [
                            r.metadata.name
                            for r in cluster_roles.items
                            if any(
                                "*" in (rule.verbs or [])
                                or "*" in (rule.resources or [])
                                for rule in (r.rules or [])
                            )
                        ],
                    },
                    "cluster_role_bindings": {
                        "count": len(cluster_bindings.items),
                        "system_bindings": [
                            b.metadata.name
                            for b in cluster_bindings.items
                            if b.metadata.name.startswith("system:")
                        ],
                        "cluster_admin_bindings": [
                            {
                                "name": b.metadata.name,
                                "subjects": [
                                    {"kind": s.kind, "name": s.name}
                                    for s in (b.subjects or [])
                                ],
                            }
                            for b in cluster_bindings.items
                            if b.role_ref.name == "cluster-admin"
                        ],
                    },
                },
                source_id="rbac",
            )
        )

        return evidence

    def _collect_network_policy_evidence(self) -> list[Evidence]:
        """Collect network policy evidence."""
        evidence: list[Evidence] = []

        namespaces = self._get_namespaces()
        all_policies: list[dict[str, Any]] = []
        namespaces_with_policies: set[str] = set()

        for ns in namespaces:
            self._rate_limit()
            policies = self._networking_v1.list_namespaced_network_policy(namespace=ns)
            if policies.items:
                namespaces_with_policies.add(ns)
                for policy in policies.items:
                    all_policies.append({
                        "namespace": ns,
                        "name": policy.metadata.name,
                        "policy_types": policy.spec.policy_types or [],
                    })

        namespaces_without_policies = set(namespaces) - namespaces_with_policies

        evidence.append(
            self._create_evidence(
                evidence_type="network_policies",
                raw_data={
                    "total_policies": len(all_policies),
                    "namespaces_with_policies": list(namespaces_with_policies),
                    "namespaces_without_policies": list(namespaces_without_policies),
                    "policies": all_policies,
                },
                source_id="network-policies",
            )
        )

        return evidence

    def _collect_pod_security_evidence(self) -> list[Evidence]:
        """Collect pod security configuration evidence."""
        namespaces = self._get_namespaces()
        security_issues: list[dict[str, Any]] = []

        for ns in namespaces:
            self._rate_limit()
            pods = self._core_v1.list_namespaced_pod(namespace=ns)

            for pod in pods.items:
                issues = self._check_pod_security(pod, ns)
                if issues:
                    security_issues.append({
                        "namespace": ns,
                        "pod": pod.metadata.name,
                        "issues": issues,
                    })

        return [
            self._create_evidence(
                evidence_type="pod_security",
                raw_data={
                    "pods_with_issues": len(security_issues),
                    "issues": security_issues,
                },
                source_id="pod-security",
            )
        ]

    def _check_pod_security(self, pod: Any, namespace: str) -> list[str]:
        """Check pod for security issues."""
        issues: list[str] = []

        spec = pod.spec
        if spec.host_network:
            issues.append("hostNetwork enabled")
        if spec.host_pid:
            issues.append("hostPID enabled")
        if spec.host_ipc:
            issues.append("hostIPC enabled")

        for container in spec.containers:
            ctx = container.security_context
            if ctx:
                if ctx.privileged:
                    issues.append(f"Container {container.name}: privileged mode")
                if ctx.run_as_user == 0:
                    issues.append(f"Container {container.name}: runs as root")
                if ctx.allow_privilege_escalation:
                    issues.append(
                        f"Container {container.name}: privilege escalation allowed"
                    )

        return issues

    def _collect_secrets_inventory_evidence(self) -> list[Evidence]:
        """Collect secrets inventory evidence (metadata only)."""
        namespaces = self._get_namespaces()
        secrets_summary: list[dict[str, Any]] = []

        for ns in namespaces:
            self._rate_limit()
            secrets = self._core_v1.list_namespaced_secret(namespace=ns)

            ns_summary = {
                "namespace": ns,
                "count": len(secrets.items),
                "types": {},
            }
            for secret in secrets.items:
                secret_type = secret.type or "Opaque"
                ns_summary["types"][secret_type] = (
                    ns_summary["types"].get(secret_type, 0) + 1
                )
            secrets_summary.append(ns_summary)

        return [
            self._create_evidence(
                evidence_type="secrets_inventory",
                raw_data={
                    "total_secrets": sum(s["count"] for s in secrets_summary),
                    "by_namespace": secrets_summary,
                },
                source_id="secrets-inventory",
            )
        ]

    def _collect_resource_quota_evidence(self) -> list[Evidence]:
        """Collect resource quota evidence."""
        namespaces = self._get_namespaces()
        quotas: list[dict[str, Any]] = []

        for ns in namespaces:
            self._rate_limit()
            quota_list = self._core_v1.list_namespaced_resource_quota(namespace=ns)

            for quota in quota_list.items:
                quotas.append({
                    "namespace": ns,
                    "name": quota.metadata.name,
                    "hard": quota.status.hard or {},
                    "used": quota.status.used or {},
                })

        namespaces_without_quotas = [
            ns for ns in namespaces if ns not in {q["namespace"] for q in quotas}
        ]

        return [
            self._create_evidence(
                evidence_type="resource_quotas",
                raw_data={
                    "total_quotas": len(quotas),
                    "quotas": quotas,
                    "namespaces_without_quotas": namespaces_without_quotas,
                },
                source_id="resource-quotas",
            )
        ]

    def _collect_limit_range_evidence(self) -> list[Evidence]:
        """Collect limit range evidence."""
        namespaces = self._get_namespaces()
        limit_ranges: list[dict[str, Any]] = []

        for ns in namespaces:
            self._rate_limit()
            lr_list = self._core_v1.list_namespaced_limit_range(namespace=ns)

            for lr in lr_list.items:
                limit_ranges.append({
                    "namespace": ns,
                    "name": lr.metadata.name,
                    "limits": [
                        {
                            "type": lim.type,
                            "default": lim.default,
                            "default_request": lim.default_request,
                            "max": getattr(lim, "max", None),
                            "min": getattr(lim, "min", None),
                        }
                        for lim in (lr.spec.limits or [])
                    ],
                })

        namespaces_without_limits = [
            ns for ns in namespaces if ns not in {lr["namespace"] for lr in limit_ranges}
        ]

        return [
            self._create_evidence(
                evidence_type="limit_ranges",
                raw_data={
                    "total_limit_ranges": len(limit_ranges),
                    "limit_ranges": limit_ranges,
                    "namespaces_without_limit_ranges": namespaces_without_limits,
                },
                source_id="limit-ranges",
            )
        ]

    def _collect_admission_controller_evidence(self) -> list[Evidence]:
        """Collect admission controller evidence."""
        # Note: Admission controller info requires API server flags access
        # which isn't directly available via API. We collect what we can.

        evidence_data: dict[str, Any] = {
            "note": "Full admission controller config requires API server access",
            "validating_webhooks": [],
            "mutating_webhooks": [],
        }

        try:
            # Try to get admission webhook configs
            admission_api = client.AdmissionregistrationV1Api(self._api_client)

            self._rate_limit()
            validating = admission_api.list_validating_webhook_configuration()
            evidence_data["validating_webhooks"] = [
                {
                    "name": wh.metadata.name,
                    "webhooks": [w.name for w in (wh.webhooks or [])],
                }
                for wh in validating.items
            ]

            self._rate_limit()
            mutating = admission_api.list_mutating_webhook_configuration()
            evidence_data["mutating_webhooks"] = [
                {
                    "name": wh.metadata.name,
                    "webhooks": [w.name for w in (wh.webhooks or [])],
                }
                for wh in mutating.items
            ]

        except ApiException as e:
            self.logger.debug(f"Could not collect webhook configs: {e}")
            evidence_data["error"] = str(e)

        return [
            self._create_evidence(
                evidence_type="admission_controllers",
                raw_data=evidence_data,
                source_id="admission-controllers",
            )
        ]

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def _sanitize_k8s_object(self, obj: Any) -> dict[str, Any]:
        """Convert Kubernetes object to dict, removing sensitive data."""
        if hasattr(obj, "to_dict"):
            data = obj.to_dict()
        else:
            data = dict(obj)

        # Remove managed fields (verbose and not needed)
        if "metadata" in data and "managed_fields" in data["metadata"]:
            del data["metadata"]["managed_fields"]

        return data

    def _extract_security_context(self, pod_spec: Any) -> dict[str, Any]:
        """Extract security context from pod spec."""
        ctx: dict[str, Any] = {}

        if pod_spec.security_context:
            sc = pod_spec.security_context
            ctx["pod"] = {
                "run_as_user": sc.run_as_user,
                "run_as_group": sc.run_as_group,
                "run_as_non_root": sc.run_as_non_root,
                "fs_group": sc.fs_group,
            }

        containers_ctx = []
        for container in pod_spec.containers:
            if container.security_context:
                csc = container.security_context
                containers_ctx.append({
                    "container": container.name,
                    "privileged": csc.privileged,
                    "run_as_user": csc.run_as_user,
                    "run_as_non_root": csc.run_as_non_root,
                    "read_only_root_filesystem": csc.read_only_root_filesystem,
                    "allow_privilege_escalation": csc.allow_privilege_escalation,
                })

        if containers_ctx:
            ctx["containers"] = containers_ctx

        return ctx
