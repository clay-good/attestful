"""
Unit tests for Kubernetes collector.

Tests resource collection, evidence collection, and error handling
with mocked Kubernetes API responses.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, MagicMock, patch


# =============================================================================
# Test Fixtures and Mocks
# =============================================================================


@pytest.fixture
def mock_k8s_sdk():
    """Mock Kubernetes SDK modules."""
    with patch.dict("sys.modules", {
        "kubernetes": MagicMock(),
        "kubernetes.client": MagicMock(),
        "kubernetes.config": MagicMock(),
        "kubernetes.client.exceptions": MagicMock(),
        "kubernetes.config.config_exception": MagicMock(),
    }):
        yield


@pytest.fixture
def mock_version_info():
    """Mock Kubernetes version info."""
    version = Mock()
    version.major = "1"
    version.minor = "28"
    version.git_version = "v1.28.0"
    version.platform = "linux/amd64"
    return version


@pytest.fixture
def mock_namespace():
    """Mock namespace object."""
    ns = Mock()
    ns.metadata = Mock()
    ns.metadata.name = "default"
    ns.metadata.labels = {"app": "test"}
    ns.metadata.annotations = {}
    ns.status = Mock()
    ns.status.phase = "Active"
    return ns


@pytest.fixture
def mock_pod():
    """Mock pod object."""
    pod = Mock()
    pod.metadata = Mock()
    pod.metadata.name = "test-pod"
    pod.metadata.labels = {"app": "test"}
    pod.metadata.creation_timestamp = datetime.now(timezone.utc)
    pod.metadata.managed_fields = []

    pod.spec = Mock()
    pod.spec.node_name = "node-1"
    pod.spec.host_network = False
    pod.spec.host_pid = False
    pod.spec.host_ipc = False
    pod.spec.service_account_name = "default"
    pod.spec.security_context = None

    container = Mock()
    container.name = "main"
    container.security_context = None
    pod.spec.containers = [container]

    pod.status = Mock()
    pod.status.phase = "Running"

    pod.to_dict = Mock(return_value={
        "metadata": {"name": "test-pod"},
        "spec": {},
        "status": {"phase": "Running"},
    })
    return pod


@pytest.fixture
def mock_deployment():
    """Mock deployment object."""
    deploy = Mock()
    deploy.metadata = Mock()
    deploy.metadata.name = "test-deployment"
    deploy.metadata.labels = {"app": "test"}
    deploy.metadata.managed_fields = []

    deploy.spec = Mock()
    deploy.spec.replicas = 3
    deploy.spec.strategy = Mock()
    deploy.spec.strategy.type = "RollingUpdate"
    deploy.spec.template = Mock()
    deploy.spec.template.spec = Mock()
    deploy.spec.template.spec.service_account_name = "default"
    deploy.spec.template.spec.security_context = None

    container = Mock()
    container.name = "main"
    container.security_context = None
    deploy.spec.template.spec.containers = [container]

    deploy.status = Mock()
    deploy.status.ready_replicas = 3

    deploy.to_dict = Mock(return_value={
        "metadata": {"name": "test-deployment"},
        "spec": {"replicas": 3},
        "status": {"ready_replicas": 3},
    })
    return deploy


@pytest.fixture
def mock_secret():
    """Mock secret object."""
    secret = Mock()
    secret.metadata = Mock()
    secret.metadata.name = "test-secret"
    secret.metadata.labels = {}
    secret.metadata.annotations = {}
    secret.metadata.creation_timestamp = datetime.now(timezone.utc)
    secret.metadata.managed_fields = []
    secret.type = "Opaque"
    secret.data = {"key": "value"}
    return secret


@pytest.fixture
def mock_service():
    """Mock service object."""
    svc = Mock()
    svc.metadata = Mock()
    svc.metadata.name = "test-service"
    svc.metadata.labels = {"app": "test"}
    svc.metadata.managed_fields = []

    svc.spec = Mock()
    svc.spec.type = "ClusterIP"
    svc.spec.cluster_ip = "10.0.0.1"
    svc.spec.external_i_ps = []

    port = Mock()
    port.port = 80
    port.protocol = "TCP"
    port.target_port = 8080
    svc.spec.ports = [port]

    svc.to_dict = Mock(return_value={
        "metadata": {"name": "test-service"},
        "spec": {"type": "ClusterIP"},
    })
    return svc


@pytest.fixture
def mock_network_policy():
    """Mock network policy object."""
    policy = Mock()
    policy.metadata = Mock()
    policy.metadata.name = "test-policy"
    policy.metadata.labels = {}
    policy.metadata.managed_fields = []

    policy.spec = Mock()
    policy.spec.pod_selector = Mock()
    policy.spec.pod_selector.match_labels = {"app": "test"}
    policy.spec.policy_types = ["Ingress", "Egress"]
    policy.spec.ingress = [Mock()]
    policy.spec.egress = [Mock()]

    policy.to_dict = Mock(return_value={
        "metadata": {"name": "test-policy"},
        "spec": {"policy_types": ["Ingress", "Egress"]},
    })
    return policy


@pytest.fixture
def mock_cluster_role():
    """Mock cluster role object."""
    role = Mock()
    role.metadata = Mock()
    role.metadata.name = "test-role"
    role.metadata.labels = {}
    role.metadata.managed_fields = []
    role.aggregation_rule = None

    rule = Mock()
    rule.api_groups = [""]
    rule.resources = ["pods"]
    rule.verbs = ["get", "list"]
    role.rules = [rule]

    role.to_dict = Mock(return_value={
        "metadata": {"name": "test-role"},
        "rules": [{"verbs": ["get", "list"]}],
    })
    return role


@pytest.fixture
def mock_node():
    """Mock node object."""
    node = Mock()
    node.metadata = Mock()
    node.metadata.name = "node-1"
    node.metadata.labels = {"node-role.kubernetes.io/worker": ""}
    node.metadata.managed_fields = []

    node.spec = Mock()
    node.spec.taints = []

    node.status = Mock()
    node.status.node_info = Mock()
    node.status.node_info.os_image = "Ubuntu 22.04"
    node.status.node_info.kernel_version = "5.15.0"
    node.status.node_info.container_runtime_version = "containerd://1.6.0"
    node.status.node_info.kubelet_version = "v1.28.0"

    condition = Mock()
    condition.type = "Ready"
    condition.status = "True"
    node.status.conditions = [condition]

    node.to_dict = Mock(return_value={
        "metadata": {"name": "node-1"},
        "status": {},
    })
    return node


# =============================================================================
# Configuration Tests
# =============================================================================


class TestKubernetesCollectorConfig:
    """Tests for KubernetesCollectorConfig."""

    def test_default_config(self, mock_k8s_sdk):
        """Test default configuration values."""
        from attestful.collectors.containers.kubernetes import KubernetesCollectorConfig

        config = KubernetesCollectorConfig()

        assert config.kubeconfig_path is None
        assert config.context is None
        assert config.in_cluster is False
        assert config.api_server is None
        assert config.api_token is None
        assert config.namespaces == []
        assert "kube-system" in config.exclude_namespaces
        assert config.max_retries == 3
        assert config.timeout == 30

    def test_custom_config(self, mock_k8s_sdk):
        """Test custom configuration."""
        from attestful.collectors.containers.kubernetes import KubernetesCollectorConfig

        config = KubernetesCollectorConfig(
            kubeconfig_path="/path/to/kubeconfig",
            context="my-cluster",
            namespaces=["production", "staging"],
            exclude_namespaces=[],
            max_retries=5,
        )

        assert config.kubeconfig_path == "/path/to/kubeconfig"
        assert config.context == "my-cluster"
        assert config.namespaces == ["production", "staging"]
        assert config.exclude_namespaces == []
        assert config.max_retries == 5

    def test_in_cluster_config(self, mock_k8s_sdk):
        """Test in-cluster configuration."""
        from attestful.collectors.containers.kubernetes import KubernetesCollectorConfig

        config = KubernetesCollectorConfig(in_cluster=True)

        assert config.in_cluster is True

    def test_direct_api_config(self, mock_k8s_sdk):
        """Test direct API server configuration."""
        from attestful.collectors.containers.kubernetes import KubernetesCollectorConfig

        config = KubernetesCollectorConfig(
            api_server="https://api.example.com:6443",
            api_token="my-token",
            ca_cert_path="/path/to/ca.crt",
        )

        assert config.api_server == "https://api.example.com:6443"
        assert config.api_token == "my-token"
        assert config.ca_cert_path == "/path/to/ca.crt"


# =============================================================================
# Collector Initialization Tests
# =============================================================================


class TestKubernetesCollectorInit:
    """Tests for KubernetesCollector initialization."""

    def test_collector_creation(self, mock_k8s_sdk):
        """Test collector can be created."""
        from attestful.collectors.containers.kubernetes import (
            KubernetesCollector,
            KubernetesCollectorConfig,
        )

        config = KubernetesCollectorConfig()
        collector = KubernetesCollector(config=config)

        assert collector.config == config
        assert collector.PLATFORM == "kubernetes"

    def test_collector_metadata(self, mock_k8s_sdk):
        """Test collector metadata."""
        from attestful.collectors.containers.kubernetes import KubernetesCollector

        collector = KubernetesCollector()

        assert collector.metadata.name == "KubernetesCollector"
        assert collector.metadata.platform == "kubernetes"
        assert "pod" in collector.metadata.resource_types
        assert "cluster_info" in collector.metadata.evidence_types

    def test_supported_resource_types(self, mock_k8s_sdk):
        """Test supported resource types."""
        from attestful.collectors.containers.kubernetes import KubernetesCollector

        expected_types = [
            "pod", "deployment", "daemonset", "statefulset", "replicaset",
            "service", "configmap", "secret", "namespace", "networkpolicy",
            "serviceaccount", "role", "rolebinding", "clusterrole",
            "clusterrolebinding", "persistentvolume", "persistentvolumeclaim",
            "ingress", "node", "cronjob", "job",
        ]

        for resource_type in expected_types:
            assert resource_type in KubernetesCollector.SUPPORTED_RESOURCE_TYPES

    def test_supported_evidence_types(self, mock_k8s_sdk):
        """Test supported evidence types."""
        from attestful.collectors.containers.kubernetes import KubernetesCollector

        expected_types = [
            "cluster_info", "rbac_config", "network_policies", "pod_security",
            "secrets_inventory", "resource_quotas", "limit_ranges",
            "admission_controllers",
        ]

        for evidence_type in expected_types:
            assert evidence_type in KubernetesCollector.SUPPORTED_EVIDENCE_TYPES


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestResourceCollection:
    """Tests for Kubernetes resource collection."""

    @patch("attestful.collectors.containers.kubernetes.config")
    @patch("attestful.collectors.containers.kubernetes.client")
    def test_collect_pods(
        self, mock_client, mock_config, mock_k8s_sdk, mock_pod, mock_namespace
    ):
        """Test collecting pod resources."""
        from attestful.collectors.containers.kubernetes import KubernetesCollector

        # Setup mocks
        mock_core_v1 = MagicMock()
        mock_client.CoreV1Api.return_value = mock_core_v1
        mock_client.AppsV1Api.return_value = MagicMock()
        mock_client.BatchV1Api.return_value = MagicMock()
        mock_client.NetworkingV1Api.return_value = MagicMock()
        mock_client.RbacAuthorizationV1Api.return_value = MagicMock()
        mock_client.VersionApi.return_value = MagicMock()
        mock_client.ApiClient.return_value = MagicMock()

        ns_list = MagicMock()
        ns_list.items = [mock_namespace]
        mock_core_v1.list_namespace.return_value = ns_list

        pod_list = MagicMock()
        pod_list.items = [mock_pod]
        mock_core_v1.list_namespaced_pod.return_value = pod_list

        collector = KubernetesCollector()
        resources = collector.collect_resources(resource_types=["pod"])

        assert len(resources) == 1
        assert resources[0].type == "pod"
        assert resources[0].name == "test-pod"

    @patch("attestful.collectors.containers.kubernetes.config")
    @patch("attestful.collectors.containers.kubernetes.client")
    def test_collect_deployments(
        self, mock_client, mock_config, mock_k8s_sdk, mock_deployment, mock_namespace
    ):
        """Test collecting deployment resources."""
        from attestful.collectors.containers.kubernetes import KubernetesCollector

        # Setup mocks
        mock_core_v1 = MagicMock()
        mock_apps_v1 = MagicMock()
        mock_client.CoreV1Api.return_value = mock_core_v1
        mock_client.AppsV1Api.return_value = mock_apps_v1
        mock_client.BatchV1Api.return_value = MagicMock()
        mock_client.NetworkingV1Api.return_value = MagicMock()
        mock_client.RbacAuthorizationV1Api.return_value = MagicMock()
        mock_client.VersionApi.return_value = MagicMock()
        mock_client.ApiClient.return_value = MagicMock()

        ns_list = MagicMock()
        ns_list.items = [mock_namespace]
        mock_core_v1.list_namespace.return_value = ns_list

        deploy_list = MagicMock()
        deploy_list.items = [mock_deployment]
        mock_apps_v1.list_namespaced_deployment.return_value = deploy_list

        collector = KubernetesCollector()
        resources = collector.collect_resources(resource_types=["deployment"])

        assert len(resources) == 1
        assert resources[0].type == "deployment"
        assert resources[0].name == "test-deployment"
        assert resources[0].metadata["replicas"] == 3

    @patch("attestful.collectors.containers.kubernetes.config")
    @patch("attestful.collectors.containers.kubernetes.client")
    def test_collect_secrets_no_values(
        self, mock_client, mock_config, mock_k8s_sdk, mock_secret, mock_namespace
    ):
        """Test that secrets collection does not include secret values."""
        from attestful.collectors.containers.kubernetes import KubernetesCollector

        # Setup mocks
        mock_core_v1 = MagicMock()
        mock_client.CoreV1Api.return_value = mock_core_v1
        mock_client.AppsV1Api.return_value = MagicMock()
        mock_client.BatchV1Api.return_value = MagicMock()
        mock_client.NetworkingV1Api.return_value = MagicMock()
        mock_client.RbacAuthorizationV1Api.return_value = MagicMock()
        mock_client.VersionApi.return_value = MagicMock()
        mock_client.ApiClient.return_value = MagicMock()

        ns_list = MagicMock()
        ns_list.items = [mock_namespace]
        mock_core_v1.list_namespace.return_value = ns_list

        secret_list = MagicMock()
        secret_list.items = [mock_secret]
        mock_core_v1.list_namespaced_secret.return_value = secret_list

        collector = KubernetesCollector()
        resources = collector.collect_resources(resource_types=["secret"])

        assert len(resources) == 1
        assert resources[0].type == "secret"
        # Verify secret values are not included
        raw_data = resources[0].raw_data
        assert "data_keys" in raw_data
        assert "value" not in str(raw_data.get("data", ""))

    @patch("attestful.collectors.containers.kubernetes.config")
    @patch("attestful.collectors.containers.kubernetes.client")
    def test_collect_network_policies(
        self, mock_client, mock_config, mock_k8s_sdk, mock_network_policy, mock_namespace
    ):
        """Test collecting network policy resources."""
        from attestful.collectors.containers.kubernetes import KubernetesCollector

        # Setup mocks
        mock_core_v1 = MagicMock()
        mock_networking_v1 = MagicMock()
        mock_client.CoreV1Api.return_value = mock_core_v1
        mock_client.AppsV1Api.return_value = MagicMock()
        mock_client.BatchV1Api.return_value = MagicMock()
        mock_client.NetworkingV1Api.return_value = mock_networking_v1
        mock_client.RbacAuthorizationV1Api.return_value = MagicMock()
        mock_client.VersionApi.return_value = MagicMock()
        mock_client.ApiClient.return_value = MagicMock()

        ns_list = MagicMock()
        ns_list.items = [mock_namespace]
        mock_core_v1.list_namespace.return_value = ns_list

        policy_list = MagicMock()
        policy_list.items = [mock_network_policy]
        mock_networking_v1.list_namespaced_network_policy.return_value = policy_list

        collector = KubernetesCollector()
        resources = collector.collect_resources(resource_types=["networkpolicy"])

        assert len(resources) == 1
        assert resources[0].type == "networkpolicy"
        assert resources[0].metadata["has_ingress"] is True
        assert resources[0].metadata["has_egress"] is True

    @patch("attestful.collectors.containers.kubernetes.config")
    @patch("attestful.collectors.containers.kubernetes.client")
    def test_collect_cluster_roles(
        self, mock_client, mock_config, mock_k8s_sdk, mock_cluster_role
    ):
        """Test collecting cluster role resources."""
        from attestful.collectors.containers.kubernetes import KubernetesCollector

        # Setup mocks
        mock_core_v1 = MagicMock()
        mock_rbac_v1 = MagicMock()
        mock_client.CoreV1Api.return_value = mock_core_v1
        mock_client.AppsV1Api.return_value = MagicMock()
        mock_client.BatchV1Api.return_value = MagicMock()
        mock_client.NetworkingV1Api.return_value = MagicMock()
        mock_client.RbacAuthorizationV1Api.return_value = mock_rbac_v1
        mock_client.VersionApi.return_value = MagicMock()
        mock_client.ApiClient.return_value = MagicMock()

        ns_list = MagicMock()
        ns_list.items = []
        mock_core_v1.list_namespace.return_value = ns_list

        role_list = MagicMock()
        role_list.items = [mock_cluster_role]
        mock_rbac_v1.list_cluster_role.return_value = role_list

        collector = KubernetesCollector()
        resources = collector.collect_resources(resource_types=["clusterrole"])

        assert len(resources) == 1
        assert resources[0].type == "clusterrole"
        assert resources[0].metadata["rules_count"] == 1

    @patch("attestful.collectors.containers.kubernetes.config")
    @patch("attestful.collectors.containers.kubernetes.client")
    def test_collect_nodes(
        self, mock_client, mock_config, mock_k8s_sdk, mock_node
    ):
        """Test collecting node resources."""
        from attestful.collectors.containers.kubernetes import KubernetesCollector

        # Setup mocks
        mock_core_v1 = MagicMock()
        mock_client.CoreV1Api.return_value = mock_core_v1
        mock_client.AppsV1Api.return_value = MagicMock()
        mock_client.BatchV1Api.return_value = MagicMock()
        mock_client.NetworkingV1Api.return_value = MagicMock()
        mock_client.RbacAuthorizationV1Api.return_value = MagicMock()
        mock_client.VersionApi.return_value = MagicMock()
        mock_client.ApiClient.return_value = MagicMock()

        ns_list = MagicMock()
        ns_list.items = []
        mock_core_v1.list_namespace.return_value = ns_list

        node_list = MagicMock()
        node_list.items = [mock_node]
        mock_core_v1.list_node.return_value = node_list

        collector = KubernetesCollector()
        resources = collector.collect_resources(resource_types=["node"])

        assert len(resources) == 1
        assert resources[0].type == "node"
        assert resources[0].metadata["ready"] is True
        assert resources[0].metadata["kubelet_version"] == "v1.28.0"


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestEvidenceCollection:
    """Tests for Kubernetes evidence collection."""

    @patch("attestful.collectors.containers.kubernetes.config")
    @patch("attestful.collectors.containers.kubernetes.client")
    def test_collect_cluster_info_evidence(
        self, mock_client, mock_config, mock_k8s_sdk, mock_version_info, mock_namespace, mock_node
    ):
        """Test collecting cluster info evidence."""
        from attestful.collectors.containers.kubernetes import KubernetesCollector

        # Setup mocks
        mock_core_v1 = MagicMock()
        mock_version_api = MagicMock()
        mock_client.CoreV1Api.return_value = mock_core_v1
        mock_client.AppsV1Api.return_value = MagicMock()
        mock_client.BatchV1Api.return_value = MagicMock()
        mock_client.NetworkingV1Api.return_value = MagicMock()
        mock_client.RbacAuthorizationV1Api.return_value = MagicMock()
        mock_client.VersionApi.return_value = mock_version_api
        mock_client.ApiClient.return_value = MagicMock()

        mock_version_api.get_code.return_value = mock_version_info

        ns_list = MagicMock()
        ns_list.items = [mock_namespace]
        mock_core_v1.list_namespace.return_value = ns_list

        node_list = MagicMock()
        node_list.items = [mock_node]
        mock_core_v1.list_node.return_value = node_list

        collector = KubernetesCollector()
        result = collector.collect_evidence(evidence_types=["cluster_info"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "cluster_info"
        assert result.evidence_items[0].raw_data["version"]["git_version"] == "v1.28.0"

    @patch("attestful.collectors.containers.kubernetes.config")
    @patch("attestful.collectors.containers.kubernetes.client")
    def test_collect_rbac_evidence(
        self, mock_client, mock_config, mock_k8s_sdk, mock_cluster_role
    ):
        """Test collecting RBAC evidence."""
        from attestful.collectors.containers.kubernetes import KubernetesCollector

        # Setup mocks
        mock_core_v1 = MagicMock()
        mock_rbac_v1 = MagicMock()
        mock_client.CoreV1Api.return_value = mock_core_v1
        mock_client.AppsV1Api.return_value = MagicMock()
        mock_client.BatchV1Api.return_value = MagicMock()
        mock_client.NetworkingV1Api.return_value = MagicMock()
        mock_client.RbacAuthorizationV1Api.return_value = mock_rbac_v1
        mock_client.VersionApi.return_value = MagicMock()
        mock_client.ApiClient.return_value = MagicMock()

        role_list = MagicMock()
        role_list.items = [mock_cluster_role]
        mock_rbac_v1.list_cluster_role.return_value = role_list

        binding_list = MagicMock()
        binding_list.items = []
        mock_rbac_v1.list_cluster_role_binding.return_value = binding_list

        collector = KubernetesCollector()
        result = collector.collect_evidence(evidence_types=["rbac_config"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "rbac_config"
        assert result.evidence_items[0].raw_data["cluster_roles"]["count"] == 1

    @patch("attestful.collectors.containers.kubernetes.config")
    @patch("attestful.collectors.containers.kubernetes.client")
    def test_collect_pod_security_evidence(
        self, mock_client, mock_config, mock_k8s_sdk, mock_pod, mock_namespace
    ):
        """Test collecting pod security evidence."""
        from attestful.collectors.containers.kubernetes import KubernetesCollector

        # Create pod with security issues
        insecure_pod = Mock()
        insecure_pod.metadata = Mock()
        insecure_pod.metadata.name = "insecure-pod"
        insecure_pod.spec = Mock()
        insecure_pod.spec.host_network = True
        insecure_pod.spec.host_pid = True
        insecure_pod.spec.host_ipc = False

        container = Mock()
        container.name = "main"
        container.security_context = Mock()
        container.security_context.privileged = True
        container.security_context.run_as_user = 0
        container.security_context.allow_privilege_escalation = True
        insecure_pod.spec.containers = [container]

        # Setup mocks
        mock_core_v1 = MagicMock()
        mock_client.CoreV1Api.return_value = mock_core_v1
        mock_client.AppsV1Api.return_value = MagicMock()
        mock_client.BatchV1Api.return_value = MagicMock()
        mock_client.NetworkingV1Api.return_value = MagicMock()
        mock_client.RbacAuthorizationV1Api.return_value = MagicMock()
        mock_client.VersionApi.return_value = MagicMock()
        mock_client.ApiClient.return_value = MagicMock()

        ns_list = MagicMock()
        ns_list.items = [mock_namespace]
        mock_core_v1.list_namespace.return_value = ns_list

        pod_list = MagicMock()
        pod_list.items = [insecure_pod]
        mock_core_v1.list_namespaced_pod.return_value = pod_list

        collector = KubernetesCollector()
        result = collector.collect_evidence(evidence_types=["pod_security"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "pod_security"
        assert result.evidence_items[0].raw_data["pods_with_issues"] == 1
        issues = result.evidence_items[0].raw_data["issues"][0]["issues"]
        assert "hostNetwork enabled" in issues
        assert "hostPID enabled" in issues

    @patch("attestful.collectors.containers.kubernetes.config")
    @patch("attestful.collectors.containers.kubernetes.client")
    def test_collect_network_policy_evidence(
        self, mock_client, mock_config, mock_k8s_sdk, mock_network_policy, mock_namespace
    ):
        """Test collecting network policy evidence."""
        from attestful.collectors.containers.kubernetes import KubernetesCollector

        # Setup mocks
        mock_core_v1 = MagicMock()
        mock_networking_v1 = MagicMock()
        mock_client.CoreV1Api.return_value = mock_core_v1
        mock_client.AppsV1Api.return_value = MagicMock()
        mock_client.BatchV1Api.return_value = MagicMock()
        mock_client.NetworkingV1Api.return_value = mock_networking_v1
        mock_client.RbacAuthorizationV1Api.return_value = MagicMock()
        mock_client.VersionApi.return_value = MagicMock()
        mock_client.ApiClient.return_value = MagicMock()

        ns_list = MagicMock()
        ns_list.items = [mock_namespace]
        mock_core_v1.list_namespace.return_value = ns_list

        policy_list = MagicMock()
        policy_list.items = [mock_network_policy]
        mock_networking_v1.list_namespaced_network_policy.return_value = policy_list

        collector = KubernetesCollector()
        result = collector.collect_evidence(evidence_types=["network_policies"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "network_policies"
        assert result.evidence_items[0].raw_data["total_policies"] == 1

    @patch("attestful.collectors.containers.kubernetes.config")
    @patch("attestful.collectors.containers.kubernetes.client")
    def test_collect_secrets_inventory_evidence(
        self, mock_client, mock_config, mock_k8s_sdk, mock_secret, mock_namespace
    ):
        """Test collecting secrets inventory evidence."""
        from attestful.collectors.containers.kubernetes import KubernetesCollector

        # Setup mocks
        mock_core_v1 = MagicMock()
        mock_client.CoreV1Api.return_value = mock_core_v1
        mock_client.AppsV1Api.return_value = MagicMock()
        mock_client.BatchV1Api.return_value = MagicMock()
        mock_client.NetworkingV1Api.return_value = MagicMock()
        mock_client.RbacAuthorizationV1Api.return_value = MagicMock()
        mock_client.VersionApi.return_value = MagicMock()
        mock_client.ApiClient.return_value = MagicMock()

        ns_list = MagicMock()
        ns_list.items = [mock_namespace]
        mock_core_v1.list_namespace.return_value = ns_list

        secret_list = MagicMock()
        secret_list.items = [mock_secret]
        mock_core_v1.list_namespaced_secret.return_value = secret_list

        collector = KubernetesCollector()
        result = collector.collect_evidence(evidence_types=["secrets_inventory"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "secrets_inventory"
        assert result.evidence_items[0].raw_data["total_secrets"] == 1


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    def test_sdk_not_available(self):
        """Test error when SDK not installed."""
        import sys

        # Temporarily remove kubernetes from modules
        original_modules = sys.modules.copy()
        for key in list(sys.modules.keys()):
            if "kubernetes" in key:
                del sys.modules[key]

        # Also need to remove the collector module
        if "attestful.collectors.containers.kubernetes" in sys.modules:
            del sys.modules["attestful.collectors.containers.kubernetes"]

        with patch.dict("sys.modules", {"kubernetes": None}):
            try:
                # Import fresh
                from attestful.collectors.containers import kubernetes as k8s_module

                # Should have K8S_SDK_AVAILABLE = False
                # Creating collector should raise ConfigurationError
                if not k8s_module.K8S_SDK_AVAILABLE:
                    from attestful.core.exceptions import ConfigurationError
                    with pytest.raises(ConfigurationError):
                        k8s_module.KubernetesCollector()
            except ImportError:
                # Expected if module can't be imported
                pass
            finally:
                # Restore original modules
                sys.modules.update(original_modules)

    @patch("attestful.collectors.containers.kubernetes.config")
    @patch("attestful.collectors.containers.kubernetes.client")
    def test_api_error_handling(
        self, mock_client, mock_config, mock_k8s_sdk
    ):
        """Test handling of API errors."""
        from attestful.collectors.containers.kubernetes import (
            KubernetesCollector,
            ApiException,
        )

        # Setup mocks
        mock_core_v1 = MagicMock()
        mock_client.CoreV1Api.return_value = mock_core_v1
        mock_client.AppsV1Api.return_value = MagicMock()
        mock_client.BatchV1Api.return_value = MagicMock()
        mock_client.NetworkingV1Api.return_value = MagicMock()
        mock_client.RbacAuthorizationV1Api.return_value = MagicMock()
        mock_client.VersionApi.return_value = MagicMock()
        mock_client.ApiClient.return_value = MagicMock()

        # Simulate API error
        mock_core_v1.list_namespace.side_effect = ApiException(status=500, reason="Internal Error")

        collector = KubernetesCollector()

        # Should handle error gracefully and return empty list or default namespace
        resources = collector.collect_resources(resource_types=["namespace"])
        # Error should be logged but not raise


# =============================================================================
# Integration Pattern Tests
# =============================================================================


class TestIntegrationPatterns:
    """Tests for common integration patterns."""

    @patch("attestful.collectors.containers.kubernetes.config")
    @patch("attestful.collectors.containers.kubernetes.client")
    def test_namespace_filtering(
        self, mock_client, mock_config, mock_k8s_sdk, mock_pod
    ):
        """Test namespace filtering."""
        from attestful.collectors.containers.kubernetes import (
            KubernetesCollector,
            KubernetesCollectorConfig,
        )

        # Setup mocks
        mock_core_v1 = MagicMock()
        mock_client.CoreV1Api.return_value = mock_core_v1
        mock_client.AppsV1Api.return_value = MagicMock()
        mock_client.BatchV1Api.return_value = MagicMock()
        mock_client.NetworkingV1Api.return_value = MagicMock()
        mock_client.RbacAuthorizationV1Api.return_value = MagicMock()
        mock_client.VersionApi.return_value = MagicMock()
        mock_client.ApiClient.return_value = MagicMock()

        pod_list = MagicMock()
        pod_list.items = [mock_pod]
        mock_core_v1.list_namespaced_pod.return_value = pod_list

        config = KubernetesCollectorConfig(namespaces=["production"])
        collector = KubernetesCollector(config=config)

        resources = collector.collect_resources(resource_types=["pod"])

        # Should only query specified namespace
        mock_core_v1.list_namespaced_pod.assert_called_with(
            namespace="production", label_selector=""
        )

    @patch("attestful.collectors.containers.kubernetes.config")
    @patch("attestful.collectors.containers.kubernetes.client")
    def test_progress_callback(
        self, mock_client, mock_config, mock_k8s_sdk, mock_namespace
    ):
        """Test progress callback functionality."""
        from attestful.collectors.containers.kubernetes import KubernetesCollector

        # Setup mocks
        mock_core_v1 = MagicMock()
        mock_client.CoreV1Api.return_value = mock_core_v1
        mock_client.AppsV1Api.return_value = MagicMock()
        mock_client.BatchV1Api.return_value = MagicMock()
        mock_client.NetworkingV1Api.return_value = MagicMock()
        mock_client.RbacAuthorizationV1Api.return_value = MagicMock()
        mock_client.VersionApi.return_value = MagicMock()
        mock_client.ApiClient.return_value = MagicMock()

        ns_list = MagicMock()
        ns_list.items = [mock_namespace]
        mock_core_v1.list_namespace.return_value = ns_list

        empty_list = MagicMock()
        empty_list.items = []
        mock_core_v1.list_namespaced_pod.return_value = empty_list

        progress_updates = []

        def callback(current, total):
            progress_updates.append((current, total))

        collector = KubernetesCollector()
        collector.collect_resources(
            resource_types=["pod"],
            progress_callback=callback,
        )

        # Should have called progress callback
        assert len(progress_updates) >= 1
        assert progress_updates[-1][0] == progress_updates[-1][1]  # Final should be complete
