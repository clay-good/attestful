"""
Docker container collector.

Collects container resources and evidence from Docker daemons
for compliance checking and proof gathering.

Supports:
- Local Docker daemon (via Unix socket)
- Remote Docker daemon (via TCP with TLS)
- Docker Compose project awareness
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlencode

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
from attestful.core.models import CollectionResult, Evidence, Resource


@dataclass
class DockerConnection:
    """Docker daemon connection configuration."""

    # Connection type
    socket_path: str | None = None  # Unix socket (e.g., /var/run/docker.sock)
    host: str | None = None  # TCP host
    port: int = 2376  # TCP port (2375=insecure, 2376=TLS)

    # TLS configuration
    tls_enabled: bool = True
    tls_verify: bool = True
    tls_ca_cert: str | None = None
    tls_client_cert: str | None = None
    tls_client_key: str | None = None

    @property
    def is_socket(self) -> bool:
        """Check if using Unix socket."""
        return self.socket_path is not None

    @property
    def base_url(self) -> str:
        """Get base URL for API calls."""
        if self.is_socket:
            return "http://localhost"
        protocol = "https" if self.tls_enabled else "http"
        return f"{protocol}://{self.host}:{self.port}"


# Docker resource types
DOCKER_RESOURCE_TYPES = [
    "containers",
    "images",
    "volumes",
    "networks",
    "configs",
    "secrets",
    "nodes",  # Swarm
    "services",  # Swarm
    "plugins",
]

# Docker evidence types
DOCKER_EVIDENCE_TYPES = [
    "system_info",
    "container_list",
    "container_config",
    "image_list",
    "image_config",
    "volume_list",
    "network_list",
    "network_config",
    "security_settings",
    "plugin_list",
    "swarm_info",
    "compose_projects",
]


@register_collector()
class DockerCollector(BaseCollector):
    """
    Docker container collector.

    Collects containers, images, volumes, networks, and other Docker resources
    for compliance evaluation. Supports both local and remote Docker daemons
    with TLS authentication.

    Resource Types:
        - containers: Running and stopped containers
        - images: Docker images with layer information
        - volumes: Named volumes
        - networks: Docker networks
        - configs: Swarm configs
        - secrets: Swarm secrets (metadata only)
        - nodes: Swarm nodes
        - services: Swarm services
        - plugins: Docker plugins

    Evidence Types:
        - system_info: Docker daemon configuration
        - container_list: All containers with metadata
        - container_config: Individual container configurations
        - image_list: All images with metadata
        - image_config: Individual image configurations
        - volume_list: All volumes
        - network_list: All networks
        - network_config: Individual network configurations
        - security_settings: Security-related settings
        - plugin_list: Installed plugins
        - swarm_info: Swarm cluster information
        - compose_projects: Docker Compose project information
    """

    metadata = CollectorMetadata(
        name="Docker",
        platform="docker",
        description="Docker container platform collector",
        mode=CollectorMode.BOTH,
        resource_types=DOCKER_RESOURCE_TYPES,
        evidence_types=DOCKER_EVIDENCE_TYPES,
        requires_credentials=False,  # Socket-based access may not need creds
        version="1.0.0",
    )

    # API version
    API_VERSION = "v1.45"

    def __init__(
        self,
        *,
        connection: DockerConnection | None = None,
        socket_path: str | None = None,
        host: str | None = None,
        port: int = 2376,
        tls_enabled: bool = True,
        tls_verify: bool = True,
        tls_ca_cert: str | None = None,
        tls_client_cert: str | None = None,
        tls_client_key: str | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize Docker collector.

        Args:
            connection: Pre-configured DockerConnection object
            socket_path: Path to Docker Unix socket
            host: Docker daemon host for TCP connection
            port: Docker daemon port (default: 2376)
            tls_enabled: Enable TLS for TCP connections
            tls_verify: Verify TLS certificates
            tls_ca_cert: Path to CA certificate
            tls_client_cert: Path to client certificate
            tls_client_key: Path to client key
            **kwargs: Additional arguments for BaseCollector
        """
        super().__init__(**kwargs)

        if connection:
            self.connection = connection
        elif socket_path:
            self.connection = DockerConnection(socket_path=socket_path)
        elif host:
            self.connection = DockerConnection(
                host=host,
                port=port,
                tls_enabled=tls_enabled,
                tls_verify=tls_verify,
                tls_ca_cert=tls_ca_cert,
                tls_client_cert=tls_client_cert,
                tls_client_key=tls_client_key,
            )
        else:
            # Default to local socket
            default_socket = os.environ.get(
                "DOCKER_HOST", "/var/run/docker.sock"
            )
            if default_socket.startswith("unix://"):
                default_socket = default_socket[7:]
            elif default_socket.startswith("tcp://"):
                # Parse TCP host
                host_port = default_socket[6:]
                if ":" in host_port:
                    host, port_str = host_port.rsplit(":", 1)
                    port = int(port_str)
                else:
                    host = host_port
                    port = 2376
                self.connection = DockerConnection(
                    host=host,
                    port=port,
                    tls_enabled=tls_enabled,
                    tls_verify=tls_verify,
                )
            else:
                self.connection = DockerConnection(socket_path=default_socket)

        self._ssl_context: ssl.SSLContext | None = None
        self._setup_ssl()

    def _setup_ssl(self) -> None:
        """Set up SSL context for TLS connections."""
        if self.connection.is_socket or not self.connection.tls_enabled:
            return

        self._ssl_context = ssl.create_default_context()

        if not self.connection.tls_verify:
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE
        else:
            self._ssl_context.verify_mode = ssl.CERT_REQUIRED

            if self.connection.tls_ca_cert:
                self._ssl_context.load_verify_locations(
                    self.connection.tls_ca_cert
                )

        if self.connection.tls_client_cert and self.connection.tls_client_key:
            self._ssl_context.load_cert_chain(
                self.connection.tls_client_cert,
                self.connection.tls_client_key,
            )

    def _make_request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any]:
        """
        Make HTTP request to Docker API.

        Args:
            method: HTTP method (GET, POST, DELETE, etc.)
            path: API path (e.g., /containers/json)
            params: Query parameters
            body: Request body for POST/PUT

        Returns:
            Parsed JSON response

        Raises:
            CollectionError: If request fails
        """
        import http.client

        # Build URL
        url_path = f"/{self.API_VERSION}{path}"
        if params:
            url_path += "?" + urlencode(params)

        # Prepare body
        body_bytes = None
        headers = {"Content-Type": "application/json"}
        if body:
            body_bytes = json.dumps(body).encode("utf-8")
            headers["Content-Length"] = str(len(body_bytes))

        try:
            if self.connection.is_socket:
                # Unix socket connection
                conn = http.client.HTTPConnection("localhost")
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(self.connection.socket_path)
                conn.sock = sock
            else:
                # TCP connection
                if self._ssl_context:
                    conn = http.client.HTTPSConnection(
                        self.connection.host,
                        self.connection.port,
                        context=self._ssl_context,
                        timeout=self.timeout,
                    )
                else:
                    conn = http.client.HTTPConnection(
                        self.connection.host,
                        self.connection.port,
                        timeout=self.timeout,
                    )

            conn.request(method, url_path, body=body_bytes, headers=headers)
            response = conn.getresponse()

            if response.status == 401:
                raise AuthenticationError(
                    "Docker API authentication failed",
                    provider="docker",
                )

            if response.status >= 400:
                error_body = response.read().decode("utf-8")
                raise CollectionError(
                    f"Docker API error {response.status}: {error_body}",
                    platform="docker",
                )

            response_body = response.read().decode("utf-8")
            conn.close()

            if not response_body:
                return {}

            return json.loads(response_body)

        except (socket.error, OSError) as e:
            raise CollectionError(
                f"Failed to connect to Docker daemon: {e}",
                platform="docker",
                cause=e,
            )

    def validate_credentials(self) -> bool:
        """Validate Docker daemon connection."""
        try:
            result = self._make_request("GET", "/version")
            self.logger.info(
                f"Connected to Docker {result.get('Version', 'unknown')} "
                f"(API {result.get('ApiVersion', 'unknown')})"
            )
            return True
        except Exception as e:
            self.logger.error(f"Docker connection failed: {e}")
            raise AuthenticationError(
                f"Failed to connect to Docker daemon: {e}",
                provider="docker",
            )

    # =========================================================================
    # Resource Collection
    # =========================================================================

    def collect_resources(
        self,
        *,
        resource_types: list[str] | None = None,
        regions: list[str] | None = None,
        filters: dict[str, Any] | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> list[Resource]:
        """
        Collect Docker resources.

        Args:
            resource_types: Types of resources to collect (None = all)
            regions: Not applicable for Docker (ignored)
            filters: Docker API filters
            progress_callback: Progress callback(current, total)

        Returns:
            List of Resource objects
        """
        self.logger.info("Starting Docker resource collection")

        types_to_collect = resource_types or DOCKER_RESOURCE_TYPES
        total_types = len(types_to_collect)
        resources: list[Resource] = []

        for idx, resource_type in enumerate(types_to_collect):
            if progress_callback:
                progress_callback(idx, total_types)

            try:
                type_resources = self._collect_resource_type(
                    resource_type, filters
                )
                resources.extend(type_resources)
                self.logger.debug(
                    f"Collected {len(type_resources)} {resource_type}"
                )
            except Exception as e:
                self.logger.warning(
                    f"Failed to collect {resource_type}: {e}"
                )

        if progress_callback:
            progress_callback(total_types, total_types)

        self.logger.info(f"Collected {len(resources)} Docker resources")
        return resources

    def _collect_resource_type(
        self,
        resource_type: str,
        filters: dict[str, Any] | None = None,
    ) -> list[Resource]:
        """Collect resources of a specific type."""
        collectors = {
            "containers": self._collect_containers,
            "images": self._collect_images,
            "volumes": self._collect_volumes,
            "networks": self._collect_networks,
            "configs": self._collect_configs,
            "secrets": self._collect_secrets,
            "nodes": self._collect_nodes,
            "services": self._collect_services,
            "plugins": self._collect_plugins,
        }

        collector = collectors.get(resource_type)
        if not collector:
            self.logger.warning(f"Unknown resource type: {resource_type}")
            return []

        return self._with_retry(
            lambda: collector(filters),
            f"collect_{resource_type}",
        )

    def _collect_containers(
        self, filters: dict[str, Any] | None
    ) -> list[Resource]:
        """Collect container resources."""
        params = {"all": "true"}
        if filters:
            params["filters"] = json.dumps(filters)

        containers = self._make_request("GET", "/containers/json", params=params)
        resources = []

        for container in containers:
            container_id = container["Id"]

            # Get detailed inspect data
            try:
                inspect = self._make_request(
                    "GET", f"/containers/{container_id}/json"
                )
            except Exception:
                inspect = {}

            resource = self._create_resource(
                resource_id=container_id,
                resource_type="docker:container",
                raw_data={**container, "inspect": inspect},
                name=container.get("Names", ["/unknown"])[0].lstrip("/"),
                metadata={
                    "image": container.get("Image"),
                    "image_id": container.get("ImageID"),
                    "state": container.get("State"),
                    "status": container.get("Status"),
                    "created": container.get("Created"),
                    "ports": container.get("Ports", []),
                    "labels": container.get("Labels", {}),
                    "compose_project": container.get("Labels", {}).get(
                        "com.docker.compose.project"
                    ),
                },
            )
            resources.append(resource)

        return resources

    def _collect_images(
        self, filters: dict[str, Any] | None
    ) -> list[Resource]:
        """Collect image resources."""
        params = {"all": "false"}
        if filters:
            params["filters"] = json.dumps(filters)

        images = self._make_request("GET", "/images/json", params=params)
        resources = []

        for image in images:
            image_id = image["Id"]

            # Get detailed inspect data
            try:
                inspect = self._make_request(
                    "GET", f"/images/{image_id}/json"
                )
            except Exception:
                inspect = {}

            repo_tags = image.get("RepoTags") or ["<none>:<none>"]
            name = repo_tags[0] if repo_tags else image_id[:12]

            resource = self._create_resource(
                resource_id=image_id,
                resource_type="docker:image",
                raw_data={**image, "inspect": inspect},
                name=name,
                metadata={
                    "repo_tags": repo_tags,
                    "repo_digests": image.get("RepoDigests", []),
                    "size": image.get("Size"),
                    "virtual_size": image.get("VirtualSize"),
                    "created": image.get("Created"),
                    "labels": image.get("Labels", {}),
                    "parent_id": image.get("ParentId"),
                },
            )
            resources.append(resource)

        return resources

    def _collect_volumes(
        self, filters: dict[str, Any] | None
    ) -> list[Resource]:
        """Collect volume resources."""
        params = {}
        if filters:
            params["filters"] = json.dumps(filters)

        result = self._make_request("GET", "/volumes", params=params)
        volumes = result.get("Volumes", []) if isinstance(result, dict) else []
        resources = []

        for volume in volumes:
            volume_name = volume["Name"]

            resource = self._create_resource(
                resource_id=volume_name,
                resource_type="docker:volume",
                raw_data=volume,
                name=volume_name,
                metadata={
                    "driver": volume.get("Driver"),
                    "scope": volume.get("Scope"),
                    "mountpoint": volume.get("Mountpoint"),
                    "created_at": volume.get("CreatedAt"),
                    "labels": volume.get("Labels", {}),
                },
            )
            resources.append(resource)

        return resources

    def _collect_networks(
        self, filters: dict[str, Any] | None
    ) -> list[Resource]:
        """Collect network resources."""
        params = {}
        if filters:
            params["filters"] = json.dumps(filters)

        networks = self._make_request("GET", "/networks", params=params)
        resources = []

        for network in networks:
            network_id = network["Id"]

            resource = self._create_resource(
                resource_id=network_id,
                resource_type="docker:network",
                raw_data=network,
                name=network.get("Name", network_id[:12]),
                metadata={
                    "driver": network.get("Driver"),
                    "scope": network.get("Scope"),
                    "internal": network.get("Internal", False),
                    "ipv6_enabled": network.get("EnableIPv6", False),
                    "containers": list(network.get("Containers", {}).keys()),
                    "labels": network.get("Labels", {}),
                },
            )
            resources.append(resource)

        return resources

    def _collect_configs(
        self, filters: dict[str, Any] | None
    ) -> list[Resource]:
        """Collect Swarm config resources."""
        try:
            configs = self._make_request("GET", "/configs")
        except CollectionError:
            # Swarm not enabled
            return []

        if not isinstance(configs, list):
            return []

        resources = []
        for config in configs:
            config_id = config["ID"]
            spec = config.get("Spec", {})

            resource = self._create_resource(
                resource_id=config_id,
                resource_type="docker:config",
                raw_data=config,
                name=spec.get("Name", config_id[:12]),
                metadata={
                    "created_at": config.get("CreatedAt"),
                    "updated_at": config.get("UpdatedAt"),
                    "labels": spec.get("Labels", {}),
                },
            )
            resources.append(resource)

        return resources

    def _collect_secrets(
        self, filters: dict[str, Any] | None
    ) -> list[Resource]:
        """Collect Swarm secret resources (metadata only)."""
        try:
            secrets = self._make_request("GET", "/secrets")
        except CollectionError:
            # Swarm not enabled
            return []

        if not isinstance(secrets, list):
            return []

        resources = []
        for secret in secrets:
            secret_id = secret["ID"]
            spec = secret.get("Spec", {})

            resource = self._create_resource(
                resource_id=secret_id,
                resource_type="docker:secret",
                raw_data=secret,  # Note: secret data is NOT included
                name=spec.get("Name", secret_id[:12]),
                metadata={
                    "created_at": secret.get("CreatedAt"),
                    "updated_at": secret.get("UpdatedAt"),
                    "labels": spec.get("Labels", {}),
                },
            )
            resources.append(resource)

        return resources

    def _collect_nodes(
        self, filters: dict[str, Any] | None
    ) -> list[Resource]:
        """Collect Swarm node resources."""
        try:
            nodes = self._make_request("GET", "/nodes")
        except CollectionError:
            # Swarm not enabled
            return []

        if not isinstance(nodes, list):
            return []

        resources = []
        for node in nodes:
            node_id = node["ID"]
            spec = node.get("Spec", {})
            status = node.get("Status", {})

            resource = self._create_resource(
                resource_id=node_id,
                resource_type="docker:node",
                raw_data=node,
                name=node.get("Description", {}).get("Hostname", node_id[:12]),
                metadata={
                    "role": spec.get("Role"),
                    "availability": spec.get("Availability"),
                    "status_state": status.get("State"),
                    "status_addr": status.get("Addr"),
                    "manager_status": node.get("ManagerStatus"),
                    "labels": spec.get("Labels", {}),
                },
            )
            resources.append(resource)

        return resources

    def _collect_services(
        self, filters: dict[str, Any] | None
    ) -> list[Resource]:
        """Collect Swarm service resources."""
        try:
            services = self._make_request("GET", "/services")
        except CollectionError:
            # Swarm not enabled
            return []

        if not isinstance(services, list):
            return []

        resources = []
        for service in services:
            service_id = service["ID"]
            spec = service.get("Spec", {})

            resource = self._create_resource(
                resource_id=service_id,
                resource_type="docker:service",
                raw_data=service,
                name=spec.get("Name", service_id[:12]),
                metadata={
                    "mode": spec.get("Mode"),
                    "replicas": spec.get("Mode", {}).get("Replicated", {}).get(
                        "Replicas"
                    ),
                    "image": spec.get("TaskTemplate", {})
                    .get("ContainerSpec", {})
                    .get("Image"),
                    "created_at": service.get("CreatedAt"),
                    "updated_at": service.get("UpdatedAt"),
                    "labels": spec.get("Labels", {}),
                },
            )
            resources.append(resource)

        return resources

    def _collect_plugins(
        self, filters: dict[str, Any] | None
    ) -> list[Resource]:
        """Collect plugin resources."""
        try:
            plugins = self._make_request("GET", "/plugins")
        except CollectionError:
            return []

        if not isinstance(plugins, list):
            return []

        resources = []
        for plugin in plugins:
            plugin_id = plugin.get("Id", plugin.get("Name"))

            resource = self._create_resource(
                resource_id=plugin_id,
                resource_type="docker:plugin",
                raw_data=plugin,
                name=plugin.get("Name", plugin_id[:12] if plugin_id else "unknown"),
                metadata={
                    "enabled": plugin.get("Enabled"),
                    "plugin_reference": plugin.get("PluginReference"),
                },
            )
            resources.append(resource)

        return resources

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
        Collect Docker evidence.

        Args:
            evidence_types: Types of evidence to collect (None = all)
            since: Only collect evidence after this time
            filters: Docker API filters
            progress_callback: Progress callback(current, total)

        Returns:
            CollectionResult with collected evidence
        """
        self.logger.info("Starting Docker evidence collection")

        types_to_collect = evidence_types or DOCKER_EVIDENCE_TYPES
        total_types = len(types_to_collect)
        all_evidence: list[Evidence] = []
        errors: list[str] = []

        for idx, evidence_type in enumerate(types_to_collect):
            if progress_callback:
                progress_callback(idx, total_types)

            try:
                evidence_items = self._collect_evidence_type(
                    evidence_type, since, filters
                )
                all_evidence.extend(evidence_items)
                self.logger.debug(
                    f"Collected {len(evidence_items)} {evidence_type} evidence items"
                )
            except Exception as e:
                error_msg = f"Failed to collect {evidence_type}: {e}"
                self.logger.warning(error_msg)
                errors.append(error_msg)

        if progress_callback:
            progress_callback(total_types, total_types)

        self.logger.info(f"Collected {len(all_evidence)} Docker evidence items")

        return CollectionResult(
            success=len(errors) == 0,
            evidence=all_evidence,
            errors=errors,
            metadata={
                "platform": "docker",
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "evidence_types": types_to_collect,
            },
        )

    def _collect_evidence_type(
        self,
        evidence_type: str,
        since: datetime | None,
        filters: dict[str, Any] | None,
    ) -> list[Evidence]:
        """Collect evidence of a specific type."""
        collectors = {
            "system_info": self._collect_system_info_evidence,
            "container_list": self._collect_container_list_evidence,
            "container_config": self._collect_container_config_evidence,
            "image_list": self._collect_image_list_evidence,
            "image_config": self._collect_image_config_evidence,
            "volume_list": self._collect_volume_list_evidence,
            "network_list": self._collect_network_list_evidence,
            "network_config": self._collect_network_config_evidence,
            "security_settings": self._collect_security_settings_evidence,
            "plugin_list": self._collect_plugin_list_evidence,
            "swarm_info": self._collect_swarm_info_evidence,
            "compose_projects": self._collect_compose_projects_evidence,
        }

        collector = collectors.get(evidence_type)
        if not collector:
            self.logger.warning(f"Unknown evidence type: {evidence_type}")
            return []

        return self._with_retry(
            lambda: collector(since, filters),
            f"collect_{evidence_type}_evidence",
        )

    def _collect_system_info_evidence(
        self, since: datetime | None, filters: dict[str, Any] | None
    ) -> list[Evidence]:
        """Collect Docker system information evidence."""
        info = self._make_request("GET", "/info")
        version = self._make_request("GET", "/version")

        return [
            self._create_evidence(
                evidence_type="system_info",
                raw_data={
                    "info": info,
                    "version": version,
                },
                source_id="docker_system",
                metadata={
                    "docker_version": version.get("Version"),
                    "api_version": version.get("ApiVersion"),
                    "os": info.get("OperatingSystem"),
                    "kernel": info.get("KernelVersion"),
                    "security_options": info.get("SecurityOptions", []),
                    "live_restore_enabled": info.get("LiveRestoreEnabled"),
                    "container_count": info.get("Containers"),
                    "image_count": info.get("Images"),
                },
            )
        ]

    def _collect_container_list_evidence(
        self, since: datetime | None, filters: dict[str, Any] | None
    ) -> list[Evidence]:
        """Collect container list evidence."""
        params = {"all": "true"}
        if filters:
            params["filters"] = json.dumps(filters)

        containers = self._make_request("GET", "/containers/json", params=params)

        # Process container list
        container_summary = []
        for container in containers:
            container_summary.append({
                "id": container.get("Id", "")[:12],
                "name": container.get("Names", ["/unknown"])[0].lstrip("/"),
                "image": container.get("Image"),
                "state": container.get("State"),
                "status": container.get("Status"),
                "created": container.get("Created"),
                "ports": container.get("Ports", []),
                "labels": container.get("Labels", {}),
            })

        return [
            self._create_evidence(
                evidence_type="container_list",
                raw_data={"containers": containers},
                source_id="docker_containers",
                metadata={
                    "total_containers": len(containers),
                    "running": sum(
                        1 for c in containers if c.get("State") == "running"
                    ),
                    "stopped": sum(
                        1 for c in containers if c.get("State") != "running"
                    ),
                    "summary": container_summary,
                },
            )
        ]

    def _collect_container_config_evidence(
        self, since: datetime | None, filters: dict[str, Any] | None
    ) -> list[Evidence]:
        """Collect detailed container configuration evidence."""
        params = {"all": "true"}
        if filters:
            params["filters"] = json.dumps(filters)

        containers = self._make_request("GET", "/containers/json", params=params)
        evidence_items = []

        for container in containers:
            container_id = container["Id"]

            try:
                inspect = self._make_request(
                    "GET", f"/containers/{container_id}/json"
                )
            except Exception:
                continue

            config = inspect.get("Config", {})
            host_config = inspect.get("HostConfig", {})

            evidence_items.append(
                self._create_evidence(
                    evidence_type="container_config",
                    raw_data=inspect,
                    source_id=container_id[:12],
                    metadata={
                        "name": inspect.get("Name", "").lstrip("/"),
                        "image": config.get("Image"),
                        "privileged": host_config.get("Privileged", False),
                        "readonly_rootfs": host_config.get("ReadonlyRootfs", False),
                        "user": config.get("User", "root"),
                        "network_mode": host_config.get("NetworkMode"),
                        "pid_mode": host_config.get("PidMode"),
                        "ipc_mode": host_config.get("IpcMode"),
                        "cap_add": host_config.get("CapAdd", []),
                        "cap_drop": host_config.get("CapDrop", []),
                        "security_opt": host_config.get("SecurityOpt", []),
                        "port_bindings": list(
                            host_config.get("PortBindings", {}).keys()
                        ),
                    },
                )
            )

        return evidence_items

    def _collect_image_list_evidence(
        self, since: datetime | None, filters: dict[str, Any] | None
    ) -> list[Evidence]:
        """Collect image list evidence."""
        images = self._make_request("GET", "/images/json")

        image_summary = []
        for image in images:
            repo_tags = image.get("RepoTags") or ["<none>:<none>"]
            image_summary.append({
                "id": image.get("Id", "")[:12],
                "tags": repo_tags,
                "size_mb": round(image.get("Size", 0) / 1024 / 1024, 2),
                "created": image.get("Created"),
            })

        return [
            self._create_evidence(
                evidence_type="image_list",
                raw_data={"images": images},
                source_id="docker_images",
                metadata={
                    "total_images": len(images),
                    "total_size_gb": round(
                        sum(i.get("Size", 0) for i in images) / 1024 / 1024 / 1024,
                        2,
                    ),
                    "summary": image_summary,
                },
            )
        ]

    def _collect_image_config_evidence(
        self, since: datetime | None, filters: dict[str, Any] | None
    ) -> list[Evidence]:
        """Collect detailed image configuration evidence."""
        images = self._make_request("GET", "/images/json")
        evidence_items = []

        for image in images:
            image_id = image["Id"]

            try:
                inspect = self._make_request("GET", f"/images/{image_id}/json")
            except Exception:
                continue

            config = inspect.get("Config", {})

            evidence_items.append(
                self._create_evidence(
                    evidence_type="image_config",
                    raw_data=inspect,
                    source_id=image_id[:12],
                    metadata={
                        "tags": image.get("RepoTags", []),
                        "user": config.get("User", ""),
                        "exposed_ports": list(config.get("ExposedPorts", {}).keys()),
                        "env_count": len(config.get("Env", [])),
                        "labels": config.get("Labels", {}),
                        "entrypoint": config.get("Entrypoint"),
                        "cmd": config.get("Cmd"),
                    },
                )
            )

        return evidence_items

    def _collect_volume_list_evidence(
        self, since: datetime | None, filters: dict[str, Any] | None
    ) -> list[Evidence]:
        """Collect volume list evidence."""
        result = self._make_request("GET", "/volumes")
        volumes = result.get("Volumes", []) if isinstance(result, dict) else []

        return [
            self._create_evidence(
                evidence_type="volume_list",
                raw_data={"volumes": volumes},
                source_id="docker_volumes",
                metadata={
                    "total_volumes": len(volumes),
                    "drivers": list(set(v.get("Driver") for v in volumes)),
                },
            )
        ]

    def _collect_network_list_evidence(
        self, since: datetime | None, filters: dict[str, Any] | None
    ) -> list[Evidence]:
        """Collect network list evidence."""
        networks = self._make_request("GET", "/networks")

        return [
            self._create_evidence(
                evidence_type="network_list",
                raw_data={"networks": networks},
                source_id="docker_networks",
                metadata={
                    "total_networks": len(networks),
                    "drivers": list(set(n.get("Driver") for n in networks)),
                    "internal_networks": sum(
                        1 for n in networks if n.get("Internal")
                    ),
                },
            )
        ]

    def _collect_network_config_evidence(
        self, since: datetime | None, filters: dict[str, Any] | None
    ) -> list[Evidence]:
        """Collect detailed network configuration evidence."""
        networks = self._make_request("GET", "/networks")
        evidence_items = []

        for network in networks:
            network_id = network["Id"]

            try:
                inspect = self._make_request("GET", f"/networks/{network_id}")
            except Exception:
                continue

            ipam = inspect.get("IPAM", {})

            evidence_items.append(
                self._create_evidence(
                    evidence_type="network_config",
                    raw_data=inspect,
                    source_id=network_id[:12],
                    metadata={
                        "name": inspect.get("Name"),
                        "driver": inspect.get("Driver"),
                        "scope": inspect.get("Scope"),
                        "internal": inspect.get("Internal", False),
                        "ipv6_enabled": inspect.get("EnableIPv6", False),
                        "ipam_driver": ipam.get("Driver"),
                        "connected_containers": len(
                            inspect.get("Containers", {})
                        ),
                    },
                )
            )

        return evidence_items

    def _collect_security_settings_evidence(
        self, since: datetime | None, filters: dict[str, Any] | None
    ) -> list[Evidence]:
        """Collect Docker security settings evidence."""
        info = self._make_request("GET", "/info")

        security_settings = {
            "security_options": info.get("SecurityOptions", []),
            "cgroup_driver": info.get("CgroupDriver"),
            "cgroup_version": info.get("CgroupVersion"),
            "kernel_version": info.get("KernelVersion"),
            "live_restore_enabled": info.get("LiveRestoreEnabled"),
            "userland_proxy": info.get("HttpProxy") is not None,
            "experimental": info.get("ExperimentalBuild", False),
            "default_runtime": info.get("DefaultRuntime"),
            "runtimes": list(info.get("Runtimes", {}).keys()),
        }

        # Parse security options
        parsed_options = {}
        for opt in info.get("SecurityOptions", []):
            if "=" in opt:
                key, value = opt.split("=", 1)
                parsed_options[key] = value
            else:
                parsed_options[opt] = True

        security_settings["parsed_security_options"] = parsed_options

        return [
            self._create_evidence(
                evidence_type="security_settings",
                raw_data=security_settings,
                source_id="docker_security",
                metadata={
                    "seccomp_enabled": "seccomp" in str(
                        info.get("SecurityOptions", [])
                    ),
                    "apparmor_enabled": "apparmor" in str(
                        info.get("SecurityOptions", [])
                    ),
                    "selinux_enabled": "selinux" in str(
                        info.get("SecurityOptions", [])
                    ),
                    "rootless": info.get("SecurityOptions", []).count(
                        "rootless"
                    )
                    > 0,
                },
            )
        ]

    def _collect_plugin_list_evidence(
        self, since: datetime | None, filters: dict[str, Any] | None
    ) -> list[Evidence]:
        """Collect plugin list evidence."""
        try:
            plugins = self._make_request("GET", "/plugins")
        except Exception:
            plugins = []

        if not isinstance(plugins, list):
            plugins = []

        return [
            self._create_evidence(
                evidence_type="plugin_list",
                raw_data={"plugins": plugins},
                source_id="docker_plugins",
                metadata={
                    "total_plugins": len(plugins),
                    "enabled_plugins": sum(
                        1 for p in plugins if p.get("Enabled")
                    ),
                },
            )
        ]

    def _collect_swarm_info_evidence(
        self, since: datetime | None, filters: dict[str, Any] | None
    ) -> list[Evidence]:
        """Collect Swarm cluster information evidence."""
        info = self._make_request("GET", "/info")
        swarm = info.get("Swarm", {})

        if not swarm.get("NodeID"):
            # Not in swarm mode
            return [
                self._create_evidence(
                    evidence_type="swarm_info",
                    raw_data={"swarm_enabled": False},
                    source_id="docker_swarm",
                    metadata={"swarm_enabled": False},
                )
            ]

        # Get node and service counts
        try:
            nodes = self._make_request("GET", "/nodes")
            node_count = len(nodes) if isinstance(nodes, list) else 0
        except Exception:
            node_count = 0

        try:
            services = self._make_request("GET", "/services")
            service_count = len(services) if isinstance(services, list) else 0
        except Exception:
            service_count = 0

        return [
            self._create_evidence(
                evidence_type="swarm_info",
                raw_data={
                    "swarm": swarm,
                    "node_count": node_count,
                    "service_count": service_count,
                },
                source_id="docker_swarm",
                metadata={
                    "swarm_enabled": True,
                    "node_id": swarm.get("NodeID"),
                    "cluster_id": swarm.get("Cluster", {}).get("ID"),
                    "is_manager": swarm.get("ControlAvailable", False),
                    "managers": swarm.get("Managers", 0),
                    "nodes": swarm.get("Nodes", 0),
                    "node_count": node_count,
                    "service_count": service_count,
                },
            )
        ]

    def _collect_compose_projects_evidence(
        self, since: datetime | None, filters: dict[str, Any] | None
    ) -> list[Evidence]:
        """Collect Docker Compose project evidence."""
        # Get all containers and group by compose project
        containers = self._make_request(
            "GET", "/containers/json", params={"all": "true"}
        )

        projects: dict[str, list[dict]] = {}
        for container in containers:
            labels = container.get("Labels", {})
            project = labels.get("com.docker.compose.project")
            if project:
                if project not in projects:
                    projects[project] = []
                projects[project].append({
                    "name": container.get("Names", ["/unknown"])[0].lstrip("/"),
                    "service": labels.get("com.docker.compose.service"),
                    "container_number": labels.get(
                        "com.docker.compose.container-number"
                    ),
                    "state": container.get("State"),
                    "image": container.get("Image"),
                })

        return [
            self._create_evidence(
                evidence_type="compose_projects",
                raw_data={"projects": projects},
                source_id="docker_compose",
                metadata={
                    "total_projects": len(projects),
                    "project_names": list(projects.keys()),
                    "total_compose_containers": sum(
                        len(containers) for containers in projects.values()
                    ),
                },
            )
        ]
