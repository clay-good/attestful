"""
GCP (Google Cloud Platform) collector for Attestful.

Dual-mode collector supporting both resource collection (for compliance checks)
and evidence collection (for audit documentation).

Requires google-cloud-* packages.
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

# Optional GCP SDK imports
try:
    from google.cloud import compute_v1
    from google.cloud import storage
    from google.cloud import kms_v1
    from google.cloud import resourcemanager_v3
    from google.cloud import logging_v2
    from google.cloud import iam_admin_v1
    from google.api_core import exceptions as gcp_exceptions
    from google.auth import default as google_auth_default
    from google.auth.credentials import Credentials

    GCP_SDK_AVAILABLE = True
except ImportError:
    GCP_SDK_AVAILABLE = False
    gcp_exceptions = None


@dataclass
class GCPCollectorConfig:
    """Configuration for GCP collector."""

    # Authentication options
    project_id: str | None = None
    credentials_file: str | None = None  # Path to service account JSON

    # Scanning scope
    project_ids: list[str] = field(default_factory=list)
    zones: list[str] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)

    # Rate limiting
    max_retries: int = 3
    timeout: int = 30


class GCPCollector(BaseCollector):
    """
    GCP collector for infrastructure resources and compliance evidence.

    Supports dual-mode operation:
    - Resource mode: Collects GCP resources for compliance checking
    - Evidence mode: Collects GCP configuration evidence for audits

    Resource Types:
    - compute_instance: Compute Engine VMs
    - compute_disk: Persistent disks
    - compute_firewall: Firewall rules
    - compute_network: VPC networks
    - compute_subnetwork: Subnetworks
    - storage_bucket: Cloud Storage buckets
    - kms_key: Cloud KMS keys
    - kms_key_ring: Cloud KMS key rings
    - iam_service_account: Service accounts
    - sql_instance: Cloud SQL instances

    Evidence Types:
    - project_info: Project metadata
    - iam_policy: IAM policy bindings
    - organization_policy: Organization policies
    - audit_log_config: Audit logging configuration
    - security_health: Security Health Analytics findings

    Example:
        collector = GCPCollector(
            config=GCPCollectorConfig(
                project_ids=["my-project-id"],
            )
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["compute_instance", "storage_bucket"]
        )

        # Collect evidence for audits
        result = collector.collect_evidence(
            evidence_types=["iam_policy", "audit_log_config"]
        )
    """

    PLATFORM = "gcp"
    SUPPORTED_RESOURCE_TYPES = [
        "compute_instance",
        "compute_disk",
        "compute_firewall",
        "compute_network",
        "compute_subnetwork",
        "storage_bucket",
        "kms_key",
        "kms_key_ring",
        "iam_service_account",
        "sql_instance",
    ]
    SUPPORTED_EVIDENCE_TYPES = [
        "project_info",
        "iam_policy",
        "organization_policy",
        "audit_log_config",
        "security_health",
    ]

    def __init__(
        self,
        config: GCPCollectorConfig | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize GCP collector.

        Args:
            config: GCP collector configuration.
            **kwargs: Additional arguments passed to BaseCollector.
        """
        if not GCP_SDK_AVAILABLE:
            raise ConfigurationError(
                "GCP SDK not installed. Install with: pip install google-cloud-compute "
                "google-cloud-storage google-cloud-kms google-cloud-resource-manager "
                "google-cloud-logging google-cloud-iam"
            )

        super().__init__(**kwargs)
        self.config = config or GCPCollectorConfig()
        self._credentials: Credentials | None = None
        self._project_ids: list[str] | None = None

    def _get_credentials(self) -> Credentials:
        """Get GCP credentials for authentication."""
        if self._credentials is None:
            if self.config.credentials_file:
                # Use service account credentials from file
                import google.auth
                self._credentials, _ = google.auth.load_credentials_from_file(
                    self.config.credentials_file
                )
                logger.info("Using service account credentials from file")
            else:
                # Use Application Default Credentials (ADC)
                self._credentials, _ = google_auth_default()
                logger.info("Using Application Default Credentials")

        return self._credentials

    def _get_project_ids(self) -> list[str]:
        """Get project IDs to scan."""
        if self._project_ids is not None:
            return self._project_ids

        if self.config.project_ids:
            self._project_ids = self.config.project_ids
            return self._project_ids

        if self.config.project_id:
            self._project_ids = [self.config.project_id]
            return self._project_ids

        # Try to discover projects using Resource Manager
        try:
            credentials = self._get_credentials()
            client = resourcemanager_v3.ProjectsClient(credentials=credentials)

            self._project_ids = []
            for project in client.search_projects():
                if project.state == resourcemanager_v3.Project.State.ACTIVE:
                    self._project_ids.append(project.project_id)

            logger.info(f"Discovered {len(self._project_ids)} GCP projects")
        except Exception as e:
            logger.warning(f"Could not discover projects: {e}")
            self._project_ids = []

        return self._project_ids

    def _get_zones(self, project_id: str) -> list[str]:
        """Get zones to scan."""
        if self.config.zones:
            return self.config.zones

        # Get all zones for the project
        try:
            credentials = self._get_credentials()
            zones_client = compute_v1.ZonesClient(credentials=credentials)

            zones = []
            for zone in zones_client.list(project=project_id):
                zones.append(zone.name)

            return zones
        except Exception as e:
            logger.warning(f"Could not list zones for project {project_id}: {e}")
            # Return common zones as fallback
            return [
                "us-central1-a", "us-central1-b", "us-central1-c",
                "us-east1-b", "us-east1-c", "us-east1-d",
                "us-west1-a", "us-west1-b", "us-west1-c",
                "europe-west1-b", "europe-west1-c", "europe-west1-d",
            ]

    def _get_regions(self, project_id: str) -> list[str]:
        """Get regions to scan."""
        if self.config.regions:
            return self.config.regions

        # Get all regions for the project
        try:
            credentials = self._get_credentials()
            regions_client = compute_v1.RegionsClient(credentials=credentials)

            regions = []
            for region in regions_client.list(project=project_id):
                regions.append(region.name)

            return regions
        except Exception as e:
            logger.warning(f"Could not list regions for project {project_id}: {e}")
            # Return common regions as fallback
            return [
                "us-central1", "us-east1", "us-west1",
                "europe-west1", "asia-east1",
            ]

    def validate_credentials(self) -> bool:
        """Validate GCP credentials."""
        try:
            credentials = self._get_credentials()

            # Try to list projects to validate credentials
            client = resourcemanager_v3.ProjectsClient(credentials=credentials)
            projects = list(client.search_projects())

            if projects:
                logger.info(f"Validated GCP credentials, found {len(projects)} project(s)")
                return True
            else:
                logger.warning("No GCP projects accessible")
                return False
        except Exception as e:
            logger.error(f"GCP credential validation failed: {e}")
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
        Collect GCP resources.

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

    def _collect_compute_instance(self) -> Iterator[Resource]:
        """Collect Compute Engine instances."""
        credentials = self._get_credentials()
        instances_client = compute_v1.InstancesClient(credentials=credentials)

        for project_id in self._get_project_ids():
            for zone in self._get_zones(project_id):
                self._rate_limit()
                try:
                    request = compute_v1.ListInstancesRequest(
                        project=project_id,
                        zone=zone,
                    )

                    for instance in instances_client.list(request=request):
                        # Build resource ID
                        resource_id = f"projects/{project_id}/zones/{zone}/instances/{instance.name}"

                        # Convert to dict (proto object)
                        instance_dict = {
                            "name": instance.name,
                            "id": instance.id,
                            "status": instance.status,
                            "machine_type": instance.machine_type,
                            "zone": zone,
                            "creation_timestamp": instance.creation_timestamp,
                            "can_ip_forward": instance.can_ip_forward,
                            "deletion_protection": instance.deletion_protection,
                            "shielded_instance_config": {
                                "enable_secure_boot": instance.shielded_instance_config.enable_secure_boot
                                if instance.shielded_instance_config else False,
                                "enable_vtpm": instance.shielded_instance_config.enable_vtpm
                                if instance.shielded_instance_config else False,
                                "enable_integrity_monitoring": instance.shielded_instance_config.enable_integrity_monitoring
                                if instance.shielded_instance_config else False,
                            } if instance.shielded_instance_config else None,
                            "confidential_instance_config": {
                                "enable_confidential_compute": instance.confidential_instance_config.enable_confidential_compute
                                if instance.confidential_instance_config else False,
                            } if instance.confidential_instance_config else None,
                            "service_accounts": [
                                {"email": sa.email, "scopes": list(sa.scopes)}
                                for sa in instance.service_accounts
                            ] if instance.service_accounts else [],
                            "network_interfaces": [
                                {
                                    "network": ni.network,
                                    "subnetwork": ni.subnetwork,
                                    "access_configs": [
                                        {"nat_ip": ac.nat_i_p, "type": ac.type_}
                                        for ac in ni.access_configs
                                    ] if ni.access_configs else [],
                                }
                                for ni in instance.network_interfaces
                            ] if instance.network_interfaces else [],
                            "disks": [
                                {
                                    "source": disk.source,
                                    "boot": disk.boot,
                                    "auto_delete": disk.auto_delete,
                                    "device_name": disk.device_name,
                                }
                                for disk in instance.disks
                            ] if instance.disks else [],
                            "labels": dict(instance.labels) if instance.labels else {},
                            "metadata": {
                                "items": [
                                    {"key": item.key, "value": item.value}
                                    for item in instance.metadata.items
                                ] if instance.metadata and instance.metadata.items else []
                            },
                        }

                        yield Resource(
                            id=resource_id,
                            type="compute_instance",
                            provider="gcp",
                            region=zone,
                            name=instance.name,
                            raw_data={
                                **instance_dict,
                                "project_id": project_id,
                            },
                            tags=dict(instance.labels) if instance.labels else {},
                        )
                except Exception as e:
                    if gcp_exceptions and isinstance(e, gcp_exceptions.NotFound):
                        continue
                    logger.error(f"Failed to collect instances in {project_id}/{zone}: {e}")

    def _collect_compute_disk(self) -> Iterator[Resource]:
        """Collect Compute Engine disks."""
        credentials = self._get_credentials()
        disks_client = compute_v1.DisksClient(credentials=credentials)

        for project_id in self._get_project_ids():
            for zone in self._get_zones(project_id):
                self._rate_limit()
                try:
                    request = compute_v1.ListDisksRequest(
                        project=project_id,
                        zone=zone,
                    )

                    for disk in disks_client.list(request=request):
                        resource_id = f"projects/{project_id}/zones/{zone}/disks/{disk.name}"

                        disk_dict = {
                            "name": disk.name,
                            "id": disk.id,
                            "status": disk.status,
                            "size_gb": disk.size_gb,
                            "type": disk.type_,
                            "zone": zone,
                            "creation_timestamp": disk.creation_timestamp,
                            "source_image": disk.source_image,
                            "source_snapshot": disk.source_snapshot,
                            "disk_encryption_key": {
                                "kms_key_name": disk.disk_encryption_key.kms_key_name
                                if disk.disk_encryption_key else None,
                            } if disk.disk_encryption_key else None,
                            "labels": dict(disk.labels) if disk.labels else {},
                        }

                        yield Resource(
                            id=resource_id,
                            type="compute_disk",
                            provider="gcp",
                            region=zone,
                            name=disk.name,
                            raw_data={
                                **disk_dict,
                                "project_id": project_id,
                            },
                            tags=dict(disk.labels) if disk.labels else {},
                        )
                except Exception as e:
                    if gcp_exceptions and isinstance(e, gcp_exceptions.NotFound):
                        continue
                    logger.error(f"Failed to collect disks in {project_id}/{zone}: {e}")

    def _collect_compute_firewall(self) -> Iterator[Resource]:
        """Collect Compute Engine firewall rules."""
        credentials = self._get_credentials()
        firewalls_client = compute_v1.FirewallsClient(credentials=credentials)

        for project_id in self._get_project_ids():
            self._rate_limit()
            try:
                request = compute_v1.ListFirewallsRequest(project=project_id)

                for firewall in firewalls_client.list(request=request):
                    resource_id = f"projects/{project_id}/global/firewalls/{firewall.name}"

                    firewall_dict = {
                        "name": firewall.name,
                        "id": firewall.id,
                        "description": firewall.description,
                        "network": firewall.network,
                        "priority": firewall.priority,
                        "direction": firewall.direction,
                        "disabled": firewall.disabled,
                        "creation_timestamp": firewall.creation_timestamp,
                        "source_ranges": list(firewall.source_ranges) if firewall.source_ranges else [],
                        "destination_ranges": list(firewall.destination_ranges) if firewall.destination_ranges else [],
                        "source_tags": list(firewall.source_tags) if firewall.source_tags else [],
                        "target_tags": list(firewall.target_tags) if firewall.target_tags else [],
                        "source_service_accounts": list(firewall.source_service_accounts) if firewall.source_service_accounts else [],
                        "target_service_accounts": list(firewall.target_service_accounts) if firewall.target_service_accounts else [],
                        "allowed": [
                            {"ip_protocol": a.I_p_protocol, "ports": list(a.ports) if a.ports else []}
                            for a in firewall.allowed
                        ] if firewall.allowed else [],
                        "denied": [
                            {"ip_protocol": d.I_p_protocol, "ports": list(d.ports) if d.ports else []}
                            for d in firewall.denied
                        ] if firewall.denied else [],
                        "log_config": {
                            "enable": firewall.log_config.enable
                        } if firewall.log_config else None,
                    }

                    yield Resource(
                        id=resource_id,
                        type="compute_firewall",
                        provider="gcp",
                        region="global",
                        name=firewall.name,
                        raw_data={
                            **firewall_dict,
                            "project_id": project_id,
                        },
                    )
            except Exception as e:
                logger.error(f"Failed to collect firewalls in {project_id}: {e}")

    def _collect_compute_network(self) -> Iterator[Resource]:
        """Collect VPC networks."""
        credentials = self._get_credentials()
        networks_client = compute_v1.NetworksClient(credentials=credentials)

        for project_id in self._get_project_ids():
            self._rate_limit()
            try:
                request = compute_v1.ListNetworksRequest(project=project_id)

                for network in networks_client.list(request=request):
                    resource_id = f"projects/{project_id}/global/networks/{network.name}"

                    network_dict = {
                        "name": network.name,
                        "id": network.id,
                        "description": network.description,
                        "creation_timestamp": network.creation_timestamp,
                        "auto_create_subnetworks": network.auto_create_subnetworks,
                        "routing_config": {
                            "routing_mode": network.routing_config.routing_mode
                        } if network.routing_config else None,
                        "mtu": network.mtu,
                        "subnetworks": list(network.subnetworks) if network.subnetworks else [],
                    }

                    yield Resource(
                        id=resource_id,
                        type="compute_network",
                        provider="gcp",
                        region="global",
                        name=network.name,
                        raw_data={
                            **network_dict,
                            "project_id": project_id,
                        },
                    )
            except Exception as e:
                logger.error(f"Failed to collect networks in {project_id}: {e}")

    def _collect_compute_subnetwork(self) -> Iterator[Resource]:
        """Collect VPC subnetworks."""
        credentials = self._get_credentials()
        subnetworks_client = compute_v1.SubnetworksClient(credentials=credentials)

        for project_id in self._get_project_ids():
            for region in self._get_regions(project_id):
                self._rate_limit()
                try:
                    request = compute_v1.ListSubnetworksRequest(
                        project=project_id,
                        region=region,
                    )

                    for subnet in subnetworks_client.list(request=request):
                        resource_id = f"projects/{project_id}/regions/{region}/subnetworks/{subnet.name}"

                        subnet_dict = {
                            "name": subnet.name,
                            "id": subnet.id,
                            "description": subnet.description,
                            "network": subnet.network,
                            "ip_cidr_range": subnet.ip_cidr_range,
                            "region": region,
                            "creation_timestamp": subnet.creation_timestamp,
                            "private_ip_google_access": subnet.private_ip_google_access,
                            "enable_flow_logs": subnet.enable_flow_logs if hasattr(subnet, 'enable_flow_logs') else False,
                            "log_config": {
                                "enable": subnet.log_config.enable if subnet.log_config else False,
                                "aggregation_interval": subnet.log_config.aggregation_interval if subnet.log_config else None,
                                "flow_sampling": subnet.log_config.flow_sampling if subnet.log_config else None,
                            } if subnet.log_config else None,
                            "purpose": subnet.purpose,
                            "role": subnet.role,
                        }

                        yield Resource(
                            id=resource_id,
                            type="compute_subnetwork",
                            provider="gcp",
                            region=region,
                            name=subnet.name,
                            raw_data={
                                **subnet_dict,
                                "project_id": project_id,
                            },
                        )
                except Exception as e:
                    if gcp_exceptions and isinstance(e, gcp_exceptions.NotFound):
                        continue
                    logger.error(f"Failed to collect subnetworks in {project_id}/{region}: {e}")

    def _collect_storage_bucket(self) -> Iterator[Resource]:
        """Collect Cloud Storage buckets."""
        credentials = self._get_credentials()

        for project_id in self._get_project_ids():
            self._rate_limit()
            try:
                storage_client = storage.Client(
                    project=project_id,
                    credentials=credentials,
                )

                for bucket in storage_client.list_buckets():
                    resource_id = f"projects/{project_id}/buckets/{bucket.name}"

                    # Get IAM policy
                    try:
                        policy = bucket.get_iam_policy()
                        iam_bindings = [
                            {"role": binding["role"], "members": list(binding["members"])}
                            for binding in policy.bindings
                        ]
                    except Exception:
                        iam_bindings = []

                    bucket_dict = {
                        "name": bucket.name,
                        "id": bucket.id,
                        "location": bucket.location,
                        "location_type": bucket.location_type,
                        "storage_class": bucket.storage_class,
                        "time_created": bucket.time_created.isoformat() if bucket.time_created else None,
                        "versioning_enabled": bucket.versioning_enabled,
                        "default_event_based_hold": bucket.default_event_based_hold,
                        "retention_policy": {
                            "retention_period": bucket.retention_period,
                            "is_locked": bucket.retention_policy_locked,
                        } if bucket.retention_period else None,
                        "uniform_bucket_level_access": {
                            "enabled": bucket.iam_configuration.uniform_bucket_level_access_enabled
                            if bucket.iam_configuration else False,
                        },
                        "public_access_prevention": bucket.iam_configuration.public_access_prevention
                        if bucket.iam_configuration else None,
                        "default_kms_key_name": bucket.default_kms_key_name,
                        "logging": {
                            "log_bucket": bucket.logging.get("logBucket"),
                            "log_object_prefix": bucket.logging.get("logObjectPrefix"),
                        } if bucket.logging else None,
                        "iam_bindings": iam_bindings,
                        "labels": bucket.labels or {},
                    }

                    yield Resource(
                        id=resource_id,
                        type="storage_bucket",
                        provider="gcp",
                        region=bucket.location,
                        name=bucket.name,
                        raw_data={
                            **bucket_dict,
                            "project_id": project_id,
                        },
                        tags=bucket.labels or {},
                    )
            except Exception as e:
                logger.error(f"Failed to collect storage buckets in {project_id}: {e}")

    def _collect_kms_key_ring(self) -> Iterator[Resource]:
        """Collect Cloud KMS key rings."""
        credentials = self._get_credentials()
        kms_client = kms_v1.KeyManagementServiceClient(credentials=credentials)

        for project_id in self._get_project_ids():
            # KMS key rings are regional
            for location in ["global", "us", "us-central1", "us-east1", "us-west1", "europe-west1"]:
                self._rate_limit()
                try:
                    parent = f"projects/{project_id}/locations/{location}"
                    key_rings = kms_client.list_key_rings(parent=parent)

                    for key_ring in key_rings:
                        key_ring_dict = {
                            "name": key_ring.name,
                            "create_time": key_ring.create_time.isoformat() if key_ring.create_time else None,
                        }

                        yield Resource(
                            id=key_ring.name,
                            type="kms_key_ring",
                            provider="gcp",
                            region=location,
                            name=key_ring.name.split("/")[-1],
                            raw_data={
                                **key_ring_dict,
                                "project_id": project_id,
                                "location": location,
                            },
                        )
                except Exception as e:
                    if gcp_exceptions and isinstance(e, gcp_exceptions.NotFound):
                        continue
                    logger.debug(f"No key rings in {project_id}/{location}: {e}")

    def _collect_kms_key(self) -> Iterator[Resource]:
        """Collect Cloud KMS keys."""
        credentials = self._get_credentials()
        kms_client = kms_v1.KeyManagementServiceClient(credentials=credentials)

        for project_id in self._get_project_ids():
            for location in ["global", "us", "us-central1", "us-east1", "us-west1", "europe-west1"]:
                self._rate_limit()
                try:
                    parent = f"projects/{project_id}/locations/{location}"
                    key_rings = list(kms_client.list_key_rings(parent=parent))

                    for key_ring in key_rings:
                        try:
                            keys = kms_client.list_crypto_keys(parent=key_ring.name)

                            for key in keys:
                                key_dict = {
                                    "name": key.name,
                                    "purpose": str(key.purpose),
                                    "create_time": key.create_time.isoformat() if key.create_time else None,
                                    "next_rotation_time": key.next_rotation_time.isoformat() if key.next_rotation_time else None,
                                    "rotation_period": str(key.rotation_period) if key.rotation_period else None,
                                    "version_template": {
                                        "algorithm": str(key.version_template.algorithm),
                                        "protection_level": str(key.version_template.protection_level),
                                    } if key.version_template else None,
                                    "labels": dict(key.labels) if key.labels else {},
                                    "destroy_scheduled_duration": str(key.destroy_scheduled_duration) if key.destroy_scheduled_duration else None,
                                }

                                yield Resource(
                                    id=key.name,
                                    type="kms_key",
                                    provider="gcp",
                                    region=location,
                                    name=key.name.split("/")[-1],
                                    raw_data={
                                        **key_dict,
                                        "project_id": project_id,
                                        "location": location,
                                        "key_ring": key_ring.name,
                                    },
                                    tags=dict(key.labels) if key.labels else {},
                                )
                        except Exception as e:
                            logger.debug(f"Error listing keys in {key_ring.name}: {e}")
                except Exception as e:
                    if gcp_exceptions and isinstance(e, gcp_exceptions.NotFound):
                        continue
                    logger.debug(f"No KMS in {project_id}/{location}: {e}")

    def _collect_iam_service_account(self) -> Iterator[Resource]:
        """Collect IAM service accounts."""
        credentials = self._get_credentials()
        iam_client = iam_admin_v1.IAMClient(credentials=credentials)

        for project_id in self._get_project_ids():
            self._rate_limit()
            try:
                request = iam_admin_v1.ListServiceAccountsRequest(
                    name=f"projects/{project_id}",
                )

                for sa in iam_client.list_service_accounts(request=request):
                    sa_dict = {
                        "name": sa.name,
                        "unique_id": sa.unique_id,
                        "email": sa.email,
                        "display_name": sa.display_name,
                        "description": sa.description,
                        "disabled": sa.disabled,
                        "oauth2_client_id": sa.oauth2_client_id,
                    }

                    # Get service account keys
                    try:
                        keys_request = iam_admin_v1.ListServiceAccountKeysRequest(
                            name=sa.name,
                        )
                        keys = list(iam_client.list_service_account_keys(request=keys_request))
                        sa_dict["keys"] = [
                            {
                                "name": key.name,
                                "key_type": str(key.key_type),
                                "valid_after_time": key.valid_after_time.isoformat() if key.valid_after_time else None,
                                "valid_before_time": key.valid_before_time.isoformat() if key.valid_before_time else None,
                                "key_origin": str(key.key_origin),
                            }
                            for key in keys
                        ]
                    except Exception:
                        sa_dict["keys"] = []

                    yield Resource(
                        id=sa.name,
                        type="iam_service_account",
                        provider="gcp",
                        region="global",
                        name=sa.email,
                        raw_data={
                            **sa_dict,
                            "project_id": project_id,
                        },
                    )
            except Exception as e:
                logger.error(f"Failed to collect service accounts in {project_id}: {e}")

    def _collect_sql_instance(self) -> Iterator[Resource]:
        """Collect Cloud SQL instances."""
        # Note: Cloud SQL uses a different API structure
        # This is a placeholder - would need google-cloud-sql-admin
        logger.debug("Cloud SQL collection not implemented yet")
        return iter([])

    # =========================================================================
    # Evidence Collection Methods
    # =========================================================================

    def collect_evidence(
        self,
        *,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """
        Collect GCP configuration evidence.

        Args:
            evidence_types: List of evidence types to collect.

        Returns:
            CollectionResult with collected evidence.
        """
        types_to_collect = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        result = CollectionResult(success=True, platform=self.PLATFORM)

        for evidence_type in types_to_collect:
            if evidence_type not in self.SUPPORTED_EVIDENCE_TYPES:
                logger.warning(f"Unknown evidence type: {evidence_type}")
                continue

            collector_method = getattr(self, f"_collect_evidence_{evidence_type}", None)
            if collector_method is None:
                logger.warning(f"No collector for evidence type: {evidence_type}")
                continue

            try:
                evidence_items = collector_method()
                for evidence in evidence_items:
                    result.add_evidence(evidence)
                logger.debug(f"Collected {evidence_type} evidence")
            except Exception as e:
                logger.error(f"Failed to collect {evidence_type} evidence: {e}")
                result.add_error(f"Failed to collect {evidence_type}: {str(e)}")
                result.partial = True

        result.complete()
        return result

    def _collect_evidence_project_info(self) -> list[Evidence]:
        """Collect project information evidence."""
        credentials = self._get_credentials()
        client = resourcemanager_v3.ProjectsClient(credentials=credentials)
        evidence_items = []

        for project_id in self._get_project_ids():
            self._rate_limit()
            try:
                project = client.get_project(name=f"projects/{project_id}")

                evidence_items.append(Evidence(
                    platform="gcp",
                    evidence_type="project_info",
                    raw_data={
                        "project_id": project.project_id,
                        "name": project.name,
                        "display_name": project.display_name,
                        "state": str(project.state),
                        "create_time": project.create_time.isoformat() if project.create_time else None,
                        "update_time": project.update_time.isoformat() if project.update_time else None,
                        "parent": project.parent,
                        "labels": dict(project.labels) if project.labels else {},
                    },
                    metadata={
                        "project_id": project_id,
                        "source": "collector:gcp",
                    },
                ))
            except Exception as e:
                logger.error(f"Failed to get project info for {project_id}: {e}")

        return evidence_items

    def _collect_evidence_iam_policy(self) -> list[Evidence]:
        """Collect IAM policy evidence."""
        credentials = self._get_credentials()
        client = resourcemanager_v3.ProjectsClient(credentials=credentials)
        evidence_items = []

        for project_id in self._get_project_ids():
            self._rate_limit()
            try:
                policy = client.get_iam_policy(resource=f"projects/{project_id}")

                bindings = [
                    {
                        "role": binding.role,
                        "members": list(binding.members),
                        "condition": {
                            "title": binding.condition.title,
                            "description": binding.condition.description,
                            "expression": binding.condition.expression,
                        } if binding.condition else None,
                    }
                    for binding in policy.bindings
                ]

                evidence_items.append(Evidence(
                    platform="gcp",
                    evidence_type="iam_policy",
                    raw_data={
                        "project_id": project_id,
                        "version": policy.version,
                        "etag": policy.etag.decode() if isinstance(policy.etag, bytes) else policy.etag,
                        "bindings": bindings,
                        "total_bindings": len(bindings),
                    },
                    metadata={
                        "project_id": project_id,
                        "source": "collector:gcp",
                    },
                ))
            except Exception as e:
                logger.error(f"Failed to get IAM policy for {project_id}: {e}")

        return evidence_items

    def _collect_evidence_audit_log_config(self) -> list[Evidence]:
        """Collect audit log configuration evidence."""
        credentials = self._get_credentials()
        client = resourcemanager_v3.ProjectsClient(credentials=credentials)
        evidence_items = []

        for project_id in self._get_project_ids():
            self._rate_limit()
            try:
                policy = client.get_iam_policy(resource=f"projects/{project_id}")

                # Extract audit configs from the IAM policy
                audit_configs = []
                if hasattr(policy, 'audit_configs'):
                    for config in policy.audit_configs:
                        audit_configs.append({
                            "service": config.service,
                            "audit_log_configs": [
                                {
                                    "log_type": str(alc.log_type),
                                    "exempted_members": list(alc.exempted_members) if alc.exempted_members else [],
                                }
                                for alc in config.audit_log_configs
                            ] if config.audit_log_configs else [],
                        })

                evidence_items.append(Evidence(
                    platform="gcp",
                    evidence_type="audit_log_config",
                    raw_data={
                        "project_id": project_id,
                        "audit_configs": audit_configs,
                        "total_services_with_audit": len(audit_configs),
                    },
                    metadata={
                        "project_id": project_id,
                        "source": "collector:gcp",
                    },
                ))
            except Exception as e:
                logger.error(f"Failed to get audit log config for {project_id}: {e}")

        return evidence_items

    def _collect_evidence_organization_policy(self) -> list[Evidence]:
        """Collect organization policy evidence."""
        # Organization policies require org-level access
        logger.debug("Organization policy collection requires org-level access")
        return []

    def _collect_evidence_security_health(self) -> list[Evidence]:
        """Collect Security Health Analytics evidence."""
        # Security Command Center requires additional setup
        logger.debug("Security Health Analytics collection requires Security Command Center")
        return []

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _rate_limit(self) -> None:
        """Apply rate limiting between API calls."""
        import time

        if self.rate_limit_per_second > 0:
            min_interval = 1.0 / self.rate_limit_per_second
            elapsed = time.time() - self._last_request_time

            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)

        self._last_request_time = time.time()
        self._request_count += 1
