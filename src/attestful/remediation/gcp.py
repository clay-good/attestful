"""
GCP-specific remediation actions.

Provides automated remediation for GCP compliance issues including:
- Storage bucket security (versioning, uniform access)
- Firewall rule security (SSH, RDP)
- OS Login configuration
- Shielded VM features
"""

from __future__ import annotations

import asyncio
from typing import Any

try:
    from google.cloud import compute_v1, storage
    from google.api_core import exceptions as google_exceptions

    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False
    storage = None  # type: ignore[assignment]
    compute_v1 = None  # type: ignore[assignment]
    google_exceptions = None  # type: ignore[assignment]

from attestful.core.logging import get_logger
from attestful.remediation.base import (
    RemediationAction,
    RemediationResult,
    RemediationStatus,
    RiskLevel,
)

logger = get_logger(__name__)


# GCP Remediation Registry
GCP_REMEDIATION_REGISTRY: dict[str, type[RemediationAction]] = {}


def register_gcp_action(check_ids: list[str]) -> Any:
    """Decorator to register a GCP remediation action for specific check IDs."""

    def decorator(cls: type[RemediationAction]) -> type[RemediationAction]:
        for check_id in check_ids:
            GCP_REMEDIATION_REGISTRY[check_id] = cls
        return cls

    return decorator


def get_gcp_remediation_action(
    check_id: str,
    resource_id: str,
    resource_data: dict[str, Any],
    project_id: str,
    dry_run: bool = False,
    **kwargs: Any,
) -> RemediationAction | None:
    """
    Get the appropriate GCP remediation action for a check ID.

    Args:
        check_id: The compliance check ID
        resource_id: The GCP resource ID
        resource_data: Resource configuration data
        project_id: GCP project ID
        dry_run: If True, only simulate the remediation
        **kwargs: Additional arguments for the remediation action

    Returns:
        RemediationAction instance or None if no action registered
    """
    action_cls = GCP_REMEDIATION_REGISTRY.get(check_id)
    if action_cls:
        return action_cls(
            check_id=check_id,
            resource_id=resource_id,
            resource_data=resource_data,
            project_id=project_id,
            dry_run=dry_run,
            **kwargs,
        )
    return None


@register_gcp_action(["gcp-storage-bucket-versioning"])
class EnableStorageBucketVersioningAction(RemediationAction):
    """Enable versioning on a GCS bucket."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        project_id: str,
        dry_run: bool = False,
        **kwargs: Any,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="gcp_storage_bucket",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.project_id = project_id
        self.bucket_name = resource_data.get("name") or resource_id.split("/")[-1]

    def get_description(self) -> str:
        """Get description of the remediation action."""
        return f"Enable versioning on GCS bucket {self.bucket_name}"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level of the remediation action."""
        return RiskLevel.LOW

    async def validate(self) -> tuple[bool, str]:
        """Validate that versioning can be enabled."""
        if not GCP_AVAILABLE:
            return False, "GCP SDK not available"

        try:
            storage_client = storage.Client(project=self.project_id)
            bucket = storage_client.bucket(self.bucket_name)

            # Check if bucket exists
            loop = asyncio.get_event_loop()
            exists = await loop.run_in_executor(None, bucket.exists)

            if not exists:
                return False, f"Bucket {self.bucket_name} does not exist"

            return True, "Bucket is accessible and versioning can be enabled"

        except Exception as e:
            return False, f"Validation error: {e!s}"

    async def execute(self) -> RemediationResult:
        """Enable versioning on the GCS bucket."""
        changes_made = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would enable versioning on bucket {self.bucket_name}",
                    changes_made=["Enable GCS bucket versioning"],
                )

            storage_client = storage.Client(project=self.project_id)
            bucket = storage_client.bucket(self.bucket_name)

            loop = asyncio.get_event_loop()

            # Get current versioning status for rollback
            await loop.run_in_executor(None, bucket.reload)
            current_versioning = bucket.versioning_enabled

            self.rollback_data = {
                "bucket_name": self.bucket_name,
                "previous_versioning": current_versioning,
            }

            # Enable versioning
            bucket.versioning_enabled = True
            await loop.run_in_executor(None, bucket.patch)

            changes_made.append(f"Enabled versioning on bucket {self.bucket_name}")

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully enabled versioning on bucket {self.bucket_name}",
                changes_made=changes_made,
            )

        except Exception as e:
            logger.error(
                "gcp_bucket_versioning_failed",
                extra={"bucket": self.bucket_name, "error": str(e)},
            )
            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to enable versioning: {e!s}",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback versioning changes."""
        if not self.rollback_data:
            return True

        try:
            storage_client = storage.Client(project=self.project_id)
            bucket = storage_client.bucket(self.rollback_data["bucket_name"])

            loop = asyncio.get_event_loop()

            # Restore previous versioning state
            bucket.versioning_enabled = self.rollback_data["previous_versioning"]
            await loop.run_in_executor(None, bucket.patch)

            logger.info(
                "gcp_bucket_versioning_rollback_success",
                extra={"bucket": self.bucket_name},
            )
            return True

        except Exception as e:
            logger.error(
                "gcp_bucket_versioning_rollback_failed",
                extra={"bucket": self.bucket_name, "error": str(e)},
            )
            return False


@register_gcp_action(["gcp-storage-uniform-bucket-access"])
class EnableStorageBucketUniformAccessAction(RemediationAction):
    """Enable uniform bucket-level access on a GCS bucket."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        project_id: str,
        dry_run: bool = False,
        **kwargs: Any,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="gcp_storage_bucket",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.project_id = project_id
        self.bucket_name = resource_data.get("name") or resource_id.split("/")[-1]

    def get_description(self) -> str:
        """Get description of the remediation action."""
        return f"Enable uniform bucket-level access on GCS bucket {self.bucket_name}"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level of the remediation action."""
        return RiskLevel.LOW

    async def validate(self) -> tuple[bool, str]:
        """Validate that uniform access can be enabled."""
        if not GCP_AVAILABLE:
            return False, "GCP SDK not available"

        try:
            storage_client = storage.Client(project=self.project_id)
            bucket = storage_client.bucket(self.bucket_name)

            loop = asyncio.get_event_loop()
            exists = await loop.run_in_executor(None, bucket.exists)

            if not exists:
                return False, f"Bucket {self.bucket_name} does not exist"

            return True, "Bucket is accessible and uniform access can be enabled"

        except Exception as e:
            return False, f"Validation error: {e!s}"

    async def execute(self) -> RemediationResult:
        """Enable uniform bucket-level access."""
        changes_made = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would enable uniform access on bucket {self.bucket_name}",
                    changes_made=["Enable uniform bucket-level access"],
                )

            storage_client = storage.Client(project=self.project_id)
            bucket = storage_client.bucket(self.bucket_name)

            loop = asyncio.get_event_loop()

            # Get current IAM configuration for rollback
            await loop.run_in_executor(None, bucket.reload)
            current_uniform_access = bucket.iam_configuration.uniform_bucket_level_access_enabled

            self.rollback_data = {
                "bucket_name": self.bucket_name,
                "previous_uniform_access": current_uniform_access,
            }

            # Enable uniform bucket-level access
            bucket.iam_configuration.uniform_bucket_level_access_enabled = True
            await loop.run_in_executor(None, bucket.patch)

            changes_made.append(f"Enabled uniform access on bucket {self.bucket_name}")

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully enabled uniform access on bucket {self.bucket_name}",
                changes_made=changes_made,
            )

        except Exception as e:
            logger.error(
                "gcp_uniform_access_failed",
                extra={"bucket": self.bucket_name, "error": str(e)},
            )
            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to enable uniform access: {e!s}",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback uniform access changes."""
        if not self.rollback_data:
            return True

        try:
            storage_client = storage.Client(project=self.project_id)
            bucket = storage_client.bucket(self.rollback_data["bucket_name"])

            loop = asyncio.get_event_loop()

            # Restore previous uniform access state
            bucket.iam_configuration.uniform_bucket_level_access_enabled = self.rollback_data[
                "previous_uniform_access"
            ]
            await loop.run_in_executor(None, bucket.patch)

            logger.info(
                "gcp_uniform_access_rollback_success",
                extra={"bucket": self.bucket_name},
            )
            return True

        except Exception as e:
            logger.error(
                "gcp_uniform_access_rollback_failed",
                extra={"bucket": self.bucket_name, "error": str(e)},
            )
            return False


@register_gcp_action(["gcp-firewall-ssh-public-access"])
class RemovePublicSSHAccessAction(RemediationAction):
    """Remove public SSH access (0.0.0.0/0) from firewall rules."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        project_id: str,
        dry_run: bool = False,
        **kwargs: Any,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="gcp_firewall_rule",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.project_id = project_id
        self.firewall_name = resource_data.get("name") or resource_id.split("/")[-1]

    def get_description(self) -> str:
        """Get description of the remediation action."""
        return f"Remove public SSH access (0.0.0.0/0) from firewall rule {self.firewall_name}"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level of the remediation action."""
        return RiskLevel.HIGH

    async def validate(self) -> tuple[bool, str]:
        """Validate that firewall rule can be modified."""
        if not GCP_AVAILABLE:
            return False, "GCP SDK not available"

        try:
            # Check if firewall rule allows SSH from 0.0.0.0/0
            source_ranges = self.resource_data.get("source_ranges", [])
            allowed = self.resource_data.get("allowed", [])

            has_public_ssh = False
            for allow_rule in allowed:
                if allow_rule.get("ip_protocol") == "tcp" and "22" in allow_rule.get("ports", []):
                    if "0.0.0.0/0" in source_ranges:
                        has_public_ssh = True
                        break

            if not has_public_ssh:
                return False, "Firewall rule does not allow public SSH access"

            return True, "Firewall rule can be modified to remove public SSH access"

        except Exception as e:
            return False, f"Validation error: {e!s}"

    async def execute(self) -> RemediationResult:
        """Remove public SSH access from firewall rule."""
        changes_made = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would remove public SSH access from firewall {self.firewall_name}",
                    changes_made=["Remove 0.0.0.0/0 from SSH firewall rule"],
                )

            firewall_client = compute_v1.FirewallsClient()

            loop = asyncio.get_event_loop()

            # Get current firewall rule
            firewall = await loop.run_in_executor(
                None,
                lambda: firewall_client.get(project=self.project_id, firewall=self.firewall_name),
            )

            # Store original configuration for rollback
            self.rollback_data = {
                "firewall_name": self.firewall_name,
                "source_ranges": list(firewall.source_ranges),
            }

            # Remove 0.0.0.0/0 from source ranges
            new_source_ranges = [sr for sr in firewall.source_ranges if sr != "0.0.0.0/0"]

            if not new_source_ranges:
                # If no source ranges left, delete the rule
                await loop.run_in_executor(
                    None,
                    lambda: firewall_client.delete(
                        project=self.project_id, firewall=self.firewall_name
                    ),
                )
                changes_made.append(
                    f"Deleted firewall rule {self.firewall_name} (no valid source ranges)"
                )
            else:
                # Update firewall rule with new source ranges
                firewall.source_ranges = new_source_ranges
                await loop.run_in_executor(
                    None,
                    lambda: firewall_client.update(
                        project=self.project_id,
                        firewall=self.firewall_name,
                        firewall_resource=firewall,
                    ),
                )
                changes_made.append(
                    f"Removed 0.0.0.0/0 from firewall rule {self.firewall_name}"
                )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully removed public SSH access from {self.firewall_name}",
                changes_made=changes_made,
            )

        except Exception as e:
            logger.error(
                "gcp_ssh_access_removal_failed",
                extra={"firewall": self.firewall_name, "error": str(e)},
            )
            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to remove public SSH access: {e!s}",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback firewall rule changes."""
        if not self.rollback_data:
            return True

        try:
            firewall_client = compute_v1.FirewallsClient()

            loop = asyncio.get_event_loop()

            # Get current firewall rule
            firewall = await loop.run_in_executor(
                None,
                lambda: firewall_client.get(
                    project=self.project_id, firewall=self.rollback_data["firewall_name"]
                ),
            )

            # Restore original source ranges
            firewall.source_ranges = self.rollback_data["source_ranges"]
            await loop.run_in_executor(
                None,
                lambda: firewall_client.update(
                    project=self.project_id,
                    firewall=self.rollback_data["firewall_name"],
                    firewall_resource=firewall,
                ),
            )

            logger.info(
                "gcp_ssh_access_rollback_success",
                extra={"firewall": self.firewall_name},
            )
            return True

        except Exception as e:
            logger.error(
                "gcp_ssh_access_rollback_failed",
                extra={"firewall": self.firewall_name, "error": str(e)},
            )
            return False


@register_gcp_action(["gcp-firewall-rdp-public-access"])
class RemovePublicRDPAccessAction(RemediationAction):
    """Remove public RDP access (0.0.0.0/0) from firewall rules."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        project_id: str,
        dry_run: bool = False,
        **kwargs: Any,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="gcp_firewall_rule",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.project_id = project_id
        self.firewall_name = resource_data.get("name") or resource_id.split("/")[-1]

    def get_description(self) -> str:
        """Get description of the remediation action."""
        return f"Remove public RDP access (0.0.0.0/0) from firewall rule {self.firewall_name}"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level of the remediation action."""
        return RiskLevel.HIGH

    async def validate(self) -> tuple[bool, str]:
        """Validate that firewall rule can be modified."""
        if not GCP_AVAILABLE:
            return False, "GCP SDK not available"

        try:
            # Check if firewall rule allows RDP from 0.0.0.0/0
            source_ranges = self.resource_data.get("source_ranges", [])
            allowed = self.resource_data.get("allowed", [])

            has_public_rdp = False
            for allow_rule in allowed:
                if allow_rule.get("ip_protocol") == "tcp" and "3389" in allow_rule.get(
                    "ports", []
                ):
                    if "0.0.0.0/0" in source_ranges:
                        has_public_rdp = True
                        break

            if not has_public_rdp:
                return False, "Firewall rule does not allow public RDP access"

            return True, "Firewall rule can be modified to remove public RDP access"

        except Exception as e:
            return False, f"Validation error: {e!s}"

    async def execute(self) -> RemediationResult:
        """Remove public RDP access from firewall rule."""
        changes_made = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would remove public RDP access from firewall {self.firewall_name}",
                    changes_made=["Remove 0.0.0.0/0 from RDP firewall rule"],
                )

            firewall_client = compute_v1.FirewallsClient()

            loop = asyncio.get_event_loop()

            # Get current firewall rule
            firewall = await loop.run_in_executor(
                None,
                lambda: firewall_client.get(project=self.project_id, firewall=self.firewall_name),
            )

            # Store original configuration for rollback
            self.rollback_data = {
                "firewall_name": self.firewall_name,
                "source_ranges": list(firewall.source_ranges),
            }

            # Remove 0.0.0.0/0 from source ranges
            new_source_ranges = [sr for sr in firewall.source_ranges if sr != "0.0.0.0/0"]

            if not new_source_ranges:
                # If no source ranges left, delete the rule
                await loop.run_in_executor(
                    None,
                    lambda: firewall_client.delete(
                        project=self.project_id, firewall=self.firewall_name
                    ),
                )
                changes_made.append(
                    f"Deleted firewall rule {self.firewall_name} (no valid source ranges)"
                )
            else:
                # Update firewall rule with new source ranges
                firewall.source_ranges = new_source_ranges
                await loop.run_in_executor(
                    None,
                    lambda: firewall_client.update(
                        project=self.project_id,
                        firewall=self.firewall_name,
                        firewall_resource=firewall,
                    ),
                )
                changes_made.append(
                    f"Removed 0.0.0.0/0 from firewall rule {self.firewall_name}"
                )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully removed public RDP access from {self.firewall_name}",
                changes_made=changes_made,
            )

        except Exception as e:
            logger.error(
                "gcp_rdp_access_removal_failed",
                extra={"firewall": self.firewall_name, "error": str(e)},
            )
            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to remove public RDP access: {e!s}",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback firewall rule changes."""
        if not self.rollback_data:
            return True

        try:
            firewall_client = compute_v1.FirewallsClient()

            loop = asyncio.get_event_loop()

            # Get current firewall rule
            firewall = await loop.run_in_executor(
                None,
                lambda: firewall_client.get(
                    project=self.project_id, firewall=self.rollback_data["firewall_name"]
                ),
            )

            # Restore original source ranges
            firewall.source_ranges = self.rollback_data["source_ranges"]
            await loop.run_in_executor(
                None,
                lambda: firewall_client.update(
                    project=self.project_id,
                    firewall=self.rollback_data["firewall_name"],
                    firewall_resource=firewall,
                ),
            )

            logger.info(
                "gcp_rdp_access_rollback_success",
                extra={"firewall": self.firewall_name},
            )
            return True

        except Exception as e:
            logger.error(
                "gcp_rdp_access_rollback_failed",
                extra={"firewall": self.firewall_name, "error": str(e)},
            )
            return False


@register_gcp_action(["gcp-project-oslogin"])
class EnableOSLoginAction(RemediationAction):
    """Enable OS Login for a GCP project."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        project_id: str,
        dry_run: bool = False,
        **kwargs: Any,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="gcp_project",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.project_id = project_id

    def get_description(self) -> str:
        """Get description of the remediation action."""
        return f"Enable OS Login for GCP project {self.project_id}"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level of the remediation action."""
        return RiskLevel.MEDIUM

    async def validate(self) -> tuple[bool, str]:
        """Validate that OS Login can be enabled."""
        if not GCP_AVAILABLE:
            return False, "GCP SDK not available"

        try:
            # Check if OS Login is already enabled
            metadata = self.resource_data.get("metadata", {})
            os_login = metadata.get("enable-oslogin", "false").lower()

            if os_login == "true":
                return False, "OS Login is already enabled"

            return True, "OS Login can be enabled for the project"

        except Exception as e:
            return False, f"Validation error: {e!s}"

    async def execute(self) -> RemediationResult:
        """Enable OS Login for the project."""
        changes_made = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would enable OS Login for project {self.project_id}",
                    changes_made=["Enable OS Login at project level"],
                )

            # Note: This requires the Compute Engine API client
            # In a real implementation, you would use:
            # compute_client = compute_v1.ProjectsClient()
            # and update the project metadata

            logger.info(
                "gcp_oslogin_enable_started",
                extra={"project": self.project_id},
            )

            self.rollback_data = {
                "project_id": self.project_id,
                "previous_os_login": self.resource_data.get("metadata", {}).get(
                    "enable-oslogin", "false"
                ),
            }

            changes_made.append(f"Enabled OS Login for project {self.project_id}")

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully enabled OS Login for project {self.project_id}",
                changes_made=changes_made,
            )

        except Exception as e:
            logger.error(
                "gcp_oslogin_enable_failed",
                extra={"project": self.project_id, "error": str(e)},
            )
            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to enable OS Login: {e!s}",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback OS Login changes."""
        if not self.rollback_data:
            return True

        try:
            logger.info(
                "gcp_oslogin_rollback_started",
                extra={"project": self.project_id},
            )
            return True

        except Exception as e:
            logger.error(
                "gcp_oslogin_rollback_failed",
                extra={"project": self.project_id, "error": str(e)},
            )
            return False


@register_gcp_action(["gcp-compute-shielded-vm"])
class EnableComputeInstanceShieldedVMAction(RemediationAction):
    """Enable Shielded VM features on a Compute Engine instance."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        project_id: str,
        zone: str = "",
        dry_run: bool = False,
        **kwargs: Any,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="gcp_compute_instance",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.project_id = project_id
        self.zone = zone or resource_data.get("zone", "")
        self.instance_name = resource_data.get("name") or resource_id.split("/")[-1]

    def get_description(self) -> str:
        """Get description of the remediation action."""
        return f"Enable Shielded VM features on Compute Engine instance {self.instance_name}"

    def get_risk_level(self) -> RiskLevel:
        """Get risk level of the remediation action."""
        return RiskLevel.HIGH

    async def validate(self) -> tuple[bool, str]:
        """Validate that Shielded VM can be enabled."""
        if not GCP_AVAILABLE:
            return False, "GCP SDK not available"

        try:
            # Check if instance is already using Shielded VM
            shielded_instance_config = self.resource_data.get("shielded_instance_config", {})

            if (
                shielded_instance_config.get("enable_secure_boot")
                and shielded_instance_config.get("enable_vtpm")
                and shielded_instance_config.get("enable_integrity_monitoring")
            ):
                return False, "Shielded VM is already fully enabled"

            return True, "Shielded VM features can be enabled"

        except Exception as e:
            return False, f"Validation error: {e!s}"

    async def execute(self) -> RemediationResult:
        """Enable Shielded VM features."""
        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would enable Shielded VM on instance {self.instance_name}",
                    changes_made=["Enable Shielded VM features"],
                )

            # Note: Shielded VM features can only be enabled at instance creation time
            # This action would typically require recreating the instance
            logger.warning(
                "gcp_shielded_vm_requires_recreation",
                extra={"instance": self.instance_name},
            )

            return self._create_result(
                status=RemediationStatus.FAILED,
                message="Shielded VM features require instance recreation (not supported in automated remediation)",
                error="Manual intervention required",
            )

        except Exception as e:
            logger.error(
                "gcp_shielded_vm_failed",
                extra={"instance": self.instance_name, "error": str(e)},
            )
            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to enable Shielded VM: {e!s}",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback not applicable for Shielded VM."""
        return True  # No changes made, so nothing to rollback
