"""
Compliance scanner service that orchestrates asset collection and compliance checking.
"""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from sqlalchemy.orm import Session

from attestful.collectors.base import BaseCollector
from attestful.collectors.cloud.aws import AWSCollector
from attestful.collectors.cloud.azure import AzureCollector
from attestful.collectors.cloud.gcp import GCPCollector
from attestful.collectors.containers.kubernetes import KubernetesCollector
from attestful.config.settings import settings
from attestful.core.exceptions import AttestfulError
from attestful.core.logging import get_logger
from attestful.storage.database import get_db
from attestful.storage.models import AttestfulAsset, AttestfulComplianceCheckResult, AttestfulScan

logger = get_logger(__name__)


# Progress callback type
ProgressCallback = Callable[[str, str, int, int], None]  # (account_id, region, current, total)


class ComplianceScanner:
    """
    Compliance scanner service.

    Orchestrates asset collection from cloud providers and executes
    compliance checks against collected assets.
    """

    def __init__(
        self,
        provider: str = "aws",
        region: str | None = None,
        regions: list[str] | None = None,
        all_regions: bool = False,
        account_ids: list[str] | None = None,
        all_accounts: bool = False,
        cross_account_role_name: str | None = None,
        subscription_id: str | None = None,
        subscription_ids: list[str] | None = None,
        all_subscriptions: bool = False,
        project_id: str | None = None,
        project_ids: list[str] | None = None,
        all_projects: bool = False,
        kubeconfig: str | None = None,
        context: str | None = None,
        namespace: str | None = None,
        all_namespaces: bool = True,
        cluster_name: str | None = None,
        standards: list[str] | None = None,
        resource_types: list[str] | None = None,
        profile: str | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        """
        Initialize compliance scanner.

        Args:
            provider: Cloud provider (aws, azure, gcp, kubernetes)
            region: Primary region/location to scan
            regions: List of specific regions/locations to scan
            all_regions: If True, scan all enabled regions/locations
            account_ids: List of specific AWS account IDs to scan (AWS only)
            all_accounts: If True, scan all accounts in AWS Organization (AWS only)
            cross_account_role_name: IAM role name to assume in each account (AWS only)
            subscription_id: Azure subscription ID to scan (Azure only)
            subscription_ids: List of Azure subscription IDs to scan (Azure only)
            all_subscriptions: If True, scan all accessible subscriptions (Azure only)
            project_id: GCP project ID to scan (GCP only)
            project_ids: List of GCP project IDs to scan (GCP only)
            all_projects: If True, scan all accessible projects (GCP only)
            kubeconfig: Path to kubeconfig file (Kubernetes only)
            context: Kubernetes context to use (Kubernetes only)
            namespace: Specific namespace to scan (Kubernetes only)
            all_namespaces: Scan all namespaces (Kubernetes only, default: True)
            cluster_name: Cluster name for identification (Kubernetes only)
            standards: List of compliance standards to check
            resource_types: List of specific resource types to collect
            profile: AWS profile name (for AWS provider)
            progress_callback: Optional callback for progress updates
        """
        self.provider = provider
        self.region = region or self._get_default_region(provider)
        self.regions = regions
        self.all_regions = all_regions

        # AWS-specific parameters
        self.account_ids = account_ids
        self.all_accounts = all_accounts
        self.cross_account_role_name = cross_account_role_name

        # Azure-specific parameters
        self.subscription_id = subscription_id
        self.subscription_ids = subscription_ids
        self.all_subscriptions = all_subscriptions

        # GCP-specific parameters
        self.project_id = project_id
        self.project_ids = project_ids
        self.all_projects = all_projects

        # Kubernetes-specific parameters
        self.kubeconfig = kubeconfig
        self.context = context
        self.namespace = namespace
        self.all_namespaces = all_namespaces
        self.cluster_name = cluster_name

        self.standards = standards or []
        self.resource_types = resource_types
        self.profile = profile
        self.progress_callback = progress_callback
        self.logger = get_logger(f"{__name__}.{provider}")

        # Performance enhancements
        self.use_cache = True
        self.cache_ttl = 300  # 5 minutes
        self.max_concurrent_checks = 50
        self.batch_size = 1000

    def _get_default_region(self, provider: str) -> str:
        """Get default region for provider."""
        if provider == "aws":
            return "us-east-1"
        elif provider == "azure":
            return "eastus"
        elif provider == "gcp":
            return "us-central1"
        elif provider == "kubernetes":
            return self.cluster_name or "default"
        return "default"

    def _create_collector(self) -> BaseCollector:
        """Create asset collector for provider with multi-region and multi-account support."""
        if self.provider == "aws":
            return AWSCollector(
                region=self.region,
                regions=self.regions,
                all_regions=self.all_regions,
                account_ids=self.account_ids,
                all_accounts=self.all_accounts,
                cross_account_role_name=self.cross_account_role_name,
                profile=self.profile,
            )
        elif self.provider == "azure":
            return AzureCollector(
                subscription_id=self.subscription_id,
                subscription_ids=self.subscription_ids,
                all_subscriptions=self.all_subscriptions,
                location=self.region,
                locations=self.regions,
                all_locations=self.all_regions,
            )
        elif self.provider == "gcp":
            return GCPCollector(
                project_id=self.project_id,
                project_ids=self.project_ids,
                all_projects=self.all_projects,
                zone=self.region,
                zones=self.regions,
                all_zones=self.all_regions,
            )
        elif self.provider == "kubernetes":
            return KubernetesCollector(
                kubeconfig=self.kubeconfig,
                context=self.context,
                namespace=self.namespace,
                all_namespaces=self.all_namespaces,
                cluster_name=self.cluster_name,
            )
        else:
            raise AttestfulError(f"Unsupported provider: {self.provider}")

    async def scan(
        self, resource_types: list[str] | None = None
    ) -> dict[str, Any]:
        """
        Execute compliance scan across one or more regions.

        Args:
            resource_types: Specific resource types to scan (None = all)

        Returns:
            Scan results summary
        """
        scan_start = datetime.now(timezone.utc)

        # Use provided resource_types or fall back to instance variable
        scan_resource_types = resource_types or self.resource_types

        # Determine regions being scanned
        target_regions = []
        if self.all_regions:
            target_regions = ["all enabled regions"]
        elif self.regions:
            target_regions = self.regions
        else:
            target_regions = [self.region]

        # Determine accounts being scanned
        target_accounts = []
        if self.all_accounts:
            target_accounts = ["all accounts in organization"]
        elif self.account_ids:
            target_accounts = self.account_ids
        else:
            target_accounts = ["current account"]

        self.logger.info(
            "Starting compliance scan",
            provider=self.provider,
            regions=target_regions,
            accounts=target_accounts,
            multi_region=len(target_regions) > 1 or self.all_regions,
            multi_account=len(target_accounts) > 1 or self.all_accounts,
            standards=self.standards,
            resource_types=scan_resource_types,
        )

        # Create collector
        collector = self._create_collector()

        # Collect resources
        self.logger.info(
            "Collecting resources",
            provider=self.provider,
            regions=target_regions,
            resource_types=scan_resource_types,
        )

        all_resources = collector.collect_resources(resource_types=scan_resource_types)

        self.logger.info(
            "Resource collection complete",
            total_resources=len(all_resources),
        )

        # Calculate duration
        scan_end = datetime.now(timezone.utc)
        duration = (scan_end - scan_start).total_seconds()

        # Extract unique accounts and regions from resources
        unique_accounts: set[str] = set()
        unique_regions: set[str] = set()
        for resource in all_resources:
            if resource.tags.get("account_id"):
                unique_accounts.add(resource.tags["account_id"])
            if resource.tags.get("region"):
                unique_regions.add(resource.tags["region"])

        return {
            "provider": self.provider,
            "region": self.region,
            "regions_scanned": list(unique_regions) if unique_regions else [self.region],
            "accounts_scanned": list(unique_accounts) if unique_accounts else ["current"],
            "multi_region": len(unique_regions) > 1,
            "multi_account": len(unique_accounts) > 1,
            "standards": self.standards,
            "resources_scanned": len(all_resources),
            "duration_seconds": duration,
            "started_at": scan_start.isoformat(),
            "completed_at": scan_end.isoformat(),
        }

    def _calculate_stats(self, results: list[Any]) -> dict[str, int]:
        """Calculate statistics from compliance results."""
        stats = {
            "passed": 0,
            "failed": 0,
            "errors": 0,
            "skipped": 0,
        }

        for result in results:
            status = getattr(result, "status", None)
            if status == "pass":
                stats["passed"] += 1
            elif status == "fail":
                stats["failed"] += 1
            elif status == "error":
                stats["errors"] += 1
            elif status == "skip":
                stats["skipped"] += 1

        return stats
