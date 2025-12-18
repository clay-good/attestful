"""
Terraform Cloud collector for Attestful.

Collects infrastructure as code, workspace configuration, and run history
evidence from Terraform Cloud/Enterprise for compliance frameworks including
SOC 2, NIST 800-53, ISO 27001, and HITRUST.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Iterator

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from attestful.collectors.base import BaseCollector, CollectorMetadata, CollectorMode
from attestful.core.exceptions import CollectionError, ConfigurationError
from attestful.core.logging import get_logger
from attestful.core.models import CollectionResult, Evidence, Resource

logger = get_logger(__name__)


@dataclass
class TerraformCloudCollectorConfig:
    """Configuration for Terraform Cloud collector."""

    # API Token
    api_token: str = ""

    # Organization name
    organization: str = ""

    # API settings
    api_url: str = "https://app.terraform.io/api/v2"
    timeout: int = 30
    max_retries: int = 3
    page_size: int = 100

    # Collection options
    days_of_history: int = 90


class TerraformCloudCollector(BaseCollector):
    """
    Terraform Cloud collector for infrastructure as code evidence.

    Collects evidence related to:
    - Workspaces and their configurations
    - Runs and their outcomes
    - State versions and changes
    - Policy checks and Sentinel policies
    - Variable sets and variables
    - Teams and access controls

    Evidence Types:
    - workspaces: Workspace configurations and settings
    - runs: Run history and outcomes
    - state_versions: State version history
    - policies: Sentinel policies and policy sets
    - variables: Variable sets and workspace variables
    - teams: Team configurations and access

    Resource Types:
    - terraform_workspace: Workspace resources
    - terraform_run: Run resources
    - terraform_policy_set: Policy set resources
    - terraform_team: Team resources

    Example:
        collector = TerraformCloudCollector(
            config=TerraformCloudCollectorConfig(
                api_token="your-api-token",
                organization="your-org",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["workspaces", "runs", "policies"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["terraform_workspace", "terraform_run"]
        )
    """

    PLATFORM = "terraform_cloud"

    metadata = CollectorMetadata(
        name="TerraformCloudCollector",
        platform="terraform_cloud",
        description="Collects infrastructure as code evidence from Terraform Cloud",
        mode=CollectorMode.BOTH,
        resource_types=[
            "terraform_workspace",
            "terraform_run",
            "terraform_policy_set",
            "terraform_team",
        ],
        evidence_types=[
            "workspaces",
            "runs",
            "state_versions",
            "policies",
            "variables",
            "teams",
        ],
    )

    SUPPORTED_RESOURCE_TYPES = [
        "terraform_workspace",
        "terraform_run",
        "terraform_policy_set",
        "terraform_team",
    ]

    SUPPORTED_EVIDENCE_TYPES = [
        "workspaces",
        "runs",
        "state_versions",
        "policies",
        "variables",
        "teams",
    ]

    # Compliance control mappings
    EVIDENCE_CONTROL_MAPPINGS = {
        "workspaces": {
            "soc2": ["CC6.1", "CC6.6", "CC8.1"],
            "nist_800_53": ["CM-2", "CM-3", "CM-6", "SA-10"],
            "iso_27001": ["A.12.1.2", "A.14.2.2", "A.14.2.4"],
            "hitrust": ["09.b", "10.k"],
        },
        "runs": {
            "soc2": ["CC6.1", "CC8.1", "CC7.1"],
            "nist_800_53": ["CM-3", "CM-4", "SA-10", "SA-11"],
            "iso_27001": ["A.12.1.2", "A.14.2.2", "A.14.2.3"],
            "hitrust": ["09.b", "10.k", "10.m"],
        },
        "state_versions": {
            "soc2": ["CC6.1", "CC8.1"],
            "nist_800_53": ["CM-2", "CM-3", "CM-5"],
            "iso_27001": ["A.12.1.2", "A.14.2.2"],
            "hitrust": ["09.b", "10.k"],
        },
        "policies": {
            "soc2": ["CC5.2", "CC6.1", "CC6.6"],
            "nist_800_53": ["AC-3", "CM-7", "SA-10"],
            "iso_27001": ["A.9.1.2", "A.14.2.1"],
            "hitrust": ["01.c", "09.b"],
        },
        "variables": {
            "soc2": ["CC6.1", "CC6.6", "CC6.7"],
            "nist_800_53": ["CM-6", "SC-12", "SC-28"],
            "iso_27001": ["A.10.1.1", "A.14.2.4"],
            "hitrust": ["06.d", "09.b"],
        },
        "teams": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-3", "AC-6"],
            "iso_27001": ["A.9.2.1", "A.9.2.2", "A.9.4.1"],
            "hitrust": ["01.b", "01.c", "01.d"],
        },
    }

    def __init__(self, config: TerraformCloudCollectorConfig | None = None):
        """Initialize the Terraform Cloud collector."""
        self.config = config or TerraformCloudCollectorConfig()
        self._session: requests.Session | None = None

    @property
    def session(self) -> requests.Session:
        """Get or create an authenticated session."""
        if self._session is None:
            self._session = self._create_session()
        return self._session

    @property
    def base_url(self) -> str:
        """Get the Terraform Cloud API base URL."""
        return self.config.api_url

    def _create_session(self) -> requests.Session:
        """Create an authenticated session with retry logic."""
        session = requests.Session()

        # Configure retries
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        # Set default headers for JSON:API
        session.headers["Content-Type"] = "application/vnd.api+json"
        session.headers["Authorization"] = f"Bearer {self.config.api_token}"

        return session

    def _make_request(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make an authenticated API request."""
        url = f"{self.base_url}/{endpoint}"
        params = params or {}

        try:
            response = self.session.get(
                url,
                params=params,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.warning(f"API request failed: {endpoint} - {e}")
            raise

    def _paginate(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Paginate through Terraform Cloud API results using page-based pagination."""
        params = params or {}
        params["page[size]"] = self.config.page_size
        page_number = 1

        while True:
            params["page[number]"] = page_number

            try:
                data = self._make_request(endpoint, params=params)

                items = data.get("data", [])
                for item in items:
                    yield item

                # Check for next page
                meta = data.get("meta", {})
                pagination = meta.get("pagination", {})
                current_page = pagination.get("current-page", 1)
                total_pages = pagination.get("total-pages", 1)

                if current_page >= total_pages:
                    break

                page_number += 1

            except requests.RequestException:
                break

    def validate_credentials(self) -> bool:
        """Validate Terraform Cloud credentials."""
        if not self.config.api_token:
            raise ConfigurationError("Terraform Cloud api_token is required")

        if not self.config.organization:
            raise ConfigurationError("Terraform Cloud organization is required")

        try:
            # Test authentication by getting organization details
            data = self._make_request(f"organizations/{self.config.organization}")
            org_name = data.get("data", {}).get("attributes", {}).get("name", "Unknown")
            logger.info(f"Authenticated to Terraform Cloud organization: {org_name}")
            return True
        except requests.RequestException as e:
            if "401" in str(e) or "Unauthorized" in str(e):
                raise ConfigurationError("Invalid Terraform Cloud API token")
            if "404" in str(e) or "Not Found" in str(e):
                raise ConfigurationError(f"Organization not found: {self.config.organization}")
            raise ConfigurationError(f"Failed to validate Terraform Cloud credentials: {e}")

    def collect_evidence(
        self,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """Collect evidence from Terraform Cloud."""
        evidence_types = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        invalid_types = set(evidence_types) - set(self.SUPPORTED_EVIDENCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported evidence types: {invalid_types}")

        logger.info(f"Collecting Terraform Cloud evidence: {evidence_types}")
        evidence_items: list[Evidence] = []
        errors: list[str] = []

        collection_methods = {
            "workspaces": self._collect_workspaces_evidence,
            "runs": self._collect_runs_evidence,
            "state_versions": self._collect_state_versions_evidence,
            "policies": self._collect_policies_evidence,
            "variables": self._collect_variables_evidence,
            "teams": self._collect_teams_evidence,
        }

        for evidence_type in evidence_types:
            try:
                method = collection_methods.get(evidence_type)
                if method:
                    evidence = method()
                    if evidence:
                        evidence_items.append(evidence)
            except Exception as e:
                error_msg = f"Error collecting {evidence_type}: {e}"
                logger.error(error_msg)
                errors.append(error_msg)

        result = CollectionResult(
            platform=self.PLATFORM,
            evidence_items=evidence_items,
            errors=errors,
        )
        result.complete()
        return result

    def _collect_workspaces_evidence(self) -> Evidence:
        """Collect workspaces evidence."""
        logger.info("Collecting Terraform Cloud workspaces...")
        workspaces = []

        for workspace in self._paginate(f"organizations/{self.config.organization}/workspaces"):
            attrs = workspace.get("attributes", {})
            workspaces.append({
                "id": workspace.get("id"),
                "name": attrs.get("name"),
                "description": attrs.get("description"),
                "auto_apply": attrs.get("auto-apply", False),
                "file_triggers_enabled": attrs.get("file-triggers-enabled", True),
                "queue_all_runs": attrs.get("queue-all-runs", False),
                "speculative_enabled": attrs.get("speculative-enabled", True),
                "terraform_version": attrs.get("terraform-version"),
                "working_directory": attrs.get("working-directory"),
                "execution_mode": attrs.get("execution-mode"),
                "vcs_repo": attrs.get("vcs-repo"),
                "locked": attrs.get("locked", False),
                "resource_count": attrs.get("resource-count", 0),
                "created_at": attrs.get("created-at"),
                "updated_at": attrs.get("updated-at"),
                "environment": attrs.get("environment"),
            })

        # Categorize workspaces
        auto_apply_count = sum(1 for w in workspaces if w.get("auto_apply"))
        locked_count = sum(1 for w in workspaces if w.get("locked"))
        vcs_connected_count = sum(1 for w in workspaces if w.get("vcs_repo"))

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="workspaces",
            raw_data={
                "workspaces": workspaces,
                "total_count": len(workspaces),
                "auto_apply_count": auto_apply_count,
                "locked_count": locked_count,
                "vcs_connected_count": vcs_connected_count,
            },
            metadata={
                "source": "collector:terraform_cloud",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["workspaces"],
            },
        )

    def _collect_runs_evidence(self) -> Evidence:
        """Collect runs evidence."""
        logger.info("Collecting Terraform Cloud runs...")
        runs = []

        # Calculate date range
        since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)

        # Get workspaces first, then runs for each
        for workspace in self._paginate(f"organizations/{self.config.organization}/workspaces"):
            workspace_id = workspace.get("id")
            workspace_name = workspace.get("attributes", {}).get("name")

            try:
                for run in self._paginate(f"workspaces/{workspace_id}/runs"):
                    attrs = run.get("attributes", {})
                    created_at_str = attrs.get("created-at", "")

                    # Filter by date
                    if created_at_str:
                        try:
                            created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
                            if created_at < since:
                                continue
                        except (ValueError, TypeError):
                            pass

                    runs.append({
                        "id": run.get("id"),
                        "workspace_id": workspace_id,
                        "workspace_name": workspace_name,
                        "status": attrs.get("status"),
                        "source": attrs.get("source"),
                        "is_destroy": attrs.get("is-destroy", False),
                        "message": attrs.get("message"),
                        "has_changes": attrs.get("has-changes", False),
                        "auto_apply": attrs.get("auto-apply", False),
                        "plan_only": attrs.get("plan-only", False),
                        "created_at": attrs.get("created-at"),
                        "status_timestamps": attrs.get("status-timestamps", {}),
                    })
            except requests.RequestException as e:
                logger.warning(f"Error collecting runs for workspace {workspace_name}: {e}")

        # Categorize runs
        status_counts = {}
        for run in runs:
            status = run.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        successful_count = status_counts.get("applied", 0) + status_counts.get("planned_and_finished", 0)
        failed_count = status_counts.get("errored", 0) + status_counts.get("canceled", 0)

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="runs",
            raw_data={
                "runs": runs,
                "total_count": len(runs),
                "status_counts": status_counts,
                "successful_count": successful_count,
                "failed_count": failed_count,
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:terraform_cloud",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["runs"],
            },
        )

    def _collect_state_versions_evidence(self) -> Evidence:
        """Collect state versions evidence."""
        logger.info("Collecting Terraform Cloud state versions...")
        state_versions = []

        # Calculate date range
        since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)

        # Get workspaces first, then state versions for each
        for workspace in self._paginate(f"organizations/{self.config.organization}/workspaces"):
            workspace_id = workspace.get("id")
            workspace_name = workspace.get("attributes", {}).get("name")

            try:
                for state in self._paginate(f"workspaces/{workspace_id}/state-versions"):
                    attrs = state.get("attributes", {})
                    created_at_str = attrs.get("created-at", "")

                    # Filter by date
                    if created_at_str:
                        try:
                            created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
                            if created_at < since:
                                continue
                        except (ValueError, TypeError):
                            pass

                    state_versions.append({
                        "id": state.get("id"),
                        "workspace_id": workspace_id,
                        "workspace_name": workspace_name,
                        "serial": attrs.get("serial"),
                        "created_at": attrs.get("created-at"),
                        "size": attrs.get("size"),
                        "hosted_state_download_url": attrs.get("hosted-state-download-url") is not None,
                        "resources_processed": attrs.get("resources-processed", False),
                    })
            except requests.RequestException as e:
                logger.warning(f"Error collecting state versions for workspace {workspace_name}: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="state_versions",
            raw_data={
                "state_versions": state_versions,
                "total_count": len(state_versions),
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:terraform_cloud",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["state_versions"],
            },
        )

    def _collect_policies_evidence(self) -> Evidence:
        """Collect policies evidence."""
        logger.info("Collecting Terraform Cloud policies...")
        policy_sets = []
        policies = []

        # Get policy sets
        try:
            for policy_set in self._paginate(f"organizations/{self.config.organization}/policy-sets"):
                attrs = policy_set.get("attributes", {})
                policy_sets.append({
                    "id": policy_set.get("id"),
                    "name": attrs.get("name"),
                    "description": attrs.get("description"),
                    "global": attrs.get("global", False),
                    "kind": attrs.get("kind"),
                    "agent_enabled": attrs.get("agent-enabled", False),
                    "policy_count": attrs.get("policy-count", 0),
                    "workspace_count": attrs.get("workspace-count", 0),
                    "created_at": attrs.get("created-at"),
                    "updated_at": attrs.get("updated-at"),
                })

                # Get policies in this set
                try:
                    for policy in self._paginate(f"policy-sets/{policy_set.get('id')}/policies"):
                        policy_attrs = policy.get("attributes", {})
                        policies.append({
                            "id": policy.get("id"),
                            "policy_set_id": policy_set.get("id"),
                            "policy_set_name": attrs.get("name"),
                            "name": policy_attrs.get("name"),
                            "description": policy_attrs.get("description"),
                            "enforcement_level": policy_attrs.get("enforcement-level"),
                        })
                except requests.RequestException:
                    pass

        except requests.RequestException as e:
            logger.warning(f"Error collecting policies: {e}")

        # Categorize
        global_policy_sets = sum(1 for ps in policy_sets if ps.get("global"))
        enforcement_levels = {}
        for policy in policies:
            level = policy.get("enforcement_level", "unknown")
            enforcement_levels[level] = enforcement_levels.get(level, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="policies",
            raw_data={
                "policy_sets": policy_sets,
                "policies": policies,
                "policy_set_count": len(policy_sets),
                "policy_count": len(policies),
                "global_policy_sets": global_policy_sets,
                "enforcement_levels": enforcement_levels,
            },
            metadata={
                "source": "collector:terraform_cloud",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["policies"],
            },
        )

    def _collect_variables_evidence(self) -> Evidence:
        """Collect variables evidence."""
        logger.info("Collecting Terraform Cloud variables...")
        variable_sets = []
        workspace_variables = []

        # Get variable sets
        try:
            for var_set in self._paginate(f"organizations/{self.config.organization}/varsets"):
                attrs = var_set.get("attributes", {})
                var_set_vars = []

                # Get variables in this set
                try:
                    for var in self._paginate(f"varsets/{var_set.get('id')}/relationships/vars"):
                        var_attrs = var.get("attributes", {})
                        var_set_vars.append({
                            "key": var_attrs.get("key"),
                            "sensitive": var_attrs.get("sensitive", False),
                            "category": var_attrs.get("category"),
                            "hcl": var_attrs.get("hcl", False),
                        })
                except requests.RequestException:
                    pass

                variable_sets.append({
                    "id": var_set.get("id"),
                    "name": attrs.get("name"),
                    "description": attrs.get("description"),
                    "global": attrs.get("global", False),
                    "variable_count": len(var_set_vars),
                    "variables": var_set_vars,
                })
        except requests.RequestException as e:
            logger.warning(f"Error collecting variable sets: {e}")

        # Get workspace variables
        for workspace in self._paginate(f"organizations/{self.config.organization}/workspaces"):
            workspace_id = workspace.get("id")
            workspace_name = workspace.get("attributes", {}).get("name")

            try:
                for var in self._paginate(f"workspaces/{workspace_id}/vars"):
                    attrs = var.get("attributes", {})
                    workspace_variables.append({
                        "id": var.get("id"),
                        "workspace_id": workspace_id,
                        "workspace_name": workspace_name,
                        "key": attrs.get("key"),
                        "sensitive": attrs.get("sensitive", False),
                        "category": attrs.get("category"),
                        "hcl": attrs.get("hcl", False),
                    })
            except requests.RequestException:
                pass

        # Count sensitive variables
        sensitive_var_set_vars = sum(
            1 for vs in variable_sets
            for v in vs.get("variables", [])
            if v.get("sensitive")
        )
        sensitive_workspace_vars = sum(1 for v in workspace_variables if v.get("sensitive"))

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="variables",
            raw_data={
                "variable_sets": variable_sets,
                "workspace_variables": workspace_variables,
                "variable_set_count": len(variable_sets),
                "workspace_variable_count": len(workspace_variables),
                "sensitive_variable_set_vars": sensitive_var_set_vars,
                "sensitive_workspace_vars": sensitive_workspace_vars,
            },
            metadata={
                "source": "collector:terraform_cloud",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["variables"],
            },
        )

    def _collect_teams_evidence(self) -> Evidence:
        """Collect teams evidence."""
        logger.info("Collecting Terraform Cloud teams...")
        teams = []

        try:
            for team in self._paginate(f"organizations/{self.config.organization}/teams"):
                attrs = team.get("attributes", {})
                permissions = attrs.get("organization-access", {})

                # Get team members
                members = []
                try:
                    for membership in self._paginate(f"teams/{team.get('id')}/organization-memberships"):
                        user = membership.get("relationships", {}).get("user", {}).get("data", {})
                        members.append({
                            "user_id": user.get("id"),
                        })
                except requests.RequestException:
                    pass

                teams.append({
                    "id": team.get("id"),
                    "name": attrs.get("name"),
                    "visibility": attrs.get("visibility"),
                    "sso_team_id": attrs.get("sso-team-id"),
                    "member_count": len(members),
                    "permissions": {
                        "manage_policies": permissions.get("manage-policies", False),
                        "manage_workspaces": permissions.get("manage-workspaces", False),
                        "manage_vcs_settings": permissions.get("manage-vcs-settings", False),
                        "manage_providers": permissions.get("manage-providers", False),
                        "manage_modules": permissions.get("manage-modules", False),
                        "manage_run_tasks": permissions.get("manage-run-tasks", False),
                        "manage_membership": permissions.get("manage-membership", False),
                    },
                })
        except requests.RequestException as e:
            logger.warning(f"Error collecting teams: {e}")

        # Count by visibility
        visibility_counts = {}
        for team in teams:
            vis = team.get("visibility", "unknown")
            visibility_counts[vis] = visibility_counts.get(vis, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="teams",
            raw_data={
                "teams": teams,
                "total_count": len(teams),
                "visibility_counts": visibility_counts,
            },
            metadata={
                "source": "collector:terraform_cloud",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["teams"],
            },
        )

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """Collect resources from Terraform Cloud for compliance checks."""
        resource_types = resource_types or self.SUPPORTED_RESOURCE_TYPES
        invalid_types = set(resource_types) - set(self.SUPPORTED_RESOURCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported resource types: {invalid_types}")

        logger.info(f"Collecting Terraform Cloud resources: {resource_types}")
        resources: list[Resource] = []

        collection_methods = {
            "terraform_workspace": self._collect_workspace_resources,
            "terraform_run": self._collect_run_resources,
            "terraform_policy_set": self._collect_policy_set_resources,
            "terraform_team": self._collect_team_resources,
        }

        for resource_type in resource_types:
            method = collection_methods.get(resource_type)
            if method:
                resources.extend(method())

        return resources

    def _collect_workspace_resources(self) -> list[Resource]:
        """Collect workspace resources."""
        logger.info("Collecting Terraform Cloud workspace resources...")
        resources = []

        for workspace in self._paginate(f"organizations/{self.config.organization}/workspaces"):
            attrs = workspace.get("attributes", {})
            resources.append(
                Resource(
                    id=str(workspace.get("id", "")),
                    type="terraform_workspace",
                    provider="terraform_cloud",
                    region="global",
                    name=attrs.get("name", "Unknown"),
                    tags={
                        "auto_apply": str(attrs.get("auto-apply", False)).lower(),
                        "locked": str(attrs.get("locked", False)).lower(),
                        "execution_mode": attrs.get("execution-mode", "remote"),
                        "vcs_connected": str(attrs.get("vcs-repo") is not None).lower(),
                    },
                    metadata={
                        "id": workspace.get("id"),
                        "name": attrs.get("name"),
                        "description": attrs.get("description"),
                        "auto_apply": attrs.get("auto-apply", False),
                        "locked": attrs.get("locked", False),
                        "terraform_version": attrs.get("terraform-version"),
                        "execution_mode": attrs.get("execution-mode"),
                        "resource_count": attrs.get("resource-count", 0),
                    },
                    raw_data=workspace,
                )
            )

        return resources

    def _collect_run_resources(self) -> list[Resource]:
        """Collect run resources."""
        logger.info("Collecting Terraform Cloud run resources...")
        resources = []

        # Calculate date range
        since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)

        for workspace in self._paginate(f"organizations/{self.config.organization}/workspaces"):
            workspace_id = workspace.get("id")
            workspace_name = workspace.get("attributes", {}).get("name")

            try:
                for run in self._paginate(f"workspaces/{workspace_id}/runs"):
                    attrs = run.get("attributes", {})
                    created_at_str = attrs.get("created-at", "")

                    # Filter by date
                    if created_at_str:
                        try:
                            created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
                            if created_at < since:
                                continue
                        except (ValueError, TypeError):
                            pass

                    resources.append(
                        Resource(
                            id=str(run.get("id", "")),
                            type="terraform_run",
                            provider="terraform_cloud",
                            region="global",
                            name=f"{workspace_name}/{run.get('id', 'Unknown')}",
                            tags={
                                "status": attrs.get("status", "unknown"),
                                "source": attrs.get("source", "unknown"),
                                "is_destroy": str(attrs.get("is-destroy", False)).lower(),
                                "workspace_id": workspace_id,
                            },
                            metadata={
                                "id": run.get("id"),
                                "workspace_id": workspace_id,
                                "workspace_name": workspace_name,
                                "status": attrs.get("status"),
                                "source": attrs.get("source"),
                                "is_destroy": attrs.get("is-destroy", False),
                                "has_changes": attrs.get("has-changes", False),
                                "created_at": attrs.get("created-at"),
                            },
                            raw_data=run,
                        )
                    )
            except requests.RequestException:
                pass

        return resources

    def _collect_policy_set_resources(self) -> list[Resource]:
        """Collect policy set resources."""
        logger.info("Collecting Terraform Cloud policy set resources...")
        resources = []

        try:
            for policy_set in self._paginate(f"organizations/{self.config.organization}/policy-sets"):
                attrs = policy_set.get("attributes", {})
                resources.append(
                    Resource(
                        id=str(policy_set.get("id", "")),
                        type="terraform_policy_set",
                        provider="terraform_cloud",
                        region="global",
                        name=attrs.get("name", "Unknown"),
                        tags={
                            "global": str(attrs.get("global", False)).lower(),
                            "kind": attrs.get("kind", "sentinel"),
                            "policy_count": str(attrs.get("policy-count", 0)),
                        },
                        metadata={
                            "id": policy_set.get("id"),
                            "name": attrs.get("name"),
                            "description": attrs.get("description"),
                            "global": attrs.get("global", False),
                            "kind": attrs.get("kind"),
                            "policy_count": attrs.get("policy-count", 0),
                            "workspace_count": attrs.get("workspace-count", 0),
                        },
                        raw_data=policy_set,
                    )
                )
        except requests.RequestException as e:
            logger.warning(f"Error collecting policy set resources: {e}")

        return resources

    def _collect_team_resources(self) -> list[Resource]:
        """Collect team resources."""
        logger.info("Collecting Terraform Cloud team resources...")
        resources = []

        try:
            for team in self._paginate(f"organizations/{self.config.organization}/teams"):
                attrs = team.get("attributes", {})
                permissions = attrs.get("organization-access", {})

                resources.append(
                    Resource(
                        id=str(team.get("id", "")),
                        type="terraform_team",
                        provider="terraform_cloud",
                        region="global",
                        name=attrs.get("name", "Unknown"),
                        tags={
                            "visibility": attrs.get("visibility", "organization"),
                            "manage_workspaces": str(permissions.get("manage-workspaces", False)).lower(),
                            "manage_policies": str(permissions.get("manage-policies", False)).lower(),
                        },
                        metadata={
                            "id": team.get("id"),
                            "name": attrs.get("name"),
                            "visibility": attrs.get("visibility"),
                            "permissions": permissions,
                        },
                        raw_data=team,
                    )
                )
        except requests.RequestException as e:
            logger.warning(f"Error collecting team resources: {e}")

        return resources
