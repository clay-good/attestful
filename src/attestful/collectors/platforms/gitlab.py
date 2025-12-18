"""
GitLab collector for Attestful.

Collects source control, CI/CD, and security evidence from GitLab
for compliance frameworks including SOC 2, NIST 800-53, and ISO 27001.
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
class GitLabCollectorConfig:
    """Configuration for GitLab collector."""

    # Authentication
    token: str = ""

    # Instance settings
    base_url: str = "https://gitlab.com"  # Can be self-hosted instance

    # Scope
    group_id: str = ""  # GitLab group ID or path
    include_subgroups: bool = True

    # API settings
    timeout: int = 30
    max_retries: int = 3
    page_size: int = 100

    # Collection options
    include_archived: bool = False
    days_of_history: int = 90


class GitLabCollector(BaseCollector):
    """
    GitLab collector for source control and DevOps evidence.

    Collects evidence related to:
    - Projects (repositories) and configurations
    - Protected branches and merge request approvals
    - CI/CD pipelines and security scanning
    - Group and project members and permissions
    - Merge requests and code reviews
    - Security vulnerabilities and SAST/DAST results
    - Audit events (group-level)
    - Deploy keys and tokens

    Evidence Types:
    - projects: All projects with configurations
    - protected_branches: Branch protection rules
    - merge_requests: Recent merge requests and approvals
    - pipelines: CI/CD pipeline runs and security jobs
    - members: Group and project members with access levels
    - vulnerabilities: Security scanning results
    - audit_events: Group audit log events
    - deploy_keys: Deploy keys inventory

    Resource Types:
    - gitlab_project: Project resources
    - gitlab_user: User/member resources
    - gitlab_group: Group resources
    - gitlab_runner: CI/CD runner resources

    Compliance Mappings:
    - SOC 2 CC8 (Change Management): Protected branches, merge requests, approvals
    - NIST 800-53 CM-3 (Configuration Change Control): Pipelines, audit events
    - NIST 800-53 SA-11 (Developer Testing): Security scanning, SAST/DAST
    - ISO 27001 A.12.1 (Operational Security): CI/CD pipelines, deploy keys

    Example:
        collector = GitLabCollector(
            config=GitLabCollectorConfig(
                token="glpat-...",
                group_id="my-group",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["projects", "protected_branches", "vulnerabilities"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["gitlab_project"]
        )
    """

    PLATFORM = "gitlab"

    metadata = CollectorMetadata(
        name="GitLabCollector",
        platform="gitlab",
        description="Collects source control, CI/CD, and security evidence from GitLab",
        mode=CollectorMode.BOTH,
        resource_types=["gitlab_project", "gitlab_user", "gitlab_group", "gitlab_runner"],
        evidence_types=[
            "projects",
            "protected_branches",
            "merge_requests",
            "pipelines",
            "members",
            "vulnerabilities",
            "audit_events",
            "deploy_keys",
        ],
    )

    SUPPORTED_RESOURCE_TYPES = [
        "gitlab_project",
        "gitlab_user",
        "gitlab_group",
        "gitlab_runner",
    ]
    SUPPORTED_EVIDENCE_TYPES = [
        "projects",
        "protected_branches",
        "merge_requests",
        "pipelines",
        "members",
        "vulnerabilities",
        "audit_events",
        "deploy_keys",
    ]

    def __init__(
        self,
        config: GitLabCollectorConfig | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize GitLab collector.

        Args:
            config: GitLab collector configuration.
            **kwargs: Additional arguments passed to BaseCollector.
        """
        super().__init__(**kwargs)
        self.config = config or GitLabCollectorConfig()
        self._session: requests.Session | None = None

    @property
    def api_url(self) -> str:
        """Get the GitLab API base URL."""
        base = self.config.base_url.rstrip("/")
        return f"{base}/api/v4"

    def _get_session(self) -> requests.Session:
        """Get or create requests session with retry logic."""
        if self._session is None:
            self._session = requests.Session()

            # Set up retries
            retry = Retry(
                total=self.config.max_retries,
                backoff_factor=0.5,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry)
            self._session.mount("https://", adapter)
            self._session.mount("http://", adapter)  # For self-hosted instances

            # Set headers
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            if self.config.token:
                headers["PRIVATE-TOKEN"] = self.config.token

            self._session.headers.update(headers)

        return self._session

    def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs: Any,
    ) -> requests.Response:
        """Make an API request with rate limiting."""
        self._rate_limit()

        session = self._get_session()
        url = f"{self.api_url}/{endpoint.lstrip('/')}"

        kwargs.setdefault("timeout", self.config.timeout)

        response = session.request(method, url, **kwargs)

        # Handle rate limiting
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 60))
            logger.warning(f"Rate limited, waiting {retry_after}s")
            import time
            time.sleep(retry_after)
            return self._request(method, endpoint, **kwargs)

        response.raise_for_status()
        return response

    def _paginate(self, endpoint: str, **kwargs: Any) -> Iterator[dict[str, Any]]:
        """Paginate through API results using keyset or offset pagination."""
        params = kwargs.pop("params", {})
        params.setdefault("per_page", self.config.page_size)

        page = 1
        while True:
            params["page"] = page
            response = self._request("GET", endpoint, params=params, **kwargs)
            items = response.json()

            if not items:
                break

            for item in items:
                yield item

            # Check for more pages
            total_pages = int(response.headers.get("X-Total-Pages", 1))
            if page >= total_pages:
                break

            page += 1

    def validate_credentials(self) -> bool:
        """Validate GitLab API credentials."""
        try:
            response = self._request("GET", "/user")
            user = response.json()
            logger.info(f"Validated GitLab credentials for {user.get('username')}")
            return True
        except Exception as e:
            logger.error(f"GitLab credential validation failed: {e}")
            return False

    def _get_group_projects(self) -> Iterator[dict[str, Any]]:
        """Get all projects in the configured group."""
        if not self.config.group_id:
            # If no group specified, get all accessible projects
            yield from self._paginate("/projects", params={"membership": True})
            return

        # URL-encode the group path if needed
        group_id = self.config.group_id.replace("/", "%2F")

        params = {
            "include_subgroups": str(self.config.include_subgroups).lower(),
            "archived": str(self.config.include_archived).lower(),
        }

        yield from self._paginate(f"/groups/{group_id}/projects", params=params)

    # =========================================================================
    # Resource Collection Methods
    # =========================================================================

    def collect_resources(
        self,
        *,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """
        Collect GitLab resources.

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

    def _collect_gitlab_project(self) -> Iterator[Resource]:
        """Collect GitLab projects as resources."""
        for project in self._get_group_projects():
            yield Resource(
                id=str(project["id"]),
                type="gitlab_project",
                provider="gitlab",
                region="global",
                name=project.get("path_with_namespace", project.get("name", str(project["id"]))),
                tags={
                    "visibility": project.get("visibility", ""),
                    "archived": str(project.get("archived", False)),
                    "default_branch": project.get("default_branch", ""),
                },
                metadata={
                    "description": project.get("description", ""),
                    "web_url": project.get("web_url", ""),
                    "created_at": project.get("created_at"),
                    "last_activity_at": project.get("last_activity_at"),
                    "namespace": project.get("namespace", {}).get("full_path", ""),
                    "merge_requests_enabled": project.get("merge_requests_enabled", True),
                    "issues_enabled": project.get("issues_enabled", True),
                    "wiki_enabled": project.get("wiki_enabled", True),
                    "jobs_enabled": project.get("jobs_enabled", True),
                    "container_registry_enabled": project.get("container_registry_enabled", False),
                },
                raw_data=project,
            )

    def _collect_gitlab_user(self) -> Iterator[Resource]:
        """Collect GitLab users as resources."""
        if self.config.group_id:
            group_id = self.config.group_id.replace("/", "%2F")
            endpoint = f"/groups/{group_id}/members/all"
        else:
            # Fallback to project members
            for project in self._get_group_projects():
                try:
                    for member in self._paginate(f"/projects/{project['id']}/members/all"):
                        yield Resource(
                            id=str(member["id"]),
                            type="gitlab_user",
                            provider="gitlab",
                            region="global",
                            name=member.get("username", str(member["id"])),
                            tags={
                                "access_level": str(member.get("access_level", 0)),
                                "state": member.get("state", ""),
                            },
                            metadata={
                                "name": member.get("name", ""),
                                "email": member.get("email", ""),
                                "web_url": member.get("web_url", ""),
                                "expires_at": member.get("expires_at"),
                            },
                            raw_data=member,
                        )
                except Exception as e:
                    logger.warning(f"Failed to get members for project {project.get('name')}: {e}")
            return

        try:
            for member in self._paginate(endpoint):
                yield Resource(
                    id=str(member["id"]),
                    type="gitlab_user",
                    provider="gitlab",
                    region="global",
                    name=member.get("username", str(member["id"])),
                    tags={
                        "access_level": str(member.get("access_level", 0)),
                        "state": member.get("state", ""),
                    },
                    metadata={
                        "name": member.get("name", ""),
                        "email": member.get("email", ""),
                        "web_url": member.get("web_url", ""),
                        "expires_at": member.get("expires_at"),
                    },
                    raw_data=member,
                )
        except Exception as e:
            logger.error(f"Failed to collect group members: {e}")

    def _collect_gitlab_group(self) -> Iterator[Resource]:
        """Collect GitLab groups as resources."""
        if self.config.group_id:
            group_id = self.config.group_id.replace("/", "%2F")
            try:
                response = self._request("GET", f"/groups/{group_id}")
                group = response.json()
                yield Resource(
                    id=str(group["id"]),
                    type="gitlab_group",
                    provider="gitlab",
                    region="global",
                    name=group.get("full_path", group.get("name", str(group["id"]))),
                    tags={
                        "visibility": group.get("visibility", ""),
                    },
                    metadata={
                        "description": group.get("description", ""),
                        "web_url": group.get("web_url", ""),
                        "created_at": group.get("created_at"),
                        "projects_count": group.get("projects", []),
                    },
                    raw_data=group,
                )

                # Also collect subgroups
                if self.config.include_subgroups:
                    for subgroup in self._paginate(f"/groups/{group_id}/subgroups"):
                        yield Resource(
                            id=str(subgroup["id"]),
                            type="gitlab_group",
                            provider="gitlab",
                            region="global",
                            name=subgroup.get("full_path", subgroup.get("name", str(subgroup["id"]))),
                            tags={
                                "visibility": subgroup.get("visibility", ""),
                                "parent_id": str(group["id"]),
                            },
                            metadata={
                                "description": subgroup.get("description", ""),
                                "web_url": subgroup.get("web_url", ""),
                            },
                            raw_data=subgroup,
                        )
            except Exception as e:
                logger.error(f"Failed to collect group: {e}")
        else:
            # Get all accessible groups
            for group in self._paginate("/groups"):
                yield Resource(
                    id=str(group["id"]),
                    type="gitlab_group",
                    provider="gitlab",
                    region="global",
                    name=group.get("full_path", group.get("name", str(group["id"]))),
                    tags={
                        "visibility": group.get("visibility", ""),
                    },
                    metadata={
                        "description": group.get("description", ""),
                        "web_url": group.get("web_url", ""),
                    },
                    raw_data=group,
                )

    def _collect_gitlab_runner(self) -> Iterator[Resource]:
        """Collect GitLab CI/CD runners as resources."""
        if self.config.group_id:
            group_id = self.config.group_id.replace("/", "%2F")
            try:
                for runner in self._paginate(f"/groups/{group_id}/runners"):
                    yield Resource(
                        id=str(runner["id"]),
                        type="gitlab_runner",
                        provider="gitlab",
                        region="global",
                        name=runner.get("description", f"runner-{runner['id']}"),
                        tags={
                            "status": runner.get("status", ""),
                            "runner_type": runner.get("runner_type", ""),
                            "is_shared": str(runner.get("is_shared", False)),
                            "active": str(runner.get("active", True)),
                        },
                        metadata={
                            "ip_address": runner.get("ip_address"),
                            "contacted_at": runner.get("contacted_at"),
                            "tag_list": runner.get("tag_list", []),
                            "version": runner.get("version"),
                            "online": runner.get("online", False),
                        },
                        raw_data=runner,
                    )
            except Exception as e:
                logger.warning(f"Failed to collect group runners: {e}")
        else:
            # Try to get runners from each project
            for project in self._get_group_projects():
                try:
                    for runner in self._paginate(f"/projects/{project['id']}/runners"):
                        yield Resource(
                            id=str(runner["id"]),
                            type="gitlab_runner",
                            provider="gitlab",
                            region="global",
                            name=runner.get("description", f"runner-{runner['id']}"),
                            tags={
                                "status": runner.get("status", ""),
                                "active": str(runner.get("active", True)),
                            },
                            metadata={
                                "project": project.get("path_with_namespace"),
                            },
                            raw_data=runner,
                        )
                except Exception as e:
                    logger.debug(f"Failed to get runners for project {project.get('name')}: {e}")

    # =========================================================================
    # Evidence Collection Methods
    # =========================================================================

    def collect_evidence(
        self,
        *,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """
        Collect GitLab evidence for compliance audits.

        Args:
            evidence_types: List of evidence types to collect.

        Returns:
            CollectionResult with collected evidence.
        """
        types_to_collect = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        evidence_items: list[Evidence] = []
        errors: list[str] = []

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
                    evidence_items.append(evidence)
                    logger.debug(f"Collected {evidence_type} evidence")
            except Exception as e:
                error_msg = f"Failed to collect {evidence_type}: {e}"
                logger.error(error_msg)
                errors.append(error_msg)

        result = CollectionResult(
            platform=self.PLATFORM,
            evidence_items=evidence_items,
            errors=errors,
        )
        result.complete()
        return result

    def _evidence_projects(self) -> Evidence:
        """Collect all GitLab projects with configurations."""
        projects = list(self._get_group_projects())

        # Analyze project configurations
        visibility_counts: dict[str, int] = {}
        projects_with_issues: list[dict[str, Any]] = []

        for project in projects:
            visibility = project.get("visibility", "unknown")
            visibility_counts[visibility] = visibility_counts.get(visibility, 0) + 1

            # Check for security concerns
            issues = []
            if project.get("visibility") == "public":
                issues.append("Public visibility")
            if not project.get("merge_requests_enabled"):
                issues.append("Merge requests disabled")
            if project.get("jobs_enabled") and not project.get("only_allow_merge_if_pipeline_succeeds"):
                issues.append("No CI requirement for merges")

            if issues:
                projects_with_issues.append({
                    "id": project["id"],
                    "name": project.get("path_with_namespace"),
                    "issues": issues,
                })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="projects",
            raw_data={
                "projects": projects,
                "total_count": len(projects),
                "visibility_breakdown": visibility_counts,
                "projects_with_issues": projects_with_issues,
                "issues_count": len(projects_with_issues),
            },
            metadata={
                "source": "collector:gitlab",
                "collection_method": "automated",
                "compliance_controls": ["SOC2:CC8.1", "NIST:CM-3", "ISO27001:A.12.1"],
            },
        )

    def _evidence_protected_branches(self) -> Evidence:
        """Collect protected branch configurations."""
        protected_branches_data: list[dict[str, Any]] = []
        projects_without_protection: list[dict[str, Any]] = []

        for project in self._get_group_projects():
            project_id = project["id"]
            project_name = project.get("path_with_namespace", str(project_id))

            try:
                branches = list(self._paginate(f"/projects/{project_id}/protected_branches"))

                if not branches:
                    projects_without_protection.append({
                        "id": project_id,
                        "name": project_name,
                        "default_branch": project.get("default_branch"),
                    })
                else:
                    for branch in branches:
                        protected_branches_data.append({
                            "project_id": project_id,
                            "project_name": project_name,
                            "branch_name": branch.get("name"),
                            "push_access_levels": branch.get("push_access_levels", []),
                            "merge_access_levels": branch.get("merge_access_levels", []),
                            "allow_force_push": branch.get("allow_force_push", False),
                            "code_owner_approval_required": branch.get("code_owner_approval_required", False),
                        })
            except Exception as e:
                logger.warning(f"Failed to get protected branches for {project_name}: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="protected_branches",
            raw_data={
                "protected_branches": protected_branches_data,
                "total_protected": len(protected_branches_data),
                "projects_without_protection": projects_without_protection,
                "unprotected_count": len(projects_without_protection),
            },
            metadata={
                "source": "collector:gitlab",
                "collection_method": "automated",
                "compliance_controls": ["SOC2:CC8.1", "NIST:CM-5", "ISO27001:A.12.5"],
            },
        )

    def _evidence_merge_requests(self) -> Evidence:
        """Collect recent merge requests and approval data."""
        since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        merge_requests_data: list[dict[str, Any]] = []
        by_state: dict[str, int] = {}

        for project in self._get_group_projects():
            project_id = project["id"]
            project_name = project.get("path_with_namespace", str(project_id))

            try:
                params = {
                    "updated_after": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "state": "all",
                }
                for mr in self._paginate(f"/projects/{project_id}/merge_requests", params=params):
                    state = mr.get("state", "unknown")
                    by_state[state] = by_state.get(state, 0) + 1

                    merge_requests_data.append({
                        "id": mr["id"],
                        "iid": mr["iid"],
                        "project": project_name,
                        "title": mr.get("title"),
                        "state": state,
                        "source_branch": mr.get("source_branch"),
                        "target_branch": mr.get("target_branch"),
                        "author": mr.get("author", {}).get("username"),
                        "merged_by": mr.get("merged_by", {}).get("username") if mr.get("merged_by") else None,
                        "created_at": mr.get("created_at"),
                        "merged_at": mr.get("merged_at"),
                        "has_conflicts": mr.get("has_conflicts", False),
                        "user_notes_count": mr.get("user_notes_count", 0),
                        "upvotes": mr.get("upvotes", 0),
                        "downvotes": mr.get("downvotes", 0),
                    })

                    # Limit per project to avoid overwhelming data
                    if len([m for m in merge_requests_data if m["project"] == project_name]) >= 100:
                        break
            except Exception as e:
                logger.warning(f"Failed to get MRs for {project_name}: {e}")

        # Calculate review metrics
        reviewed_mrs = sum(1 for mr in merge_requests_data if mr.get("user_notes_count", 0) > 0)
        review_rate = (reviewed_mrs / len(merge_requests_data) * 100) if merge_requests_data else 0

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="merge_requests",
            raw_data={
                "merge_requests": merge_requests_data,
                "total_count": len(merge_requests_data),
                "by_state": by_state,
                "review_metrics": {
                    "with_comments": reviewed_mrs,
                    "review_rate_percent": round(review_rate, 2),
                },
                "period_start": since.isoformat(),
                "period_end": datetime.now(timezone.utc).isoformat(),
            },
            metadata={
                "source": "collector:gitlab",
                "collection_method": "automated",
                "compliance_controls": ["SOC2:CC8.1", "NIST:CM-3", "ISO27001:A.14.2"],
            },
        )

    def _evidence_pipelines(self) -> Evidence:
        """Collect CI/CD pipeline data."""
        since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        pipelines_data: list[dict[str, Any]] = []
        by_status: dict[str, int] = {}
        security_jobs: list[dict[str, Any]] = []

        for project in self._get_group_projects():
            project_id = project["id"]
            project_name = project.get("path_with_namespace", str(project_id))

            try:
                params = {"updated_after": since.strftime("%Y-%m-%dT%H:%M:%SZ")}
                for pipeline in self._paginate(f"/projects/{project_id}/pipelines", params=params):
                    status = pipeline.get("status", "unknown")
                    by_status[status] = by_status.get(status, 0) + 1

                    pipeline_info = {
                        "id": pipeline["id"],
                        "project": project_name,
                        "ref": pipeline.get("ref"),
                        "status": status,
                        "source": pipeline.get("source"),
                        "created_at": pipeline.get("created_at"),
                        "updated_at": pipeline.get("updated_at"),
                        "web_url": pipeline.get("web_url"),
                    }

                    # Get pipeline jobs to check for security scanning
                    try:
                        jobs = list(self._paginate(f"/projects/{project_id}/pipelines/{pipeline['id']}/jobs"))
                        job_names = [j.get("name", "").lower() for j in jobs]

                        # Identify security-related jobs
                        security_keywords = ["sast", "dast", "dependency", "container", "secret", "security", "scan"]
                        sec_jobs = [j for j in jobs if any(kw in j.get("name", "").lower() for kw in security_keywords)]

                        if sec_jobs:
                            pipeline_info["security_jobs"] = [
                                {"name": j.get("name"), "status": j.get("status")}
                                for j in sec_jobs
                            ]
                            security_jobs.extend([{
                                "pipeline_id": pipeline["id"],
                                "project": project_name,
                                "job_name": j.get("name"),
                                "status": j.get("status"),
                            } for j in sec_jobs])

                    except Exception:
                        pass

                    pipelines_data.append(pipeline_info)

                    # Limit per project
                    if len([p for p in pipelines_data if p["project"] == project_name]) >= 50:
                        break
            except Exception as e:
                logger.warning(f"Failed to get pipelines for {project_name}: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="pipelines",
            raw_data={
                "pipelines": pipelines_data,
                "total_count": len(pipelines_data),
                "by_status": by_status,
                "security_jobs": security_jobs,
                "security_jobs_count": len(security_jobs),
                "period_start": since.isoformat(),
                "period_end": datetime.now(timezone.utc).isoformat(),
            },
            metadata={
                "source": "collector:gitlab",
                "collection_method": "automated",
                "compliance_controls": ["SOC2:CC7.1", "NIST:SA-11", "ISO27001:A.14.2"],
            },
        )

    def _evidence_members(self) -> Evidence:
        """Collect group and project members with access levels."""
        members_data: list[dict[str, Any]] = []
        by_access_level: dict[str, int] = {}
        high_privilege_users: list[dict[str, Any]] = []

        # GitLab access levels
        access_level_names = {
            0: "None",
            5: "Minimal",
            10: "Guest",
            20: "Reporter",
            30: "Developer",
            40: "Maintainer",
            50: "Owner",
        }

        seen_users: set[int] = set()

        if self.config.group_id:
            group_id = self.config.group_id.replace("/", "%2F")
            try:
                for member in self._paginate(f"/groups/{group_id}/members/all"):
                    if member["id"] in seen_users:
                        continue
                    seen_users.add(member["id"])

                    access_level = member.get("access_level", 0)
                    access_name = access_level_names.get(access_level, f"Level {access_level}")
                    by_access_level[access_name] = by_access_level.get(access_name, 0) + 1

                    member_info = {
                        "id": member["id"],
                        "username": member.get("username"),
                        "name": member.get("name"),
                        "state": member.get("state"),
                        "access_level": access_level,
                        "access_level_name": access_name,
                        "expires_at": member.get("expires_at"),
                        "group_saml_identity": member.get("group_saml_identity"),
                    }
                    members_data.append(member_info)

                    # Track high-privilege users (Maintainer+)
                    if access_level >= 40:
                        high_privilege_users.append(member_info)
            except Exception as e:
                logger.warning(f"Failed to get group members: {e}")

        # Also collect from projects if no group or to supplement
        for project in self._get_group_projects():
            project_id = project["id"]
            project_name = project.get("path_with_namespace", str(project_id))

            try:
                for member in self._paginate(f"/projects/{project_id}/members/all"):
                    if member["id"] in seen_users:
                        continue
                    seen_users.add(member["id"])

                    access_level = member.get("access_level", 0)
                    access_name = access_level_names.get(access_level, f"Level {access_level}")
                    by_access_level[access_name] = by_access_level.get(access_name, 0) + 1

                    member_info = {
                        "id": member["id"],
                        "username": member.get("username"),
                        "name": member.get("name"),
                        "state": member.get("state"),
                        "access_level": access_level,
                        "access_level_name": access_name,
                        "project": project_name,
                    }
                    members_data.append(member_info)

                    if access_level >= 40:
                        high_privilege_users.append(member_info)
            except Exception as e:
                logger.debug(f"Failed to get members for {project_name}: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="members",
            raw_data={
                "members": members_data,
                "total_count": len(members_data),
                "by_access_level": by_access_level,
                "high_privilege_users": high_privilege_users,
                "high_privilege_count": len(high_privilege_users),
            },
            metadata={
                "source": "collector:gitlab",
                "collection_method": "automated",
                "compliance_controls": ["SOC2:CC6.1", "NIST:AC-2", "ISO27001:A.9.2"],
            },
        )

    def _evidence_vulnerabilities(self) -> Evidence:
        """Collect security vulnerabilities from GitLab security scanning."""
        vulnerabilities_data: list[dict[str, Any]] = []
        by_severity: dict[str, int] = {}
        by_state: dict[str, int] = {}

        for project in self._get_group_projects():
            project_id = project["id"]
            project_name = project.get("path_with_namespace", str(project_id))

            try:
                for vuln in self._paginate(f"/projects/{project_id}/vulnerabilities"):
                    severity = vuln.get("severity", "unknown")
                    state = vuln.get("state", "unknown")

                    by_severity[severity] = by_severity.get(severity, 0) + 1
                    by_state[state] = by_state.get(state, 0) + 1

                    vulnerabilities_data.append({
                        "id": vuln["id"],
                        "project": project_name,
                        "title": vuln.get("title"),
                        "severity": severity,
                        "state": state,
                        "scanner": vuln.get("scanner", {}).get("name"),
                        "detected_at": vuln.get("created_at"),
                        "dismissed_at": vuln.get("dismissed_at"),
                        "resolved_at": vuln.get("resolved_at"),
                        "location": vuln.get("location", {}),
                    })
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 403:
                    logger.debug(f"Vulnerability API not available for {project_name} (requires Ultimate)")
                else:
                    logger.warning(f"Failed to get vulnerabilities for {project_name}: {e}")
            except Exception as e:
                logger.warning(f"Failed to get vulnerabilities for {project_name}: {e}")

        # Calculate risk summary
        critical_high = sum(by_severity.get(s, 0) for s in ["critical", "high"])

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="vulnerabilities",
            raw_data={
                "vulnerabilities": vulnerabilities_data,
                "total_count": len(vulnerabilities_data),
                "by_severity": by_severity,
                "by_state": by_state,
                "risk_summary": {
                    "critical_high_count": critical_high,
                    "open_count": by_state.get("detected", 0),
                    "resolved_count": by_state.get("resolved", 0),
                    "dismissed_count": by_state.get("dismissed", 0),
                },
            },
            metadata={
                "source": "collector:gitlab",
                "collection_method": "automated",
                "compliance_controls": ["SOC2:CC7.1", "NIST:RA-5", "ISO27001:A.12.6"],
            },
        )

    def _evidence_audit_events(self) -> Evidence:
        """Collect group audit events."""
        since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        events_data: list[dict[str, Any]] = []
        by_action: dict[str, int] = {}

        if self.config.group_id:
            group_id = self.config.group_id.replace("/", "%2F")
            try:
                params = {"created_after": since.strftime("%Y-%m-%dT%H:%M:%SZ")}
                for event in self._paginate(f"/groups/{group_id}/audit_events", params=params):
                    action = event.get("event_type", event.get("action_type", "unknown"))
                    by_action[action] = by_action.get(action, 0) + 1

                    events_data.append({
                        "id": event["id"],
                        "author_id": event.get("author_id"),
                        "author_name": event.get("author", {}).get("name") if event.get("author") else None,
                        "entity_id": event.get("entity_id"),
                        "entity_type": event.get("entity_type"),
                        "entity_path": event.get("entity_path"),
                        "event_type": action,
                        "details": event.get("details", {}),
                        "created_at": event.get("created_at"),
                        "ip_address": event.get("ip_address"),
                    })

                    if len(events_data) >= 1000:
                        break
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 403:
                    logger.warning("Audit events API not available (requires Premium/Ultimate)")
                else:
                    logger.warning(f"Failed to get audit events: {e}")
            except Exception as e:
                logger.warning(f"Failed to get audit events: {e}")

        # Identify security-relevant events
        security_keywords = ["permission", "access", "member", "token", "deploy", "secret", "key", "auth"]
        security_events = [
            e for e in events_data
            if any(kw in (e.get("event_type") or "").lower() for kw in security_keywords)
        ]

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="audit_events",
            raw_data={
                "events": events_data,
                "total_count": len(events_data),
                "by_action": by_action,
                "security_events": security_events,
                "security_events_count": len(security_events),
                "period_start": since.isoformat(),
                "period_end": datetime.now(timezone.utc).isoformat(),
            },
            metadata={
                "source": "collector:gitlab",
                "collection_method": "automated",
                "compliance_controls": ["SOC2:CC7.2", "NIST:AU-2", "ISO27001:A.12.4"],
            },
        )

    def _evidence_deploy_keys(self) -> Evidence:
        """Collect deploy keys inventory."""
        deploy_keys_data: list[dict[str, Any]] = []
        projects_with_deploy_keys: list[str] = []

        for project in self._get_group_projects():
            project_id = project["id"]
            project_name = project.get("path_with_namespace", str(project_id))

            try:
                keys = list(self._paginate(f"/projects/{project_id}/deploy_keys"))
                if keys:
                    projects_with_deploy_keys.append(project_name)

                for key in keys:
                    deploy_keys_data.append({
                        "id": key["id"],
                        "project": project_name,
                        "title": key.get("title"),
                        "can_push": key.get("can_push", False),
                        "created_at": key.get("created_at"),
                        "expires_at": key.get("expires_at"),
                        # Don't include the actual key content
                        "fingerprint": key.get("fingerprint"),
                    })
            except Exception as e:
                logger.debug(f"Failed to get deploy keys for {project_name}: {e}")

        # Identify keys with push access (security concern)
        keys_with_push = [k for k in deploy_keys_data if k.get("can_push")]

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="deploy_keys",
            raw_data={
                "deploy_keys": deploy_keys_data,
                "total_count": len(deploy_keys_data),
                "projects_with_keys": projects_with_deploy_keys,
                "projects_count": len(projects_with_deploy_keys),
                "keys_with_push_access": keys_with_push,
                "push_access_count": len(keys_with_push),
            },
            metadata={
                "source": "collector:gitlab",
                "collection_method": "automated",
                "compliance_controls": ["SOC2:CC6.3", "NIST:IA-5", "ISO27001:A.9.4"],
            },
        )
