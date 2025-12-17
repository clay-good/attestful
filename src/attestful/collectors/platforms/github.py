"""
GitHub collector for Attestful.

Collects source control, security, and DevOps evidence from GitHub
for compliance frameworks including SOC 2, NIST 800-53, and ISO 27001.
"""

from __future__ import annotations

from dataclasses import dataclass, field
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
class GitHubCollectorConfig:
    """Configuration for GitHub collector."""

    # Authentication
    token: str = ""

    # Organization/user scope
    organization: str = ""

    # API settings
    api_url: str = "https://api.github.com"
    timeout: int = 30
    max_retries: int = 3
    page_size: int = 100

    # Collection options
    include_archived: bool = False
    days_of_history: int = 90


class GitHubCollector(BaseCollector):
    """
    GitHub collector for source control and DevOps evidence.

    Collects evidence related to:
    - Repository configurations and security settings
    - Branch protection rules
    - Code scanning and security alerts
    - Dependabot alerts and updates
    - Collaborators and access permissions
    - Commit history and contributor activity
    - Pull request and review workflows
    - GitHub Actions and workflows
    - Audit log events (Enterprise/Organization)

    Evidence Types:
    - repositories: All repositories with configurations
    - branch_protection: Branch protection rules
    - security_alerts: Code scanning and Dependabot alerts
    - collaborators: Repository collaborators and permissions
    - commits: Recent commit activity
    - pull_requests: Recent pull requests and reviews
    - workflows: GitHub Actions workflows
    - audit_log: Organization audit events (if available)

    Resource Types:
    - github_repository: Repository resources
    - github_user: User/member resources
    - github_team: Team resources

    Example:
        collector = GitHubCollector(
            config=GitHubCollectorConfig(
                token="ghp_...",
                organization="my-org",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["repositories", "branch_protection", "security_alerts"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["github_repository"]
        )
    """

    PLATFORM = "github"

    metadata = CollectorMetadata(
        name="GitHubCollector",
        platform="github",
        description="Collects source control and security evidence from GitHub",
        mode=CollectorMode.BOTH,
        resource_types=["github_repository", "github_user", "github_team"],
        evidence_types=[
            "repositories",
            "branch_protection",
            "security_alerts",
            "collaborators",
            "commits",
            "pull_requests",
            "workflows",
            "audit_log",
        ],
    )

    SUPPORTED_RESOURCE_TYPES = [
        "github_repository",
        "github_user",
        "github_team",
    ]
    SUPPORTED_EVIDENCE_TYPES = [
        "repositories",
        "branch_protection",
        "security_alerts",
        "collaborators",
        "commits",
        "pull_requests",
        "workflows",
        "audit_log",
    ]

    def __init__(
        self,
        config: GitHubCollectorConfig | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize GitHub collector.

        Args:
            config: GitHub collector configuration.
            **kwargs: Additional arguments passed to BaseCollector.
        """
        super().__init__(**kwargs)
        self.config = config or GitHubCollectorConfig()
        self._session: requests.Session | None = None

    @property
    def base_url(self) -> str:
        """Get the GitHub API base URL."""
        return self.config.api_url.rstrip("/")

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

            # Set headers
            headers = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            if self.config.token:
                headers["Authorization"] = f"Bearer {self.config.token}"

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
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        kwargs.setdefault("timeout", self.config.timeout)

        response = session.request(method, url, **kwargs)

        # Handle rate limiting
        if response.status_code == 403:
            remaining = response.headers.get("X-RateLimit-Remaining", "0")
            if remaining == "0":
                reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
                wait_seconds = max(1, reset_time - int(datetime.now().timestamp()))
                logger.warning(f"Rate limited, waiting {wait_seconds}s")
                import time
                time.sleep(min(wait_seconds, 60))  # Cap at 60 seconds
                return self._request(method, endpoint, **kwargs)

        response.raise_for_status()
        return response

    def _paginate(self, endpoint: str, **kwargs: Any) -> Iterator[dict[str, Any]]:
        """Paginate through API results."""
        params = kwargs.pop("params", {})
        params.setdefault("per_page", self.config.page_size)
        page = 1

        while True:
            params["page"] = page
            response = self._request("GET", endpoint, params=params, **kwargs)
            items = response.json()

            # Handle non-list responses (e.g., search results)
            if isinstance(items, dict):
                items = items.get("items", [])

            if not items:
                break

            for item in items:
                yield item

            # Check for next page
            if len(items) < self.config.page_size:
                break

            page += 1

    def validate_credentials(self) -> bool:
        """Validate GitHub API credentials."""
        try:
            response = self._request("GET", "/user")
            user = response.json()
            logger.info(f"Validated GitHub credentials for {user.get('login')}")
            return True
        except Exception as e:
            logger.error(f"GitHub credential validation failed: {e}")
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
        Collect GitHub resources.

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

    def _collect_github_repository(self) -> Iterator[Resource]:
        """Collect GitHub repositories as resources."""
        endpoint = f"/orgs/{self.config.organization}/repos" if self.config.organization else "/user/repos"

        for repo in self._paginate(endpoint):
            if not self.config.include_archived and repo.get("archived"):
                continue

            yield Resource(
                id=str(repo["id"]),
                type="github_repository",
                provider="github",
                region="global",
                name=repo.get("full_name", repo["name"]),
                tags={
                    "visibility": repo.get("visibility", "unknown"),
                    "default_branch": repo.get("default_branch", "main"),
                    "archived": str(repo.get("archived", False)).lower(),
                },
                raw_data=repo,
            )

    def _collect_github_user(self) -> Iterator[Resource]:
        """Collect GitHub organization members as resources."""
        if not self.config.organization:
            logger.warning("Organization not configured, skipping user collection")
            return

        for member in self._paginate(f"/orgs/{self.config.organization}/members"):
            yield Resource(
                id=str(member["id"]),
                type="github_user",
                provider="github",
                region="global",
                name=member.get("login", str(member["id"])),
                tags={
                    "type": member.get("type", "User"),
                    "site_admin": str(member.get("site_admin", False)).lower(),
                },
                raw_data=member,
            )

    def _collect_github_team(self) -> Iterator[Resource]:
        """Collect GitHub organization teams as resources."""
        if not self.config.organization:
            logger.warning("Organization not configured, skipping team collection")
            return

        for team in self._paginate(f"/orgs/{self.config.organization}/teams"):
            yield Resource(
                id=str(team["id"]),
                type="github_team",
                provider="github",
                region="global",
                name=team.get("name", str(team["id"])),
                tags={
                    "privacy": team.get("privacy", "unknown"),
                    "permission": team.get("permission", "unknown"),
                },
                raw_data=team,
            )

    # =========================================================================
    # Evidence Collection Methods
    # =========================================================================

    def collect_evidence(
        self,
        *,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """
        Collect GitHub evidence for compliance audits.

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

    def _evidence_repositories(self) -> Evidence:
        """Collect all repositories with configuration details."""
        endpoint = f"/orgs/{self.config.organization}/repos" if self.config.organization else "/user/repos"
        repos = []

        for repo in self._paginate(endpoint):
            if not self.config.include_archived and repo.get("archived"):
                continue

            repos.append({
                "id": repo["id"],
                "name": repo["name"],
                "full_name": repo["full_name"],
                "private": repo.get("private", False),
                "visibility": repo.get("visibility", "unknown"),
                "default_branch": repo.get("default_branch"),
                "archived": repo.get("archived", False),
                "has_issues": repo.get("has_issues", False),
                "has_wiki": repo.get("has_wiki", False),
                "has_discussions": repo.get("has_discussions", False),
                "fork": repo.get("fork", False),
                "allow_forking": repo.get("allow_forking", True),
                "delete_branch_on_merge": repo.get("delete_branch_on_merge", False),
                "allow_merge_commit": repo.get("allow_merge_commit", True),
                "allow_squash_merge": repo.get("allow_squash_merge", True),
                "allow_rebase_merge": repo.get("allow_rebase_merge", True),
                "created_at": repo.get("created_at"),
                "updated_at": repo.get("updated_at"),
                "pushed_at": repo.get("pushed_at"),
            })

        # Summary statistics
        visibility_counts: dict[str, int] = {}
        for repo in repos:
            vis = repo.get("visibility", "unknown")
            visibility_counts[vis] = visibility_counts.get(vis, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="repositories",
            raw_data={
                "repositories": repos,
                "total_count": len(repos),
                "visibility_breakdown": visibility_counts,
                "private_count": sum(1 for r in repos if r.get("private")),
                "public_count": sum(1 for r in repos if not r.get("private")),
            },
            metadata={
                "source": "collector:github",
                "collection_method": "automated",
            },
        )

    def _evidence_branch_protection(self) -> Evidence:
        """Collect branch protection rules for all repositories."""
        endpoint = f"/orgs/{self.config.organization}/repos" if self.config.organization else "/user/repos"
        protection_data: list[dict[str, Any]] = []

        for repo in self._paginate(endpoint):
            if not self.config.include_archived and repo.get("archived"):
                continue

            repo_name = repo["full_name"]
            default_branch = repo.get("default_branch", "main")

            try:
                self._rate_limit()
                response = self._request(
                    "GET",
                    f"/repos/{repo_name}/branches/{default_branch}/protection",
                )
                protection = response.json()

                protection_data.append({
                    "repository": repo_name,
                    "branch": default_branch,
                    "protected": True,
                    "required_reviews": protection.get("required_pull_request_reviews") is not None,
                    "required_reviews_count": (
                        protection.get("required_pull_request_reviews", {})
                        .get("required_approving_review_count", 0)
                    ),
                    "dismiss_stale_reviews": (
                        protection.get("required_pull_request_reviews", {})
                        .get("dismiss_stale_reviews", False)
                    ),
                    "require_code_owner_reviews": (
                        protection.get("required_pull_request_reviews", {})
                        .get("require_code_owner_reviews", False)
                    ),
                    "required_status_checks": protection.get("required_status_checks") is not None,
                    "require_branches_up_to_date": (
                        protection.get("required_status_checks", {})
                        .get("strict", False)
                    ),
                    "enforce_admins": protection.get("enforce_admins", {}).get("enabled", False),
                    "required_signatures": protection.get("required_signatures", {}).get("enabled", False),
                    "allow_force_pushes": protection.get("allow_force_pushes", {}).get("enabled", False),
                    "allow_deletions": protection.get("allow_deletions", {}).get("enabled", False),
                })
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    protection_data.append({
                        "repository": repo_name,
                        "branch": default_branch,
                        "protected": False,
                    })
                else:
                    logger.warning(f"Failed to get protection for {repo_name}: {e}")
            except Exception as e:
                logger.warning(f"Failed to get protection for {repo_name}: {e}")

        # Summary statistics
        protected_count = sum(1 for p in protection_data if p.get("protected"))
        with_reviews = sum(1 for p in protection_data if p.get("required_reviews"))

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="branch_protection",
            raw_data={
                "repositories": protection_data,
                "summary": {
                    "total_repositories": len(protection_data),
                    "protected_count": protected_count,
                    "unprotected_count": len(protection_data) - protected_count,
                    "with_required_reviews": with_reviews,
                    "protection_rate": round(
                        protected_count / len(protection_data) * 100, 2
                    ) if protection_data else 0,
                },
            },
            metadata={
                "source": "collector:github",
                "collection_method": "automated",
            },
        )

    def _evidence_security_alerts(self) -> Evidence:
        """Collect security alerts (code scanning and Dependabot)."""
        endpoint = f"/orgs/{self.config.organization}/repos" if self.config.organization else "/user/repos"
        alerts_data: list[dict[str, Any]] = []

        for repo in self._paginate(endpoint):
            if not self.config.include_archived and repo.get("archived"):
                continue

            repo_name = repo["full_name"]
            repo_alerts = {
                "repository": repo_name,
                "code_scanning_alerts": [],
                "dependabot_alerts": [],
            }

            # Get code scanning alerts
            try:
                self._rate_limit()
                for alert in self._paginate(f"/repos/{repo_name}/code-scanning/alerts"):
                    repo_alerts["code_scanning_alerts"].append({
                        "number": alert.get("number"),
                        "state": alert.get("state"),
                        "severity": alert.get("rule", {}).get("severity"),
                        "security_severity": alert.get("rule", {}).get("security_severity_level"),
                        "tool": alert.get("tool", {}).get("name"),
                        "created_at": alert.get("created_at"),
                        "dismissed_at": alert.get("dismissed_at"),
                        "dismissed_reason": alert.get("dismissed_reason"),
                    })
            except requests.exceptions.HTTPError:
                pass  # Code scanning may not be enabled
            except Exception as e:
                logger.warning(f"Failed to get code scanning alerts for {repo_name}: {e}")

            # Get Dependabot alerts
            try:
                self._rate_limit()
                for alert in self._paginate(f"/repos/{repo_name}/dependabot/alerts"):
                    repo_alerts["dependabot_alerts"].append({
                        "number": alert.get("number"),
                        "state": alert.get("state"),
                        "severity": alert.get("security_advisory", {}).get("severity"),
                        "package": alert.get("dependency", {}).get("package", {}).get("name"),
                        "ecosystem": alert.get("dependency", {}).get("package", {}).get("ecosystem"),
                        "created_at": alert.get("created_at"),
                        "dismissed_at": alert.get("dismissed_at"),
                        "dismissed_reason": alert.get("dismissed_reason"),
                        "fixed_at": alert.get("fixed_at"),
                    })
            except requests.exceptions.HTTPError:
                pass  # Dependabot may not be enabled
            except Exception as e:
                logger.warning(f"Failed to get Dependabot alerts for {repo_name}: {e}")

            if repo_alerts["code_scanning_alerts"] or repo_alerts["dependabot_alerts"]:
                alerts_data.append(repo_alerts)

        # Summary statistics
        total_code_scanning = sum(len(r["code_scanning_alerts"]) for r in alerts_data)
        total_dependabot = sum(len(r["dependabot_alerts"]) for r in alerts_data)
        open_code_scanning = sum(
            1 for r in alerts_data
            for a in r["code_scanning_alerts"]
            if a.get("state") == "open"
        )
        open_dependabot = sum(
            1 for r in alerts_data
            for a in r["dependabot_alerts"]
            if a.get("state") == "open"
        )

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="security_alerts",
            raw_data={
                "repositories": alerts_data,
                "summary": {
                    "repositories_with_alerts": len(alerts_data),
                    "total_code_scanning_alerts": total_code_scanning,
                    "open_code_scanning_alerts": open_code_scanning,
                    "total_dependabot_alerts": total_dependabot,
                    "open_dependabot_alerts": open_dependabot,
                },
            },
            metadata={
                "source": "collector:github",
                "collection_method": "automated",
            },
        )

    def _evidence_collaborators(self) -> Evidence:
        """Collect repository collaborators and permissions."""
        endpoint = f"/orgs/{self.config.organization}/repos" if self.config.organization else "/user/repos"
        collaborators_data: list[dict[str, Any]] = []

        for repo in self._paginate(endpoint):
            if not self.config.include_archived and repo.get("archived"):
                continue

            repo_name = repo["full_name"]

            try:
                self._rate_limit()
                collaborators = list(self._paginate(f"/repos/{repo_name}/collaborators"))

                collaborators_data.append({
                    "repository": repo_name,
                    "collaborator_count": len(collaborators),
                    "collaborators": [
                        {
                            "login": c.get("login"),
                            "id": c.get("id"),
                            "type": c.get("type"),
                            "permissions": c.get("permissions", {}),
                            "role_name": c.get("role_name"),
                        }
                        for c in collaborators
                    ],
                    "admin_count": sum(
                        1 for c in collaborators
                        if c.get("permissions", {}).get("admin")
                    ),
                })
            except Exception as e:
                logger.warning(f"Failed to get collaborators for {repo_name}: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="collaborators",
            raw_data={
                "repositories": collaborators_data,
                "summary": {
                    "total_repositories": len(collaborators_data),
                    "total_collaborators": sum(r["collaborator_count"] for r in collaborators_data),
                    "total_admins": sum(r["admin_count"] for r in collaborators_data),
                },
            },
            metadata={
                "source": "collector:github",
                "collection_method": "automated",
            },
        )

    def _evidence_commits(self) -> Evidence:
        """Collect recent commit activity."""
        endpoint = f"/orgs/{self.config.organization}/repos" if self.config.organization else "/user/repos"
        commits_data: list[dict[str, Any]] = []
        since = (datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)).isoformat()

        for repo in self._paginate(endpoint):
            if not self.config.include_archived and repo.get("archived"):
                continue

            repo_name = repo["full_name"]

            try:
                self._rate_limit()
                commits = list(self._paginate(
                    f"/repos/{repo_name}/commits",
                    params={"since": since},
                ))

                # Aggregate by author
                author_commits: dict[str, int] = {}
                for commit in commits:
                    author = commit.get("commit", {}).get("author", {}).get("email", "unknown")
                    author_commits[author] = author_commits.get(author, 0) + 1

                commits_data.append({
                    "repository": repo_name,
                    "commit_count": len(commits),
                    "unique_authors": len(author_commits),
                    "author_breakdown": author_commits,
                    "first_commit_date": commits[-1].get("commit", {}).get("author", {}).get("date") if commits else None,
                    "last_commit_date": commits[0].get("commit", {}).get("author", {}).get("date") if commits else None,
                })
            except Exception as e:
                logger.warning(f"Failed to get commits for {repo_name}: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="commits",
            raw_data={
                "repositories": commits_data,
                "summary": {
                    "total_repositories": len(commits_data),
                    "total_commits": sum(r["commit_count"] for r in commits_data),
                    "active_repositories": sum(1 for r in commits_data if r["commit_count"] > 0),
                    "period_days": self.config.days_of_history,
                },
            },
            metadata={
                "source": "collector:github",
                "collection_method": "automated",
                "period_start": since,
            },
        )

    def _evidence_pull_requests(self) -> Evidence:
        """Collect recent pull requests and review information."""
        endpoint = f"/orgs/{self.config.organization}/repos" if self.config.organization else "/user/repos"
        pr_data: list[dict[str, Any]] = []
        since = (datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)).isoformat()

        for repo in self._paginate(endpoint):
            if not self.config.include_archived and repo.get("archived"):
                continue

            repo_name = repo["full_name"]

            try:
                self._rate_limit()
                prs = list(self._paginate(
                    f"/repos/{repo_name}/pulls",
                    params={"state": "all", "sort": "updated", "direction": "desc"},
                ))

                # Filter by date and collect relevant info
                recent_prs = []
                for pr in prs:
                    updated = pr.get("updated_at", "")
                    if updated < since:
                        break

                    recent_prs.append({
                        "number": pr.get("number"),
                        "title": pr.get("title"),
                        "state": pr.get("state"),
                        "merged": pr.get("merged_at") is not None,
                        "author": pr.get("user", {}).get("login"),
                        "created_at": pr.get("created_at"),
                        "updated_at": pr.get("updated_at"),
                        "merged_at": pr.get("merged_at"),
                        "requested_reviewers": len(pr.get("requested_reviewers", [])),
                        "draft": pr.get("draft", False),
                    })

                if recent_prs:
                    merged_count = sum(1 for p in recent_prs if p["merged"])
                    pr_data.append({
                        "repository": repo_name,
                        "pull_request_count": len(recent_prs),
                        "merged_count": merged_count,
                        "open_count": sum(1 for p in recent_prs if p["state"] == "open"),
                        "closed_without_merge": len(recent_prs) - merged_count - sum(1 for p in recent_prs if p["state"] == "open"),
                        "pull_requests": recent_prs,
                    })
            except Exception as e:
                logger.warning(f"Failed to get pull requests for {repo_name}: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="pull_requests",
            raw_data={
                "repositories": pr_data,
                "summary": {
                    "total_repositories": len(pr_data),
                    "total_pull_requests": sum(r["pull_request_count"] for r in pr_data),
                    "total_merged": sum(r["merged_count"] for r in pr_data),
                    "period_days": self.config.days_of_history,
                },
            },
            metadata={
                "source": "collector:github",
                "collection_method": "automated",
                "period_start": since,
            },
        )

    def _evidence_workflows(self) -> Evidence:
        """Collect GitHub Actions workflows."""
        endpoint = f"/orgs/{self.config.organization}/repos" if self.config.organization else "/user/repos"
        workflows_data: list[dict[str, Any]] = []

        for repo in self._paginate(endpoint):
            if not self.config.include_archived and repo.get("archived"):
                continue

            repo_name = repo["full_name"]

            try:
                self._rate_limit()
                response = self._request("GET", f"/repos/{repo_name}/actions/workflows")
                workflows = response.json().get("workflows", [])

                if workflows:
                    workflows_data.append({
                        "repository": repo_name,
                        "workflow_count": len(workflows),
                        "workflows": [
                            {
                                "id": w.get("id"),
                                "name": w.get("name"),
                                "path": w.get("path"),
                                "state": w.get("state"),
                                "created_at": w.get("created_at"),
                                "updated_at": w.get("updated_at"),
                            }
                            for w in workflows
                        ],
                    })
            except Exception as e:
                logger.warning(f"Failed to get workflows for {repo_name}: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="workflows",
            raw_data={
                "repositories": workflows_data,
                "summary": {
                    "repositories_with_workflows": len(workflows_data),
                    "total_workflows": sum(r["workflow_count"] for r in workflows_data),
                },
            },
            metadata={
                "source": "collector:github",
                "collection_method": "automated",
            },
        )

    def _evidence_audit_log(self) -> Evidence:
        """Collect organization audit log events."""
        if not self.config.organization:
            logger.warning("Organization not configured, skipping audit log collection")
            return Evidence(
                platform=self.PLATFORM,
                evidence_type="audit_log",
                raw_data={"events": [], "error": "Organization not configured"},
                metadata={"source": "collector:github"},
            )

        events: list[dict[str, Any]] = []
        event_types: dict[str, int] = {}

        try:
            # Note: Audit log API requires GitHub Enterprise or specific org permissions
            for event in self._paginate(
                f"/orgs/{self.config.organization}/audit-log",
                params={"per_page": 100},
            ):
                events.append({
                    "@timestamp": event.get("@timestamp"),
                    "action": event.get("action"),
                    "actor": event.get("actor"),
                    "actor_location": event.get("actor_location"),
                    "org": event.get("org"),
                    "repo": event.get("repo"),
                    "user": event.get("user"),
                    "team": event.get("team"),
                })

                action = event.get("action", "unknown")
                event_types[action] = event_types.get(action, 0) + 1

                # Limit to 1000 events
                if len(events) >= 1000:
                    break

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.info("Audit log not available (requires Enterprise or specific permissions)")
                return Evidence(
                    platform=self.PLATFORM,
                    evidence_type="audit_log",
                    raw_data={
                        "events": [],
                        "error": "Audit log not available (requires Enterprise or specific permissions)",
                    },
                    metadata={"source": "collector:github"},
                )
            raise
        except Exception as e:
            logger.warning(f"Failed to get audit log: {e}")
            return Evidence(
                platform=self.PLATFORM,
                evidence_type="audit_log",
                raw_data={"events": [], "error": str(e)},
                metadata={"source": "collector:github"},
            )

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="audit_log",
            raw_data={
                "events": events,
                "total_events": len(events),
                "action_breakdown": event_types,
            },
            metadata={
                "source": "collector:github",
                "collection_method": "automated",
            },
        )
