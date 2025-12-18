"""
Jira collector for Attestful.

Collects issue tracking, project management, and change management evidence
from Jira Cloud and Jira Data Center for compliance frameworks including
SOC 2, NIST 800-53, and ISO 27001.
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
class JiraCollectorConfig:
    """Configuration for Jira collector."""

    # Authentication - API token for Cloud, PAT for Data Center
    email: str = ""
    api_token: str = ""

    # Instance URL (e.g., https://company.atlassian.net or https://jira.company.com)
    base_url: str = ""

    # Project scope (empty = all accessible projects)
    project_keys: list[str] = field(default_factory=list)

    # API settings
    timeout: int = 30
    max_retries: int = 3
    page_size: int = 100

    # Collection options
    days_of_history: int = 90

    # Jira type (cloud or server/datacenter)
    is_cloud: bool = True


class JiraCollector(BaseCollector):
    """
    Jira collector for issue tracking and change management evidence.

    Collects evidence related to:
    - Projects and project configurations
    - Issues (bugs, stories, tasks, epics)
    - Issue history and audit trails
    - Workflows and statuses
    - Users and permissions
    - Custom fields and configurations
    - Components and versions
    - Security schemes and permission schemes

    Evidence Types:
    - projects: All projects with configurations
    - issues: Issues with full details and history
    - workflows: Workflow configurations
    - users: User accounts and permissions
    - audit_log: Audit events (Cloud only)
    - security_schemes: Security level configurations
    - permission_schemes: Permission configurations
    - components: Project components

    Resource Types:
    - jira_project: Project resources
    - jira_user: User resources
    - jira_workflow: Workflow resources
    - jira_issue: Issue resources (for compliance checks)

    Example:
        collector = JiraCollector(
            config=JiraCollectorConfig(
                email="user@company.com",
                api_token="ATATT...",
                base_url="https://company.atlassian.net",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["projects", "issues", "audit_log"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["jira_project"]
        )
    """

    PLATFORM = "jira"

    metadata = CollectorMetadata(
        name="JiraCollector",
        platform="jira",
        description="Collects issue tracking and change management evidence from Jira",
        mode=CollectorMode.BOTH,
        resource_types=[
            "jira_project",
            "jira_user",
            "jira_workflow",
            "jira_issue",
        ],
        evidence_types=[
            "projects",
            "issues",
            "workflows",
            "users",
            "audit_log",
            "security_schemes",
            "permission_schemes",
            "components",
        ],
    )

    SUPPORTED_RESOURCE_TYPES = [
        "jira_project",
        "jira_user",
        "jira_workflow",
        "jira_issue",
    ]

    SUPPORTED_EVIDENCE_TYPES = [
        "projects",
        "issues",
        "workflows",
        "users",
        "audit_log",
        "security_schemes",
        "permission_schemes",
        "components",
    ]

    # Compliance control mappings
    EVIDENCE_CONTROL_MAPPINGS = {
        "projects": {
            "soc2": ["CC6.1", "CC6.2", "CC8.1"],
            "nist_800_53": ["CM-3", "CM-4", "SA-10"],
            "iso_27001": ["A.12.1.2", "A.14.2.2"],
            "hitrust": ["01.c", "09.b"],
        },
        "issues": {
            "soc2": ["CC8.1", "CC7.2", "CC7.4"],
            "nist_800_53": ["CM-3", "IR-5", "IR-6"],
            "iso_27001": ["A.12.1.2", "A.16.1.5"],
            "hitrust": ["09.b", "11.a"],
        },
        "workflows": {
            "soc2": ["CC8.1", "CC5.2"],
            "nist_800_53": ["CM-3", "CM-4"],
            "iso_27001": ["A.12.1.2"],
            "hitrust": ["09.b"],
        },
        "users": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-3", "IA-2"],
            "iso_27001": ["A.9.2.1", "A.9.2.2"],
            "hitrust": ["01.b", "01.c"],
        },
        "audit_log": {
            "soc2": ["CC7.2", "CC7.3", "CC7.4"],
            "nist_800_53": ["AU-2", "AU-3", "AU-6"],
            "iso_27001": ["A.12.4.1", "A.12.4.3"],
            "hitrust": ["09.aa", "09.ab"],
        },
        "security_schemes": {
            "soc2": ["CC6.1", "CC6.3"],
            "nist_800_53": ["AC-3", "AC-6"],
            "iso_27001": ["A.9.1.1", "A.9.4.1"],
            "hitrust": ["01.c", "01.v"],
        },
        "permission_schemes": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-3", "AC-6"],
            "iso_27001": ["A.9.2.1", "A.9.4.1"],
            "hitrust": ["01.c", "01.v"],
        },
        "components": {
            "soc2": ["CC8.1"],
            "nist_800_53": ["CM-3", "CM-8"],
            "iso_27001": ["A.8.1.1", "A.12.1.2"],
            "hitrust": ["07.a", "09.b"],
        },
    }

    def __init__(self, config: JiraCollectorConfig | None = None):
        """Initialize the Jira collector."""
        self.config = config or JiraCollectorConfig()
        self._session: requests.Session | None = None

    @property
    def session(self) -> requests.Session:
        """Get or create an authenticated session."""
        if self._session is None:
            self._session = self._create_session()
        return self._session

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

        # Configure authentication
        if self.config.is_cloud:
            # Jira Cloud uses Basic Auth with email:api_token
            session.auth = (self.config.email, self.config.api_token)
        else:
            # Jira Data Center uses Bearer token
            session.headers["Authorization"] = f"Bearer {self.config.api_token}"

        session.headers["Accept"] = "application/json"
        session.headers["Content-Type"] = "application/json"

        return session

    def _api_url(self, endpoint: str) -> str:
        """Build full API URL."""
        base = self.config.base_url.rstrip("/")
        if self.config.is_cloud:
            return f"{base}/rest/api/3/{endpoint.lstrip('/')}"
        else:
            return f"{base}/rest/api/2/{endpoint.lstrip('/')}"

    def _paginate(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        results_key: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Paginate through API results."""
        params = params or {}
        params["maxResults"] = self.config.page_size
        start_at = 0

        while True:
            params["startAt"] = start_at
            try:
                response = self.session.get(
                    self._api_url(endpoint),
                    params=params,
                    timeout=self.config.timeout,
                )
                response.raise_for_status()
                data = response.json()

                # Handle different response formats
                if results_key:
                    items = data.get(results_key, [])
                    total = data.get("total", len(items))
                elif isinstance(data, list):
                    items = data
                    total = len(items)  # For list responses, we got everything in one call
                else:
                    items = data.get("values", data.get("issues", []))
                    total = data.get("total", len(items))

                if not items:
                    break

                for item in items:
                    yield item

                # Check if there are more results
                start_at += len(items)
                if start_at >= total:
                    break

            except requests.RequestException as e:
                logger.warning(f"Pagination error at offset {start_at}: {e}")
                break

    def validate_credentials(self) -> bool:
        """Validate Jira credentials."""
        if not self.config.base_url:
            raise ConfigurationError("Jira base_url is required")
        if not self.config.api_token:
            raise ConfigurationError("Jira api_token is required")
        if self.config.is_cloud and not self.config.email:
            raise ConfigurationError("Jira email is required for Cloud instances")

        try:
            response = self.session.get(
                self._api_url("myself"),
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            user_data = response.json()
            logger.info(f"Authenticated as: {user_data.get('displayName', 'Unknown')}")
            return True
        except requests.HTTPError as e:
            if e.response.status_code == 401:
                raise ConfigurationError("Invalid Jira credentials")
            raise ConfigurationError(f"Jira API error: {e}")
        except requests.RequestException as e:
            raise ConfigurationError(f"Failed to connect to Jira: {e}")

    def collect_evidence(
        self,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """Collect evidence from Jira."""
        evidence_types = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        invalid_types = set(evidence_types) - set(self.SUPPORTED_EVIDENCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported evidence types: {invalid_types}")

        logger.info(f"Collecting Jira evidence: {evidence_types}")
        evidence_items: list[Evidence] = []
        errors: list[str] = []

        collection_methods = {
            "projects": self._collect_projects_evidence,
            "issues": self._collect_issues_evidence,
            "workflows": self._collect_workflows_evidence,
            "users": self._collect_users_evidence,
            "audit_log": self._collect_audit_log_evidence,
            "security_schemes": self._collect_security_schemes_evidence,
            "permission_schemes": self._collect_permission_schemes_evidence,
            "components": self._collect_components_evidence,
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

    def _collect_projects_evidence(self) -> Evidence:
        """Collect projects evidence."""
        logger.info("Collecting Jira projects...")
        projects = []

        for project in self._paginate("project/search", results_key="values"):
            project_detail = self._get_project_detail(project["key"])
            projects.append(project_detail)

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="projects",
            raw_data={
                "projects": projects,
                "total_count": len(projects),
            },
            metadata={
                "source": "collector:jira",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["projects"],
            },
        )

    def _get_project_detail(self, project_key: str) -> dict[str, Any]:
        """Get detailed project information."""
        try:
            response = self.session.get(
                self._api_url(f"project/{project_key}"),
                params={"expand": "description,lead,issueTypes,url,projectKeys"},
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.warning(f"Error getting project detail for {project_key}: {e}")
            return {"key": project_key, "error": str(e)}

    def _collect_issues_evidence(self) -> Evidence:
        """Collect issues evidence."""
        logger.info("Collecting Jira issues...")
        issues = []
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        cutoff_str = cutoff_date.strftime("%Y-%m-%d")

        # Build JQL query
        jql_parts = [f"updated >= '{cutoff_str}'"]
        if self.config.project_keys:
            project_list = ", ".join(self.config.project_keys)
            jql_parts.append(f"project IN ({project_list})")
        jql = " AND ".join(jql_parts)

        params = {
            "jql": jql,
            "fields": "summary,status,issuetype,priority,assignee,reporter,created,updated,resolution,labels,components,fixVersions",
            "expand": "changelog",
        }

        for issue in self._paginate("search", params=params, results_key="issues"):
            issues.append(self._normalize_issue(issue))

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="issues",
            raw_data={
                "issues": issues,
                "total_count": len(issues),
                "jql_query": jql,
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:jira",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["issues"],
            },
        )

    def _normalize_issue(self, issue: dict[str, Any]) -> dict[str, Any]:
        """Normalize issue data."""
        fields = issue.get("fields", {})
        return {
            "key": issue.get("key"),
            "id": issue.get("id"),
            "summary": fields.get("summary"),
            "status": fields.get("status", {}).get("name") if fields.get("status") else None,
            "issue_type": fields.get("issuetype", {}).get("name") if fields.get("issuetype") else None,
            "priority": fields.get("priority", {}).get("name") if fields.get("priority") else None,
            "assignee": fields.get("assignee", {}).get("displayName") if fields.get("assignee") else None,
            "reporter": fields.get("reporter", {}).get("displayName") if fields.get("reporter") else None,
            "created": fields.get("created"),
            "updated": fields.get("updated"),
            "resolution": fields.get("resolution", {}).get("name") if fields.get("resolution") else None,
            "labels": fields.get("labels", []),
            "components": [c.get("name") for c in fields.get("components", [])],
            "fix_versions": [v.get("name") for v in fields.get("fixVersions", [])],
            "changelog": self._normalize_changelog(issue.get("changelog", {})),
        }

    def _normalize_changelog(self, changelog: dict[str, Any]) -> list[dict[str, Any]]:
        """Normalize changelog data."""
        histories = []
        for history in changelog.get("histories", []):
            for item in history.get("items", []):
                histories.append({
                    "field": item.get("field"),
                    "from": item.get("fromString"),
                    "to": item.get("toString"),
                    "author": history.get("author", {}).get("displayName"),
                    "created": history.get("created"),
                })
        return histories

    def _collect_workflows_evidence(self) -> Evidence:
        """Collect workflows evidence."""
        logger.info("Collecting Jira workflows...")
        workflows = []

        try:
            response = self.session.get(
                self._api_url("workflow/search"),
                params={"expand": "statuses,transitions"},
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            data = response.json()
            workflows = data.get("values", [])
        except requests.RequestException as e:
            logger.warning(f"Error collecting workflows: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="workflows",
            raw_data={
                "workflows": workflows,
                "total_count": len(workflows),
            },
            metadata={
                "source": "collector:jira",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["workflows"],
            },
        )

    def _collect_users_evidence(self) -> Evidence:
        """Collect users evidence."""
        logger.info("Collecting Jira users...")
        users = []

        for user in self._paginate("users/search"):
            users.append({
                "account_id": user.get("accountId"),
                "display_name": user.get("displayName"),
                "email_address": user.get("emailAddress"),
                "active": user.get("active"),
                "account_type": user.get("accountType"),
                "timezone": user.get("timeZone"),
            })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="users",
            raw_data={
                "users": users,
                "total_count": len(users),
                "active_count": sum(1 for u in users if u.get("active")),
            },
            metadata={
                "source": "collector:jira",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["users"],
            },
        )

    def _collect_audit_log_evidence(self) -> Evidence:
        """Collect audit log evidence (Cloud only)."""
        logger.info("Collecting Jira audit log...")
        audit_records = []

        if not self.config.is_cloud:
            logger.warning("Audit log collection is only available for Jira Cloud")
            return Evidence(
                platform=self.PLATFORM,
                evidence_type="audit_log",
                raw_data={
                    "audit_records": [],
                    "total_count": 0,
                    "note": "Audit log not available for Jira Data Center via REST API",
                },
                metadata={
                    "source": "collector:jira",
                    "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["audit_log"],
                },
            )

        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        cutoff_ms = int(cutoff_date.timestamp() * 1000)

        try:
            # Jira Cloud audit log endpoint
            base = self.config.base_url.rstrip("/")
            audit_url = f"{base}/rest/api/3/auditing/record"

            params = {
                "from": cutoff_ms,
                "limit": self.config.page_size,
            }

            offset = 0
            while True:
                params["offset"] = offset
                response = self.session.get(
                    audit_url,
                    params=params,
                    timeout=self.config.timeout,
                )
                response.raise_for_status()
                data = response.json()
                records = data.get("records", [])

                if not records:
                    break

                for record in records:
                    audit_records.append({
                        "id": record.get("id"),
                        "summary": record.get("summary"),
                        "category": record.get("category"),
                        "event_source": record.get("eventSource"),
                        "created": record.get("created"),
                        "author": record.get("authorAccountId"),
                        "object_item": record.get("objectItem", {}).get("name"),
                    })

                offset += len(records)
                if len(records) < self.config.page_size:
                    break

        except requests.RequestException as e:
            logger.warning(f"Error collecting audit log: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="audit_log",
            raw_data={
                "audit_records": audit_records,
                "total_count": len(audit_records),
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:jira",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["audit_log"],
            },
        )

    def _collect_security_schemes_evidence(self) -> Evidence:
        """Collect security schemes evidence."""
        logger.info("Collecting Jira security schemes...")
        schemes = []

        try:
            response = self.session.get(
                self._api_url("issuesecurityschemes"),
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            data = response.json()
            schemes = data.get("issueSecuritySchemes", [])
        except requests.RequestException as e:
            logger.warning(f"Error collecting security schemes: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="security_schemes",
            raw_data={
                "security_schemes": schemes,
                "total_count": len(schemes),
            },
            metadata={
                "source": "collector:jira",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["security_schemes"],
            },
        )

    def _collect_permission_schemes_evidence(self) -> Evidence:
        """Collect permission schemes evidence."""
        logger.info("Collecting Jira permission schemes...")
        schemes = []

        try:
            response = self.session.get(
                self._api_url("permissionscheme"),
                params={"expand": "permissions,all"},
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            data = response.json()
            schemes = data.get("permissionSchemes", [])
        except requests.RequestException as e:
            logger.warning(f"Error collecting permission schemes: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="permission_schemes",
            raw_data={
                "permission_schemes": schemes,
                "total_count": len(schemes),
            },
            metadata={
                "source": "collector:jira",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["permission_schemes"],
            },
        )

    def _collect_components_evidence(self) -> Evidence:
        """Collect components evidence across projects."""
        logger.info("Collecting Jira components...")
        components = []

        # Get components for each project
        for project in self._paginate("project/search", results_key="values"):
            project_key = project.get("key")
            try:
                response = self.session.get(
                    self._api_url(f"project/{project_key}/components"),
                    timeout=self.config.timeout,
                )
                response.raise_for_status()
                project_components = response.json()
                for component in project_components:
                    component["project_key"] = project_key
                    components.append(component)
            except requests.RequestException as e:
                logger.warning(f"Error collecting components for {project_key}: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="components",
            raw_data={
                "components": components,
                "total_count": len(components),
            },
            metadata={
                "source": "collector:jira",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["components"],
            },
        )

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """Collect resources from Jira for compliance checks."""
        resource_types = resource_types or self.SUPPORTED_RESOURCE_TYPES
        invalid_types = set(resource_types) - set(self.SUPPORTED_RESOURCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported resource types: {invalid_types}")

        logger.info(f"Collecting Jira resources: {resource_types}")
        resources: list[Resource] = []

        collection_methods = {
            "jira_project": self._collect_project_resources,
            "jira_user": self._collect_user_resources,
            "jira_workflow": self._collect_workflow_resources,
            "jira_issue": self._collect_issue_resources,
        }

        for resource_type in resource_types:
            method = collection_methods.get(resource_type)
            if method:
                resources.extend(method())

        return resources

    def _collect_project_resources(self) -> list[Resource]:
        """Collect project resources."""
        logger.info("Collecting Jira project resources...")
        resources = []

        for project in self._paginate("project/search", results_key="values"):
            project_detail = self._get_project_detail(project["key"])
            resources.append(
                Resource(
                    id=str(project.get("id", project.get("key"))),
                    type="jira_project",
                    provider="jira",
                    region="global",
                    name=project.get("name"),
                    tags={
                        "project_type": project.get("projectTypeKey", "unknown"),
                        "is_private": str(project.get("isPrivate", False)).lower(),
                    },
                    metadata={
                        "key": project.get("key"),
                        "project_type_key": project.get("projectTypeKey"),
                        "simplified": project.get("simplified", False),
                        "style": project.get("style"),
                        "lead": project_detail.get("lead", {}).get("displayName") if project_detail.get("lead") else None,
                        "description": project_detail.get("description"),
                        "url": project_detail.get("url"),
                    },
                    raw_data=project_detail,
                )
            )

        return resources

    def _collect_user_resources(self) -> list[Resource]:
        """Collect user resources."""
        logger.info("Collecting Jira user resources...")
        resources = []

        for user in self._paginate("users/search"):
            resources.append(
                Resource(
                    id=str(user.get("accountId", user.get("key", ""))),
                    type="jira_user",
                    provider="jira",
                    region="global",
                    name=user.get("displayName", "Unknown"),
                    tags={
                        "active": str(user.get("active", False)).lower(),
                        "account_type": user.get("accountType", "unknown"),
                    },
                    metadata={
                        "account_id": user.get("accountId"),
                        "display_name": user.get("displayName"),
                        "email_address": user.get("emailAddress"),
                        "active": user.get("active", False),
                        "account_type": user.get("accountType"),
                        "timezone": user.get("timeZone"),
                    },
                    raw_data=user,
                )
            )

        return resources

    def _collect_workflow_resources(self) -> list[Resource]:
        """Collect workflow resources."""
        logger.info("Collecting Jira workflow resources...")
        resources = []

        try:
            response = self.session.get(
                self._api_url("workflow/search"),
                params={"expand": "statuses,transitions"},
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            data = response.json()

            for workflow in data.get("values", []):
                workflow_id = workflow.get("id", {})
                resources.append(
                    Resource(
                        id=str(workflow_id.get("entityId", workflow_id.get("name", ""))),
                        type="jira_workflow",
                        provider="jira",
                        region="global",
                        name=workflow_id.get("name", "Unknown"),
                        tags={
                            "is_default": str(workflow.get("isDefault", False)).lower(),
                        },
                        metadata={
                            "name": workflow_id.get("name"),
                            "entity_id": workflow_id.get("entityId"),
                            "description": workflow.get("description"),
                            "is_default": workflow.get("isDefault", False),
                            "statuses": [s.get("name") for s in workflow.get("statuses", [])],
                            "transitions": [t.get("name") for t in workflow.get("transitions", [])],
                        },
                        raw_data=workflow,
                    )
                )
        except requests.RequestException as e:
            logger.warning(f"Error collecting workflow resources: {e}")

        return resources

    def _collect_issue_resources(self) -> list[Resource]:
        """Collect issue resources (limited set for compliance checks)."""
        logger.info("Collecting Jira issue resources...")
        resources = []
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        cutoff_str = cutoff_date.strftime("%Y-%m-%d")

        jql_parts = [f"updated >= '{cutoff_str}'"]
        if self.config.project_keys:
            project_list = ", ".join(self.config.project_keys)
            jql_parts.append(f"project IN ({project_list})")
        jql = " AND ".join(jql_parts)

        params = {
            "jql": jql,
            "fields": "summary,status,issuetype,priority,assignee,reporter,created,updated,project",
        }

        count = 0
        max_issues = 1000  # Limit to prevent excessive resource collection

        for issue in self._paginate("search", params=params, results_key="issues"):
            if count >= max_issues:
                logger.info(f"Reached max issue limit of {max_issues}")
                break

            fields = issue.get("fields", {})
            resources.append(
                Resource(
                    id=str(issue.get("id", issue.get("key", ""))),
                    type="jira_issue",
                    provider="jira",
                    region="global",
                    name=issue.get("key", "Unknown"),
                    tags={
                        "issue_type": (fields.get("issuetype", {}).get("name") or "unknown").lower(),
                        "status": (fields.get("status", {}).get("name") or "unknown").lower().replace(" ", "_"),
                        "project": fields.get("project", {}).get("key") or "unknown",
                    },
                    metadata={
                        "key": issue.get("key"),
                        "summary": fields.get("summary"),
                        "status": fields.get("status", {}).get("name") if fields.get("status") else None,
                        "issue_type": fields.get("issuetype", {}).get("name") if fields.get("issuetype") else None,
                        "priority": fields.get("priority", {}).get("name") if fields.get("priority") else None,
                        "assignee": fields.get("assignee", {}).get("displayName") if fields.get("assignee") else None,
                        "reporter": fields.get("reporter", {}).get("displayName") if fields.get("reporter") else None,
                        "project_key": fields.get("project", {}).get("key") if fields.get("project") else None,
                        "created": fields.get("created"),
                        "updated": fields.get("updated"),
                    },
                    raw_data=issue,
                )
            )
            count += 1

        return resources
