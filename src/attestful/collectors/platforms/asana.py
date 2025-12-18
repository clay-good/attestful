"""
Asana collector for Attestful.

Collects project management, task tracking, and team collaboration evidence
from Asana for compliance frameworks including SOC 2, NIST 800-53,
ISO 27001, and HITRUST.
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
class AsanaCollectorConfig:
    """Configuration for Asana collector."""

    # Personal Access Token or OAuth token
    access_token: str = ""

    # Workspace GID (optional - if not set, collects from all workspaces)
    workspace_gid: str = ""

    # API settings
    timeout: int = 30
    max_retries: int = 3
    page_size: int = 100

    # Collection options
    days_of_history: int = 90

    # Project filter (optional - collect specific projects only)
    project_gids: list[str] = field(default_factory=list)


class AsanaCollector(BaseCollector):
    """
    Asana collector for project management evidence.

    Collects evidence related to:
    - Workspaces and workspace settings
    - Users and user membership
    - Teams and team membership
    - Projects and project configurations
    - Tasks with assignees and due dates
    - Portfolios for strategic planning
    - Goals for OKR tracking
    - Custom fields and templates

    Evidence Types:
    - users: User accounts and workspace membership
    - teams: Team configurations and membership
    - projects: Project definitions and settings
    - tasks: Tasks with details and history
    - portfolios: Portfolio configurations
    - goals: Goal tracking and status
    - workspaces: Workspace configurations

    Resource Types:
    - asana_user: User resources
    - asana_team: Team resources
    - asana_project: Project resources
    - asana_task: Task resources

    Example:
        collector = AsanaCollector(
            config=AsanaCollectorConfig(
                access_token="1/1234567890:abcdef...",
                workspace_gid="1234567890",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["users", "projects", "tasks"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["asana_user", "asana_project"]
        )
    """

    PLATFORM = "asana"
    API_URL = "https://app.asana.com/api/1.0"

    metadata = CollectorMetadata(
        name="AsanaCollector",
        platform="asana",
        description="Collects project management evidence from Asana",
        mode=CollectorMode.BOTH,
        resource_types=[
            "asana_user",
            "asana_team",
            "asana_project",
            "asana_task",
        ],
        evidence_types=[
            "users",
            "teams",
            "projects",
            "tasks",
            "portfolios",
            "goals",
            "workspaces",
        ],
    )

    SUPPORTED_RESOURCE_TYPES = [
        "asana_user",
        "asana_team",
        "asana_project",
        "asana_task",
    ]

    SUPPORTED_EVIDENCE_TYPES = [
        "users",
        "teams",
        "projects",
        "tasks",
        "portfolios",
        "goals",
        "workspaces",
    ]

    # Compliance control mappings
    EVIDENCE_CONTROL_MAPPINGS = {
        "users": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-3", "IA-2"],
            "iso_27001": ["A.9.2.1", "A.9.2.2", "A.9.2.3"],
            "hitrust": ["01.b", "01.c", "01.q"],
        },
        "teams": {
            "soc2": ["CC6.1", "CC6.2"],
            "nist_800_53": ["AC-2", "AC-5", "AC-6"],
            "iso_27001": ["A.6.1.2", "A.9.1.1"],
            "hitrust": ["01.a", "01.c"],
        },
        "projects": {
            "soc2": ["CC6.1", "CC6.2", "CC8.1"],
            "nist_800_53": ["CM-3", "CM-4", "SA-10"],
            "iso_27001": ["A.12.1.2", "A.14.2.2"],
            "hitrust": ["01.c", "09.b"],
        },
        "tasks": {
            "soc2": ["CC8.1", "CC7.2", "CC7.4"],
            "nist_800_53": ["CM-3", "IR-5", "IR-6"],
            "iso_27001": ["A.12.1.2", "A.16.1.5"],
            "hitrust": ["09.b", "11.a"],
        },
        "portfolios": {
            "soc2": ["CC3.1", "CC5.2"],
            "nist_800_53": ["PM-1", "PM-4", "SA-10"],
            "iso_27001": ["A.6.1.1", "A.12.1.2"],
            "hitrust": ["00.a", "09.b"],
        },
        "goals": {
            "soc2": ["CC3.1", "CC3.2", "CC5.2"],
            "nist_800_53": ["PM-1", "PM-6", "PM-9"],
            "iso_27001": ["A.6.1.1", "A.18.2.1"],
            "hitrust": ["00.a", "05.a"],
        },
        "workspaces": {
            "soc2": ["CC6.1", "CC6.6"],
            "nist_800_53": ["AC-2", "AC-6", "CM-2"],
            "iso_27001": ["A.9.1.1", "A.9.1.2"],
            "hitrust": ["01.a", "01.c"],
        },
    }

    def __init__(self, config: AsanaCollectorConfig | None = None):
        """Initialize the Asana collector."""
        self.config = config or AsanaCollectorConfig()
        self._session: requests.Session | None = None
        self._workspaces: list[dict[str, Any]] | None = None

    @property
    def session(self) -> requests.Session:
        """Get or create an authenticated session."""
        if self._session is None:
            self._session = self._create_session()
        return self._session

    def _create_session(self) -> requests.Session:
        """Create an authenticated session with retry logic."""
        if not self.config.access_token:
            raise ConfigurationError("Asana access token is required")

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
        session.headers["Authorization"] = f"Bearer {self.config.access_token}"
        session.headers["Accept"] = "application/json"
        session.headers["Content-Type"] = "application/json"

        return session

    def _api_url(self, endpoint: str) -> str:
        """Build full API URL."""
        return f"{self.API_URL}/{endpoint.lstrip('/')}"

    def _get(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make a GET request to the API."""
        try:
            response = self.session.get(
                self._api_url(endpoint),
                params=params,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as e:
            if e.response.status_code == 401:
                raise ConfigurationError("Invalid Asana access token")
            elif e.response.status_code == 403:
                raise ConfigurationError("Insufficient permissions for Asana API")
            raise CollectionError(f"Asana API error: {e}")
        except requests.RequestException as e:
            raise CollectionError(f"Failed to connect to Asana: {e}")

    def _paginate(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Paginate through API results."""
        params = params or {}
        params["limit"] = self.config.page_size
        offset: str | None = None

        while True:
            if offset:
                params["offset"] = offset

            try:
                response = self.session.get(
                    self._api_url(endpoint),
                    params=params,
                    timeout=self.config.timeout,
                )
                response.raise_for_status()
                data = response.json()

                items = data.get("data", [])
                if not items:
                    break

                for item in items:
                    yield item

                # Check for next page
                next_page = data.get("next_page")
                if next_page and next_page.get("offset"):
                    offset = next_page["offset"]
                else:
                    break

            except requests.RequestException as e:
                logger.warning(f"Pagination error: {e}")
                break

    def _get_workspaces(self) -> list[dict[str, Any]]:
        """Get workspaces for the authenticated user."""
        if self._workspaces is None:
            if self.config.workspace_gid:
                # Fetch specific workspace
                data = self._get(f"workspaces/{self.config.workspace_gid}")
                self._workspaces = [data.get("data", {})]
            else:
                # Fetch all workspaces
                self._workspaces = list(self._paginate("workspaces"))
        return self._workspaces

    def validate_credentials(self) -> bool:
        """Validate Asana credentials."""
        if not self.config.access_token:
            raise ConfigurationError("Asana access token is required")

        try:
            data = self._get("users/me")
            user = data.get("data", {})
            logger.info(f"Authenticated as: {user.get('name', 'Unknown')}")
            return True
        except ConfigurationError:
            raise
        except CollectionError as e:
            raise ConfigurationError(f"Failed to validate Asana credentials: {e}")

    def collect_evidence(
        self,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """Collect evidence from Asana."""
        evidence_types = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        invalid_types = set(evidence_types) - set(self.SUPPORTED_EVIDENCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported evidence types: {invalid_types}")

        logger.info(f"Collecting Asana evidence: {evidence_types}")
        evidence_items: list[Evidence] = []
        errors: list[str] = []

        collection_methods = {
            "users": self._collect_users_evidence,
            "teams": self._collect_teams_evidence,
            "projects": self._collect_projects_evidence,
            "tasks": self._collect_tasks_evidence,
            "portfolios": self._collect_portfolios_evidence,
            "goals": self._collect_goals_evidence,
            "workspaces": self._collect_workspaces_evidence,
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

    def _collect_users_evidence(self) -> Evidence:
        """Collect users evidence."""
        logger.info("Collecting Asana users...")
        users = []

        for workspace in self._get_workspaces():
            workspace_gid = workspace.get("gid")
            if not workspace_gid:
                continue

            params = {
                "workspace": workspace_gid,
                "opt_fields": "gid,name,email,photo,workspaces,resource_type",
            }

            for user in self._paginate("users", params=params):
                users.append({
                    "gid": user.get("gid"),
                    "name": user.get("name"),
                    "email": user.get("email"),
                    "photo": user.get("photo"),
                    "resource_type": user.get("resource_type"),
                    "workspace_gid": workspace_gid,
                    "workspace_name": workspace.get("name"),
                })

        # Deduplicate users (same user may appear in multiple workspaces)
        unique_users = {u["gid"]: u for u in users}.values()

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="users",
            raw_data={
                "users": list(unique_users),
                "total_count": len(list(unique_users)),
            },
            metadata={
                "source": "collector:asana",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["users"],
            },
        )

    def _collect_teams_evidence(self) -> Evidence:
        """Collect teams evidence."""
        logger.info("Collecting Asana teams...")
        teams = []

        for workspace in self._get_workspaces():
            workspace_gid = workspace.get("gid")
            if not workspace_gid:
                continue

            # Only organizations have teams
            if workspace.get("is_organization", False):
                params = {
                    "organization": workspace_gid,
                    "opt_fields": "gid,name,description,html_description,permalink_url,visibility",
                }

                for team in self._paginate("teams", params=params):
                    # Get team members
                    members = []
                    try:
                        member_params = {"opt_fields": "gid,name,email"}
                        for member in self._paginate(f"teams/{team['gid']}/users", params=member_params):
                            members.append({
                                "gid": member.get("gid"),
                                "name": member.get("name"),
                                "email": member.get("email"),
                            })
                    except Exception as e:
                        logger.warning(f"Error fetching team members: {e}")

                    teams.append({
                        "gid": team.get("gid"),
                        "name": team.get("name"),
                        "description": team.get("description"),
                        "permalink_url": team.get("permalink_url"),
                        "visibility": team.get("visibility"),
                        "workspace_gid": workspace_gid,
                        "workspace_name": workspace.get("name"),
                        "members": members,
                        "member_count": len(members),
                    })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="teams",
            raw_data={
                "teams": teams,
                "total_count": len(teams),
            },
            metadata={
                "source": "collector:asana",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["teams"],
            },
        )

    def _collect_projects_evidence(self) -> Evidence:
        """Collect projects evidence."""
        logger.info("Collecting Asana projects...")
        projects = []

        for workspace in self._get_workspaces():
            workspace_gid = workspace.get("gid")
            if not workspace_gid:
                continue

            params = {
                "workspace": workspace_gid,
                "opt_fields": "gid,name,archived,color,created_at,modified_at,notes,owner,public,team,current_status,due_on,start_on,permalink_url,default_view",
            }

            for project in self._paginate("projects", params=params):
                # Filter by project_gids if specified
                if self.config.project_gids and project.get("gid") not in self.config.project_gids:
                    continue

                projects.append({
                    "gid": project.get("gid"),
                    "name": project.get("name"),
                    "archived": project.get("archived", False),
                    "color": project.get("color"),
                    "created_at": project.get("created_at"),
                    "modified_at": project.get("modified_at"),
                    "notes": project.get("notes"),
                    "owner": project.get("owner", {}).get("name") if project.get("owner") else None,
                    "owner_gid": project.get("owner", {}).get("gid") if project.get("owner") else None,
                    "public": project.get("public", False),
                    "team": project.get("team", {}).get("name") if project.get("team") else None,
                    "team_gid": project.get("team", {}).get("gid") if project.get("team") else None,
                    "current_status": project.get("current_status"),
                    "due_on": project.get("due_on"),
                    "start_on": project.get("start_on"),
                    "permalink_url": project.get("permalink_url"),
                    "default_view": project.get("default_view"),
                    "workspace_gid": workspace_gid,
                    "workspace_name": workspace.get("name"),
                })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="projects",
            raw_data={
                "projects": projects,
                "total_count": len(projects),
                "archived_count": sum(1 for p in projects if p.get("archived")),
                "public_count": sum(1 for p in projects if p.get("public")),
            },
            metadata={
                "source": "collector:asana",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["projects"],
            },
        )

    def _collect_tasks_evidence(self) -> Evidence:
        """Collect tasks evidence."""
        logger.info("Collecting Asana tasks...")
        tasks = []
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        cutoff_str = cutoff_date.strftime("%Y-%m-%d")

        for workspace in self._get_workspaces():
            workspace_gid = workspace.get("gid")
            if not workspace_gid:
                continue

            # Get projects first, then tasks from each project
            project_params = {"workspace": workspace_gid, "opt_fields": "gid,name"}

            for project in self._paginate("projects", params=project_params):
                # Filter by project_gids if specified
                if self.config.project_gids and project.get("gid") not in self.config.project_gids:
                    continue

                task_params = {
                    "project": project.get("gid"),
                    "opt_fields": "gid,name,assignee,assignee_status,completed,completed_at,created_at,modified_at,due_on,due_at,start_on,start_at,notes,num_subtasks,parent,permalink_url,resource_subtype,tags,custom_fields",
                    "modified_since": cutoff_str,
                }

                try:
                    for task in self._paginate("tasks", params=task_params):
                        tasks.append(self._normalize_task(task, project, workspace))
                except Exception as e:
                    logger.warning(f"Error fetching tasks for project {project.get('gid')}: {e}")

        # Calculate statistics
        by_status = {"completed": 0, "incomplete": 0}
        overdue_count = 0
        now = datetime.now(timezone.utc).date()

        for task in tasks:
            if task.get("completed"):
                by_status["completed"] += 1
            else:
                by_status["incomplete"] += 1
                if task.get("due_on"):
                    try:
                        due_date = datetime.strptime(task["due_on"], "%Y-%m-%d").date()
                        if due_date < now:
                            overdue_count += 1
                    except ValueError:
                        pass

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="tasks",
            raw_data={
                "tasks": tasks,
                "total_count": len(tasks),
                "by_status": by_status,
                "overdue_count": overdue_count,
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:asana",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["tasks"],
            },
        )

    def _normalize_task(
        self,
        task: dict[str, Any],
        project: dict[str, Any],
        workspace: dict[str, Any],
    ) -> dict[str, Any]:
        """Normalize task data."""
        return {
            "gid": task.get("gid"),
            "name": task.get("name"),
            "assignee": task.get("assignee", {}).get("name") if task.get("assignee") else None,
            "assignee_gid": task.get("assignee", {}).get("gid") if task.get("assignee") else None,
            "assignee_status": task.get("assignee_status"),
            "completed": task.get("completed", False),
            "completed_at": task.get("completed_at"),
            "created_at": task.get("created_at"),
            "modified_at": task.get("modified_at"),
            "due_on": task.get("due_on"),
            "due_at": task.get("due_at"),
            "start_on": task.get("start_on"),
            "start_at": task.get("start_at"),
            "num_subtasks": task.get("num_subtasks", 0),
            "has_parent": task.get("parent") is not None,
            "permalink_url": task.get("permalink_url"),
            "resource_subtype": task.get("resource_subtype"),
            "tags": [tag.get("name") for tag in task.get("tags", [])],
            "project_gid": project.get("gid"),
            "project_name": project.get("name"),
            "workspace_gid": workspace.get("gid"),
            "workspace_name": workspace.get("name"),
        }

    def _collect_portfolios_evidence(self) -> Evidence:
        """Collect portfolios evidence."""
        logger.info("Collecting Asana portfolios...")
        portfolios = []

        for workspace in self._get_workspaces():
            workspace_gid = workspace.get("gid")
            if not workspace_gid:
                continue

            params = {
                "workspace": workspace_gid,
                "opt_fields": "gid,name,color,created_at,owner,public,permalink_url,members,custom_field_settings",
            }

            try:
                for portfolio in self._paginate("portfolios", params=params):
                    # Get portfolio items (projects)
                    items = []
                    try:
                        item_params = {"opt_fields": "gid,name,resource_type"}
                        for item in self._paginate(f"portfolios/{portfolio['gid']}/items", params=item_params):
                            items.append({
                                "gid": item.get("gid"),
                                "name": item.get("name"),
                                "resource_type": item.get("resource_type"),
                            })
                    except Exception as e:
                        logger.warning(f"Error fetching portfolio items: {e}")

                    portfolios.append({
                        "gid": portfolio.get("gid"),
                        "name": portfolio.get("name"),
                        "color": portfolio.get("color"),
                        "created_at": portfolio.get("created_at"),
                        "owner": portfolio.get("owner", {}).get("name") if portfolio.get("owner") else None,
                        "owner_gid": portfolio.get("owner", {}).get("gid") if portfolio.get("owner") else None,
                        "public": portfolio.get("public", False),
                        "permalink_url": portfolio.get("permalink_url"),
                        "members": [m.get("name") for m in portfolio.get("members", [])],
                        "member_count": len(portfolio.get("members", [])),
                        "items": items,
                        "item_count": len(items),
                        "workspace_gid": workspace_gid,
                        "workspace_name": workspace.get("name"),
                    })
            except Exception as e:
                logger.warning(f"Error fetching portfolios: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="portfolios",
            raw_data={
                "portfolios": portfolios,
                "total_count": len(portfolios),
            },
            metadata={
                "source": "collector:asana",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["portfolios"],
            },
        )

    def _collect_goals_evidence(self) -> Evidence:
        """Collect goals evidence."""
        logger.info("Collecting Asana goals...")
        goals = []

        for workspace in self._get_workspaces():
            workspace_gid = workspace.get("gid")
            if not workspace_gid:
                continue

            params = {
                "workspace": workspace_gid,
                "opt_fields": "gid,name,owner,team,time_period,due_on,start_on,status,current_status_update,html_notes,num_likes,is_workspace_level,liked",
            }

            try:
                for goal in self._paginate("goals", params=params):
                    goals.append({
                        "gid": goal.get("gid"),
                        "name": goal.get("name"),
                        "owner": goal.get("owner", {}).get("name") if goal.get("owner") else None,
                        "owner_gid": goal.get("owner", {}).get("gid") if goal.get("owner") else None,
                        "team": goal.get("team", {}).get("name") if goal.get("team") else None,
                        "team_gid": goal.get("team", {}).get("gid") if goal.get("team") else None,
                        "time_period": goal.get("time_period", {}).get("display_name") if goal.get("time_period") else None,
                        "due_on": goal.get("due_on"),
                        "start_on": goal.get("start_on"),
                        "status": goal.get("status"),
                        "is_workspace_level": goal.get("is_workspace_level", False),
                        "num_likes": goal.get("num_likes", 0),
                        "workspace_gid": workspace_gid,
                        "workspace_name": workspace.get("name"),
                    })
            except Exception as e:
                logger.warning(f"Error fetching goals: {e}")

        # Group by status
        by_status = {}
        for goal in goals:
            status = goal.get("status", "unknown")
            by_status[status] = by_status.get(status, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="goals",
            raw_data={
                "goals": goals,
                "total_count": len(goals),
                "by_status": by_status,
            },
            metadata={
                "source": "collector:asana",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["goals"],
            },
        )

    def _collect_workspaces_evidence(self) -> Evidence:
        """Collect workspaces evidence."""
        logger.info("Collecting Asana workspaces...")
        workspaces = []

        for workspace in self._get_workspaces():
            workspace_gid = workspace.get("gid")
            if not workspace_gid:
                continue

            # Get detailed workspace info
            try:
                data = self._get(f"workspaces/{workspace_gid}")
                ws = data.get("data", workspace)
            except Exception:
                ws = workspace

            workspaces.append({
                "gid": ws.get("gid"),
                "name": ws.get("name"),
                "is_organization": ws.get("is_organization", False),
                "email_domains": ws.get("email_domains", []),
            })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="workspaces",
            raw_data={
                "workspaces": workspaces,
                "total_count": len(workspaces),
                "organization_count": sum(1 for w in workspaces if w.get("is_organization")),
            },
            metadata={
                "source": "collector:asana",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["workspaces"],
            },
        )

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """Collect resources from Asana for compliance checks."""
        resource_types = resource_types or self.SUPPORTED_RESOURCE_TYPES
        invalid_types = set(resource_types) - set(self.SUPPORTED_RESOURCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported resource types: {invalid_types}")

        logger.info(f"Collecting Asana resources: {resource_types}")
        resources: list[Resource] = []

        collection_methods = {
            "asana_user": self._collect_user_resources,
            "asana_team": self._collect_team_resources,
            "asana_project": self._collect_project_resources,
            "asana_task": self._collect_task_resources,
        }

        for resource_type in resource_types:
            try:
                method = collection_methods.get(resource_type)
                if method:
                    resources.extend(method())
            except Exception as e:
                logger.error(f"Error collecting {resource_type} resources: {e}")

        return resources

    def _collect_user_resources(self) -> list[Resource]:
        """Collect user resources."""
        logger.info("Collecting Asana user resources...")
        resources = []

        for workspace in self._get_workspaces():
            workspace_gid = workspace.get("gid")
            if not workspace_gid:
                continue

            params = {
                "workspace": workspace_gid,
                "opt_fields": "gid,name,email,photo,resource_type",
            }

            for user in self._paginate("users", params=params):
                resources.append(
                    Resource(
                        id=str(user.get("gid", "")),
                        type="asana_user",
                        provider="asana",
                        region="global",
                        name=user.get("name", "Unknown"),
                        tags={
                            "has_email": str(bool(user.get("email"))).lower(),
                            "has_photo": str(bool(user.get("photo"))).lower(),
                            "workspace_gid": workspace_gid,
                        },
                        metadata={
                            "gid": user.get("gid"),
                            "name": user.get("name"),
                            "email": user.get("email"),
                            "photo": user.get("photo"),
                            "resource_type": user.get("resource_type"),
                            "workspace_gid": workspace_gid,
                            "workspace_name": workspace.get("name"),
                        },
                        raw_data=user,
                    )
                )

        return resources

    def _collect_team_resources(self) -> list[Resource]:
        """Collect team resources."""
        logger.info("Collecting Asana team resources...")
        resources = []

        for workspace in self._get_workspaces():
            workspace_gid = workspace.get("gid")
            if not workspace_gid:
                continue

            if workspace.get("is_organization", False):
                params = {
                    "organization": workspace_gid,
                    "opt_fields": "gid,name,description,permalink_url,visibility",
                }

                for team in self._paginate("teams", params=params):
                    resources.append(
                        Resource(
                            id=str(team.get("gid", "")),
                            type="asana_team",
                            provider="asana",
                            region="global",
                            name=team.get("name", "Unknown"),
                            tags={
                                "visibility": team.get("visibility", "unknown"),
                                "workspace_gid": workspace_gid,
                            },
                            metadata={
                                "gid": team.get("gid"),
                                "name": team.get("name"),
                                "description": team.get("description"),
                                "permalink_url": team.get("permalink_url"),
                                "visibility": team.get("visibility"),
                                "workspace_gid": workspace_gid,
                                "workspace_name": workspace.get("name"),
                            },
                            raw_data=team,
                        )
                    )

        return resources

    def _collect_project_resources(self) -> list[Resource]:
        """Collect project resources."""
        logger.info("Collecting Asana project resources...")
        resources = []

        for workspace in self._get_workspaces():
            workspace_gid = workspace.get("gid")
            if not workspace_gid:
                continue

            params = {
                "workspace": workspace_gid,
                "opt_fields": "gid,name,archived,color,created_at,modified_at,owner,public,team,permalink_url",
            }

            for project in self._paginate("projects", params=params):
                # Filter by project_gids if specified
                if self.config.project_gids and project.get("gid") not in self.config.project_gids:
                    continue

                resources.append(
                    Resource(
                        id=str(project.get("gid", "")),
                        type="asana_project",
                        provider="asana",
                        region="global",
                        name=project.get("name", "Unknown"),
                        tags={
                            "archived": str(project.get("archived", False)).lower(),
                            "public": str(project.get("public", False)).lower(),
                            "has_owner": str(bool(project.get("owner"))).lower(),
                            "workspace_gid": workspace_gid,
                        },
                        metadata={
                            "gid": project.get("gid"),
                            "name": project.get("name"),
                            "archived": project.get("archived", False),
                            "color": project.get("color"),
                            "created_at": project.get("created_at"),
                            "modified_at": project.get("modified_at"),
                            "owner": project.get("owner", {}).get("name") if project.get("owner") else None,
                            "owner_gid": project.get("owner", {}).get("gid") if project.get("owner") else None,
                            "public": project.get("public", False),
                            "team": project.get("team", {}).get("name") if project.get("team") else None,
                            "team_gid": project.get("team", {}).get("gid") if project.get("team") else None,
                            "permalink_url": project.get("permalink_url"),
                            "workspace_gid": workspace_gid,
                            "workspace_name": workspace.get("name"),
                        },
                        raw_data=project,
                    )
                )

        return resources

    def _collect_task_resources(self) -> list[Resource]:
        """Collect task resources (limited set for compliance checks)."""
        logger.info("Collecting Asana task resources...")
        resources = []
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        cutoff_str = cutoff_date.strftime("%Y-%m-%d")

        count = 0
        max_tasks = 1000  # Limit to prevent excessive resource collection

        for workspace in self._get_workspaces():
            workspace_gid = workspace.get("gid")
            if not workspace_gid:
                continue

            project_params = {"workspace": workspace_gid, "opt_fields": "gid,name"}

            for project in self._paginate("projects", params=project_params):
                if count >= max_tasks:
                    break

                # Filter by project_gids if specified
                if self.config.project_gids and project.get("gid") not in self.config.project_gids:
                    continue

                task_params = {
                    "project": project.get("gid"),
                    "opt_fields": "gid,name,assignee,completed,completed_at,created_at,modified_at,due_on,permalink_url",
                    "modified_since": cutoff_str,
                }

                try:
                    for task in self._paginate("tasks", params=task_params):
                        if count >= max_tasks:
                            break

                        resources.append(
                            Resource(
                                id=str(task.get("gid", "")),
                                type="asana_task",
                                provider="asana",
                                region="global",
                                name=task.get("name", "Unknown"),
                                tags={
                                    "completed": str(task.get("completed", False)).lower(),
                                    "has_assignee": str(bool(task.get("assignee"))).lower(),
                                    "has_due_date": str(bool(task.get("due_on"))).lower(),
                                    "project_gid": project.get("gid", ""),
                                },
                                metadata={
                                    "gid": task.get("gid"),
                                    "name": task.get("name"),
                                    "assignee": task.get("assignee", {}).get("name") if task.get("assignee") else None,
                                    "assignee_gid": task.get("assignee", {}).get("gid") if task.get("assignee") else None,
                                    "completed": task.get("completed", False),
                                    "completed_at": task.get("completed_at"),
                                    "created_at": task.get("created_at"),
                                    "modified_at": task.get("modified_at"),
                                    "due_on": task.get("due_on"),
                                    "permalink_url": task.get("permalink_url"),
                                    "project_gid": project.get("gid"),
                                    "project_name": project.get("name"),
                                    "workspace_gid": workspace_gid,
                                    "workspace_name": workspace.get("name"),
                                },
                                raw_data=task,
                            )
                        )
                        count += 1
                except Exception as e:
                    logger.warning(f"Error fetching tasks for project {project.get('gid')}: {e}")

            if count >= max_tasks:
                logger.info(f"Reached max task limit of {max_tasks}")
                break

        return resources
