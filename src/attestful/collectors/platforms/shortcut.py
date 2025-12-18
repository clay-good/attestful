"""
Shortcut collector for Attestful.

Collects project management, issue tracking, and workflow evidence
from Shortcut (formerly Clubhouse) for compliance frameworks including
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
class ShortcutCollectorConfig:
    """Configuration for Shortcut collector."""

    # API token (from Shortcut Settings > API Tokens)
    api_token: str = ""

    # API settings
    timeout: int = 30
    max_retries: int = 3
    page_size: int = 100

    # Collection options
    days_of_history: int = 90


class ShortcutCollector(BaseCollector):
    """
    Shortcut collector for project management evidence.

    Collects evidence related to:
    - Workspaces and workspace settings
    - Members (users) and member permissions
    - Teams and team membership
    - Projects and project configurations
    - Stories (issues) with workflow states
    - Epics for feature planning
    - Iterations (sprints) for agile tracking
    - Milestones for release planning
    - Labels and categories
    - Workflows and workflow states

    Evidence Types:
    - members: User accounts and permissions
    - teams: Team configurations
    - projects: Project definitions
    - stories: Issues/tasks with full details
    - epics: Feature-level planning items
    - iterations: Sprint/iteration configurations
    - workflows: Workflow configurations and states

    Resource Types:
    - shortcut_member: User resources
    - shortcut_team: Team resources
    - shortcut_project: Project resources
    - shortcut_story: Story/issue resources

    Example:
        collector = ShortcutCollector(
            config=ShortcutCollectorConfig(
                api_token="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["members", "projects", "stories"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["shortcut_member", "shortcut_project"]
        )
    """

    PLATFORM = "shortcut"
    API_URL = "https://api.app.shortcut.com/api/v3"

    metadata = CollectorMetadata(
        name="ShortcutCollector",
        platform="shortcut",
        description="Collects project management evidence from Shortcut",
        mode=CollectorMode.BOTH,
        resource_types=[
            "shortcut_member",
            "shortcut_team",
            "shortcut_project",
            "shortcut_story",
        ],
        evidence_types=[
            "members",
            "teams",
            "projects",
            "stories",
            "epics",
            "iterations",
            "workflows",
        ],
    )

    SUPPORTED_RESOURCE_TYPES = [
        "shortcut_member",
        "shortcut_team",
        "shortcut_project",
        "shortcut_story",
    ]

    SUPPORTED_EVIDENCE_TYPES = [
        "members",
        "teams",
        "projects",
        "stories",
        "epics",
        "iterations",
        "workflows",
    ]

    # Compliance control mappings
    EVIDENCE_CONTROL_MAPPINGS = {
        "members": {
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
        "stories": {
            "soc2": ["CC8.1", "CC7.2", "CC7.4"],
            "nist_800_53": ["CM-3", "IR-5", "IR-6"],
            "iso_27001": ["A.12.1.2", "A.16.1.5"],
            "hitrust": ["09.b", "11.a"],
        },
        "epics": {
            "soc2": ["CC8.1", "CC3.1"],
            "nist_800_53": ["CM-3", "SA-10", "SA-11"],
            "iso_27001": ["A.12.1.2", "A.14.2.1"],
            "hitrust": ["09.b", "10.k"],
        },
        "iterations": {
            "soc2": ["CC5.2", "CC8.1"],
            "nist_800_53": ["CM-3", "SA-11"],
            "iso_27001": ["A.12.1.2", "A.14.2.9"],
            "hitrust": ["09.b", "10.l"],
        },
        "workflows": {
            "soc2": ["CC8.1", "CC5.2"],
            "nist_800_53": ["CM-3", "CM-4"],
            "iso_27001": ["A.12.1.2"],
            "hitrust": ["09.b"],
        },
    }

    def __init__(self, config: ShortcutCollectorConfig | None = None):
        """Initialize the Shortcut collector."""
        self.config = config or ShortcutCollectorConfig()
        self._session: requests.Session | None = None

    @property
    def session(self) -> requests.Session:
        """Get or create an authenticated session."""
        if self._session is None:
            self._session = self._create_session()
        return self._session

    def _create_session(self) -> requests.Session:
        """Create an authenticated session with retry logic."""
        if not self.config.api_token:
            raise ConfigurationError("Shortcut API token is required")

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
        session.headers["Shortcut-Token"] = self.config.api_token
        session.headers["Accept"] = "application/json"
        session.headers["Content-Type"] = "application/json"

        return session

    def _api_url(self, endpoint: str) -> str:
        """Build full API URL."""
        return f"{self.API_URL}/{endpoint.lstrip('/')}"

    def _get(self, endpoint: str, params: dict[str, Any] | None = None) -> Any:
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
                raise ConfigurationError("Invalid Shortcut API token")
            raise CollectionError(f"Shortcut API error: {e}")
        except requests.RequestException as e:
            raise CollectionError(f"Failed to connect to Shortcut: {e}")

    def _search_stories(
        self,
        query: str,
        page_size: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Search for stories with pagination."""
        page_size = page_size or self.config.page_size
        next_cursor: str | None = None

        while True:
            payload = {
                "query": query,
                "page_size": page_size,
            }
            if next_cursor:
                payload["next"] = next_cursor

            try:
                response = self.session.post(
                    self._api_url("search/stories"),
                    json=payload,
                    timeout=self.config.timeout,
                )
                response.raise_for_status()
                data = response.json()

                stories = data.get("data", [])
                if not stories:
                    break

                for story in stories:
                    yield story

                next_cursor = data.get("next")
                if not next_cursor:
                    break

            except requests.RequestException as e:
                logger.warning(f"Story search error: {e}")
                break

    def validate_credentials(self) -> bool:
        """Validate Shortcut credentials."""
        if not self.config.api_token:
            raise ConfigurationError("Shortcut API token is required")

        try:
            member = self._get("member")
            logger.info(f"Authenticated as: {member.get('profile', {}).get('name', 'Unknown')}")
            return True
        except ConfigurationError:
            raise
        except CollectionError as e:
            raise ConfigurationError(f"Failed to validate Shortcut credentials: {e}")

    def collect_evidence(
        self,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """Collect evidence from Shortcut."""
        evidence_types = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        invalid_types = set(evidence_types) - set(self.SUPPORTED_EVIDENCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported evidence types: {invalid_types}")

        logger.info(f"Collecting Shortcut evidence: {evidence_types}")
        evidence_items: list[Evidence] = []
        errors: list[str] = []

        collection_methods = {
            "members": self._collect_members_evidence,
            "teams": self._collect_teams_evidence,
            "projects": self._collect_projects_evidence,
            "stories": self._collect_stories_evidence,
            "epics": self._collect_epics_evidence,
            "iterations": self._collect_iterations_evidence,
            "workflows": self._collect_workflows_evidence,
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

    def _collect_members_evidence(self) -> Evidence:
        """Collect members evidence."""
        logger.info("Collecting Shortcut members...")
        members = self._get("members")

        member_list = []
        for member in members:
            profile = member.get("profile", {})
            member_list.append({
                "id": member.get("id"),
                "name": profile.get("name"),
                "email_address": profile.get("email_address"),
                "mention_name": profile.get("mention_name"),
                "role": member.get("role"),
                "state": member.get("state"),
                "disabled": member.get("disabled", False),
                "created_at": member.get("created_at"),
                "updated_at": member.get("updated_at"),
                "two_factor_auth_activated": profile.get("two_factor_auth_activated"),
            })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="members",
            raw_data={
                "members": member_list,
                "total_count": len(member_list),
                "active_count": sum(1 for m in member_list if not m.get("disabled")),
                "disabled_count": sum(1 for m in member_list if m.get("disabled")),
                "mfa_enabled_count": sum(1 for m in member_list if m.get("two_factor_auth_activated")),
            },
            metadata={
                "source": "collector:shortcut",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["members"],
            },
        )

    def _collect_teams_evidence(self) -> Evidence:
        """Collect teams evidence."""
        logger.info("Collecting Shortcut teams...")
        teams_data = self._get("groups")  # Shortcut calls teams "groups"

        teams = []
        for team in teams_data:
            teams.append({
                "id": team.get("id"),
                "name": team.get("name"),
                "description": team.get("description"),
                "mention_name": team.get("mention_name"),
                "color": team.get("color"),
                "member_ids": team.get("member_ids", []),
                "workflow_ids": team.get("workflow_ids", []),
                "num_stories_started": team.get("num_stories_started"),
                "archived": team.get("archived", False),
            })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="teams",
            raw_data={
                "teams": teams,
                "total_count": len(teams),
                "active_count": sum(1 for t in teams if not t.get("archived")),
            },
            metadata={
                "source": "collector:shortcut",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["teams"],
            },
        )

    def _collect_projects_evidence(self) -> Evidence:
        """Collect projects evidence."""
        logger.info("Collecting Shortcut projects...")
        projects_data = self._get("projects")

        projects = []
        for project in projects_data:
            projects.append({
                "id": project.get("id"),
                "name": project.get("name"),
                "description": project.get("description"),
                "abbreviation": project.get("abbreviation"),
                "color": project.get("color"),
                "team_id": project.get("team_id"),
                "iteration_length": project.get("iteration_length"),
                "start_time": project.get("start_time"),
                "archived": project.get("archived", False),
                "created_at": project.get("created_at"),
                "updated_at": project.get("updated_at"),
                "follower_ids": project.get("follower_ids", []),
                "stats": project.get("stats", {}),
            })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="projects",
            raw_data={
                "projects": projects,
                "total_count": len(projects),
                "active_count": sum(1 for p in projects if not p.get("archived")),
            },
            metadata={
                "source": "collector:shortcut",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["projects"],
            },
        )

    def _collect_stories_evidence(self) -> Evidence:
        """Collect stories evidence."""
        logger.info("Collecting Shortcut stories...")
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        cutoff_str = cutoff_date.strftime("%Y-%m-%d")

        stories = []
        query = f"updated:>{cutoff_str}"

        for story in self._search_stories(query):
            stories.append(self._normalize_story(story))

        # Calculate statistics
        by_type = {}
        by_state = {}
        for story in stories:
            story_type = story.get("story_type", "unknown")
            state = story.get("workflow_state_name", "unknown")
            by_type[story_type] = by_type.get(story_type, 0) + 1
            by_state[state] = by_state.get(state, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="stories",
            raw_data={
                "stories": stories,
                "total_count": len(stories),
                "by_type": by_type,
                "by_state": by_state,
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:shortcut",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["stories"],
            },
        )

    def _normalize_story(self, story: dict[str, Any]) -> dict[str, Any]:
        """Normalize story data."""
        return {
            "id": story.get("id"),
            "name": story.get("name"),
            "story_type": story.get("story_type"),
            "workflow_state_id": story.get("workflow_state_id"),
            "workflow_state_name": story.get("workflow_state", {}).get("name") if story.get("workflow_state") else None,
            "epic_id": story.get("epic_id"),
            "project_id": story.get("project_id"),
            "iteration_id": story.get("iteration_id"),
            "estimate": story.get("estimate"),
            "started": story.get("started", False),
            "completed": story.get("completed", False),
            "blocked": story.get("blocked", False),
            "blocker": story.get("blocker", False),
            "archived": story.get("archived", False),
            "owner_ids": story.get("owner_ids", []),
            "follower_ids": story.get("follower_ids", []),
            "requested_by_id": story.get("requested_by_id"),
            "labels": [label.get("name") for label in story.get("labels", [])],
            "created_at": story.get("created_at"),
            "updated_at": story.get("updated_at"),
            "started_at": story.get("started_at"),
            "completed_at": story.get("completed_at"),
            "deadline": story.get("deadline"),
        }

    def _collect_epics_evidence(self) -> Evidence:
        """Collect epics evidence."""
        logger.info("Collecting Shortcut epics...")
        epics_data = self._get("epics")

        epics = []
        for epic in epics_data:
            epics.append({
                "id": epic.get("id"),
                "name": epic.get("name"),
                "description": epic.get("description"),
                "state": epic.get("state"),
                "milestone_id": epic.get("milestone_id"),
                "team_ids": epic.get("group_ids", []),  # group_ids are team IDs
                "owner_ids": epic.get("owner_ids", []),
                "follower_ids": epic.get("follower_ids", []),
                "planned_start_date": epic.get("planned_start_date"),
                "deadline": epic.get("deadline"),
                "started": epic.get("started", False),
                "completed": epic.get("completed", False),
                "archived": epic.get("archived", False),
                "created_at": epic.get("created_at"),
                "updated_at": epic.get("updated_at"),
                "completed_at": epic.get("completed_at"),
                "stats": epic.get("stats", {}),
                "labels": [label.get("name") for label in epic.get("labels", [])],
            })

        # Group by state
        by_state = {}
        for epic in epics:
            state = epic.get("state", "unknown")
            by_state[state] = by_state.get(state, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="epics",
            raw_data={
                "epics": epics,
                "total_count": len(epics),
                "by_state": by_state,
                "active_count": sum(1 for e in epics if not e.get("archived") and not e.get("completed")),
            },
            metadata={
                "source": "collector:shortcut",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["epics"],
            },
        )

    def _collect_iterations_evidence(self) -> Evidence:
        """Collect iterations evidence."""
        logger.info("Collecting Shortcut iterations...")
        iterations_data = self._get("iterations")

        iterations = []
        for iteration in iterations_data:
            iterations.append({
                "id": iteration.get("id"),
                "name": iteration.get("name"),
                "description": iteration.get("description"),
                "status": iteration.get("status"),
                "team_ids": iteration.get("group_ids", []),
                "follower_ids": iteration.get("follower_ids", []),
                "start_date": iteration.get("start_date"),
                "end_date": iteration.get("end_date"),
                "created_at": iteration.get("created_at"),
                "updated_at": iteration.get("updated_at"),
                "stats": iteration.get("stats", {}),
                "labels": [label.get("name") for label in iteration.get("labels", [])],
            })

        # Group by status
        by_status = {}
        for iteration in iterations:
            status = iteration.get("status", "unknown")
            by_status[status] = by_status.get(status, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="iterations",
            raw_data={
                "iterations": iterations,
                "total_count": len(iterations),
                "by_status": by_status,
            },
            metadata={
                "source": "collector:shortcut",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["iterations"],
            },
        )

    def _collect_workflows_evidence(self) -> Evidence:
        """Collect workflows evidence."""
        logger.info("Collecting Shortcut workflows...")
        workflows_data = self._get("workflows")

        workflows = []
        for workflow in workflows_data:
            states = []
            for state in workflow.get("states", []):
                states.append({
                    "id": state.get("id"),
                    "name": state.get("name"),
                    "description": state.get("description"),
                    "type": state.get("type"),
                    "position": state.get("position"),
                    "color": state.get("color"),
                    "num_stories": state.get("num_stories"),
                })

            workflows.append({
                "id": workflow.get("id"),
                "name": workflow.get("name"),
                "description": workflow.get("description"),
                "team_id": workflow.get("team_id"),
                "default_state_id": workflow.get("default_state_id"),
                "auto_assign_owner": workflow.get("auto_assign_owner", False),
                "created_at": workflow.get("created_at"),
                "updated_at": workflow.get("updated_at"),
                "states": states,
            })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="workflows",
            raw_data={
                "workflows": workflows,
                "total_count": len(workflows),
            },
            metadata={
                "source": "collector:shortcut",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["workflows"],
            },
        )

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """Collect resources from Shortcut for compliance checks."""
        resource_types = resource_types or self.SUPPORTED_RESOURCE_TYPES
        invalid_types = set(resource_types) - set(self.SUPPORTED_RESOURCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported resource types: {invalid_types}")

        logger.info(f"Collecting Shortcut resources: {resource_types}")
        resources: list[Resource] = []

        collection_methods = {
            "shortcut_member": self._collect_member_resources,
            "shortcut_team": self._collect_team_resources,
            "shortcut_project": self._collect_project_resources,
            "shortcut_story": self._collect_story_resources,
        }

        for resource_type in resource_types:
            try:
                method = collection_methods.get(resource_type)
                if method:
                    resources.extend(method())
            except Exception as e:
                logger.error(f"Error collecting {resource_type} resources: {e}")

        return resources

    def _collect_member_resources(self) -> list[Resource]:
        """Collect member resources."""
        logger.info("Collecting Shortcut member resources...")
        resources = []
        members = self._get("members")

        for member in members:
            profile = member.get("profile", {})
            resources.append(
                Resource(
                    id=str(member.get("id", "")),
                    type="shortcut_member",
                    provider="shortcut",
                    region="global",
                    name=profile.get("name", "Unknown"),
                    tags={
                        "role": member.get("role", "unknown"),
                        "state": member.get("state", "unknown"),
                        "disabled": str(member.get("disabled", False)).lower(),
                        "mfa_enabled": str(profile.get("two_factor_auth_activated", False)).lower(),
                    },
                    metadata={
                        "id": member.get("id"),
                        "name": profile.get("name"),
                        "email_address": profile.get("email_address"),
                        "mention_name": profile.get("mention_name"),
                        "role": member.get("role"),
                        "state": member.get("state"),
                        "disabled": member.get("disabled", False),
                        "two_factor_auth_activated": profile.get("two_factor_auth_activated"),
                        "created_at": member.get("created_at"),
                        "updated_at": member.get("updated_at"),
                    },
                    raw_data=member,
                )
            )

        return resources

    def _collect_team_resources(self) -> list[Resource]:
        """Collect team resources."""
        logger.info("Collecting Shortcut team resources...")
        resources = []
        teams = self._get("groups")

        for team in teams:
            resources.append(
                Resource(
                    id=str(team.get("id", "")),
                    type="shortcut_team",
                    provider="shortcut",
                    region="global",
                    name=team.get("name", "Unknown"),
                    tags={
                        "archived": str(team.get("archived", False)).lower(),
                        "member_count": str(len(team.get("member_ids", []))),
                    },
                    metadata={
                        "id": team.get("id"),
                        "name": team.get("name"),
                        "description": team.get("description"),
                        "mention_name": team.get("mention_name"),
                        "color": team.get("color"),
                        "member_ids": team.get("member_ids", []),
                        "workflow_ids": team.get("workflow_ids", []),
                        "archived": team.get("archived", False),
                    },
                    raw_data=team,
                )
            )

        return resources

    def _collect_project_resources(self) -> list[Resource]:
        """Collect project resources."""
        logger.info("Collecting Shortcut project resources...")
        resources = []
        projects = self._get("projects")

        for project in projects:
            resources.append(
                Resource(
                    id=str(project.get("id", "")),
                    type="shortcut_project",
                    provider="shortcut",
                    region="global",
                    name=project.get("name", "Unknown"),
                    tags={
                        "archived": str(project.get("archived", False)).lower(),
                        "abbreviation": project.get("abbreviation", ""),
                    },
                    metadata={
                        "id": project.get("id"),
                        "name": project.get("name"),
                        "description": project.get("description"),
                        "abbreviation": project.get("abbreviation"),
                        "color": project.get("color"),
                        "team_id": project.get("team_id"),
                        "iteration_length": project.get("iteration_length"),
                        "archived": project.get("archived", False),
                        "created_at": project.get("created_at"),
                        "updated_at": project.get("updated_at"),
                        "stats": project.get("stats", {}),
                    },
                    raw_data=project,
                )
            )

        return resources

    def _collect_story_resources(self) -> list[Resource]:
        """Collect story resources (limited set for compliance checks)."""
        logger.info("Collecting Shortcut story resources...")
        resources = []
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        cutoff_str = cutoff_date.strftime("%Y-%m-%d")

        query = f"updated:>{cutoff_str}"
        count = 0
        max_stories = 1000  # Limit to prevent excessive resource collection

        for story in self._search_stories(query):
            if count >= max_stories:
                logger.info(f"Reached max story limit of {max_stories}")
                break

            resources.append(
                Resource(
                    id=str(story.get("id", "")),
                    type="shortcut_story",
                    provider="shortcut",
                    region="global",
                    name=story.get("name", "Unknown"),
                    tags={
                        "story_type": story.get("story_type", "unknown"),
                        "completed": str(story.get("completed", False)).lower(),
                        "started": str(story.get("started", False)).lower(),
                        "blocked": str(story.get("blocked", False)).lower(),
                        "archived": str(story.get("archived", False)).lower(),
                    },
                    metadata={
                        "id": story.get("id"),
                        "name": story.get("name"),
                        "story_type": story.get("story_type"),
                        "workflow_state_id": story.get("workflow_state_id"),
                        "epic_id": story.get("epic_id"),
                        "project_id": story.get("project_id"),
                        "iteration_id": story.get("iteration_id"),
                        "estimate": story.get("estimate"),
                        "started": story.get("started", False),
                        "completed": story.get("completed", False),
                        "blocked": story.get("blocked", False),
                        "archived": story.get("archived", False),
                        "owner_ids": story.get("owner_ids", []),
                        "requested_by_id": story.get("requested_by_id"),
                        "labels": [label.get("name") for label in story.get("labels", [])],
                        "created_at": story.get("created_at"),
                        "updated_at": story.get("updated_at"),
                    },
                    raw_data=story,
                )
            )
            count += 1

        return resources
