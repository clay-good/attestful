"""
Linear collector for Attestful.

Collects project management, issue tracking, and team collaboration evidence
from Linear for compliance frameworks including SOC 2, NIST 800-53,
ISO 27001, and HITRUST.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from attestful.collectors.base import BaseCollector, CollectorMetadata, CollectorMode
from attestful.core.exceptions import CollectionError, ConfigurationError
from attestful.core.logging import get_logger
from attestful.core.models import CollectionResult, Evidence, Resource

logger = get_logger(__name__)


@dataclass
class LinearCollectorConfig:
    """Configuration for Linear collector."""

    # Linear API key
    api_key: str = ""

    # API settings
    timeout: int = 30
    max_retries: int = 3
    page_size: int = 100

    # Collection options
    days_of_history: int = 90


class LinearCollector(BaseCollector):
    """
    Linear collector for project management and issue tracking evidence.

    Collects evidence related to:
    - Users and their roles
    - Teams and their configurations
    - Projects and roadmaps
    - Issues and their states
    - Cycles (sprints)
    - Audit logs (activity tracking)

    Evidence Types:
    - users: Linear users with roles
    - teams: Teams and their members
    - projects: Projects and milestones
    - issues: Issues metadata and states
    - cycles: Cycles (sprints) data
    - audit_logs: Activity and change logs

    Resource Types:
    - linear_user: User resources
    - linear_team: Team resources
    - linear_project: Project resources
    - linear_issue: Issue resources

    Example:
        collector = LinearCollector(
            config=LinearCollectorConfig(
                api_key="lin_api_xxx",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["users", "teams", "issues"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["linear_user", "linear_team"]
        )
    """

    PLATFORM = "linear"

    metadata = CollectorMetadata(
        name="LinearCollector",
        platform="linear",
        description="Collects project management and issue tracking evidence from Linear",
        mode=CollectorMode.BOTH,
        resource_types=[
            "linear_user",
            "linear_team",
            "linear_project",
            "linear_issue",
        ],
        evidence_types=[
            "users",
            "teams",
            "projects",
            "issues",
            "cycles",
            "audit_logs",
        ],
    )

    SUPPORTED_RESOURCE_TYPES = [
        "linear_user",
        "linear_team",
        "linear_project",
        "linear_issue",
    ]

    SUPPORTED_EVIDENCE_TYPES = [
        "users",
        "teams",
        "projects",
        "issues",
        "cycles",
        "audit_logs",
    ]

    # Compliance control mappings
    EVIDENCE_CONTROL_MAPPINGS = {
        "users": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-3", "IA-2", "IA-4"],
            "iso_27001": ["A.9.2.1", "A.9.2.2", "A.9.2.3"],
            "hitrust": ["01.b", "01.c", "01.d"],
        },
        "teams": {
            "soc2": ["CC6.1", "CC6.3", "CC5.3"],
            "nist_800_53": ["AC-2", "AC-6", "PM-10"],
            "iso_27001": ["A.6.1.1", "A.9.2.1"],
            "hitrust": ["01.c", "01.d", "05.a"],
        },
        "projects": {
            "soc2": ["CC5.2", "CC5.3", "CC3.1"],
            "nist_800_53": ["CM-3", "PM-4", "SA-3"],
            "iso_27001": ["A.6.1.5", "A.12.1.1", "A.14.2.2"],
            "hitrust": ["03.a", "09.b", "10.k"],
        },
        "issues": {
            "soc2": ["CC5.2", "CC7.4", "CC8.1"],
            "nist_800_53": ["CM-3", "CM-4", "SI-2"],
            "iso_27001": ["A.12.6.1", "A.14.2.2", "A.14.2.3"],
            "hitrust": ["09.b", "10.c", "10.m"],
        },
        "cycles": {
            "soc2": ["CC5.2", "CC5.3"],
            "nist_800_53": ["PM-4", "SA-3"],
            "iso_27001": ["A.6.1.5", "A.14.2.1"],
            "hitrust": ["03.a", "10.k"],
        },
        "audit_logs": {
            "soc2": ["CC7.2", "CC7.3", "CC7.4"],
            "nist_800_53": ["AU-2", "AU-3", "AU-6", "AU-12"],
            "iso_27001": ["A.12.4.1", "A.12.4.3"],
            "hitrust": ["09.aa", "09.ab"],
        },
    }

    # GraphQL API endpoint
    API_URL = "https://api.linear.app/graphql"

    def __init__(self, config: LinearCollectorConfig | None = None):
        """Initialize the Linear collector."""
        self.config = config or LinearCollectorConfig()
        self._session: requests.Session | None = None

    @property
    def session(self) -> requests.Session:
        """Get or create an authenticated session."""
        if self._session is None:
            self._session = self._create_session()
        return self._session

    def _create_session(self) -> requests.Session:
        """Create an authenticated session with retry logic."""
        if not self.config.api_key:
            raise ConfigurationError("Linear API key not configured")

        session = requests.Session()

        # Configure retries
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["POST"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)

        # Set authentication header
        session.headers["Authorization"] = self.config.api_key
        session.headers["Content-Type"] = "application/json"

        return session

    def _graphql_query(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a GraphQL query."""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        try:
            response = self.session.post(
                self.API_URL,
                json=payload,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            data = response.json()

            if "errors" in data:
                errors = data["errors"]
                error_msg = errors[0].get("message", "Unknown GraphQL error") if errors else "Unknown error"
                raise requests.RequestException(f"GraphQL error: {error_msg}")

            return data.get("data", {})
        except requests.RequestException as e:
            logger.warning(f"GraphQL query failed: {e}")
            raise

    def _paginate_query(
        self,
        query: str,
        data_path: str,
        variables: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a paginated GraphQL query."""
        variables = variables or {}
        variables["first"] = self.config.page_size
        all_items: list[dict[str, Any]] = []
        cursor = None

        while True:
            if cursor:
                variables["after"] = cursor

            try:
                data = self._graphql_query(query, variables)

                # Navigate to the data using the path
                result = data
                for key in data_path.split("."):
                    result = result.get(key, {})

                nodes = result.get("nodes", [])
                all_items.extend(nodes)

                # Check for next page
                page_info = result.get("pageInfo", {})
                if not page_info.get("hasNextPage"):
                    break

                cursor = page_info.get("endCursor")
                if not cursor:
                    break

            except requests.RequestException:
                break

        return all_items

    def validate_credentials(self) -> bool:
        """Validate Linear credentials."""
        query = """
        query {
            viewer {
                id
                name
                email
            }
        }
        """

        try:
            data = self._graphql_query(query)
            viewer = data.get("viewer", {})
            logger.info(f"Linear credentials validated for {viewer.get('email')}")
            return True
        except Exception as e:
            raise ConfigurationError(f"Failed to validate Linear credentials: {e}")

    def collect_evidence(
        self,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """Collect evidence from Linear."""
        evidence_types = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        invalid_types = set(evidence_types) - set(self.SUPPORTED_EVIDENCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported evidence types: {invalid_types}")

        logger.info(f"Collecting Linear evidence: {evidence_types}")
        evidence_items: list[Evidence] = []
        errors: list[str] = []

        collection_methods = {
            "users": self._collect_users_evidence,
            "teams": self._collect_teams_evidence,
            "projects": self._collect_projects_evidence,
            "issues": self._collect_issues_evidence,
            "cycles": self._collect_cycles_evidence,
            "audit_logs": self._collect_audit_logs_evidence,
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
        logger.info("Collecting Linear users...")

        query = """
        query($first: Int!, $after: String) {
            users(first: $first, after: $after) {
                nodes {
                    id
                    name
                    displayName
                    email
                    active
                    admin
                    guest
                    createdAt
                    lastSeen
                    avatarUrl
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        """

        users = []
        try:
            users = self._paginate_query(query, "users")
        except Exception as e:
            logger.warning(f"Error collecting users: {e}")

        # Calculate statistics
        active_count = sum(1 for u in users if u.get("active", False))
        admin_count = sum(1 for u in users if u.get("admin", False))
        guest_count = sum(1 for u in users if u.get("guest", False))

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="users",
            raw_data={
                "users": users,
                "total_count": len(users),
                "active_count": active_count,
                "admin_count": admin_count,
                "guest_count": guest_count,
                "inactive_count": len(users) - active_count,
            },
            metadata={
                "source": "collector:linear",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["users"],
            },
        )

    def _collect_teams_evidence(self) -> Evidence:
        """Collect teams evidence."""
        logger.info("Collecting Linear teams...")

        query = """
        query($first: Int!, $after: String) {
            teams(first: $first, after: $after) {
                nodes {
                    id
                    name
                    key
                    description
                    private
                    createdAt
                    members {
                        nodes {
                            id
                            name
                            email
                        }
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        """

        teams = []
        try:
            teams = self._paginate_query(query, "teams")
        except Exception as e:
            logger.warning(f"Error collecting teams: {e}")

        # Normalize team data
        normalized_teams = []
        for team in teams:
            members = team.get("members", {}).get("nodes", [])
            normalized_teams.append({
                "id": team.get("id"),
                "name": team.get("name"),
                "key": team.get("key"),
                "description": team.get("description"),
                "private": team.get("private", False),
                "created_at": team.get("createdAt"),
                "member_count": len(members),
                "members": [
                    {"id": m.get("id"), "name": m.get("name"), "email": m.get("email")}
                    for m in members
                ],
            })

        # Calculate statistics
        private_count = sum(1 for t in normalized_teams if t.get("private", False))

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="teams",
            raw_data={
                "teams": normalized_teams,
                "total_count": len(normalized_teams),
                "private_count": private_count,
                "public_count": len(normalized_teams) - private_count,
            },
            metadata={
                "source": "collector:linear",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["teams"],
            },
        )

    def _collect_projects_evidence(self) -> Evidence:
        """Collect projects evidence."""
        logger.info("Collecting Linear projects...")

        query = """
        query($first: Int!, $after: String) {
            projects(first: $first, after: $after) {
                nodes {
                    id
                    name
                    description
                    state
                    progress
                    startDate
                    targetDate
                    createdAt
                    updatedAt
                    lead {
                        id
                        name
                        email
                    }
                    teams {
                        nodes {
                            id
                            name
                        }
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        """

        projects = []
        try:
            projects = self._paginate_query(query, "projects")
        except Exception as e:
            logger.warning(f"Error collecting projects: {e}")

        # Normalize project data
        normalized_projects = []
        state_counts: dict[str, int] = {}

        for project in projects:
            state = project.get("state", "unknown")
            state_counts[state] = state_counts.get(state, 0) + 1

            lead = project.get("lead", {})
            teams = project.get("teams", {}).get("nodes", [])

            normalized_projects.append({
                "id": project.get("id"),
                "name": project.get("name"),
                "description": project.get("description"),
                "state": state,
                "progress": project.get("progress"),
                "start_date": project.get("startDate"),
                "target_date": project.get("targetDate"),
                "created_at": project.get("createdAt"),
                "updated_at": project.get("updatedAt"),
                "lead": {
                    "id": lead.get("id"),
                    "name": lead.get("name"),
                    "email": lead.get("email"),
                } if lead else None,
                "teams": [{"id": t.get("id"), "name": t.get("name")} for t in teams],
            })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="projects",
            raw_data={
                "projects": normalized_projects,
                "total_count": len(normalized_projects),
                "state_breakdown": state_counts,
            },
            metadata={
                "source": "collector:linear",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["projects"],
            },
        )

    def _collect_issues_evidence(self) -> Evidence:
        """Collect issues evidence."""
        logger.info("Collecting Linear issues...")

        # Get issues from the configured history period
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        cutoff_iso = cutoff_date.isoformat()

        query = """
        query($first: Int!, $after: String, $filter: IssueFilter) {
            issues(first: $first, after: $after, filter: $filter) {
                nodes {
                    id
                    identifier
                    title
                    priority
                    state {
                        id
                        name
                        type
                    }
                    assignee {
                        id
                        name
                        email
                    }
                    creator {
                        id
                        name
                    }
                    team {
                        id
                        name
                    }
                    project {
                        id
                        name
                    }
                    createdAt
                    updatedAt
                    completedAt
                    labels {
                        nodes {
                            id
                            name
                        }
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        """

        issues = []
        try:
            issues = self._paginate_query(
                query,
                "issues",
                variables={"filter": {"updatedAt": {"gte": cutoff_iso}}},
            )
        except Exception as e:
            logger.warning(f"Error collecting issues: {e}")

        # Normalize and analyze issues
        normalized_issues = []
        state_counts: dict[str, int] = {}
        priority_counts: dict[int, int] = {}

        for issue in issues:
            state = issue.get("state", {})
            state_name = state.get("name", "unknown")
            state_type = state.get("type", "unknown")
            state_counts[state_name] = state_counts.get(state_name, 0) + 1

            priority = issue.get("priority", 0)
            priority_counts[priority] = priority_counts.get(priority, 0) + 1

            assignee = issue.get("assignee", {})
            creator = issue.get("creator", {})
            team = issue.get("team", {})
            project = issue.get("project", {})
            labels = issue.get("labels", {}).get("nodes", [])

            normalized_issues.append({
                "id": issue.get("id"),
                "identifier": issue.get("identifier"),
                "title": issue.get("title"),
                "priority": priority,
                "state": state_name,
                "state_type": state_type,
                "assignee": {
                    "id": assignee.get("id"),
                    "name": assignee.get("name"),
                    "email": assignee.get("email"),
                } if assignee else None,
                "creator": {
                    "id": creator.get("id"),
                    "name": creator.get("name"),
                } if creator else None,
                "team": {
                    "id": team.get("id"),
                    "name": team.get("name"),
                } if team else None,
                "project": {
                    "id": project.get("id"),
                    "name": project.get("name"),
                } if project else None,
                "created_at": issue.get("createdAt"),
                "updated_at": issue.get("updatedAt"),
                "completed_at": issue.get("completedAt"),
                "labels": [{"id": l.get("id"), "name": l.get("name")} for l in labels],
            })

        # Calculate metrics
        completed_count = sum(1 for i in normalized_issues if i.get("completed_at"))
        unassigned_count = sum(1 for i in normalized_issues if not i.get("assignee"))

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="issues",
            raw_data={
                "issues": normalized_issues,
                "total_count": len(normalized_issues),
                "state_breakdown": state_counts,
                "priority_breakdown": priority_counts,
                "completed_count": completed_count,
                "unassigned_count": unassigned_count,
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:linear",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["issues"],
            },
        )

    def _collect_cycles_evidence(self) -> Evidence:
        """Collect cycles (sprints) evidence."""
        logger.info("Collecting Linear cycles...")

        query = """
        query($first: Int!, $after: String) {
            cycles(first: $first, after: $after) {
                nodes {
                    id
                    name
                    number
                    startsAt
                    endsAt
                    completedAt
                    progress
                    scopeHistory
                    completedScopeHistory
                    team {
                        id
                        name
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        """

        cycles = []
        try:
            cycles = self._paginate_query(query, "cycles")
        except Exception as e:
            logger.warning(f"Error collecting cycles: {e}")

        # Normalize cycle data
        normalized_cycles = []
        for cycle in cycles:
            team = cycle.get("team", {})
            normalized_cycles.append({
                "id": cycle.get("id"),
                "name": cycle.get("name"),
                "number": cycle.get("number"),
                "starts_at": cycle.get("startsAt"),
                "ends_at": cycle.get("endsAt"),
                "completed_at": cycle.get("completedAt"),
                "progress": cycle.get("progress"),
                "team": {
                    "id": team.get("id"),
                    "name": team.get("name"),
                } if team else None,
            })

        # Calculate statistics
        completed_count = sum(1 for c in normalized_cycles if c.get("completed_at"))
        in_progress_count = sum(
            1 for c in normalized_cycles
            if not c.get("completed_at") and c.get("starts_at")
        )

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="cycles",
            raw_data={
                "cycles": normalized_cycles,
                "total_count": len(normalized_cycles),
                "completed_count": completed_count,
                "in_progress_count": in_progress_count,
            },
            metadata={
                "source": "collector:linear",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["cycles"],
            },
        )

    def _collect_audit_logs_evidence(self) -> Evidence:
        """Collect audit logs evidence."""
        logger.info("Collecting Linear audit logs...")

        # Linear doesn't have a direct audit log API in their public GraphQL schema
        # We'll collect issue history as a proxy for change tracking
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        cutoff_iso = cutoff_date.isoformat()

        query = """
        query($first: Int!, $after: String, $filter: IssueFilter) {
            issues(first: $first, after: $after, filter: $filter, orderBy: updatedAt) {
                nodes {
                    id
                    identifier
                    title
                    updatedAt
                    history(first: 50) {
                        nodes {
                            id
                            createdAt
                            actorId
                            fromState {
                                id
                                name
                            }
                            toState {
                                id
                                name
                            }
                            fromAssignee {
                                id
                                name
                            }
                            toAssignee {
                                id
                                name
                            }
                        }
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        """

        audit_events = []
        event_types: dict[str, int] = {}

        try:
            issues = self._paginate_query(
                query,
                "issues",
                variables={"filter": {"updatedAt": {"gte": cutoff_iso}}},
            )

            for issue in issues:
                history = issue.get("history", {}).get("nodes", [])
                for event in history:
                    event_type = "unknown"

                    # Determine event type based on changes
                    if event.get("fromState") or event.get("toState"):
                        event_type = "state_change"
                    elif event.get("fromAssignee") or event.get("toAssignee"):
                        event_type = "assignee_change"
                    else:
                        event_type = "update"

                    event_types[event_type] = event_types.get(event_type, 0) + 1

                    audit_events.append({
                        "id": event.get("id"),
                        "issue_id": issue.get("id"),
                        "issue_identifier": issue.get("identifier"),
                        "timestamp": event.get("createdAt"),
                        "actor_id": event.get("actorId"),
                        "event_type": event_type,
                        "from_state": event.get("fromState", {}).get("name") if event.get("fromState") else None,
                        "to_state": event.get("toState", {}).get("name") if event.get("toState") else None,
                        "from_assignee": event.get("fromAssignee", {}).get("name") if event.get("fromAssignee") else None,
                        "to_assignee": event.get("toAssignee", {}).get("name") if event.get("toAssignee") else None,
                    })

        except Exception as e:
            logger.warning(f"Error collecting audit logs: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="audit_logs",
            raw_data={
                "events": audit_events,
                "total_count": len(audit_events),
                "event_types": event_types,
                "days_of_history": self.config.days_of_history,
                "note": "Derived from issue history - Linear does not expose direct audit logs",
            },
            metadata={
                "source": "collector:linear",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["audit_logs"],
            },
        )

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """Collect resources from Linear for compliance checks."""
        resource_types = resource_types or self.SUPPORTED_RESOURCE_TYPES
        invalid_types = set(resource_types) - set(self.SUPPORTED_RESOURCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported resource types: {invalid_types}")

        logger.info(f"Collecting Linear resources: {resource_types}")
        resources: list[Resource] = []

        collection_methods = {
            "linear_user": self._collect_user_resources,
            "linear_team": self._collect_team_resources,
            "linear_project": self._collect_project_resources,
            "linear_issue": self._collect_issue_resources,
        }

        for resource_type in resource_types:
            try:
                method = collection_methods.get(resource_type)
                if method:
                    resources.extend(method())
            except Exception as e:
                logger.error(f"Error collecting {resource_type}: {e}")

        return resources

    def _collect_user_resources(self) -> list[Resource]:
        """Collect user resources."""
        logger.info("Collecting Linear user resources...")

        query = """
        query($first: Int!, $after: String) {
            users(first: $first, after: $after) {
                nodes {
                    id
                    name
                    displayName
                    email
                    active
                    admin
                    guest
                    createdAt
                    lastSeen
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        """

        resources = []
        try:
            users = self._paginate_query(query, "users")

            for user in users:
                # Determine role
                if user.get("admin"):
                    role = "admin"
                elif user.get("guest"):
                    role = "guest"
                else:
                    role = "member"

                resources.append(
                    Resource(
                        id=str(user.get("id", "")),
                        type="linear_user",
                        provider="linear",
                        region="global",
                        name=user.get("displayName") or user.get("name") or "Unknown",
                        tags={
                            "role": role,
                            "active": str(user.get("active", False)).lower(),
                            "admin": str(user.get("admin", False)).lower(),
                            "guest": str(user.get("guest", False)).lower(),
                        },
                        metadata={
                            "id": user.get("id"),
                            "name": user.get("name"),
                            "display_name": user.get("displayName"),
                            "email": user.get("email"),
                            "active": user.get("active"),
                            "admin": user.get("admin"),
                            "guest": user.get("guest"),
                            "created_at": user.get("createdAt"),
                            "last_seen": user.get("lastSeen"),
                        },
                        raw_data=user,
                    )
                )

        except Exception as e:
            logger.warning(f"Error collecting user resources: {e}")

        return resources

    def _collect_team_resources(self) -> list[Resource]:
        """Collect team resources."""
        logger.info("Collecting Linear team resources...")

        query = """
        query($first: Int!, $after: String) {
            teams(first: $first, after: $after) {
                nodes {
                    id
                    name
                    key
                    description
                    private
                    createdAt
                    members {
                        nodes {
                            id
                        }
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        """

        resources = []
        try:
            teams = self._paginate_query(query, "teams")

            for team in teams:
                member_count = len(team.get("members", {}).get("nodes", []))

                resources.append(
                    Resource(
                        id=str(team.get("id", "")),
                        type="linear_team",
                        provider="linear",
                        region="global",
                        name=team.get("name") or "Unknown",
                        tags={
                            "key": team.get("key", ""),
                            "private": str(team.get("private", False)).lower(),
                            "member_count": str(member_count),
                        },
                        metadata={
                            "id": team.get("id"),
                            "name": team.get("name"),
                            "key": team.get("key"),
                            "description": team.get("description"),
                            "private": team.get("private"),
                            "member_count": member_count,
                            "created_at": team.get("createdAt"),
                        },
                        raw_data=team,
                    )
                )

        except Exception as e:
            logger.warning(f"Error collecting team resources: {e}")

        return resources

    def _collect_project_resources(self) -> list[Resource]:
        """Collect project resources."""
        logger.info("Collecting Linear project resources...")

        query = """
        query($first: Int!, $after: String) {
            projects(first: $first, after: $after) {
                nodes {
                    id
                    name
                    description
                    state
                    progress
                    startDate
                    targetDate
                    createdAt
                    lead {
                        id
                        name
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        """

        resources = []
        try:
            projects = self._paginate_query(query, "projects")

            for project in projects:
                lead = project.get("lead", {})

                resources.append(
                    Resource(
                        id=str(project.get("id", "")),
                        type="linear_project",
                        provider="linear",
                        region="global",
                        name=project.get("name") or "Unknown",
                        tags={
                            "state": project.get("state", "unknown"),
                            "has_lead": str(bool(lead)).lower(),
                        },
                        metadata={
                            "id": project.get("id"),
                            "name": project.get("name"),
                            "description": project.get("description"),
                            "state": project.get("state"),
                            "progress": project.get("progress"),
                            "start_date": project.get("startDate"),
                            "target_date": project.get("targetDate"),
                            "lead": lead.get("name") if lead else None,
                            "created_at": project.get("createdAt"),
                        },
                        raw_data=project,
                    )
                )

        except Exception as e:
            logger.warning(f"Error collecting project resources: {e}")

        return resources

    def _collect_issue_resources(self) -> list[Resource]:
        """Collect issue resources."""
        logger.info("Collecting Linear issue resources...")

        # Only collect recent issues
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        cutoff_iso = cutoff_date.isoformat()

        query = """
        query($first: Int!, $after: String, $filter: IssueFilter) {
            issues(first: $first, after: $after, filter: $filter) {
                nodes {
                    id
                    identifier
                    title
                    priority
                    state {
                        id
                        name
                        type
                    }
                    assignee {
                        id
                        name
                    }
                    team {
                        id
                        name
                    }
                    createdAt
                    updatedAt
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        """

        resources = []
        try:
            issues = self._paginate_query(
                query,
                "issues",
                variables={"filter": {"updatedAt": {"gte": cutoff_iso}}},
            )

            for issue in issues:
                state = issue.get("state", {})
                assignee = issue.get("assignee", {})
                team = issue.get("team", {})

                resources.append(
                    Resource(
                        id=str(issue.get("id", "")),
                        type="linear_issue",
                        provider="linear",
                        region="global",
                        name=f"{issue.get('identifier', '')}: {issue.get('title', 'Untitled')}",
                        tags={
                            "state": state.get("name", "unknown"),
                            "state_type": state.get("type", "unknown"),
                            "priority": str(issue.get("priority", 0)),
                            "has_assignee": str(bool(assignee)).lower(),
                            "team": team.get("name", "") if team else "",
                        },
                        metadata={
                            "id": issue.get("id"),
                            "identifier": issue.get("identifier"),
                            "title": issue.get("title"),
                            "priority": issue.get("priority"),
                            "state": state.get("name"),
                            "state_type": state.get("type"),
                            "assignee": assignee.get("name") if assignee else None,
                            "team": team.get("name") if team else None,
                            "created_at": issue.get("createdAt"),
                            "updated_at": issue.get("updatedAt"),
                        },
                        raw_data=issue,
                    )
                )

        except Exception as e:
            logger.warning(f"Error collecting issue resources: {e}")

        return resources
