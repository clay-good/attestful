"""
Monday.com collector for Attestful.

Collects work management, project tracking, and team collaboration evidence
from Monday.com for compliance frameworks including SOC 2, NIST 800-53,
ISO 27001, and HITRUST.
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
class MondayCollectorConfig:
    """Configuration for Monday.com collector."""

    # API token (from Monday.com > Admin > API)
    api_token: str = ""

    # API settings
    timeout: int = 30
    max_retries: int = 3
    page_size: int = 100

    # Collection options
    days_of_history: int = 90

    # Board filter (optional - collect specific boards only)
    board_ids: list[int] | None = None


class MondayCollector(BaseCollector):
    """
    Monday.com collector for work management evidence.

    Collects evidence related to:
    - Users and user roles
    - Teams and team membership
    - Workspaces and workspace settings
    - Boards (projects) and board configurations
    - Items (tasks) with columns and values
    - Updates (comments/activity)
    - Audit logs (activity tracking)

    Evidence Types:
    - users: User accounts and roles
    - teams: Team configurations and membership
    - workspaces: Workspace configurations
    - boards: Board definitions and settings
    - items: Items/tasks with details
    - updates: Activity updates on items
    - activity_logs: User activity tracking

    Resource Types:
    - monday_user: User resources
    - monday_team: Team resources
    - monday_board: Board resources
    - monday_item: Item resources

    Example:
        collector = MondayCollector(
            config=MondayCollectorConfig(
                api_token="eyJhbGciOiJIUzI1...",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["users", "boards", "items"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["monday_user", "monday_board"]
        )
    """

    PLATFORM = "monday"
    API_URL = "https://api.monday.com/v2"

    metadata = CollectorMetadata(
        name="MondayCollector",
        platform="monday",
        description="Collects work management evidence from Monday.com",
        mode=CollectorMode.BOTH,
        resource_types=[
            "monday_user",
            "monday_team",
            "monday_board",
            "monday_item",
        ],
        evidence_types=[
            "users",
            "teams",
            "workspaces",
            "boards",
            "items",
            "updates",
            "activity_logs",
        ],
    )

    SUPPORTED_RESOURCE_TYPES = [
        "monday_user",
        "monday_team",
        "monday_board",
        "monday_item",
    ]

    SUPPORTED_EVIDENCE_TYPES = [
        "users",
        "teams",
        "workspaces",
        "boards",
        "items",
        "updates",
        "activity_logs",
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
        "workspaces": {
            "soc2": ["CC6.1", "CC6.6"],
            "nist_800_53": ["AC-2", "AC-6", "CM-2"],
            "iso_27001": ["A.9.1.1", "A.9.1.2"],
            "hitrust": ["01.a", "01.c"],
        },
        "boards": {
            "soc2": ["CC6.1", "CC6.2", "CC8.1"],
            "nist_800_53": ["CM-3", "CM-4", "SA-10"],
            "iso_27001": ["A.12.1.2", "A.14.2.2"],
            "hitrust": ["01.c", "09.b"],
        },
        "items": {
            "soc2": ["CC8.1", "CC7.2", "CC7.4"],
            "nist_800_53": ["CM-3", "IR-5", "IR-6"],
            "iso_27001": ["A.12.1.2", "A.16.1.5"],
            "hitrust": ["09.b", "11.a"],
        },
        "updates": {
            "soc2": ["CC7.2", "CC7.3"],
            "nist_800_53": ["AU-2", "AU-3", "AU-6"],
            "iso_27001": ["A.12.4.1", "A.12.4.3"],
            "hitrust": ["09.aa", "09.ab"],
        },
        "activity_logs": {
            "soc2": ["CC7.2", "CC7.3", "CC7.4"],
            "nist_800_53": ["AU-2", "AU-3", "AU-6", "AU-12"],
            "iso_27001": ["A.12.4.1", "A.12.4.3"],
            "hitrust": ["09.aa", "09.ab", "09.ad"],
        },
    }

    def __init__(self, config: MondayCollectorConfig | None = None):
        """Initialize the Monday.com collector."""
        self.config = config or MondayCollectorConfig()
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
            raise ConfigurationError("Monday.com API token is required")

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
        session.headers["Authorization"] = self.config.api_token
        session.headers["Content-Type"] = "application/json"
        session.headers["API-Version"] = "2024-01"

        return session

    def _graphql(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
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
                if any("authentication" in str(e).lower() for e in errors):
                    raise ConfigurationError("Invalid Monday.com API token")
                raise CollectionError(f"GraphQL errors: {errors}")

            return data.get("data", {})
        except requests.HTTPError as e:
            if e.response.status_code == 401:
                raise ConfigurationError("Invalid Monday.com API token")
            raise CollectionError(f"Monday.com API error: {e}")
        except requests.RequestException as e:
            raise CollectionError(f"Failed to connect to Monday.com: {e}")

    def _paginate_items(
        self,
        board_id: int,
        cursor: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Paginate through items on a board."""
        query = """
        query ($board_id: ID!, $cursor: String, $limit: Int!) {
            boards(ids: [$board_id]) {
                items_page(limit: $limit, cursor: $cursor) {
                    cursor
                    items {
                        id
                        name
                        state
                        created_at
                        updated_at
                        creator_id
                        group {
                            id
                            title
                        }
                        column_values {
                            id
                            text
                            type
                            value
                        }
                    }
                }
            }
        }
        """

        while True:
            variables = {
                "board_id": str(board_id),
                "limit": self.config.page_size,
                "cursor": cursor,
            }

            try:
                data = self._graphql(query, variables)
                boards = data.get("boards", [])
                if not boards:
                    break

                items_page = boards[0].get("items_page", {})
                items = items_page.get("items", [])

                if not items:
                    break

                for item in items:
                    yield item

                cursor = items_page.get("cursor")
                if not cursor:
                    break

            except Exception as e:
                logger.warning(f"Pagination error: {e}")
                break

    def validate_credentials(self) -> bool:
        """Validate Monday.com credentials."""
        if not self.config.api_token:
            raise ConfigurationError("Monday.com API token is required")

        query = """
        query {
            me {
                id
                name
                email
            }
        }
        """

        try:
            data = self._graphql(query)
            me = data.get("me", {})
            logger.info(f"Authenticated as: {me.get('name', 'Unknown')}")
            return True
        except ConfigurationError:
            raise
        except CollectionError as e:
            raise ConfigurationError(f"Failed to validate Monday.com credentials: {e}")

    def collect_evidence(
        self,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """Collect evidence from Monday.com."""
        evidence_types = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        invalid_types = set(evidence_types) - set(self.SUPPORTED_EVIDENCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported evidence types: {invalid_types}")

        logger.info(f"Collecting Monday.com evidence: {evidence_types}")
        evidence_items: list[Evidence] = []
        errors: list[str] = []

        collection_methods = {
            "users": self._collect_users_evidence,
            "teams": self._collect_teams_evidence,
            "workspaces": self._collect_workspaces_evidence,
            "boards": self._collect_boards_evidence,
            "items": self._collect_items_evidence,
            "updates": self._collect_updates_evidence,
            "activity_logs": self._collect_activity_logs_evidence,
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
        logger.info("Collecting Monday.com users...")

        query = """
        query {
            users {
                id
                name
                email
                title
                photo_thumb
                phone
                location
                timezone
                is_admin
                is_guest
                is_pending
                is_verified
                enabled
                created_at
                account {
                    id
                    name
                }
            }
        }
        """

        data = self._graphql(query)
        users_data = data.get("users", [])

        users = []
        for user in users_data:
            users.append({
                "id": user.get("id"),
                "name": user.get("name"),
                "email": user.get("email"),
                "title": user.get("title"),
                "phone": user.get("phone"),
                "location": user.get("location"),
                "timezone": user.get("timezone"),
                "is_admin": user.get("is_admin", False),
                "is_guest": user.get("is_guest", False),
                "is_pending": user.get("is_pending", False),
                "is_verified": user.get("is_verified", False),
                "enabled": user.get("enabled", True),
                "created_at": user.get("created_at"),
                "account_id": user.get("account", {}).get("id") if user.get("account") else None,
                "account_name": user.get("account", {}).get("name") if user.get("account") else None,
            })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="users",
            raw_data={
                "users": users,
                "total_count": len(users),
                "admin_count": sum(1 for u in users if u.get("is_admin")),
                "guest_count": sum(1 for u in users if u.get("is_guest")),
                "pending_count": sum(1 for u in users if u.get("is_pending")),
                "enabled_count": sum(1 for u in users if u.get("enabled")),
            },
            metadata={
                "source": "collector:monday",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["users"],
            },
        )

    def _collect_teams_evidence(self) -> Evidence:
        """Collect teams evidence."""
        logger.info("Collecting Monday.com teams...")

        query = """
        query {
            teams {
                id
                name
                picture_url
                users {
                    id
                    name
                    email
                }
            }
        }
        """

        data = self._graphql(query)
        teams_data = data.get("teams", [])

        teams = []
        for team in teams_data:
            members = team.get("users", [])
            teams.append({
                "id": team.get("id"),
                "name": team.get("name"),
                "picture_url": team.get("picture_url"),
                "members": [{"id": m.get("id"), "name": m.get("name"), "email": m.get("email")} for m in members],
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
                "source": "collector:monday",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["teams"],
            },
        )

    def _collect_workspaces_evidence(self) -> Evidence:
        """Collect workspaces evidence."""
        logger.info("Collecting Monday.com workspaces...")

        query = """
        query {
            workspaces {
                id
                name
                kind
                description
                created_at
                account_product {
                    id
                    kind
                }
            }
        }
        """

        data = self._graphql(query)
        workspaces_data = data.get("workspaces", [])

        workspaces = []
        for workspace in workspaces_data:
            workspaces.append({
                "id": workspace.get("id"),
                "name": workspace.get("name"),
                "kind": workspace.get("kind"),
                "description": workspace.get("description"),
                "created_at": workspace.get("created_at"),
            })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="workspaces",
            raw_data={
                "workspaces": workspaces,
                "total_count": len(workspaces),
            },
            metadata={
                "source": "collector:monday",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["workspaces"],
            },
        )

    def _collect_boards_evidence(self) -> Evidence:
        """Collect boards evidence."""
        logger.info("Collecting Monday.com boards...")

        query = """
        query ($limit: Int!, $page: Int!) {
            boards(limit: $limit, page: $page) {
                id
                name
                state
                board_kind
                description
                permissions
                item_terminology
                items_count
                workspace_id
                created_at
                updated_at
                creator {
                    id
                    name
                }
                owners {
                    id
                    name
                }
                subscribers {
                    id
                    name
                }
                columns {
                    id
                    title
                    type
                }
                groups {
                    id
                    title
                    color
                }
            }
        }
        """

        boards = []
        page = 1

        while True:
            variables = {"limit": self.config.page_size, "page": page}
            data = self._graphql(query, variables)
            boards_data = data.get("boards", [])

            if not boards_data:
                break

            for board in boards_data:
                # Filter by board_ids if specified
                if self.config.board_ids and int(board.get("id", 0)) not in self.config.board_ids:
                    continue

                boards.append({
                    "id": board.get("id"),
                    "name": board.get("name"),
                    "state": board.get("state"),
                    "board_kind": board.get("board_kind"),
                    "description": board.get("description"),
                    "permissions": board.get("permissions"),
                    "item_terminology": board.get("item_terminology"),
                    "items_count": board.get("items_count", 0),
                    "workspace_id": board.get("workspace_id"),
                    "created_at": board.get("created_at"),
                    "updated_at": board.get("updated_at"),
                    "creator": board.get("creator", {}).get("name") if board.get("creator") else None,
                    "creator_id": board.get("creator", {}).get("id") if board.get("creator") else None,
                    "owners": [o.get("name") for o in board.get("owners", [])],
                    "owner_count": len(board.get("owners", [])),
                    "subscribers": [s.get("name") for s in board.get("subscribers", [])],
                    "subscriber_count": len(board.get("subscribers", [])),
                    "column_count": len(board.get("columns", [])),
                    "group_count": len(board.get("groups", [])),
                })

            if len(boards_data) < self.config.page_size:
                break
            page += 1

        # Group by state
        by_state = {}
        for board in boards:
            state = board.get("state", "unknown")
            by_state[state] = by_state.get(state, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="boards",
            raw_data={
                "boards": boards,
                "total_count": len(boards),
                "by_state": by_state,
            },
            metadata={
                "source": "collector:monday",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["boards"],
            },
        )

    def _collect_items_evidence(self) -> Evidence:
        """Collect items evidence."""
        logger.info("Collecting Monday.com items...")

        # First get boards
        board_query = """
        query ($limit: Int!, $page: Int!) {
            boards(limit: $limit, page: $page) {
                id
                name
            }
        }
        """

        items = []
        page = 1

        while True:
            variables = {"limit": 50, "page": page}
            data = self._graphql(board_query, variables)
            boards_data = data.get("boards", [])

            if not boards_data:
                break

            for board in boards_data:
                board_id = int(board.get("id", 0))

                # Filter by board_ids if specified
                if self.config.board_ids and board_id not in self.config.board_ids:
                    continue

                try:
                    for item in self._paginate_items(board_id):
                        items.append(self._normalize_item(item, board))
                except Exception as e:
                    logger.warning(f"Error fetching items for board {board_id}: {e}")

            if len(boards_data) < 50:
                break
            page += 1

        # Calculate statistics
        by_state = {}
        for item in items:
            state = item.get("state", "unknown")
            by_state[state] = by_state.get(state, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="items",
            raw_data={
                "items": items,
                "total_count": len(items),
                "by_state": by_state,
            },
            metadata={
                "source": "collector:monday",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["items"],
            },
        )

    def _normalize_item(self, item: dict[str, Any], board: dict[str, Any]) -> dict[str, Any]:
        """Normalize item data."""
        column_values = {}
        for col in item.get("column_values", []):
            column_values[col.get("id")] = {
                "text": col.get("text"),
                "type": col.get("type"),
            }

        return {
            "id": item.get("id"),
            "name": item.get("name"),
            "state": item.get("state"),
            "created_at": item.get("created_at"),
            "updated_at": item.get("updated_at"),
            "creator_id": item.get("creator_id"),
            "board_id": board.get("id"),
            "board_name": board.get("name"),
            "group_id": item.get("group", {}).get("id") if item.get("group") else None,
            "group_title": item.get("group", {}).get("title") if item.get("group") else None,
            "column_values": column_values,
        }

    def _collect_updates_evidence(self) -> Evidence:
        """Collect updates (comments/activity) evidence."""
        logger.info("Collecting Monday.com updates...")

        query = """
        query ($limit: Int!, $page: Int!) {
            updates(limit: $limit, page: $page) {
                id
                body
                text_body
                created_at
                updated_at
                creator_id
                creator {
                    id
                    name
                }
                item_id
            }
        }
        """

        updates = []
        page = 1

        while True:
            variables = {"limit": self.config.page_size, "page": page}

            try:
                data = self._graphql(query, variables)
                updates_data = data.get("updates", [])

                if not updates_data:
                    break

                for update in updates_data:
                    updates.append({
                        "id": update.get("id"),
                        "text_body": update.get("text_body"),
                        "created_at": update.get("created_at"),
                        "updated_at": update.get("updated_at"),
                        "creator_id": update.get("creator_id"),
                        "creator_name": update.get("creator", {}).get("name") if update.get("creator") else None,
                        "item_id": update.get("item_id"),
                    })

                if len(updates_data) < self.config.page_size:
                    break
                page += 1

            except Exception as e:
                logger.warning(f"Error fetching updates: {e}")
                break

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="updates",
            raw_data={
                "updates": updates,
                "total_count": len(updates),
            },
            metadata={
                "source": "collector:monday",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["updates"],
            },
        )

    def _collect_activity_logs_evidence(self) -> Evidence:
        """Collect activity logs evidence."""
        logger.info("Collecting Monday.com activity logs...")

        # Activity logs require board context
        board_query = """
        query ($limit: Int!, $page: Int!) {
            boards(limit: $limit, page: $page) {
                id
                name
                activity_logs {
                    id
                    event
                    data
                    created_at
                    user_id
                }
            }
        }
        """

        activity_logs = []
        page = 1

        while True:
            variables = {"limit": 25, "page": page}

            try:
                data = self._graphql(board_query, variables)
                boards_data = data.get("boards", [])

                if not boards_data:
                    break

                for board in boards_data:
                    board_id = board.get("id")

                    # Filter by board_ids if specified
                    if self.config.board_ids and int(board_id) not in self.config.board_ids:
                        continue

                    logs = board.get("activity_logs", [])
                    for log in logs:
                        activity_logs.append({
                            "id": log.get("id"),
                            "event": log.get("event"),
                            "data": log.get("data"),
                            "created_at": log.get("created_at"),
                            "user_id": log.get("user_id"),
                            "board_id": board_id,
                            "board_name": board.get("name"),
                        })

                if len(boards_data) < 25:
                    break
                page += 1

            except Exception as e:
                logger.warning(f"Error fetching activity logs: {e}")
                break

        # Group by event type
        by_event = {}
        for log in activity_logs:
            event = log.get("event", "unknown")
            by_event[event] = by_event.get(event, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="activity_logs",
            raw_data={
                "activity_logs": activity_logs,
                "total_count": len(activity_logs),
                "by_event": by_event,
            },
            metadata={
                "source": "collector:monday",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["activity_logs"],
            },
        )

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """Collect resources from Monday.com for compliance checks."""
        resource_types = resource_types or self.SUPPORTED_RESOURCE_TYPES
        invalid_types = set(resource_types) - set(self.SUPPORTED_RESOURCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported resource types: {invalid_types}")

        logger.info(f"Collecting Monday.com resources: {resource_types}")
        resources: list[Resource] = []

        collection_methods = {
            "monday_user": self._collect_user_resources,
            "monday_team": self._collect_team_resources,
            "monday_board": self._collect_board_resources,
            "monday_item": self._collect_item_resources,
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
        logger.info("Collecting Monday.com user resources...")

        query = """
        query {
            users {
                id
                name
                email
                title
                is_admin
                is_guest
                is_pending
                is_verified
                enabled
                created_at
            }
        }
        """

        data = self._graphql(query)
        users_data = data.get("users", [])

        resources = []
        for user in users_data:
            resources.append(
                Resource(
                    id=str(user.get("id", "")),
                    type="monday_user",
                    provider="monday",
                    region="global",
                    name=user.get("name", "Unknown"),
                    tags={
                        "is_admin": str(user.get("is_admin", False)).lower(),
                        "is_guest": str(user.get("is_guest", False)).lower(),
                        "is_pending": str(user.get("is_pending", False)).lower(),
                        "enabled": str(user.get("enabled", True)).lower(),
                    },
                    metadata={
                        "id": user.get("id"),
                        "name": user.get("name"),
                        "email": user.get("email"),
                        "title": user.get("title"),
                        "is_admin": user.get("is_admin", False),
                        "is_guest": user.get("is_guest", False),
                        "is_pending": user.get("is_pending", False),
                        "is_verified": user.get("is_verified", False),
                        "enabled": user.get("enabled", True),
                        "created_at": user.get("created_at"),
                    },
                    raw_data=user,
                )
            )

        return resources

    def _collect_team_resources(self) -> list[Resource]:
        """Collect team resources."""
        logger.info("Collecting Monday.com team resources...")

        query = """
        query {
            teams {
                id
                name
                users {
                    id
                }
            }
        }
        """

        data = self._graphql(query)
        teams_data = data.get("teams", [])

        resources = []
        for team in teams_data:
            member_count = len(team.get("users", []))
            resources.append(
                Resource(
                    id=str(team.get("id", "")),
                    type="monday_team",
                    provider="monday",
                    region="global",
                    name=team.get("name", "Unknown"),
                    tags={
                        "member_count": str(member_count),
                    },
                    metadata={
                        "id": team.get("id"),
                        "name": team.get("name"),
                        "member_count": member_count,
                        "member_ids": [u.get("id") for u in team.get("users", [])],
                    },
                    raw_data=team,
                )
            )

        return resources

    def _collect_board_resources(self) -> list[Resource]:
        """Collect board resources."""
        logger.info("Collecting Monday.com board resources...")

        query = """
        query ($limit: Int!, $page: Int!) {
            boards(limit: $limit, page: $page) {
                id
                name
                state
                board_kind
                permissions
                items_count
                workspace_id
                created_at
                owners {
                    id
                }
            }
        }
        """

        resources = []
        page = 1

        while True:
            variables = {"limit": self.config.page_size, "page": page}
            data = self._graphql(query, variables)
            boards_data = data.get("boards", [])

            if not boards_data:
                break

            for board in boards_data:
                # Filter by board_ids if specified
                if self.config.board_ids and int(board.get("id", 0)) not in self.config.board_ids:
                    continue

                resources.append(
                    Resource(
                        id=str(board.get("id", "")),
                        type="monday_board",
                        provider="monday",
                        region="global",
                        name=board.get("name", "Unknown"),
                        tags={
                            "state": board.get("state", "unknown"),
                            "board_kind": board.get("board_kind", "unknown"),
                            "permissions": board.get("permissions", "unknown"),
                        },
                        metadata={
                            "id": board.get("id"),
                            "name": board.get("name"),
                            "state": board.get("state"),
                            "board_kind": board.get("board_kind"),
                            "permissions": board.get("permissions"),
                            "items_count": board.get("items_count", 0),
                            "workspace_id": board.get("workspace_id"),
                            "created_at": board.get("created_at"),
                            "owner_count": len(board.get("owners", [])),
                        },
                        raw_data=board,
                    )
                )

            if len(boards_data) < self.config.page_size:
                break
            page += 1

        return resources

    def _collect_item_resources(self) -> list[Resource]:
        """Collect item resources (limited set for compliance checks)."""
        logger.info("Collecting Monday.com item resources...")

        # First get boards
        board_query = """
        query ($limit: Int!, $page: Int!) {
            boards(limit: $limit, page: $page) {
                id
                name
            }
        }
        """

        resources = []
        page = 1
        count = 0
        max_items = 1000  # Limit to prevent excessive resource collection

        while count < max_items:
            variables = {"limit": 50, "page": page}
            data = self._graphql(board_query, variables)
            boards_data = data.get("boards", [])

            if not boards_data:
                break

            for board in boards_data:
                if count >= max_items:
                    break

                board_id = int(board.get("id", 0))

                # Filter by board_ids if specified
                if self.config.board_ids and board_id not in self.config.board_ids:
                    continue

                try:
                    for item in self._paginate_items(board_id):
                        if count >= max_items:
                            break

                        resources.append(
                            Resource(
                                id=str(item.get("id", "")),
                                type="monday_item",
                                provider="monday",
                                region="global",
                                name=item.get("name", "Unknown"),
                                tags={
                                    "state": item.get("state", "unknown"),
                                    "board_id": str(board_id),
                                    "has_group": str(bool(item.get("group"))).lower(),
                                },
                                metadata={
                                    "id": item.get("id"),
                                    "name": item.get("name"),
                                    "state": item.get("state"),
                                    "created_at": item.get("created_at"),
                                    "updated_at": item.get("updated_at"),
                                    "creator_id": item.get("creator_id"),
                                    "board_id": board_id,
                                    "board_name": board.get("name"),
                                    "group_id": item.get("group", {}).get("id") if item.get("group") else None,
                                    "group_title": item.get("group", {}).get("title") if item.get("group") else None,
                                },
                                raw_data=item,
                            )
                        )
                        count += 1
                except Exception as e:
                    logger.warning(f"Error fetching items for board {board_id}: {e}")

            if len(boards_data) < 50:
                break
            page += 1

        if count >= max_items:
            logger.info(f"Reached max item limit of {max_items}")

        return resources
