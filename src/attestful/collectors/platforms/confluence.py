"""
Confluence collector for Attestful.

Collects documentation, knowledge management, and policy evidence from
Atlassian Confluence for compliance frameworks including SOC 2, NIST 800-53,
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
class ConfluenceCollectorConfig:
    """Configuration for Confluence collector."""

    # Confluence Cloud URL (e.g., https://company.atlassian.net)
    url: str = ""

    # Authentication - API token for Cloud, or username/password for Server
    username: str = ""  # Email for Cloud
    api_token: str = ""  # API token for Cloud, or password for Server

    # For Confluence Server/Data Center with PAT
    personal_access_token: str = ""

    # API settings
    timeout: int = 30
    max_retries: int = 3
    page_size: int = 100

    # Collection options
    days_of_history: int = 90

    # Whether this is Confluence Cloud (vs Server/Data Center)
    is_cloud: bool = True


class ConfluenceCollector(BaseCollector):
    """
    Confluence collector for documentation and knowledge management evidence.

    Collects evidence related to:
    - Spaces and their configurations
    - Pages and their metadata
    - Users and groups
    - Permissions and access controls
    - Audit logs (activity tracking)

    Evidence Types:
    - spaces: Confluence spaces with configurations
    - pages: Pages metadata and structure
    - users: Confluence users
    - groups: User groups
    - permissions: Space and page permissions
    - audit_logs: Activity and change logs

    Resource Types:
    - confluence_space: Space resources
    - confluence_page: Page resources
    - confluence_user: User resources
    - confluence_group: Group resources

    Example:
        collector = ConfluenceCollector(
            config=ConfluenceCollectorConfig(
                url="https://company.atlassian.net",
                username="user@company.com",
                api_token="your-api-token",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["spaces", "pages", "permissions"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["confluence_space", "confluence_page"]
        )
    """

    PLATFORM = "confluence"

    metadata = CollectorMetadata(
        name="ConfluenceCollector",
        platform="confluence",
        description="Collects documentation and knowledge management evidence from Confluence",
        mode=CollectorMode.BOTH,
        resource_types=[
            "confluence_space",
            "confluence_page",
            "confluence_user",
            "confluence_group",
        ],
        evidence_types=[
            "spaces",
            "pages",
            "users",
            "groups",
            "permissions",
            "audit_logs",
        ],
    )

    SUPPORTED_RESOURCE_TYPES = [
        "confluence_space",
        "confluence_page",
        "confluence_user",
        "confluence_group",
    ]

    SUPPORTED_EVIDENCE_TYPES = [
        "spaces",
        "pages",
        "users",
        "groups",
        "permissions",
        "audit_logs",
    ]

    # Compliance control mappings
    EVIDENCE_CONTROL_MAPPINGS = {
        "spaces": {
            "soc2": ["CC5.2", "CC6.1", "CC6.6"],
            "nist_800_53": ["AC-3", "AC-6", "CM-3"],
            "iso_27001": ["A.8.1.1", "A.9.1.2", "A.12.1.1"],
            "hitrust": ["01.c", "06.c", "09.b"],
        },
        "pages": {
            "soc2": ["CC5.2", "CC5.3", "CC6.1"],
            "nist_800_53": ["CM-3", "CM-6", "SA-5"],
            "iso_27001": ["A.8.1.1", "A.12.1.1", "A.14.2.2"],
            "hitrust": ["06.c", "09.b", "10.k"],
        },
        "users": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-3", "IA-2", "IA-4"],
            "iso_27001": ["A.9.2.1", "A.9.2.2", "A.9.2.3"],
            "hitrust": ["01.b", "01.c", "01.d"],
        },
        "groups": {
            "soc2": ["CC6.1", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-6"],
            "iso_27001": ["A.9.2.1", "A.9.2.2"],
            "hitrust": ["01.c", "01.d"],
        },
        "permissions": {
            "soc2": ["CC6.1", "CC6.3", "CC6.6"],
            "nist_800_53": ["AC-3", "AC-6", "AU-9"],
            "iso_27001": ["A.9.1.2", "A.9.4.1", "A.9.4.5"],
            "hitrust": ["01.c", "01.v", "06.c"],
        },
        "audit_logs": {
            "soc2": ["CC7.2", "CC7.3", "CC7.4"],
            "nist_800_53": ["AU-2", "AU-3", "AU-6", "AU-12"],
            "iso_27001": ["A.12.4.1", "A.12.4.3"],
            "hitrust": ["09.aa", "09.ab"],
        },
    }

    def __init__(self, config: ConfluenceCollectorConfig | None = None):
        """Initialize the Confluence collector."""
        self.config = config or ConfluenceCollectorConfig()
        self._session: requests.Session | None = None

    @property
    def base_url(self) -> str:
        """Get the base URL for API requests."""
        if not self.config.url:
            raise ConfigurationError("Confluence URL not configured")
        url = self.config.url.rstrip("/")
        if self.config.is_cloud:
            return f"{url}/wiki/api/v2"
        else:
            return f"{url}/rest/api"

    @property
    def api_v1_url(self) -> str:
        """Get the v1 API URL (used for some endpoints)."""
        if not self.config.url:
            raise ConfigurationError("Confluence URL not configured")
        url = self.config.url.rstrip("/")
        if self.config.is_cloud:
            return f"{url}/wiki/rest/api"
        else:
            return f"{url}/rest/api"

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

        # Set authentication
        if self.config.personal_access_token:
            session.headers["Authorization"] = f"Bearer {self.config.personal_access_token}"
        elif self.config.username and self.config.api_token:
            session.auth = (self.config.username, self.config.api_token)
        else:
            raise ConfigurationError(
                "Confluence authentication not configured. "
                "Provide username/api_token or personal_access_token."
            )

        # Set default headers
        session.headers["Accept"] = "application/json"
        session.headers["Content-Type"] = "application/json"

        return session

    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        use_v1: bool = False,
    ) -> dict[str, Any]:
        """Make an API request."""
        base = self.api_v1_url if use_v1 else self.base_url
        url = f"{base}/{endpoint.lstrip('/')}"

        try:
            response = self.session.request(
                method,
                url,
                params=params,
                json=json_data,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return response.json() if response.content else {}
        except requests.RequestException as e:
            logger.warning(f"API request failed: {endpoint} - {e}")
            raise

    def _paginate(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        results_key: str = "results",
        use_v1: bool = False,
    ) -> Iterator[dict[str, Any]]:
        """Paginate through API results."""
        params = params or {}
        params["limit"] = self.config.page_size
        start = 0

        while True:
            params["start"] = start

            try:
                data = self._make_request("GET", endpoint, params=params, use_v1=use_v1)
                items = data.get(results_key, [])

                for item in items:
                    yield item

                # Check for more results
                size = data.get("size", len(items))
                if size < self.config.page_size:
                    break

                start += size

            except requests.RequestException:
                break

    def _paginate_v2(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        results_key: str = "results",
    ) -> Iterator[dict[str, Any]]:
        """Paginate through v2 API results using cursor-based pagination."""
        params = params or {}
        params["limit"] = self.config.page_size
        cursor = None

        while True:
            if cursor:
                params["cursor"] = cursor

            try:
                data = self._make_request("GET", endpoint, params=params)
                items = data.get(results_key, [])

                for item in items:
                    yield item

                # Check for next page using _links
                links = data.get("_links", {})
                next_link = links.get("next")
                if not next_link:
                    break

                # Extract cursor from next link
                if "cursor=" in next_link:
                    cursor = next_link.split("cursor=")[1].split("&")[0]
                else:
                    break

            except requests.RequestException:
                break

    def validate_credentials(self) -> bool:
        """Validate Confluence credentials."""
        try:
            # Try to get current user info
            if self.config.is_cloud:
                self._make_request("GET", "user/current", use_v1=True)
            else:
                self._make_request("GET", "user/current", use_v1=True)
            logger.info("Confluence credentials validated")
            return True
        except requests.RequestException as e:
            logger.error(f"Confluence credential validation failed: {e}")
            raise ConfigurationError(f"Failed to validate Confluence credentials: {e}")

    def collect_evidence(
        self,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """Collect evidence from Confluence."""
        evidence_types = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        invalid_types = set(evidence_types) - set(self.SUPPORTED_EVIDENCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported evidence types: {invalid_types}")

        logger.info(f"Collecting Confluence evidence: {evidence_types}")
        evidence_items: list[Evidence] = []
        errors: list[str] = []

        collection_methods = {
            "spaces": self._collect_spaces_evidence,
            "pages": self._collect_pages_evidence,
            "users": self._collect_users_evidence,
            "groups": self._collect_groups_evidence,
            "permissions": self._collect_permissions_evidence,
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

    def _collect_spaces_evidence(self) -> Evidence:
        """Collect spaces evidence."""
        logger.info("Collecting Confluence spaces...")
        spaces = []

        try:
            if self.config.is_cloud:
                # v2 API for Cloud
                for space in self._paginate_v2("spaces"):
                    spaces.append(self._normalize_space(space))
            else:
                # v1 API for Server
                for space in self._paginate("space", use_v1=True):
                    spaces.append(self._normalize_space(space))
        except Exception as e:
            logger.warning(f"Error collecting spaces: {e}")

        # Categorize spaces
        global_count = sum(1 for s in spaces if s.get("type") == "global")
        personal_count = sum(1 for s in spaces if s.get("type") == "personal")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="spaces",
            raw_data={
                "spaces": spaces,
                "total_count": len(spaces),
                "global_count": global_count,
                "personal_count": personal_count,
            },
            metadata={
                "source": "collector:confluence",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["spaces"],
            },
        )

    def _normalize_space(self, space: dict[str, Any]) -> dict[str, Any]:
        """Normalize space data across API versions."""
        return {
            "id": space.get("id"),
            "key": space.get("key"),
            "name": space.get("name"),
            "type": space.get("type"),
            "status": space.get("status"),
            "description": space.get("description", {}).get("plain", {}).get("value", "")
            if isinstance(space.get("description"), dict)
            else space.get("description", ""),
            "homepage_id": space.get("homepageId") or space.get("homepage", {}).get("id"),
            "created_at": space.get("createdAt"),
        }

    def _collect_pages_evidence(self) -> Evidence:
        """Collect pages evidence."""
        logger.info("Collecting Confluence pages...")
        pages = []
        pages_by_space: dict[str, int] = {}

        try:
            if self.config.is_cloud:
                # v2 API for Cloud
                for page in self._paginate_v2("pages"):
                    normalized = self._normalize_page(page)
                    pages.append(normalized)

                    space_id = normalized.get("space_id", "unknown")
                    pages_by_space[space_id] = pages_by_space.get(space_id, 0) + 1
            else:
                # v1 API for Server - need to iterate through spaces
                for space in self._paginate("space", use_v1=True):
                    space_key = space.get("key")
                    try:
                        for page in self._paginate(
                            f"space/{space_key}/content/page",
                            use_v1=True,
                        ):
                            normalized = self._normalize_page(page)
                            pages.append(normalized)
                            pages_by_space[space_key] = pages_by_space.get(space_key, 0) + 1
                    except Exception as e:
                        logger.warning(f"Error collecting pages for space {space_key}: {e}")

        except Exception as e:
            logger.warning(f"Error collecting pages: {e}")

        # Identify stale pages (not updated in configured days)
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        stale_pages = []
        for page in pages:
            updated_at = page.get("updated_at")
            if updated_at:
                try:
                    if isinstance(updated_at, str):
                        updated_date = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
                    else:
                        updated_date = updated_at
                    if updated_date < cutoff:
                        stale_pages.append(page)
                except (ValueError, TypeError):
                    pass

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="pages",
            raw_data={
                "pages": pages,
                "total_count": len(pages),
                "pages_by_space": pages_by_space,
                "stale_pages_count": len(stale_pages),
                "stale_threshold_days": self.config.days_of_history,
            },
            metadata={
                "source": "collector:confluence",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["pages"],
            },
        )

    def _normalize_page(self, page: dict[str, Any]) -> dict[str, Any]:
        """Normalize page data across API versions."""
        # Handle v2 API format
        if "spaceId" in page:
            return {
                "id": page.get("id"),
                "title": page.get("title"),
                "space_id": page.get("spaceId"),
                "parent_id": page.get("parentId"),
                "parent_type": page.get("parentType"),
                "status": page.get("status"),
                "created_at": page.get("createdAt"),
                "updated_at": page.get("version", {}).get("createdAt"),
                "author_id": page.get("authorId"),
                "owner_id": page.get("ownerId"),
                "version": page.get("version", {}).get("number"),
            }
        # Handle v1 API format
        else:
            version = page.get("version", {})
            return {
                "id": page.get("id"),
                "title": page.get("title"),
                "space_key": page.get("space", {}).get("key") if isinstance(page.get("space"), dict) else page.get("_expandable", {}).get("space", "").split("/")[-1],
                "status": page.get("status"),
                "created_at": page.get("history", {}).get("createdDate"),
                "updated_at": version.get("when"),
                "author": version.get("by", {}).get("displayName"),
                "version": version.get("number"),
            }

    def _collect_users_evidence(self) -> Evidence:
        """Collect users evidence."""
        logger.info("Collecting Confluence users...")
        users = []

        try:
            # For Cloud, use the admin API to get users
            if self.config.is_cloud:
                # Try the v1 group/member approach
                for group in self._paginate("group", use_v1=True):
                    group_name = group.get("name")
                    try:
                        for member in self._paginate(
                            f"group/{group_name}/member",
                            use_v1=True,
                        ):
                            # Avoid duplicates
                            if not any(u.get("account_id") == member.get("accountId") for u in users):
                                users.append(self._normalize_user(member))
                    except Exception as e:
                        logger.warning(f"Error getting members for group {group_name}: {e}")
            else:
                # For Server, try user search
                try:
                    for user in self._paginate("user/list", use_v1=True):
                        users.append(self._normalize_user(user))
                except Exception as e:
                    logger.warning(f"Error listing users: {e}")

        except Exception as e:
            logger.warning(f"Error collecting users: {e}")

        # Calculate statistics
        active_count = sum(1 for u in users if u.get("active", True))

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="users",
            raw_data={
                "users": users,
                "total_count": len(users),
                "active_count": active_count,
            },
            metadata={
                "source": "collector:confluence",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["users"],
            },
        )

    def _normalize_user(self, user: dict[str, Any]) -> dict[str, Any]:
        """Normalize user data."""
        return {
            "account_id": user.get("accountId") or user.get("userKey"),
            "username": user.get("username") or user.get("publicName"),
            "display_name": user.get("displayName") or user.get("publicName"),
            "email": user.get("email"),
            "account_type": user.get("accountType", "atlassian"),
            "active": user.get("active", True),
            "profile_picture": user.get("profilePicture", {}).get("path"),
        }

    def _collect_groups_evidence(self) -> Evidence:
        """Collect groups evidence."""
        logger.info("Collecting Confluence groups...")
        groups = []

        try:
            for group in self._paginate("group", use_v1=True):
                group_name = group.get("name")

                # Get member count
                member_count = 0
                try:
                    members_data = self._make_request(
                        "GET",
                        f"group/{group_name}/member",
                        params={"limit": 1},
                        use_v1=True,
                    )
                    member_count = members_data.get("size", 0)
                except Exception:
                    pass

                groups.append({
                    "id": group.get("id"),
                    "name": group_name,
                    "type": group.get("type"),
                    "member_count": member_count,
                })

        except Exception as e:
            logger.warning(f"Error collecting groups: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="groups",
            raw_data={
                "groups": groups,
                "total_count": len(groups),
            },
            metadata={
                "source": "collector:confluence",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["groups"],
            },
        )

    def _collect_permissions_evidence(self) -> Evidence:
        """Collect permissions evidence."""
        logger.info("Collecting Confluence permissions...")
        permissions_data = []

        try:
            # Get space permissions
            if self.config.is_cloud:
                for space in self._paginate_v2("spaces"):
                    space_id = space.get("id")
                    space_key = space.get("key")

                    try:
                        perms = self._make_request(
                            "GET",
                            f"spaces/{space_id}/permissions",
                        )
                        permissions_data.append({
                            "space_id": space_id,
                            "space_key": space_key,
                            "permissions": perms.get("results", []),
                        })
                    except Exception as e:
                        logger.warning(f"Error getting permissions for space {space_key}: {e}")
            else:
                for space in self._paginate("space", use_v1=True):
                    space_key = space.get("key")

                    try:
                        perms = self._make_request(
                            "GET",
                            f"space/{space_key}",
                            params={"expand": "permissions"},
                            use_v1=True,
                        )
                        permissions_data.append({
                            "space_key": space_key,
                            "permissions": perms.get("permissions", []),
                        })
                    except Exception as e:
                        logger.warning(f"Error getting permissions for space {space_key}: {e}")

        except Exception as e:
            logger.warning(f"Error collecting permissions: {e}")

        # Analyze permissions
        spaces_with_anonymous_access = []
        for perm_data in permissions_data:
            perms = perm_data.get("permissions", [])
            for perm in perms:
                # Check for anonymous access
                subjects = perm.get("subjects", {})
                if subjects.get("anonymous") or perm.get("anonymousAccess"):
                    spaces_with_anonymous_access.append(
                        perm_data.get("space_key") or perm_data.get("space_id")
                    )
                    break

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="permissions",
            raw_data={
                "permissions": permissions_data,
                "total_spaces": len(permissions_data),
                "spaces_with_anonymous_access": list(set(spaces_with_anonymous_access)),
                "anonymous_access_count": len(set(spaces_with_anonymous_access)),
            },
            metadata={
                "source": "collector:confluence",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["permissions"],
            },
        )

    def _collect_audit_logs_evidence(self) -> Evidence:
        """Collect audit logs evidence."""
        logger.info("Collecting Confluence audit logs...")
        audit_events = []
        event_types: dict[str, int] = {}

        try:
            # Audit API is available on Confluence Server/Data Center
            # For Cloud, use content history as a proxy
            if not self.config.is_cloud:
                # Server audit API
                cutoff = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
                params = {
                    "startDate": int(cutoff.timestamp() * 1000),
                    "limit": 1000,
                }

                try:
                    data = self._make_request("GET", "audit", params=params, use_v1=True)
                    for record in data.get("results", []):
                        event_type = record.get("summary", "unknown")
                        event_types[event_type] = event_types.get(event_type, 0) + 1

                        audit_events.append({
                            "id": record.get("author", {}).get("accountId"),
                            "timestamp": record.get("creationDate"),
                            "action": event_type,
                            "author": record.get("author", {}).get("displayName"),
                            "affected_object": record.get("affectedObject", {}).get("name"),
                            "category": record.get("category"),
                            "description": record.get("description"),
                        })
                except Exception as e:
                    logger.warning(f"Error collecting audit logs: {e}")
            else:
                # For Cloud, collect recent content changes as audit proxy
                try:
                    for page in self._paginate_v2("pages", params={"sort": "-modified-date"}):
                        version = page.get("version", {})
                        audit_events.append({
                            "timestamp": version.get("createdAt"),
                            "action": "page_updated",
                            "page_id": page.get("id"),
                            "page_title": page.get("title"),
                            "author_id": page.get("authorId"),
                            "version": version.get("number"),
                        })

                        if len(audit_events) >= 1000:
                            break

                    event_types["page_updated"] = len(audit_events)
                except Exception as e:
                    logger.warning(f"Error collecting page changes: {e}")

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
                "note": "Cloud uses page history as audit proxy" if self.config.is_cloud else None,
            },
            metadata={
                "source": "collector:confluence",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["audit_logs"],
            },
        )

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """Collect resources from Confluence for compliance checks."""
        resource_types = resource_types or self.SUPPORTED_RESOURCE_TYPES
        invalid_types = set(resource_types) - set(self.SUPPORTED_RESOURCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported resource types: {invalid_types}")

        logger.info(f"Collecting Confluence resources: {resource_types}")
        resources: list[Resource] = []

        collection_methods = {
            "confluence_space": self._collect_space_resources,
            "confluence_page": self._collect_page_resources,
            "confluence_user": self._collect_user_resources,
            "confluence_group": self._collect_group_resources,
        }

        for resource_type in resource_types:
            try:
                method = collection_methods.get(resource_type)
                if method:
                    resources.extend(method())
            except Exception as e:
                logger.error(f"Error collecting {resource_type}: {e}")

        return resources

    def _collect_space_resources(self) -> list[Resource]:
        """Collect space resources."""
        logger.info("Collecting Confluence space resources...")
        resources = []

        try:
            if self.config.is_cloud:
                for space in self._paginate_v2("spaces"):
                    normalized = self._normalize_space(space)
                    resources.append(self._create_space_resource(normalized, space))
            else:
                for space in self._paginate("space", use_v1=True):
                    normalized = self._normalize_space(space)
                    resources.append(self._create_space_resource(normalized, space))
        except Exception as e:
            logger.warning(f"Error collecting space resources: {e}")

        return resources

    def _create_space_resource(self, normalized: dict[str, Any], raw: dict[str, Any]) -> Resource:
        """Create a space resource."""
        space_type = normalized.get("type", "global")
        return Resource(
            id=str(normalized.get("id") or normalized.get("key", "")),
            type="confluence_space",
            provider="confluence",
            region="global",
            name=normalized.get("name") or normalized.get("key") or "Unknown",
            tags={
                "type": space_type,
                "status": normalized.get("status", "current"),
                "key": normalized.get("key", ""),
            },
            metadata={
                "id": normalized.get("id"),
                "key": normalized.get("key"),
                "name": normalized.get("name"),
                "type": space_type,
                "status": normalized.get("status"),
            },
            raw_data=raw,
        )

    def _collect_page_resources(self) -> list[Resource]:
        """Collect page resources."""
        logger.info("Collecting Confluence page resources...")
        resources = []

        try:
            if self.config.is_cloud:
                for page in self._paginate_v2("pages"):
                    normalized = self._normalize_page(page)
                    resources.append(self._create_page_resource(normalized, page))
            else:
                for space in self._paginate("space", use_v1=True):
                    space_key = space.get("key")
                    try:
                        for page in self._paginate(
                            f"space/{space_key}/content/page",
                            use_v1=True,
                        ):
                            normalized = self._normalize_page(page)
                            resources.append(self._create_page_resource(normalized, page))
                    except Exception as e:
                        logger.warning(f"Error collecting pages for space {space_key}: {e}")
        except Exception as e:
            logger.warning(f"Error collecting page resources: {e}")

        return resources

    def _create_page_resource(self, normalized: dict[str, Any], raw: dict[str, Any]) -> Resource:
        """Create a page resource."""
        return Resource(
            id=str(normalized.get("id", "")),
            type="confluence_page",
            provider="confluence",
            region="global",
            name=normalized.get("title") or "Untitled",
            tags={
                "status": normalized.get("status", "current"),
                "space": normalized.get("space_id") or normalized.get("space_key", ""),
                "version": str(normalized.get("version", 1)),
            },
            metadata={
                "id": normalized.get("id"),
                "title": normalized.get("title"),
                "space_id": normalized.get("space_id"),
                "space_key": normalized.get("space_key"),
                "status": normalized.get("status"),
                "version": normalized.get("version"),
                "updated_at": normalized.get("updated_at"),
            },
            raw_data=raw,
        )

    def _collect_user_resources(self) -> list[Resource]:
        """Collect user resources."""
        logger.info("Collecting Confluence user resources...")
        resources = []
        seen_ids: set[str] = set()

        try:
            for group in self._paginate("group", use_v1=True):
                group_name = group.get("name")
                try:
                    for member in self._paginate(
                        f"group/{group_name}/member",
                        use_v1=True,
                    ):
                        user_id = member.get("accountId") or member.get("userKey")
                        if user_id and user_id not in seen_ids:
                            seen_ids.add(user_id)
                            normalized = self._normalize_user(member)
                            resources.append(self._create_user_resource(normalized, member))
                except Exception as e:
                    logger.warning(f"Error getting members for group {group_name}: {e}")
        except Exception as e:
            logger.warning(f"Error collecting user resources: {e}")

        return resources

    def _create_user_resource(self, normalized: dict[str, Any], raw: dict[str, Any]) -> Resource:
        """Create a user resource."""
        return Resource(
            id=str(normalized.get("account_id", "")),
            type="confluence_user",
            provider="confluence",
            region="global",
            name=normalized.get("display_name") or normalized.get("username") or "Unknown",
            tags={
                "account_type": normalized.get("account_type", "atlassian"),
                "active": str(normalized.get("active", True)).lower(),
            },
            metadata={
                "account_id": normalized.get("account_id"),
                "username": normalized.get("username"),
                "display_name": normalized.get("display_name"),
                "email": normalized.get("email"),
                "account_type": normalized.get("account_type"),
                "active": normalized.get("active"),
            },
            raw_data=raw,
        )

    def _collect_group_resources(self) -> list[Resource]:
        """Collect group resources."""
        logger.info("Collecting Confluence group resources...")
        resources = []

        try:
            for group in self._paginate("group", use_v1=True):
                group_name = group.get("name")

                # Get member count
                member_count = 0
                try:
                    members_data = self._make_request(
                        "GET",
                        f"group/{group_name}/member",
                        params={"limit": 1},
                        use_v1=True,
                    )
                    member_count = members_data.get("size", 0)
                except Exception:
                    pass

                resources.append(
                    Resource(
                        id=str(group.get("id") or group_name),
                        type="confluence_group",
                        provider="confluence",
                        region="global",
                        name=group_name or "Unknown",
                        tags={
                            "type": group.get("type", "group"),
                            "member_count": str(member_count),
                        },
                        metadata={
                            "id": group.get("id"),
                            "name": group_name,
                            "type": group.get("type"),
                            "member_count": member_count,
                        },
                        raw_data=group,
                    )
                )
        except Exception as e:
            logger.warning(f"Error collecting group resources: {e}")

        return resources
