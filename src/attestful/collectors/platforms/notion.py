"""
Notion collector for Attestful.

Collects documentation, knowledge management, and policy evidence
from Notion for compliance frameworks including SOC 2, NIST 800-53,
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
class NotionCollectorConfig:
    """Configuration for Notion collector."""

    # API token (Internal Integration Token)
    api_token: str = ""

    # API settings
    timeout: int = 30
    max_retries: int = 3
    page_size: int = 100

    # Collection options
    days_of_history: int = 90

    # Optional filters
    root_page_id: str = ""  # Limit to specific workspace area


class NotionCollector(BaseCollector):
    """
    Notion collector for documentation and knowledge management evidence.

    Collects evidence related to:
    - Pages and their content structure
    - Databases and their schemas
    - Users and workspace members
    - Comments and discussions
    - Page/database permissions
    - Workspace audit logs (Enterprise only)

    Evidence Types:
    - pages: Documentation pages with metadata
    - databases: Database schemas and configurations
    - users: Workspace users and bot integrations
    - comments: Page comments and discussions
    - permissions: Access control settings
    - audit_logs: Workspace audit events (Enterprise only)

    Resource Types:
    - notion_page: Page resources
    - notion_database: Database resources
    - notion_user: User resources

    Example:
        collector = NotionCollector(
            config=NotionCollectorConfig(
                api_token="secret_xxx",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["pages", "databases", "users"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["notion_page", "notion_database"]
        )
    """

    PLATFORM = "notion"

    metadata = CollectorMetadata(
        name="NotionCollector",
        platform="notion",
        description="Collects documentation and knowledge management evidence from Notion",
        mode=CollectorMode.BOTH,
        resource_types=[
            "notion_page",
            "notion_database",
            "notion_user",
        ],
        evidence_types=[
            "pages",
            "databases",
            "users",
            "comments",
            "permissions",
            "audit_logs",
        ],
    )

    SUPPORTED_RESOURCE_TYPES = [
        "notion_page",
        "notion_database",
        "notion_user",
    ]

    SUPPORTED_EVIDENCE_TYPES = [
        "pages",
        "databases",
        "users",
        "comments",
        "permissions",
        "audit_logs",
    ]

    # Compliance control mappings
    EVIDENCE_CONTROL_MAPPINGS = {
        "pages": {
            "soc2": ["CC2.2", "CC2.3", "CC5.2"],
            "nist_800_53": ["AT-3", "CP-9", "SA-5"],
            "iso_27001": ["A.7.2.2", "A.12.1.1", "A.18.1.1"],
            "hitrust": ["02.e", "05.a", "06.a"],
        },
        "databases": {
            "soc2": ["CC2.2", "CC5.2", "CC6.1"],
            "nist_800_53": ["CM-8", "SA-5", "PM-5"],
            "iso_27001": ["A.8.1.1", "A.12.1.1"],
            "hitrust": ["07.a", "09.b"],
        },
        "users": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-3", "IA-2"],
            "iso_27001": ["A.9.2.1", "A.9.2.2"],
            "hitrust": ["01.b", "01.c"],
        },
        "comments": {
            "soc2": ["CC2.3", "CC7.2"],
            "nist_800_53": ["AU-6", "IR-4"],
            "iso_27001": ["A.12.4.1", "A.16.1.5"],
            "hitrust": ["09.aa", "11.a"],
        },
        "permissions": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "nist_800_53": ["AC-2", "AC-3", "AC-6"],
            "iso_27001": ["A.9.2.1", "A.9.2.3", "A.9.4.1"],
            "hitrust": ["01.c", "01.e"],
        },
        "audit_logs": {
            "soc2": ["CC7.2", "CC7.3", "CC7.4"],
            "nist_800_53": ["AU-2", "AU-3", "AU-6", "AU-12"],
            "iso_27001": ["A.12.4.1", "A.12.4.3"],
            "hitrust": ["09.aa", "09.ab"],
        },
    }

    # Notion API version
    NOTION_VERSION = "2022-06-28"

    def __init__(self, config: NotionCollectorConfig | None = None):
        """Initialize the Notion collector."""
        self.config = config or NotionCollectorConfig()
        self._session: requests.Session | None = None

    @property
    def session(self) -> requests.Session:
        """Get or create an authenticated session."""
        if self._session is None:
            self._session = self._create_session()
        return self._session

    @property
    def api_url(self) -> str:
        """Get the Notion API base URL."""
        return "https://api.notion.com/v1"

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

        # Set authentication and headers
        session.headers["Authorization"] = f"Bearer {self.config.api_token}"
        session.headers["Notion-Version"] = self.NOTION_VERSION
        session.headers["Content-Type"] = "application/json"

        return session

    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make an authenticated API request."""
        url = f"{self.api_url}/{endpoint}"

        try:
            response = self.session.request(
                method,
                url,
                params=params,
                json=data,
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
        method: str = "POST",
        data: dict[str, Any] | None = None,
        results_key: str = "results",
    ) -> Iterator[dict[str, Any]]:
        """Paginate through Notion API results."""
        data = data or {}
        data["page_size"] = self.config.page_size
        start_cursor = None

        while True:
            if start_cursor:
                data["start_cursor"] = start_cursor

            try:
                if method == "POST":
                    result = self._make_request("POST", endpoint, data=data)
                else:
                    result = self._make_request("GET", endpoint, params=data)

                items = result.get(results_key, [])
                for item in items:
                    yield item

                # Check for next page
                if result.get("has_more"):
                    start_cursor = result.get("next_cursor")
                else:
                    break

            except requests.RequestException:
                break

    def validate_credentials(self) -> bool:
        """Validate Notion credentials."""
        if not self.config.api_token:
            raise ConfigurationError("Notion api_token is required")

        try:
            # Test by getting current user/bot info
            result = self._make_request("GET", "users/me")
            bot_name = result.get("name", "Unknown")
            logger.info(f"Authenticated as: {bot_name}")
            return True
        except requests.HTTPError as e:
            if e.response.status_code == 401:
                raise ConfigurationError("Invalid Notion API token")
            raise ConfigurationError(f"Notion API error: {e}")
        except requests.RequestException as e:
            raise ConfigurationError(f"Failed to connect to Notion: {e}")

    def collect_evidence(
        self,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """Collect evidence from Notion."""
        evidence_types = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        invalid_types = set(evidence_types) - set(self.SUPPORTED_EVIDENCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported evidence types: {invalid_types}")

        logger.info(f"Collecting Notion evidence: {evidence_types}")
        evidence_items: list[Evidence] = []
        errors: list[str] = []

        collection_methods = {
            "pages": self._collect_pages_evidence,
            "databases": self._collect_databases_evidence,
            "users": self._collect_users_evidence,
            "comments": self._collect_comments_evidence,
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

    def _collect_pages_evidence(self) -> Evidence:
        """Collect pages evidence."""
        logger.info("Collecting Notion pages...")
        pages = []
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)

        # Search for all pages
        search_data = {
            "filter": {"property": "object", "value": "page"},
            "sort": {"direction": "descending", "timestamp": "last_edited_time"},
        }

        for page in self._paginate("search", data=search_data):
            last_edited = page.get("last_edited_time", "")
            if last_edited:
                try:
                    edited_dt = datetime.fromisoformat(last_edited.replace("Z", "+00:00"))
                    if edited_dt < cutoff_date:
                        continue
                except ValueError:
                    pass

            pages.append(self._normalize_page(page))

        # Categorize pages
        by_parent_type: dict[str, int] = {}
        for p in pages:
            parent_type = p.get("parent_type", "unknown")
            by_parent_type[parent_type] = by_parent_type.get(parent_type, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="pages",
            raw_data={
                "pages": pages,
                "total_count": len(pages),
                "by_parent_type": by_parent_type,
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:notion",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["pages"],
            },
        )

    def _normalize_page(self, page: dict[str, Any]) -> dict[str, Any]:
        """Normalize page data."""
        properties = page.get("properties", {})
        parent = page.get("parent", {})

        # Extract title from properties
        title = ""
        title_prop = properties.get("title") or properties.get("Name")
        if title_prop:
            title_content = title_prop.get("title", [])
            if title_content:
                title = title_content[0].get("plain_text", "")

        # Determine parent type
        parent_type = parent.get("type", "unknown")

        return {
            "id": page.get("id"),
            "title": title,
            "url": page.get("url"),
            "created_time": page.get("created_time"),
            "last_edited_time": page.get("last_edited_time"),
            "created_by": page.get("created_by", {}).get("id"),
            "last_edited_by": page.get("last_edited_by", {}).get("id"),
            "archived": page.get("archived", False),
            "parent_type": parent_type,
            "parent_id": parent.get(parent_type) if parent_type != "workspace" else "workspace",
            "icon": page.get("icon", {}).get("type") if page.get("icon") else None,
            "cover": page.get("cover", {}).get("type") if page.get("cover") else None,
        }

    def _collect_databases_evidence(self) -> Evidence:
        """Collect databases evidence."""
        logger.info("Collecting Notion databases...")
        databases = []

        # Search for all databases
        search_data = {
            "filter": {"property": "object", "value": "database"},
        }

        for db in self._paginate("search", data=search_data):
            databases.append(self._normalize_database(db))

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="databases",
            raw_data={
                "databases": databases,
                "total_count": len(databases),
            },
            metadata={
                "source": "collector:notion",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["databases"],
            },
        )

    def _normalize_database(self, db: dict[str, Any]) -> dict[str, Any]:
        """Normalize database data."""
        title_list = db.get("title", [])
        title = title_list[0].get("plain_text", "") if title_list else ""

        properties = db.get("properties", {})
        property_schemas = []
        for prop_name, prop_config in properties.items():
            property_schemas.append({
                "name": prop_name,
                "type": prop_config.get("type"),
                "id": prop_config.get("id"),
            })

        parent = db.get("parent", {})
        parent_type = parent.get("type", "unknown")

        return {
            "id": db.get("id"),
            "title": title,
            "url": db.get("url"),
            "created_time": db.get("created_time"),
            "last_edited_time": db.get("last_edited_time"),
            "archived": db.get("archived", False),
            "is_inline": db.get("is_inline", False),
            "parent_type": parent_type,
            "parent_id": parent.get(parent_type) if parent_type != "workspace" else "workspace",
            "property_count": len(properties),
            "property_schemas": property_schemas,
        }

    def _collect_users_evidence(self) -> Evidence:
        """Collect users evidence."""
        logger.info("Collecting Notion users...")
        users = []

        # List all users
        try:
            result = self._make_request("GET", "users", params={"page_size": self.config.page_size})
            user_list = result.get("results", [])

            for user in user_list:
                users.append({
                    "id": user.get("id"),
                    "type": user.get("type"),  # person or bot
                    "name": user.get("name"),
                    "avatar_url": user.get("avatar_url"),
                    "email": user.get("person", {}).get("email") if user.get("type") == "person" else None,
                    "bot_owner_type": user.get("bot", {}).get("owner", {}).get("type") if user.get("type") == "bot" else None,
                })

            # Handle pagination if needed
            while result.get("has_more"):
                result = self._make_request(
                    "GET",
                    "users",
                    params={
                        "page_size": self.config.page_size,
                        "start_cursor": result.get("next_cursor"),
                    },
                )
                for user in result.get("results", []):
                    users.append({
                        "id": user.get("id"),
                        "type": user.get("type"),
                        "name": user.get("name"),
                        "avatar_url": user.get("avatar_url"),
                        "email": user.get("person", {}).get("email") if user.get("type") == "person" else None,
                        "bot_owner_type": user.get("bot", {}).get("owner", {}).get("type") if user.get("type") == "bot" else None,
                    })

        except requests.RequestException as e:
            logger.warning(f"Error collecting users: {e}")

        # Categorize by type
        by_type: dict[str, int] = {}
        for u in users:
            user_type = u.get("type", "unknown")
            by_type[user_type] = by_type.get(user_type, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="users",
            raw_data={
                "users": users,
                "total_count": len(users),
                "by_type": by_type,
                "person_count": by_type.get("person", 0),
                "bot_count": by_type.get("bot", 0),
            },
            metadata={
                "source": "collector:notion",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["users"],
            },
        )

    def _collect_comments_evidence(self) -> Evidence:
        """Collect comments evidence from recent pages."""
        logger.info("Collecting Notion comments...")
        comments = []
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)

        # Get recent pages first, then collect their comments
        search_data = {
            "filter": {"property": "object", "value": "page"},
            "sort": {"direction": "descending", "timestamp": "last_edited_time"},
            "page_size": 50,  # Limit to recent pages
        }

        pages_checked = 0
        max_pages = 100  # Limit pages to check for comments

        for page in self._paginate("search", data=search_data):
            if pages_checked >= max_pages:
                break

            page_id = page.get("id")
            if not page_id:
                continue

            try:
                # Get comments for this page
                comment_result = self._make_request(
                    "GET",
                    "comments",
                    params={"block_id": page_id, "page_size": 50},
                )

                for comment in comment_result.get("results", []):
                    created_time = comment.get("created_time", "")
                    try:
                        created_dt = datetime.fromisoformat(created_time.replace("Z", "+00:00"))
                        if created_dt < cutoff_date:
                            continue
                    except ValueError:
                        pass

                    # Extract comment text
                    rich_text = comment.get("rich_text", [])
                    text = "".join([t.get("plain_text", "") for t in rich_text])

                    comments.append({
                        "id": comment.get("id"),
                        "parent_page_id": page_id,
                        "discussion_id": comment.get("discussion_id"),
                        "created_time": created_time,
                        "created_by": comment.get("created_by", {}).get("id"),
                        "text_preview": text[:200] if text else None,
                    })

            except requests.RequestException:
                pass  # Skip pages we can't access comments for

            pages_checked += 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="comments",
            raw_data={
                "comments": comments,
                "total_count": len(comments),
                "pages_checked": pages_checked,
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:notion",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["comments"],
            },
        )

    def _collect_permissions_evidence(self) -> Evidence:
        """Collect permissions evidence from pages and databases."""
        logger.info("Collecting Notion permissions...")
        permissions = []

        # Collect permissions from pages
        search_data = {
            "filter": {"property": "object", "value": "page"},
            "page_size": 50,
        }

        items_checked = 0
        max_items = 100

        for page in self._paginate("search", data=search_data):
            if items_checked >= max_items:
                break

            page_id = page.get("id")
            parent = page.get("parent", {})

            # Check if page has explicit sharing settings visible
            permissions.append({
                "object_type": "page",
                "object_id": page_id,
                "title": self._get_page_title(page),
                "parent_type": parent.get("type"),
                "archived": page.get("archived", False),
                "public_url": page.get("public_url"),  # None if not publicly shared
                "is_public": page.get("public_url") is not None,
            })
            items_checked += 1

        # Collect permissions from databases
        search_data = {
            "filter": {"property": "object", "value": "database"},
            "page_size": 50,
        }

        for db in self._paginate("search", data=search_data):
            if items_checked >= max_items:
                break

            db_id = db.get("id")
            parent = db.get("parent", {})
            title_list = db.get("title", [])
            title = title_list[0].get("plain_text", "") if title_list else ""

            permissions.append({
                "object_type": "database",
                "object_id": db_id,
                "title": title,
                "parent_type": parent.get("type"),
                "archived": db.get("archived", False),
                "public_url": db.get("public_url"),
                "is_public": db.get("public_url") is not None,
            })
            items_checked += 1

        # Analyze permissions
        public_count = sum(1 for p in permissions if p.get("is_public"))

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="permissions",
            raw_data={
                "permissions": permissions,
                "total_count": len(permissions),
                "public_count": public_count,
                "private_count": len(permissions) - public_count,
            },
            metadata={
                "source": "collector:notion",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["permissions"],
            },
        )

    def _get_page_title(self, page: dict[str, Any]) -> str:
        """Extract title from a page."""
        properties = page.get("properties", {})
        title_prop = properties.get("title") or properties.get("Name")
        if title_prop:
            title_content = title_prop.get("title", [])
            if title_content:
                return title_content[0].get("plain_text", "")
        return ""

    def _collect_audit_logs_evidence(self) -> Evidence:
        """Collect audit logs evidence (Enterprise only)."""
        logger.info("Collecting Notion audit logs...")
        audit_logs = []

        # Note: Audit logs require Enterprise plan and admin access
        # The API endpoint is not publicly available in standard integrations
        # This is a placeholder for when audit log access is available

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="audit_logs",
            raw_data={
                "audit_logs": audit_logs,
                "total_count": len(audit_logs),
                "note": "Audit logs require Notion Enterprise plan and admin API access",
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:notion",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["audit_logs"],
            },
        )

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """Collect resources from Notion for compliance checks."""
        resource_types = resource_types or self.SUPPORTED_RESOURCE_TYPES
        invalid_types = set(resource_types) - set(self.SUPPORTED_RESOURCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported resource types: {invalid_types}")

        logger.info(f"Collecting Notion resources: {resource_types}")
        resources: list[Resource] = []

        collection_methods = {
            "notion_page": self._collect_page_resources,
            "notion_database": self._collect_database_resources,
            "notion_user": self._collect_user_resources,
        }

        for resource_type in resource_types:
            method = collection_methods.get(resource_type)
            if method:
                resources.extend(method())

        return resources

    def _collect_page_resources(self) -> list[Resource]:
        """Collect page resources."""
        logger.info("Collecting Notion page resources...")
        resources = []
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)

        search_data = {
            "filter": {"property": "object", "value": "page"},
            "sort": {"direction": "descending", "timestamp": "last_edited_time"},
        }

        count = 0
        max_pages = 500

        for page in self._paginate("search", data=search_data):
            if count >= max_pages:
                logger.info(f"Reached max page limit of {max_pages}")
                break

            last_edited = page.get("last_edited_time", "")
            if last_edited:
                try:
                    edited_dt = datetime.fromisoformat(last_edited.replace("Z", "+00:00"))
                    if edited_dt < cutoff_date:
                        continue
                except ValueError:
                    pass

            title = self._get_page_title(page)
            parent = page.get("parent", {})
            parent_type = parent.get("type", "unknown")

            resources.append(
                Resource(
                    id=str(page.get("id", "")),
                    type="notion_page",
                    provider="notion",
                    region="global",
                    name=title or f"Page {page.get('id', '')[:8]}",
                    tags={
                        "archived": str(page.get("archived", False)).lower(),
                        "parent_type": parent_type,
                        "is_public": str(page.get("public_url") is not None).lower(),
                    },
                    metadata={
                        "title": title,
                        "url": page.get("url"),
                        "created_time": page.get("created_time"),
                        "last_edited_time": page.get("last_edited_time"),
                        "archived": page.get("archived", False),
                        "parent_type": parent_type,
                        "is_public": page.get("public_url") is not None,
                    },
                    raw_data=page,
                )
            )
            count += 1

        return resources

    def _collect_database_resources(self) -> list[Resource]:
        """Collect database resources."""
        logger.info("Collecting Notion database resources...")
        resources = []

        search_data = {
            "filter": {"property": "object", "value": "database"},
        }

        for db in self._paginate("search", data=search_data):
            title_list = db.get("title", [])
            title = title_list[0].get("plain_text", "") if title_list else ""
            parent = db.get("parent", {})
            parent_type = parent.get("type", "unknown")
            properties = db.get("properties", {})

            resources.append(
                Resource(
                    id=str(db.get("id", "")),
                    type="notion_database",
                    provider="notion",
                    region="global",
                    name=title or f"Database {db.get('id', '')[:8]}",
                    tags={
                        "archived": str(db.get("archived", False)).lower(),
                        "is_inline": str(db.get("is_inline", False)).lower(),
                        "parent_type": parent_type,
                    },
                    metadata={
                        "title": title,
                        "url": db.get("url"),
                        "created_time": db.get("created_time"),
                        "last_edited_time": db.get("last_edited_time"),
                        "archived": db.get("archived", False),
                        "is_inline": db.get("is_inline", False),
                        "parent_type": parent_type,
                        "property_count": len(properties),
                    },
                    raw_data=db,
                )
            )

        return resources

    def _collect_user_resources(self) -> list[Resource]:
        """Collect user resources."""
        logger.info("Collecting Notion user resources...")
        resources = []

        try:
            result = self._make_request("GET", "users", params={"page_size": self.config.page_size})

            for user in result.get("results", []):
                user_type = user.get("type", "unknown")
                resources.append(
                    Resource(
                        id=str(user.get("id", "")),
                        type="notion_user",
                        provider="notion",
                        region="global",
                        name=user.get("name", "Unknown"),
                        tags={
                            "type": user_type,
                        },
                        metadata={
                            "name": user.get("name"),
                            "type": user_type,
                            "email": user.get("person", {}).get("email") if user_type == "person" else None,
                            "avatar_url": user.get("avatar_url"),
                        },
                        raw_data=user,
                    )
                )

            # Handle pagination
            while result.get("has_more"):
                result = self._make_request(
                    "GET",
                    "users",
                    params={
                        "page_size": self.config.page_size,
                        "start_cursor": result.get("next_cursor"),
                    },
                )
                for user in result.get("results", []):
                    user_type = user.get("type", "unknown")
                    resources.append(
                        Resource(
                            id=str(user.get("id", "")),
                            type="notion_user",
                            provider="notion",
                            region="global",
                            name=user.get("name", "Unknown"),
                            tags={
                                "type": user_type,
                            },
                            metadata={
                                "name": user.get("name"),
                                "type": user_type,
                                "email": user.get("person", {}).get("email") if user_type == "person" else None,
                                "avatar_url": user.get("avatar_url"),
                            },
                            raw_data=user,
                        )
                    )

        except requests.RequestException as e:
            logger.warning(f"Error collecting user resources: {e}")

        return resources
