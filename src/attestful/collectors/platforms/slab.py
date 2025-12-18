"""
Slab collector for Attestful.

Collects knowledge base, documentation, and internal wiki evidence
from Slab for compliance frameworks including SOC 2, NIST 800-53,
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
class SlabCollectorConfig:
    """Configuration for Slab collector."""

    # API Token
    api_token: str = ""

    # API settings
    timeout: int = 30
    max_retries: int = 3
    page_size: int = 50

    # Collection options
    days_of_history: int = 90


class SlabCollector(BaseCollector):
    """
    Slab collector for knowledge base and documentation evidence.

    Collects evidence related to:
    - Posts (documentation articles)
    - Topics (categories/folders)
    - Users and their contributions
    - Organization settings

    Evidence Types:
    - posts: Documentation posts and articles
    - topics: Topic/category structure
    - users: User accounts and activity
    - organization: Organization settings and configuration

    Resource Types:
    - slab_post: Post/article resources
    - slab_topic: Topic/category resources
    - slab_user: User resources

    Example:
        collector = SlabCollector(
            config=SlabCollectorConfig(
                api_token="your-api-token",
            )
        )

        # Collect evidence
        result = collector.collect_evidence(
            evidence_types=["posts", "topics", "users"]
        )

        # Collect resources for compliance checks
        resources = collector.collect_resources(
            resource_types=["slab_post", "slab_topic"]
        )
    """

    PLATFORM = "slab"

    metadata = CollectorMetadata(
        name="SlabCollector",
        platform="slab",
        description="Collects knowledge base and documentation evidence from Slab",
        mode=CollectorMode.BOTH,
        resource_types=[
            "slab_post",
            "slab_topic",
            "slab_user",
        ],
        evidence_types=[
            "posts",
            "topics",
            "users",
            "organization",
        ],
    )

    SUPPORTED_RESOURCE_TYPES = [
        "slab_post",
        "slab_topic",
        "slab_user",
    ]

    SUPPORTED_EVIDENCE_TYPES = [
        "posts",
        "topics",
        "users",
        "organization",
    ]

    # Compliance control mappings
    EVIDENCE_CONTROL_MAPPINGS = {
        "posts": {
            "soc2": ["CC2.2", "CC2.3", "CC5.3"],
            "nist_800_53": ["AT-2", "AT-3", "PM-13", "SA-5"],
            "iso_27001": ["A.7.2.2", "A.12.1.1"],
            "hitrust": ["02.e", "05.a"],
        },
        "topics": {
            "soc2": ["CC2.2", "CC5.3"],
            "nist_800_53": ["PM-13", "SA-5"],
            "iso_27001": ["A.7.2.2"],
            "hitrust": ["02.e"],
        },
        "users": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "nist_800_53": ["AC-2", "IA-2", "IA-4"],
            "iso_27001": ["A.9.2.1", "A.9.2.2"],
            "hitrust": ["01.b", "01.c"],
        },
        "organization": {
            "soc2": ["CC5.2", "CC6.1"],
            "nist_800_53": ["AC-1", "CM-1"],
            "iso_27001": ["A.5.1.1", "A.5.1.2"],
            "hitrust": ["01.a", "05.a"],
        },
    }

    # GraphQL API endpoint
    GRAPHQL_URL = "https://api.slab.com/v1/graphql"

    def __init__(self, config: SlabCollectorConfig | None = None):
        """Initialize the Slab collector."""
        self.config = config or SlabCollectorConfig()
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

        # Set default headers
        session.headers["Content-Type"] = "application/json"
        session.headers["Authorization"] = self.config.api_token

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
                self.GRAPHQL_URL,
                json=payload,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            data = response.json()

            if "errors" in data:
                errors = data["errors"]
                error_msg = errors[0].get("message", "Unknown GraphQL error") if errors else "Unknown error"
                logger.warning(f"GraphQL error: {error_msg}")
                raise requests.RequestException(f"GraphQL error: {error_msg}")

            return data.get("data", {})
        except requests.RequestException as e:
            logger.warning(f"GraphQL request failed: {e}")
            raise

    def validate_credentials(self) -> bool:
        """Validate Slab credentials."""
        if not self.config.api_token:
            raise ConfigurationError("Slab api_token is required")

        try:
            # Test authentication by getting organization info
            query = """
            query {
                organization {
                    id
                    name
                }
            }
            """
            data = self._graphql_query(query)
            org = data.get("organization", {})
            org_name = org.get("name", "Unknown")
            logger.info(f"Authenticated to Slab organization: {org_name}")
            return True
        except requests.RequestException as e:
            if "401" in str(e) or "Unauthorized" in str(e):
                raise ConfigurationError("Invalid Slab API token")
            raise ConfigurationError(f"Failed to validate Slab credentials: {e}")

    def collect_evidence(
        self,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """Collect evidence from Slab."""
        evidence_types = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        invalid_types = set(evidence_types) - set(self.SUPPORTED_EVIDENCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported evidence types: {invalid_types}")

        logger.info(f"Collecting Slab evidence: {evidence_types}")
        evidence_items: list[Evidence] = []
        errors: list[str] = []

        collection_methods = {
            "posts": self._collect_posts_evidence,
            "topics": self._collect_topics_evidence,
            "users": self._collect_users_evidence,
            "organization": self._collect_organization_evidence,
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

    def _collect_posts_evidence(self) -> Evidence:
        """Collect posts evidence."""
        logger.info("Collecting Slab posts...")
        posts = []

        # Calculate date range
        since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)
        since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")

        query = """
        query($first: Int, $after: String) {
            posts(first: $first, after: $after, orderBy: UPDATED_AT_DESC) {
                edges {
                    node {
                        id
                        title
                        createdAt
                        updatedAt
                        publishedAt
                        version
                        visibility
                        author {
                            id
                            name
                            email
                        }
                        topics {
                            id
                            name
                        }
                        contributors {
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

        has_next_page = True
        cursor = None

        while has_next_page:
            try:
                variables = {"first": self.config.page_size}
                if cursor:
                    variables["after"] = cursor

                data = self._graphql_query(query, variables)
                posts_data = data.get("posts", {})
                edges = posts_data.get("edges", [])

                for edge in edges:
                    node = edge.get("node", {})
                    updated_at_str = node.get("updatedAt", "")

                    # Filter by date
                    if updated_at_str:
                        try:
                            updated_at = datetime.fromisoformat(updated_at_str.replace("Z", "+00:00"))
                            if updated_at < since:
                                continue
                        except (ValueError, TypeError):
                            pass

                    author = node.get("author", {}) or {}
                    topics = node.get("topics", []) or []
                    contributors = node.get("contributors", []) or []

                    posts.append({
                        "id": node.get("id"),
                        "title": node.get("title"),
                        "created_at": node.get("createdAt"),
                        "updated_at": node.get("updatedAt"),
                        "published_at": node.get("publishedAt"),
                        "version": node.get("version"),
                        "visibility": node.get("visibility"),
                        "author": {
                            "id": author.get("id"),
                            "name": author.get("name"),
                            "email": author.get("email"),
                        },
                        "topics": [{"id": t.get("id"), "name": t.get("name")} for t in topics],
                        "contributor_count": len(contributors),
                    })

                page_info = posts_data.get("pageInfo", {})
                has_next_page = page_info.get("hasNextPage", False)
                cursor = page_info.get("endCursor")

            except requests.RequestException:
                # Re-raise on first page (no data collected yet)
                # Otherwise break and return partial data
                if not posts:
                    raise
                break

        # Categorize posts
        visibility_counts = {}
        for post in posts:
            vis = post.get("visibility", "unknown")
            visibility_counts[vis] = visibility_counts.get(vis, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="posts",
            raw_data={
                "posts": posts,
                "total_count": len(posts),
                "visibility_counts": visibility_counts,
                "days_of_history": self.config.days_of_history,
            },
            metadata={
                "source": "collector:slab",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["posts"],
            },
        )

    def _collect_topics_evidence(self) -> Evidence:
        """Collect topics evidence."""
        logger.info("Collecting Slab topics...")
        topics = []

        query = """
        query($first: Int, $after: String) {
            topics(first: $first, after: $after) {
                edges {
                    node {
                        id
                        name
                        description
                        createdAt
                        postCount
                        visibility
                        parent {
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

        has_next_page = True
        cursor = None

        while has_next_page:
            try:
                variables = {"first": self.config.page_size}
                if cursor:
                    variables["after"] = cursor

                data = self._graphql_query(query, variables)
                topics_data = data.get("topics", {})
                edges = topics_data.get("edges", [])

                for edge in edges:
                    node = edge.get("node", {})
                    parent = node.get("parent", {}) or {}

                    topics.append({
                        "id": node.get("id"),
                        "name": node.get("name"),
                        "description": node.get("description"),
                        "created_at": node.get("createdAt"),
                        "post_count": node.get("postCount", 0),
                        "visibility": node.get("visibility"),
                        "parent": {
                            "id": parent.get("id"),
                            "name": parent.get("name"),
                        } if parent.get("id") else None,
                    })

                page_info = topics_data.get("pageInfo", {})
                has_next_page = page_info.get("hasNextPage", False)
                cursor = page_info.get("endCursor")

            except requests.RequestException:
                if not topics:
                    raise
                break

        # Count root topics (no parent)
        root_topics = sum(1 for t in topics if not t.get("parent"))

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="topics",
            raw_data={
                "topics": topics,
                "total_count": len(topics),
                "root_topic_count": root_topics,
            },
            metadata={
                "source": "collector:slab",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["topics"],
            },
        )

    def _collect_users_evidence(self) -> Evidence:
        """Collect users evidence."""
        logger.info("Collecting Slab users...")
        users = []

        query = """
        query($first: Int, $after: String) {
            users(first: $first, after: $after) {
                edges {
                    node {
                        id
                        name
                        email
                        role
                        createdAt
                        lastActiveAt
                        deactivated
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        """

        has_next_page = True
        cursor = None

        while has_next_page:
            try:
                variables = {"first": self.config.page_size}
                if cursor:
                    variables["after"] = cursor

                data = self._graphql_query(query, variables)
                users_data = data.get("users", {})
                edges = users_data.get("edges", [])

                for edge in edges:
                    node = edge.get("node", {})

                    users.append({
                        "id": node.get("id"),
                        "name": node.get("name"),
                        "email": node.get("email"),
                        "role": node.get("role"),
                        "created_at": node.get("createdAt"),
                        "last_active_at": node.get("lastActiveAt"),
                        "deactivated": node.get("deactivated", False),
                    })

                page_info = users_data.get("pageInfo", {})
                has_next_page = page_info.get("hasNextPage", False)
                cursor = page_info.get("endCursor")

            except requests.RequestException:
                if not users:
                    raise
                break

        # Categorize users
        role_counts = {}
        active_count = 0
        deactivated_count = 0

        for user in users:
            role = user.get("role", "unknown")
            role_counts[role] = role_counts.get(role, 0) + 1

            if user.get("deactivated"):
                deactivated_count += 1
            else:
                active_count += 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="users",
            raw_data={
                "users": users,
                "total_count": len(users),
                "active_count": active_count,
                "deactivated_count": deactivated_count,
                "role_counts": role_counts,
            },
            metadata={
                "source": "collector:slab",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["users"],
            },
        )

    def _collect_organization_evidence(self) -> Evidence:
        """Collect organization evidence."""
        logger.info("Collecting Slab organization info...")
        organization = {}

        query = """
        query {
            organization {
                id
                name
                subdomain
                createdAt
                userCount
                postCount
                topicCount
            }
        }
        """

        try:
            data = self._graphql_query(query)
            org = data.get("organization", {})

            organization = {
                "id": org.get("id"),
                "name": org.get("name"),
                "subdomain": org.get("subdomain"),
                "created_at": org.get("createdAt"),
                "user_count": org.get("userCount", 0),
                "post_count": org.get("postCount", 0),
                "topic_count": org.get("topicCount", 0),
            }
        except requests.RequestException as e:
            logger.warning(f"Error collecting organization info: {e}")

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="organization",
            raw_data={
                "organization": organization,
            },
            metadata={
                "source": "collector:slab",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["organization"],
            },
        )

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """Collect resources from Slab for compliance checks."""
        resource_types = resource_types or self.SUPPORTED_RESOURCE_TYPES
        invalid_types = set(resource_types) - set(self.SUPPORTED_RESOURCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported resource types: {invalid_types}")

        logger.info(f"Collecting Slab resources: {resource_types}")
        resources: list[Resource] = []

        collection_methods = {
            "slab_post": self._collect_post_resources,
            "slab_topic": self._collect_topic_resources,
            "slab_user": self._collect_user_resources,
        }

        for resource_type in resource_types:
            method = collection_methods.get(resource_type)
            if method:
                resources.extend(method())

        return resources

    def _collect_post_resources(self) -> list[Resource]:
        """Collect post resources."""
        logger.info("Collecting Slab post resources...")
        resources = []

        # Calculate date range
        since = datetime.now(timezone.utc) - timedelta(days=self.config.days_of_history)

        query = """
        query($first: Int, $after: String) {
            posts(first: $first, after: $after, orderBy: UPDATED_AT_DESC) {
                edges {
                    node {
                        id
                        title
                        createdAt
                        updatedAt
                        visibility
                        version
                        author {
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

        has_next_page = True
        cursor = None

        while has_next_page:
            try:
                variables = {"first": self.config.page_size}
                if cursor:
                    variables["after"] = cursor

                data = self._graphql_query(query, variables)
                posts_data = data.get("posts", {})
                edges = posts_data.get("edges", [])

                for edge in edges:
                    node = edge.get("node", {})
                    updated_at_str = node.get("updatedAt", "")

                    # Filter by date
                    if updated_at_str:
                        try:
                            updated_at = datetime.fromisoformat(updated_at_str.replace("Z", "+00:00"))
                            if updated_at < since:
                                continue
                        except (ValueError, TypeError):
                            pass

                    author = node.get("author", {}) or {}

                    resources.append(
                        Resource(
                            id=str(node.get("id", "")),
                            type="slab_post",
                            provider="slab",
                            region="global",
                            name=node.get("title", "Untitled"),
                            tags={
                                "visibility": node.get("visibility", "unknown"),
                                "version": str(node.get("version", 1)),
                            },
                            metadata={
                                "id": node.get("id"),
                                "title": node.get("title"),
                                "created_at": node.get("createdAt"),
                                "updated_at": node.get("updatedAt"),
                                "visibility": node.get("visibility"),
                                "version": node.get("version"),
                                "author_id": author.get("id"),
                                "author_name": author.get("name"),
                            },
                            raw_data=node,
                        )
                    )

                page_info = posts_data.get("pageInfo", {})
                has_next_page = page_info.get("hasNextPage", False)
                cursor = page_info.get("endCursor")

            except requests.RequestException:
                if not resources:
                    raise
                break

        return resources

    def _collect_topic_resources(self) -> list[Resource]:
        """Collect topic resources."""
        logger.info("Collecting Slab topic resources...")
        resources = []

        query = """
        query($first: Int, $after: String) {
            topics(first: $first, after: $after) {
                edges {
                    node {
                        id
                        name
                        description
                        postCount
                        visibility
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        """

        has_next_page = True
        cursor = None

        while has_next_page:
            try:
                variables = {"first": self.config.page_size}
                if cursor:
                    variables["after"] = cursor

                data = self._graphql_query(query, variables)
                topics_data = data.get("topics", {})
                edges = topics_data.get("edges", [])

                for edge in edges:
                    node = edge.get("node", {})

                    resources.append(
                        Resource(
                            id=str(node.get("id", "")),
                            type="slab_topic",
                            provider="slab",
                            region="global",
                            name=node.get("name", "Untitled"),
                            tags={
                                "visibility": node.get("visibility", "unknown"),
                                "post_count": str(node.get("postCount", 0)),
                            },
                            metadata={
                                "id": node.get("id"),
                                "name": node.get("name"),
                                "description": node.get("description"),
                                "post_count": node.get("postCount", 0),
                                "visibility": node.get("visibility"),
                            },
                            raw_data=node,
                        )
                    )

                page_info = topics_data.get("pageInfo", {})
                has_next_page = page_info.get("hasNextPage", False)
                cursor = page_info.get("endCursor")

            except requests.RequestException:
                if not resources:
                    raise
                break

        return resources

    def _collect_user_resources(self) -> list[Resource]:
        """Collect user resources."""
        logger.info("Collecting Slab user resources...")
        resources = []

        query = """
        query($first: Int, $after: String) {
            users(first: $first, after: $after) {
                edges {
                    node {
                        id
                        name
                        email
                        role
                        deactivated
                        lastActiveAt
                    }
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
            }
        }
        """

        has_next_page = True
        cursor = None

        while has_next_page:
            try:
                variables = {"first": self.config.page_size}
                if cursor:
                    variables["after"] = cursor

                data = self._graphql_query(query, variables)
                users_data = data.get("users", {})
                edges = users_data.get("edges", [])

                for edge in edges:
                    node = edge.get("node", {})

                    resources.append(
                        Resource(
                            id=str(node.get("id", "")),
                            type="slab_user",
                            provider="slab",
                            region="global",
                            name=node.get("name", "Unknown"),
                            tags={
                                "role": node.get("role", "unknown"),
                                "deactivated": str(node.get("deactivated", False)).lower(),
                            },
                            metadata={
                                "id": node.get("id"),
                                "name": node.get("name"),
                                "email": node.get("email"),
                                "role": node.get("role"),
                                "deactivated": node.get("deactivated", False),
                                "last_active_at": node.get("lastActiveAt"),
                            },
                            raw_data=node,
                        )
                    )

                page_info = users_data.get("pageInfo", {})
                has_next_page = page_info.get("hasNextPage", False)
                cursor = page_info.get("endCursor")

            except requests.RequestException:
                if not resources:
                    raise
                break

        return resources
