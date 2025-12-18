"""
Tests for the Slab collector.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
import pytest
import requests

from attestful.collectors.platforms.slab import SlabCollector, SlabCollectorConfig
from attestful.core.exceptions import CollectionError, ConfigurationError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_post():
    """Create a mock Slab post."""
    now = datetime.now(timezone.utc)
    return {
        "id": "post-123",
        "title": "Security Policy Documentation",
        "createdAt": (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "updatedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "publishedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version": 5,
        "visibility": "ORGANIZATION",
        "author": {
            "id": "user-123",
            "name": "John Doe",
            "email": "john@example.com",
        },
        "topics": [
            {"id": "topic-123", "name": "Security"},
        ],
        "contributors": [
            {"id": "user-123", "name": "John Doe"},
            {"id": "user-456", "name": "Jane Smith"},
        ],
    }


@pytest.fixture
def mock_private_post():
    """Create a mock private post."""
    now = datetime.now(timezone.utc)
    return {
        "id": "post-456",
        "title": "Internal HR Policies",
        "createdAt": (now - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "updatedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "publishedAt": None,
        "version": 2,
        "visibility": "PRIVATE",
        "author": {
            "id": "user-456",
            "name": "Jane Smith",
            "email": "jane@example.com",
        },
        "topics": [],
        "contributors": [],
    }


@pytest.fixture
def mock_topic():
    """Create a mock Slab topic."""
    return {
        "id": "topic-123",
        "name": "Security",
        "description": "Security policies and procedures",
        "createdAt": "2024-01-01T00:00:00Z",
        "postCount": 15,
        "visibility": "ORGANIZATION",
        "parent": None,
    }


@pytest.fixture
def mock_child_topic():
    """Create a mock child topic."""
    return {
        "id": "topic-456",
        "name": "Access Control",
        "description": "Access control policies",
        "createdAt": "2024-02-01T00:00:00Z",
        "postCount": 5,
        "visibility": "ORGANIZATION",
        "parent": {
            "id": "topic-123",
            "name": "Security",
        },
    }


@pytest.fixture
def mock_user():
    """Create a mock Slab user."""
    now = datetime.now(timezone.utc)
    return {
        "id": "user-123",
        "name": "John Doe",
        "email": "john@example.com",
        "role": "MEMBER",
        "createdAt": "2024-01-01T00:00:00Z",
        "lastActiveAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "deactivated": False,
    }


@pytest.fixture
def mock_admin_user():
    """Create a mock admin user."""
    now = datetime.now(timezone.utc)
    return {
        "id": "user-789",
        "name": "Admin User",
        "email": "admin@example.com",
        "role": "ADMIN",
        "createdAt": "2024-01-01T00:00:00Z",
        "lastActiveAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "deactivated": False,
    }


@pytest.fixture
def mock_deactivated_user():
    """Create a mock deactivated user."""
    return {
        "id": "user-999",
        "name": "Former Employee",
        "email": "former@example.com",
        "role": "MEMBER",
        "createdAt": "2024-01-01T00:00:00Z",
        "lastActiveAt": "2024-06-01T00:00:00Z",
        "deactivated": True,
    }


@pytest.fixture
def mock_organization():
    """Create a mock Slab organization."""
    return {
        "id": "org-123",
        "name": "Example Company",
        "subdomain": "example",
        "createdAt": "2023-01-01T00:00:00Z",
        "userCount": 50,
        "postCount": 200,
        "topicCount": 15,
    }


@pytest.fixture
def collector():
    """Create a SlabCollector instance."""
    config = SlabCollectorConfig(
        api_token="test-token-12345",
        days_of_history=90,
    )
    return SlabCollector(config=config)


# =============================================================================
# Initialization Tests
# =============================================================================


class TestSlabCollectorInit:
    """Tests for SlabCollector initialization."""

    def test_init_with_config(self, collector):
        """Test initialization with config."""
        assert collector.config.api_token == "test-token-12345"
        assert collector.config.days_of_history == 90

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = SlabCollector()
        assert collector.config.api_token == ""
        assert collector.config.timeout == 30
        assert collector.config.max_retries == 3
        assert collector.config.page_size == 50
        assert collector.config.days_of_history == 90

    def test_metadata(self, collector):
        """Test collector metadata."""
        assert collector.metadata.name == "SlabCollector"
        assert collector.metadata.platform == "slab"
        assert "slab_post" in collector.metadata.resource_types
        assert "slab_topic" in collector.metadata.resource_types
        assert "posts" in collector.metadata.evidence_types
        assert "topics" in collector.metadata.evidence_types

    def test_platform(self, collector):
        """Test platform attribute."""
        assert collector.PLATFORM == "slab"

    def test_graphql_url(self, collector):
        """Test GraphQL URL constant."""
        assert collector.GRAPHQL_URL == "https://api.slab.com/v1/graphql"


# =============================================================================
# Session Tests
# =============================================================================


class TestSlabSession:
    """Tests for session creation."""

    def test_session_creation(self, collector):
        """Test session is created on first access."""
        session = collector.session
        assert session is not None
        assert isinstance(session, requests.Session)

    def test_session_cached(self, collector):
        """Test session is cached."""
        session1 = collector.session
        session2 = collector.session
        assert session1 is session2

    def test_session_has_auth_header(self, collector):
        """Test session has authorization header."""
        session = collector.session
        assert "Authorization" in session.headers
        assert session.headers["Authorization"] == "test-token-12345"


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestValidateCredentials:
    """Tests for credential validation."""

    def test_validate_credentials_success(self, collector, mock_organization):
        """Test successful credential validation."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "organization": mock_organization,
            },
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.validate_credentials()
            assert result is True

    def test_validate_credentials_no_token(self):
        """Test validation fails without token."""
        collector = SlabCollector(config=SlabCollectorConfig(api_token=""))
        with pytest.raises(ConfigurationError, match="api_token is required"):
            collector.validate_credentials()

    def test_validate_credentials_invalid_token(self, collector):
        """Test validation fails with invalid token."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "errors": [{"message": "Unauthorized"}],
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(collector.session, "post", return_value=mock_response):
            with pytest.raises(ConfigurationError, match="Invalid Slab API token"):
                collector.validate_credentials()

    def test_validate_credentials_api_error(self, collector):
        """Test validation handles API errors."""
        with patch.object(
            collector.session,
            "post",
            side_effect=requests.RequestException("Connection error"),
        ):
            with pytest.raises(ConfigurationError, match="Failed to validate"):
                collector.validate_credentials()


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestCollectEvidence:
    """Tests for evidence collection."""

    def test_collect_all_evidence_types(self, collector, mock_post, mock_topic, mock_user, mock_organization):
        """Test collecting all evidence types."""
        def mock_post_request(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            payload = kwargs.get("json", {})
            query = payload.get("query", "")

            if "posts" in query:
                response.json.return_value = {
                    "data": {
                        "posts": {
                            "edges": [{"node": mock_post}],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }
            elif "topics" in query:
                response.json.return_value = {
                    "data": {
                        "topics": {
                            "edges": [{"node": mock_topic}],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }
            elif "users" in query:
                response.json.return_value = {
                    "data": {
                        "users": {
                            "edges": [{"node": mock_user}],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }
            elif "organization" in query:
                response.json.return_value = {
                    "data": {
                        "organization": mock_organization,
                    }
                }

            return response

        with patch.object(collector.session, "post", side_effect=mock_post_request):
            result = collector.collect_evidence()

            assert result.platform == "slab"
            assert len(result.evidence_items) == 4
            assert result.started_at is not None
            assert result.completed_at is not None

    def test_collect_specific_evidence_types(self, collector, mock_post):
        """Test collecting specific evidence types."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "posts": {
                    "edges": [{"node": mock_post}],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["posts"])

            assert result.platform == "slab"
            assert len(result.evidence_items) == 1
            assert result.evidence_items[0].evidence_type == "posts"

    def test_collect_evidence_invalid_type(self, collector):
        """Test collecting invalid evidence type."""
        with pytest.raises(CollectionError, match="Unsupported evidence types"):
            collector.collect_evidence(evidence_types=["invalid_type"])

    def test_collect_posts_evidence(self, collector, mock_post, mock_private_post):
        """Test collecting posts evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "posts": {
                    "edges": [{"node": mock_post}, {"node": mock_private_post}],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["posts"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "posts"
            assert evidence.platform == "slab"
            assert evidence.raw_data["total_count"] == 2
            assert "ORGANIZATION" in evidence.raw_data["visibility_counts"]
            assert "PRIVATE" in evidence.raw_data["visibility_counts"]

    def test_collect_posts_respects_date_filter(self, collector, mock_post):
        """Test posts collection respects date filter."""
        old_post = mock_post.copy()
        old_post["id"] = "post-old"
        old_post["updatedAt"] = "2020-01-01T00:00:00Z"

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "posts": {
                    "edges": [{"node": mock_post}, {"node": old_post}],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["posts"])

            evidence = result.evidence_items[0]
            # Only the recent post should be included
            assert evidence.raw_data["total_count"] == 1

    def test_collect_topics_evidence(self, collector, mock_topic, mock_child_topic):
        """Test collecting topics evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "topics": {
                    "edges": [{"node": mock_topic}, {"node": mock_child_topic}],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["topics"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "topics"
            assert evidence.raw_data["total_count"] == 2
            assert evidence.raw_data["root_topic_count"] == 1

    def test_collect_users_evidence(self, collector, mock_user, mock_admin_user, mock_deactivated_user):
        """Test collecting users evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "users": {
                    "edges": [
                        {"node": mock_user},
                        {"node": mock_admin_user},
                        {"node": mock_deactivated_user},
                    ],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["users"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "users"
            assert evidence.raw_data["total_count"] == 3
            assert evidence.raw_data["active_count"] == 2
            assert evidence.raw_data["deactivated_count"] == 1
            assert "MEMBER" in evidence.raw_data["role_counts"]
            assert "ADMIN" in evidence.raw_data["role_counts"]

    def test_collect_organization_evidence(self, collector, mock_organization):
        """Test collecting organization evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "organization": mock_organization,
            }
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["organization"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "organization"
            assert evidence.raw_data["organization"]["name"] == "Example Company"
            assert evidence.raw_data["organization"]["user_count"] == 50


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestCollectResources:
    """Tests for resource collection."""

    def test_collect_all_resource_types(self, collector, mock_post, mock_topic, mock_user):
        """Test collecting all resource types."""
        def mock_post_request(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            payload = kwargs.get("json", {})
            query = payload.get("query", "")

            if "posts" in query:
                response.json.return_value = {
                    "data": {
                        "posts": {
                            "edges": [{"node": mock_post}],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }
            elif "topics" in query:
                response.json.return_value = {
                    "data": {
                        "topics": {
                            "edges": [{"node": mock_topic}],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }
            elif "users" in query:
                response.json.return_value = {
                    "data": {
                        "users": {
                            "edges": [{"node": mock_user}],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }

            return response

        with patch.object(collector.session, "post", side_effect=mock_post_request):
            resources = collector.collect_resources()

            assert len(resources) == 3
            types = {r.type for r in resources}
            assert "slab_post" in types
            assert "slab_topic" in types
            assert "slab_user" in types

    def test_collect_specific_resource_types(self, collector, mock_post):
        """Test collecting specific resource types."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "posts": {
                    "edges": [{"node": mock_post}],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["slab_post"])

            assert len(resources) == 1
            assert resources[0].type == "slab_post"

    def test_collect_resources_invalid_type(self, collector):
        """Test collecting invalid resource type."""
        with pytest.raises(CollectionError, match="Unsupported resource types"):
            collector.collect_resources(resource_types=["invalid_type"])

    def test_collect_post_resources(self, collector, mock_post):
        """Test collecting post resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "posts": {
                    "edges": [{"node": mock_post}],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["slab_post"])

            assert len(resources) == 1
            resource = resources[0]
            assert resource.type == "slab_post"
            assert resource.provider == "slab"
            assert resource.id == "post-123"
            assert resource.name == "Security Policy Documentation"
            assert resource.tags["visibility"] == "ORGANIZATION"

    def test_collect_topic_resources(self, collector, mock_topic):
        """Test collecting topic resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "topics": {
                    "edges": [{"node": mock_topic}],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["slab_topic"])

            assert len(resources) == 1
            resource = resources[0]
            assert resource.type == "slab_topic"
            assert resource.id == "topic-123"
            assert resource.name == "Security"
            assert resource.tags["post_count"] == "15"

    def test_collect_user_resources(self, collector, mock_user):
        """Test collecting user resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "users": {
                    "edges": [{"node": mock_user}],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["slab_user"])

            assert len(resources) == 1
            resource = resources[0]
            assert resource.type == "slab_user"
            assert resource.id == "user-123"
            assert resource.name == "John Doe"
            assert resource.tags["role"] == "MEMBER"
            assert resource.tags["deactivated"] == "false"


# =============================================================================
# Pagination Tests
# =============================================================================


class TestPagination:
    """Tests for API pagination."""

    def test_pagination_multiple_pages(self, collector, mock_post):
        """Test pagination across multiple pages."""
        page1_post = mock_post.copy()
        page1_post["id"] = "post-1"

        page2_post = mock_post.copy()
        page2_post["id"] = "post-2"

        call_count = [0]

        def mock_post_request(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            call_count[0] += 1

            payload = kwargs.get("json", {})
            variables = payload.get("variables", {})
            cursor = variables.get("after")

            if not cursor:
                response.json.return_value = {
                    "data": {
                        "posts": {
                            "edges": [{"node": page1_post}],
                            "pageInfo": {"hasNextPage": True, "endCursor": "cursor1"},
                        }
                    }
                }
            else:
                response.json.return_value = {
                    "data": {
                        "posts": {
                            "edges": [{"node": page2_post}],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }
            return response

        with patch.object(collector.session, "post", side_effect=mock_post_request):
            result = collector.collect_evidence(evidence_types=["posts"])

            evidence = result.evidence_items[0]
            assert evidence.raw_data["total_count"] == 2

    def test_pagination_stops_on_error(self, collector, mock_post):
        """Test pagination stops on API error."""
        call_count = [0]

        def mock_post_request(url, **kwargs):
            call_count[0] += 1

            if call_count[0] == 1:
                response = MagicMock()
                response.raise_for_status = MagicMock()
                response.json.return_value = {
                    "data": {
                        "posts": {
                            "edges": [{"node": mock_post}],
                            "pageInfo": {"hasNextPage": True, "endCursor": "cursor1"},
                        }
                    }
                }
                return response
            else:
                raise requests.RequestException("API error")

        with patch.object(collector.session, "post", side_effect=mock_post_request):
            result = collector.collect_evidence(evidence_types=["posts"])

            # Should still have results from first page
            evidence = result.evidence_items[0]
            assert evidence.raw_data["total_count"] == 1


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    def test_api_error_logged_but_continues(self, collector, mock_post):
        """Test that API errors are logged but collection continues."""
        def mock_post_request(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            payload = kwargs.get("json", {})
            query = payload.get("query", "")

            if "posts" in query:
                response.json.return_value = {
                    "data": {
                        "posts": {
                            "edges": [{"node": mock_post}],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                }
            else:
                raise requests.RequestException("API error")
            return response

        with patch.object(collector.session, "post", side_effect=mock_post_request):
            result = collector.collect_evidence(evidence_types=["posts", "topics"])

            # Should still have posts evidence
            evidence_types = [e.evidence_type for e in result.evidence_items]
            assert "posts" in evidence_types

    def test_graphql_error_raises_exception(self, collector):
        """Test that GraphQL errors are handled."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "errors": [{"message": "Query error"}],
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["posts"])

            # Should have errors
            assert len(result.errors) > 0


# =============================================================================
# Compliance Control Mapping Tests
# =============================================================================


class TestComplianceControls:
    """Tests for compliance control mappings."""

    def test_posts_evidence_has_controls(self, collector, mock_post):
        """Test posts evidence has compliance controls."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "posts": {
                    "edges": [{"node": mock_post}],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["posts"])

            evidence = result.evidence_items[0]
            controls = evidence.metadata["compliance_controls"]
            assert "soc2" in controls
            assert "nist_800_53" in controls
            assert "iso_27001" in controls
            assert "hitrust" in controls
            # Check documentation controls
            assert "AT-2" in controls["nist_800_53"]

    def test_users_evidence_has_controls(self, collector, mock_user):
        """Test users evidence has compliance controls."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "users": {
                    "edges": [{"node": mock_user}],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["users"])

            evidence = result.evidence_items[0]
            controls = evidence.metadata["compliance_controls"]
            assert "CC6.1" in controls["soc2"]
            assert "AC-2" in controls["nist_800_53"]

    def test_all_evidence_types_have_mappings(self, collector):
        """Test all evidence types have compliance mappings."""
        for evidence_type in collector.SUPPORTED_EVIDENCE_TYPES:
            assert evidence_type in collector.EVIDENCE_CONTROL_MAPPINGS
            mappings = collector.EVIDENCE_CONTROL_MAPPINGS[evidence_type]
            assert "soc2" in mappings
            assert "nist_800_53" in mappings
            assert "iso_27001" in mappings
            assert "hitrust" in mappings
