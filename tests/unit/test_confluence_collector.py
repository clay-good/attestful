"""
Tests for the Confluence collector.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
import pytest
import requests

from attestful.collectors.platforms.confluence import ConfluenceCollector, ConfluenceCollectorConfig
from attestful.core.exceptions import CollectionError, ConfigurationError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_space():
    """Create a mock Confluence space."""
    return {
        "id": "123456",
        "key": "ENG",
        "name": "Engineering",
        "type": "global",
        "status": "current",
        "description": {
            "plain": {
                "value": "Engineering documentation",
            },
        },
        "homepageId": "789012",
        "createdAt": "2023-01-15T10:30:00Z",
    }


@pytest.fixture
def mock_personal_space():
    """Create a mock personal space."""
    return {
        "id": "234567",
        "key": "~jdoe",
        "name": "John Doe's Space",
        "type": "personal",
        "status": "current",
        "description": {},
        "homepageId": "890123",
        "createdAt": "2023-06-01T08:00:00Z",
    }


@pytest.fixture
def mock_page():
    """Create a mock Confluence page."""
    recent_date = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat().replace("+00:00", "Z")
    return {
        "id": "page-123",
        "title": "API Documentation",
        "spaceId": "123456",
        "parentId": "789012",
        "parentType": "page",
        "status": "current",
        "createdAt": "2023-01-20T14:00:00Z",
        "authorId": "user-123",
        "ownerId": "user-123",
        "version": {
            "number": 5,
            "createdAt": recent_date,
        },
    }


@pytest.fixture
def mock_stale_page():
    """Create a mock stale page (not updated recently)."""
    old_date = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat().replace("+00:00", "Z")
    return {
        "id": "page-456",
        "title": "Legacy Process",
        "spaceId": "123456",
        "parentId": "789012",
        "parentType": "page",
        "status": "current",
        "createdAt": "2022-01-01T10:00:00Z",
        "authorId": "user-456",
        "ownerId": "user-456",
        "version": {
            "number": 2,
            "createdAt": old_date,
        },
    }


@pytest.fixture
def mock_user():
    """Create a mock Confluence user."""
    return {
        "accountId": "user-123",
        "publicName": "John Doe",
        "displayName": "John Doe",
        "email": "jdoe@example.com",
        "accountType": "atlassian",
        "active": True,
        "profilePicture": {
            "path": "/wiki/aa-avatar/123",
        },
    }


@pytest.fixture
def mock_inactive_user():
    """Create a mock inactive user."""
    return {
        "accountId": "user-456",
        "publicName": "Former Employee",
        "displayName": "Former Employee",
        "email": "former@example.com",
        "accountType": "atlassian",
        "active": False,
        "profilePicture": {},
    }


@pytest.fixture
def mock_group():
    """Create a mock Confluence group."""
    return {
        "id": "group-123",
        "name": "confluence-users",
        "type": "group",
    }


@pytest.fixture
def mock_admin_group():
    """Create a mock admin group."""
    return {
        "id": "group-456",
        "name": "confluence-administrators",
        "type": "group",
    }


@pytest.fixture
def mock_space_permission():
    """Create a mock space permission."""
    return {
        "id": "perm-123",
        "operation": {
            "key": "read",
            "targetType": "space",
        },
        "subjects": {
            "group": {
                "results": [{"name": "confluence-users"}],
            },
        },
    }


@pytest.fixture
def mock_anonymous_permission():
    """Create a mock anonymous permission."""
    return {
        "id": "perm-456",
        "operation": {
            "key": "read",
            "targetType": "space",
        },
        "subjects": {
            "anonymous": True,
        },
    }


@pytest.fixture
def mock_audit_event():
    """Create a mock audit event."""
    return {
        "author": {
            "accountId": "user-123",
            "displayName": "John Doe",
        },
        "creationDate": "2024-06-20T14:30:00Z",
        "summary": "User logged in",
        "category": "Login and Logout",
        "affectedObject": {
            "name": "John Doe",
            "objectType": "USER",
        },
        "description": "User successfully logged in",
    }


@pytest.fixture
def collector_cloud():
    """Create a ConfluenceCollector for Cloud."""
    config = ConfluenceCollectorConfig(
        url="https://company.atlassian.net",
        username="user@company.com",
        api_token="test-api-token",
        is_cloud=True,
        days_of_history=90,
    )
    return ConfluenceCollector(config=config)


@pytest.fixture
def collector_server():
    """Create a ConfluenceCollector for Server."""
    config = ConfluenceCollectorConfig(
        url="https://confluence.company.com",
        personal_access_token="test-pat",
        is_cloud=False,
        days_of_history=90,
    )
    return ConfluenceCollector(config=config)


# =============================================================================
# Initialization Tests
# =============================================================================


class TestConfluenceCollectorInit:
    """Tests for ConfluenceCollector initialization."""

    def test_init_with_cloud_config(self, collector_cloud):
        """Test initialization with Cloud config."""
        assert collector_cloud.config.url == "https://company.atlassian.net"
        assert collector_cloud.config.username == "user@company.com"
        assert collector_cloud.config.api_token == "test-api-token"
        assert collector_cloud.config.is_cloud is True

    def test_init_with_server_config(self, collector_server):
        """Test initialization with Server config."""
        assert collector_server.config.url == "https://confluence.company.com"
        assert collector_server.config.personal_access_token == "test-pat"
        assert collector_server.config.is_cloud is False

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = ConfluenceCollector()
        assert collector.config.url == ""
        assert collector.config.username == ""
        assert collector.config.api_token == ""
        assert collector.config.personal_access_token == ""
        assert collector.config.timeout == 30
        assert collector.config.max_retries == 3
        assert collector.config.page_size == 100
        assert collector.config.days_of_history == 90
        assert collector.config.is_cloud is True

    def test_metadata(self, collector_cloud):
        """Test collector metadata."""
        assert collector_cloud.metadata.name == "ConfluenceCollector"
        assert collector_cloud.metadata.platform == "confluence"
        assert "confluence_space" in collector_cloud.metadata.resource_types
        assert "confluence_page" in collector_cloud.metadata.resource_types
        assert "spaces" in collector_cloud.metadata.evidence_types
        assert "pages" in collector_cloud.metadata.evidence_types
        assert "permissions" in collector_cloud.metadata.evidence_types

    def test_platform(self, collector_cloud):
        """Test platform attribute."""
        assert collector_cloud.PLATFORM == "confluence"

    def test_base_url_cloud(self, collector_cloud):
        """Test base URL for Cloud."""
        assert collector_cloud.base_url == "https://company.atlassian.net/wiki/api/v2"

    def test_base_url_server(self, collector_server):
        """Test base URL for Server."""
        assert collector_server.base_url == "https://confluence.company.com/rest/api"

    def test_base_url_requires_config(self):
        """Test base URL requires URL configuration."""
        collector = ConfluenceCollector()
        with pytest.raises(ConfigurationError, match="URL not configured"):
            _ = collector.base_url


# =============================================================================
# Session Tests
# =============================================================================


class TestConfluenceSession:
    """Tests for session creation."""

    def test_session_creation_basic_auth(self, collector_cloud):
        """Test session creation with basic auth."""
        session = collector_cloud.session
        assert session is not None
        assert isinstance(session, requests.Session)
        assert session.auth == ("user@company.com", "test-api-token")

    def test_session_creation_pat(self, collector_server):
        """Test session creation with PAT."""
        session = collector_server.session
        assert session is not None
        assert isinstance(session, requests.Session)
        assert "Bearer test-pat" in session.headers["Authorization"]

    def test_session_cached(self, collector_cloud):
        """Test session is cached."""
        session1 = collector_cloud.session
        session2 = collector_cloud.session
        assert session1 is session2

    def test_session_requires_auth(self):
        """Test session requires authentication."""
        collector = ConfluenceCollector(
            config=ConfluenceCollectorConfig(url="https://example.com")
        )
        with pytest.raises(ConfigurationError, match="authentication not configured"):
            _ = collector.session


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestValidateCredentials:
    """Tests for credential validation."""

    def test_validate_credentials_success(self, collector_cloud):
        """Test successful credential validation."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "accountId": "user-123",
            "displayName": "Test User",
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(collector_cloud.session, "request", return_value=mock_response):
            result = collector_cloud.validate_credentials()
            assert result is True

    def test_validate_credentials_failure(self, collector_cloud):
        """Test credential validation failure."""
        with patch.object(
            collector_cloud.session,
            "request",
            side_effect=requests.RequestException("Invalid credentials"),
        ):
            with pytest.raises(ConfigurationError, match="Failed to validate"):
                collector_cloud.validate_credentials()


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestCollectEvidence:
    """Tests for evidence collection."""

    def test_collect_all_evidence_types(self, collector_cloud, mock_space, mock_page, mock_user, mock_group):
        """Test collecting all evidence types."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "spaces" in url and "permissions" not in url:
                response.json.return_value = {
                    "results": [mock_space],
                    "_links": {},
                }
            elif "pages" in url:
                response.json.return_value = {
                    "results": [mock_page],
                    "_links": {},
                }
            elif "group/" in url and "member" in url:
                response.json.return_value = {
                    "results": [mock_user],
                    "size": 1,
                }
            elif "group" in url:
                response.json.return_value = {
                    "results": [mock_group],
                    "size": 1,
                }
            elif "permissions" in url:
                response.json.return_value = {
                    "results": [],
                }
            elif "user/current" in url:
                response.json.return_value = {"accountId": "test"}
            else:
                response.json.return_value = {"results": []}

            return response

        with patch.object(collector_cloud.session, "request", side_effect=mock_request):
            result = collector_cloud.collect_evidence()

            assert result.platform == "confluence"
            assert len(result.evidence_items) > 0
            assert result.started_at is not None
            assert result.completed_at is not None

    def test_collect_specific_evidence_types(self, collector_cloud, mock_space):
        """Test collecting specific evidence types."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "results": [mock_space],
            "_links": {},
        }

        with patch.object(collector_cloud.session, "request", return_value=mock_response):
            result = collector_cloud.collect_evidence(evidence_types=["spaces"])

            assert result.platform == "confluence"
            assert len(result.evidence_items) == 1
            assert result.evidence_items[0].evidence_type == "spaces"

    def test_collect_evidence_invalid_type(self, collector_cloud):
        """Test collecting invalid evidence type."""
        with pytest.raises(CollectionError, match="Unsupported evidence types"):
            collector_cloud.collect_evidence(evidence_types=["invalid_type"])

    def test_collect_spaces_evidence(self, collector_cloud, mock_space, mock_personal_space):
        """Test collecting spaces evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "results": [mock_space, mock_personal_space],
            "_links": {},
        }

        with patch.object(collector_cloud.session, "request", return_value=mock_response):
            result = collector_cloud.collect_evidence(evidence_types=["spaces"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "spaces"
            assert evidence.platform == "confluence"
            assert evidence.raw_data["total_count"] == 2
            assert evidence.raw_data["global_count"] == 1
            assert evidence.raw_data["personal_count"] == 1
            assert "compliance_controls" in evidence.metadata

    def test_collect_pages_evidence(self, collector_cloud, mock_space, mock_page, mock_stale_page):
        """Test collecting pages evidence."""
        call_count = [0]

        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            call_count[0] += 1

            if "pages" in url:
                response.json.return_value = {
                    "results": [mock_page, mock_stale_page],
                    "_links": {},
                }
            else:
                response.json.return_value = {"results": []}

            return response

        with patch.object(collector_cloud.session, "request", side_effect=mock_request):
            result = collector_cloud.collect_evidence(evidence_types=["pages"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "pages"
            assert evidence.raw_data["total_count"] == 2
            assert evidence.raw_data["stale_pages_count"] == 1

    def test_collect_users_evidence(self, collector_cloud, mock_group, mock_user, mock_inactive_user):
        """Test collecting users evidence."""
        call_count = [0]

        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            call_count[0] += 1

            if "group/" in url and "member" in url:
                response.json.return_value = {
                    "results": [mock_user, mock_inactive_user],
                    "size": 2,
                }
            elif "group" in url:
                response.json.return_value = {
                    "results": [mock_group],
                    "size": 1,
                }
            else:
                response.json.return_value = {"results": []}

            return response

        with patch.object(collector_cloud.session, "request", side_effect=mock_request):
            result = collector_cloud.collect_evidence(evidence_types=["users"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "users"
            assert evidence.raw_data["total_count"] == 2
            assert evidence.raw_data["active_count"] == 1

    def test_collect_groups_evidence(self, collector_cloud, mock_group, mock_admin_group):
        """Test collecting groups evidence."""
        call_count = [0]

        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            call_count[0] += 1

            if "member" in url:
                response.json.return_value = {"results": [], "size": 5}
            elif "group" in url:
                response.json.return_value = {
                    "results": [mock_group, mock_admin_group],
                    "size": 2,
                }
            else:
                response.json.return_value = {"results": []}

            return response

        with patch.object(collector_cloud.session, "request", side_effect=mock_request):
            result = collector_cloud.collect_evidence(evidence_types=["groups"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "groups"
            assert evidence.raw_data["total_count"] == 2

    def test_collect_permissions_evidence(self, collector_cloud, mock_space, mock_space_permission, mock_anonymous_permission):
        """Test collecting permissions evidence."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "spaces" in url and "permissions" not in url:
                response.json.return_value = {
                    "results": [mock_space],
                    "_links": {},
                }
            elif "permissions" in url:
                response.json.return_value = {
                    "results": [mock_space_permission, mock_anonymous_permission],
                }
            else:
                response.json.return_value = {"results": []}

            return response

        with patch.object(collector_cloud.session, "request", side_effect=mock_request):
            result = collector_cloud.collect_evidence(evidence_types=["permissions"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "permissions"
            assert evidence.raw_data["total_spaces"] == 1
            assert evidence.raw_data["anonymous_access_count"] == 1

    def test_collect_audit_logs_cloud(self, collector_cloud, mock_page):
        """Test collecting audit logs evidence for Cloud."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "results": [mock_page],
            "_links": {},
        }

        with patch.object(collector_cloud.session, "request", return_value=mock_response):
            result = collector_cloud.collect_evidence(evidence_types=["audit_logs"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "audit_logs"
            assert "note" in evidence.raw_data  # Cloud uses page history as proxy


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestCollectResources:
    """Tests for resource collection."""

    def test_collect_all_resource_types(self, collector_cloud, mock_space, mock_page, mock_user, mock_group):
        """Test collecting all resource types."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "spaces" in url:
                response.json.return_value = {
                    "results": [mock_space],
                    "_links": {},
                }
            elif "pages" in url:
                response.json.return_value = {
                    "results": [mock_page],
                    "_links": {},
                }
            elif "group/" in url and "member" in url:
                response.json.return_value = {
                    "results": [mock_user],
                    "size": 1,
                }
            elif "group" in url:
                response.json.return_value = {
                    "results": [mock_group],
                    "size": 1,
                }
            else:
                response.json.return_value = {"results": []}

            return response

        with patch.object(collector_cloud.session, "request", side_effect=mock_request):
            resources = collector_cloud.collect_resources()

            assert len(resources) == 4
            types = {r.type for r in resources}
            assert "confluence_space" in types
            assert "confluence_page" in types
            assert "confluence_user" in types
            assert "confluence_group" in types

    def test_collect_specific_resource_types(self, collector_cloud, mock_space):
        """Test collecting specific resource types."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "results": [mock_space],
            "_links": {},
        }

        with patch.object(collector_cloud.session, "request", return_value=mock_response):
            resources = collector_cloud.collect_resources(resource_types=["confluence_space"])

            assert len(resources) == 1
            assert resources[0].type == "confluence_space"

    def test_collect_resources_invalid_type(self, collector_cloud):
        """Test collecting invalid resource type."""
        with pytest.raises(CollectionError, match="Unsupported resource types"):
            collector_cloud.collect_resources(resource_types=["invalid_type"])

    def test_collect_space_resources(self, collector_cloud, mock_space, mock_personal_space):
        """Test collecting space resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "results": [mock_space, mock_personal_space],
            "_links": {},
        }

        with patch.object(collector_cloud.session, "request", return_value=mock_response):
            resources = collector_cloud.collect_resources(resource_types=["confluence_space"])

            assert len(resources) == 2

            # Check global space
            global_space = next(r for r in resources if r.tags.get("type") == "global")
            assert global_space.type == "confluence_space"
            assert global_space.provider == "confluence"
            assert global_space.name == "Engineering"
            assert global_space.tags["key"] == "ENG"

            # Check personal space
            personal_space = next(r for r in resources if r.tags.get("type") == "personal")
            assert personal_space.tags["type"] == "personal"

    def test_collect_page_resources(self, collector_cloud, mock_page):
        """Test collecting page resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "results": [mock_page],
            "_links": {},
        }

        with patch.object(collector_cloud.session, "request", return_value=mock_response):
            resources = collector_cloud.collect_resources(resource_types=["confluence_page"])

            assert len(resources) == 1
            assert resources[0].type == "confluence_page"
            assert resources[0].name == "API Documentation"
            assert resources[0].tags["space"] == "123456"

    def test_collect_user_resources(self, collector_cloud, mock_group, mock_user):
        """Test collecting user resources."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "member" in url:
                response.json.return_value = {
                    "results": [mock_user],
                    "size": 1,
                }
            elif "group" in url:
                response.json.return_value = {
                    "results": [mock_group],
                    "size": 1,
                }
            else:
                response.json.return_value = {"results": []}

            return response

        with patch.object(collector_cloud.session, "request", side_effect=mock_request):
            resources = collector_cloud.collect_resources(resource_types=["confluence_user"])

            assert len(resources) == 1
            assert resources[0].type == "confluence_user"
            assert resources[0].id == "user-123"
            assert resources[0].name == "John Doe"
            assert resources[0].tags["active"] == "true"

    def test_collect_group_resources(self, collector_cloud, mock_group, mock_admin_group):
        """Test collecting group resources."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "member" in url:
                response.json.return_value = {"results": [], "size": 10}
            elif "group" in url:
                response.json.return_value = {
                    "results": [mock_group, mock_admin_group],
                    "size": 2,
                }
            else:
                response.json.return_value = {"results": []}

            return response

        with patch.object(collector_cloud.session, "request", side_effect=mock_request):
            resources = collector_cloud.collect_resources(resource_types=["confluence_group"])

            assert len(resources) == 2
            group_names = {r.name for r in resources}
            assert "confluence-users" in group_names
            assert "confluence-administrators" in group_names


# =============================================================================
# Pagination Tests
# =============================================================================


class TestPagination:
    """Tests for API pagination."""

    def test_pagination_v2_multiple_pages(self, collector_cloud, mock_space):
        """Test v2 API pagination across multiple pages."""
        space2 = mock_space.copy()
        space2["id"] = "234567"
        space2["key"] = "DEV"
        space2["name"] = "Development"

        call_count = [0]

        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            call_count[0] += 1

            params = kwargs.get("params", {})
            cursor = params.get("cursor")

            if not cursor:
                response.json.return_value = {
                    "results": [mock_space],
                    "_links": {"next": "/wiki/api/v2/spaces?cursor=next-cursor"},
                }
            else:
                response.json.return_value = {
                    "results": [space2],
                    "_links": {},
                }
            return response

        with patch.object(collector_cloud.session, "request", side_effect=mock_request):
            result = collector_cloud.collect_evidence(evidence_types=["spaces"])

            evidence = result.evidence_items[0]
            assert evidence.raw_data["total_count"] == 2
            space_keys = [s["key"] for s in evidence.raw_data["spaces"]]
            assert "ENG" in space_keys
            assert "DEV" in space_keys

    def test_pagination_stops_on_error(self, collector_cloud, mock_space):
        """Test pagination stops on API error."""
        call_count = [0]

        def mock_request(method, url, **kwargs):
            call_count[0] += 1

            if call_count[0] == 1:
                response = MagicMock()
                response.raise_for_status = MagicMock()
                response.json.return_value = {
                    "results": [mock_space],
                    "_links": {"next": "/wiki/api/v2/spaces?cursor=next-cursor"},
                }
                return response
            else:
                raise requests.RequestException("API error")

        with patch.object(collector_cloud.session, "request", side_effect=mock_request):
            result = collector_cloud.collect_evidence(evidence_types=["spaces"])

            # Should still have results from first page
            evidence = result.evidence_items[0]
            assert evidence.raw_data["total_count"] == 1


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    def test_evidence_collection_error(self, collector_cloud):
        """Test graceful handling of evidence collection errors."""
        with patch.object(
            collector_cloud.session,
            "request",
            side_effect=requests.RequestException("API error"),
        ):
            result = collector_cloud.collect_evidence(evidence_types=["spaces"])

            # Should still have an evidence item with empty data
            assert len(result.evidence_items) == 1
            assert result.evidence_items[0].raw_data["total_count"] == 0

    def test_partial_evidence_collection(self, collector_cloud, mock_space):
        """Test partial evidence collection when some APIs fail."""
        call_count = [0]

        def mock_request(method, url, **kwargs):
            call_count[0] += 1

            if "spaces" in url and "permissions" not in url:
                response = MagicMock()
                response.raise_for_status = MagicMock()
                response.json.return_value = {
                    "results": [mock_space],
                    "_links": {},
                }
                return response
            else:
                raise requests.RequestException("API error")

        with patch.object(collector_cloud.session, "request", side_effect=mock_request):
            result = collector_cloud.collect_evidence(evidence_types=["spaces", "pages"])

            # Should have evidence items for both (spaces with data, pages with empty)
            assert len(result.evidence_items) == 2

    def test_resource_collection_error(self, collector_cloud):
        """Test graceful handling of resource collection errors."""
        with patch.object(
            collector_cloud.session,
            "request",
            side_effect=requests.RequestException("API error"),
        ):
            resources = collector_cloud.collect_resources(resource_types=["confluence_space"])

            # Should return empty list
            assert resources == []


# =============================================================================
# Compliance Control Mapping Tests
# =============================================================================


class TestComplianceControls:
    """Tests for compliance control mappings."""

    def test_spaces_evidence_has_controls(self, collector_cloud, mock_space):
        """Test spaces evidence has compliance controls."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "results": [mock_space],
            "_links": {},
        }

        with patch.object(collector_cloud.session, "request", return_value=mock_response):
            result = collector_cloud.collect_evidence(evidence_types=["spaces"])

            evidence = result.evidence_items[0]
            controls = evidence.metadata["compliance_controls"]
            assert "soc2" in controls
            assert "nist_800_53" in controls
            assert "iso_27001" in controls
            assert "hitrust" in controls

    def test_permissions_evidence_has_controls(self, collector_cloud, mock_space):
        """Test permissions evidence has compliance controls."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "spaces" in url and "permissions" not in url:
                response.json.return_value = {
                    "results": [mock_space],
                    "_links": {},
                }
            elif "permissions" in url:
                response.json.return_value = {"results": []}
            else:
                response.json.return_value = {"results": []}

            return response

        with patch.object(collector_cloud.session, "request", side_effect=mock_request):
            result = collector_cloud.collect_evidence(evidence_types=["permissions"])

            evidence = result.evidence_items[0]
            controls = evidence.metadata["compliance_controls"]
            assert "CC6.1" in controls["soc2"]
            assert "AC-3" in controls["nist_800_53"]

    def test_all_evidence_types_have_mappings(self, collector_cloud):
        """Test all evidence types have compliance mappings."""
        for evidence_type in collector_cloud.SUPPORTED_EVIDENCE_TYPES:
            assert evidence_type in collector_cloud.EVIDENCE_CONTROL_MAPPINGS
            mappings = collector_cloud.EVIDENCE_CONTROL_MAPPINGS[evidence_type]
            assert "soc2" in mappings
            assert "nist_800_53" in mappings
            assert "iso_27001" in mappings
            assert "hitrust" in mappings


# =============================================================================
# CLI Tests
# =============================================================================


class TestCLI:
    """Tests for CLI integration."""

    def test_cli_command_exists(self):
        """Test that the confluence CLI command exists."""
        from attestful.cli.main import collect

        commands = [cmd for cmd in collect.commands]
        assert "confluence" in commands

    def test_cli_command_options(self):
        """Test that the confluence CLI command has correct options."""
        from attestful.cli.main import collect_confluence

        param_names = [p.name for p in collect_confluence.params]
        assert "url" in param_names
        assert "username" in param_names
        assert "api_token" in param_names
        assert "personal_access_token" in param_names
        assert "server" in param_names
        assert "types" in param_names
        assert "days" in param_names
        assert "output" in param_names

    def test_cli_in_collector_list(self):
        """Test that confluence is in the collector list."""
        from attestful.cli.main import collect_list
        from click.testing import CliRunner

        runner = CliRunner()
        result = runner.invoke(collect_list, [])

        assert "confluence" in result.output.lower()
