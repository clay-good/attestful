"""
Tests for the 1Password collector.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
import pytest
import requests

from attestful.collectors.platforms.onepassword import OnePasswordCollector, OnePasswordCollectorConfig
from attestful.core.exceptions import CollectionError, ConfigurationError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_scim_user():
    """Create a mock SCIM user."""
    return {
        "id": "user-uuid-123",
        "externalId": "ext-123",
        "userName": "jdoe@example.com",
        "displayName": "John Doe",
        "active": True,
        "name": {
            "formatted": "John Doe",
            "familyName": "Doe",
            "givenName": "John",
        },
        "emails": [
            {"value": "jdoe@example.com", "primary": True},
        ],
        "roles": [],
        "meta": {
            "created": "2024-01-15T10:30:00Z",
            "lastModified": "2024-06-20T14:22:00Z",
        },
    }


@pytest.fixture
def mock_scim_admin_user():
    """Create a mock SCIM admin user."""
    return {
        "id": "admin-uuid-456",
        "externalId": "ext-456",
        "userName": "admin@example.com",
        "displayName": "Admin User",
        "active": True,
        "name": {
            "formatted": "Admin User",
        },
        "emails": [
            {"value": "admin@example.com", "primary": True},
        ],
        "roles": [
            {"value": "admin"},
        ],
        "meta": {
            "created": "2023-06-01T08:00:00Z",
            "lastModified": "2024-06-20T14:22:00Z",
        },
    }


@pytest.fixture
def mock_scim_inactive_user():
    """Create a mock inactive SCIM user."""
    return {
        "id": "inactive-uuid-789",
        "externalId": "ext-789",
        "userName": "former@example.com",
        "displayName": "Former Employee",
        "active": False,
        "name": {
            "formatted": "Former Employee",
        },
        "emails": [
            {"value": "former@example.com", "primary": True},
        ],
        "roles": [],
        "meta": {
            "created": "2022-01-01T00:00:00Z",
            "lastModified": "2024-03-15T09:00:00Z",
        },
    }


@pytest.fixture
def mock_scim_group():
    """Create a mock SCIM group."""
    return {
        "id": "group-uuid-123",
        "externalId": "ext-grp-123",
        "displayName": "Engineering Team",
        "members": [
            {"value": "user-uuid-123", "display": "John Doe"},
            {"value": "admin-uuid-456", "display": "Admin User"},
        ],
        "meta": {
            "created": "2023-01-01T00:00:00Z",
            "lastModified": "2024-06-20T14:22:00Z",
        },
    }


@pytest.fixture
def mock_vault():
    """Create a mock vault."""
    return {
        "id": "vault-uuid-123",
        "name": "Shared Vault",
        "description": "Team shared passwords",
        "type": "USER_CREATED",
        "attributeVersion": 1,
        "contentVersion": 15,
        "items": 42,
        "createdAt": "2023-01-01T00:00:00Z",
        "updatedAt": "2024-06-20T14:22:00Z",
    }


@pytest.fixture
def mock_personal_vault():
    """Create a mock personal vault."""
    return {
        "id": "vault-uuid-456",
        "name": "Personal",
        "description": "Personal vault",
        "type": "PERSONAL",
        "attributeVersion": 1,
        "contentVersion": 8,
        "items": 25,
        "createdAt": "2023-06-01T00:00:00Z",
        "updatedAt": "2024-06-15T10:00:00Z",
    }


@pytest.fixture
def mock_item():
    """Create a mock item."""
    # Use a recent date (within the last month)
    recent_date = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat().replace("+00:00", "Z")
    return {
        "id": "item-uuid-123",
        "title": "AWS Root Account",
        "category": "LOGIN",
        "tags": ["aws", "critical"],
        "createdAt": "2023-01-15T08:00:00Z",
        "updatedAt": recent_date,
        "lastEditedBy": "user-uuid-123",
        "favorite": True,
    }


@pytest.fixture
def mock_old_item():
    """Create a mock old item (not updated in over a year)."""
    # Use a date that's definitely more than 365 days ago
    old_date = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat().replace("+00:00", "Z")
    return {
        "id": "item-uuid-old",
        "title": "Legacy System",
        "category": "LOGIN",
        "tags": ["legacy"],
        "createdAt": "2020-01-01T00:00:00Z",
        "updatedAt": old_date,
        "lastEditedBy": "admin-uuid-456",
        "favorite": False,
    }


@pytest.fixture
def mock_audit_event():
    """Create a mock audit event."""
    return {
        "uuid": "event-uuid-123",
        "timestamp": "2024-06-20T14:30:00Z",
        "action": "signin",
        "object_type": "user",
        "object_uuid": "user-uuid-123",
        "actor_uuid": "user-uuid-123",
        "actor_details": {
            "name": "John Doe",
            "email": "jdoe@example.com",
        },
        "aux_id": None,
        "aux_uuid": None,
        "aux_info": None,
        "session": {
            "uuid": "session-uuid-123",
            "login_time": "2024-06-20T14:30:00Z",
            "device_uuid": "device-uuid-123",
        },
        "location": {
            "country": "US",
            "region": "California",
            "city": "San Francisco",
        },
    }


@pytest.fixture
def mock_security_event():
    """Create a mock security-related audit event."""
    return {
        "uuid": "event-uuid-456",
        "timestamp": "2024-06-20T15:00:00Z",
        "action": "vault_access",
        "object_type": "vault",
        "object_uuid": "vault-uuid-123",
        "actor_uuid": "user-uuid-123",
        "actor_details": {
            "name": "John Doe",
            "email": "jdoe@example.com",
        },
        "aux_id": None,
        "aux_uuid": None,
        "aux_info": None,
        "session": {},
        "location": {},
    }


@pytest.fixture
def collector_connect():
    """Create a OnePasswordCollector with Connect API config."""
    config = OnePasswordCollectorConfig(
        connect_url="https://connect.example.com",
        connect_token="test-connect-token",
        days_of_history=90,
    )
    return OnePasswordCollector(config=config)


@pytest.fixture
def collector_scim():
    """Create a OnePasswordCollector with SCIM API config."""
    config = OnePasswordCollectorConfig(
        scim_url="https://scim.1password.com/v2/example",
        scim_token="test-scim-token",
        days_of_history=90,
    )
    return OnePasswordCollector(config=config)


@pytest.fixture
def collector_events():
    """Create a OnePasswordCollector with Events API config."""
    config = OnePasswordCollectorConfig(
        events_token="test-events-token",
        days_of_history=90,
    )
    return OnePasswordCollector(config=config)


@pytest.fixture
def collector_all():
    """Create a OnePasswordCollector with all APIs configured."""
    config = OnePasswordCollectorConfig(
        connect_url="https://connect.example.com",
        connect_token="test-connect-token",
        scim_url="https://scim.1password.com/v2/example",
        scim_token="test-scim-token",
        events_token="test-events-token",
        days_of_history=90,
    )
    return OnePasswordCollector(config=config)


# =============================================================================
# Initialization Tests
# =============================================================================


class TestOnePasswordCollectorInit:
    """Tests for OnePasswordCollector initialization."""

    def test_init_with_connect_config(self, collector_connect):
        """Test initialization with Connect API config."""
        assert collector_connect.config.connect_url == "https://connect.example.com"
        assert collector_connect.config.connect_token == "test-connect-token"
        assert collector_connect.config.days_of_history == 90

    def test_init_with_scim_config(self, collector_scim):
        """Test initialization with SCIM API config."""
        assert collector_scim.config.scim_url == "https://scim.1password.com/v2/example"
        assert collector_scim.config.scim_token == "test-scim-token"

    def test_init_with_events_config(self, collector_events):
        """Test initialization with Events API config."""
        assert collector_events.config.events_token == "test-events-token"

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = OnePasswordCollector()
        assert collector.config.connect_url == ""
        assert collector.config.connect_token == ""
        assert collector.config.scim_url == ""
        assert collector.config.scim_token == ""
        assert collector.config.events_token == ""
        assert collector.config.timeout == 30
        assert collector.config.max_retries == 3
        assert collector.config.page_size == 100
        assert collector.config.days_of_history == 90

    def test_metadata(self, collector_all):
        """Test collector metadata."""
        assert collector_all.metadata.name == "OnePasswordCollector"
        assert collector_all.metadata.platform == "onepassword"
        assert "onepassword_user" in collector_all.metadata.resource_types
        assert "onepassword_vault" in collector_all.metadata.resource_types
        assert "users" in collector_all.metadata.evidence_types
        assert "vaults" in collector_all.metadata.evidence_types
        assert "audit_events" in collector_all.metadata.evidence_types

    def test_platform(self, collector_all):
        """Test platform attribute."""
        assert collector_all.PLATFORM == "onepassword"


# =============================================================================
# Session Tests
# =============================================================================


class TestOnePasswordSession:
    """Tests for session creation."""

    def test_connect_session_creation(self, collector_connect):
        """Test Connect session is created on first access."""
        session = collector_connect.connect_session
        assert session is not None
        assert isinstance(session, requests.Session)
        assert "Bearer test-connect-token" in session.headers["Authorization"]

    def test_connect_session_cached(self, collector_connect):
        """Test Connect session is cached."""
        session1 = collector_connect.connect_session
        session2 = collector_connect.connect_session
        assert session1 is session2

    def test_scim_session_creation(self, collector_scim):
        """Test SCIM session is created on first access."""
        session = collector_scim.scim_session
        assert session is not None
        assert isinstance(session, requests.Session)
        assert "Bearer test-scim-token" in session.headers["Authorization"]

    def test_events_session_creation(self, collector_events):
        """Test Events session is created on first access."""
        session = collector_events.events_session
        assert session is not None
        assert isinstance(session, requests.Session)
        assert "Bearer test-events-token" in session.headers["Authorization"]

    def test_connect_session_requires_token(self):
        """Test Connect session requires token."""
        collector = OnePasswordCollector(
            config=OnePasswordCollectorConfig(connect_url="https://connect.example.com")
        )
        with pytest.raises(ConfigurationError, match="Connect token not configured"):
            _ = collector.connect_session

    def test_scim_session_requires_token(self):
        """Test SCIM session requires token."""
        collector = OnePasswordCollector(
            config=OnePasswordCollectorConfig(scim_url="https://scim.example.com")
        )
        with pytest.raises(ConfigurationError, match="SCIM token not configured"):
            _ = collector.scim_session

    def test_events_session_requires_token(self):
        """Test Events session requires token."""
        collector = OnePasswordCollector()
        with pytest.raises(ConfigurationError, match="Events API token not configured"):
            _ = collector.events_session


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestValidateCredentials:
    """Tests for credential validation."""

    def test_validate_connect_credentials_success(self, collector_connect):
        """Test successful Connect API credential validation."""
        mock_response = MagicMock()
        mock_response.json.return_value = [{"id": "vault-123", "name": "Test"}]
        mock_response.raise_for_status = MagicMock()

        with patch.object(collector_connect.connect_session, "request", return_value=mock_response):
            result = collector_connect.validate_credentials()
            assert result is True

    def test_validate_scim_credentials_success(self, collector_scim):
        """Test successful SCIM API credential validation."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "Resources": [],
            "totalResults": 0,
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(collector_scim.scim_session, "request", return_value=mock_response):
            result = collector_scim.validate_credentials()
            assert result is True

    def test_validate_events_credentials_success(self, collector_events):
        """Test successful Events API credential validation."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"items": [], "cursor": None}
        mock_response.raise_for_status = MagicMock()

        with patch.object(collector_events.events_session, "post", return_value=mock_response):
            result = collector_events.validate_credentials()
            assert result is True

    def test_validate_credentials_no_config(self):
        """Test validation fails with no configuration."""
        collector = OnePasswordCollector()
        with pytest.raises(ConfigurationError, match="No valid 1Password credentials"):
            collector.validate_credentials()

    def test_validate_credentials_invalid_connect_token(self, collector_connect):
        """Test validation fails with invalid Connect token."""
        with patch.object(
            collector_connect.connect_session,
            "request",
            side_effect=requests.RequestException("Invalid token"),
        ):
            # Without SCIM or Events fallback, should raise
            with pytest.raises(ConfigurationError, match="No valid 1Password credentials"):
                collector_connect.validate_credentials()


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestCollectEvidence:
    """Tests for evidence collection."""

    def test_collect_all_evidence_types(self, collector_all, mock_scim_user, mock_scim_group, mock_vault, mock_item, mock_audit_event):
        """Test collecting all evidence types."""
        def mock_scim_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "Users" in url:
                response.json.return_value = {
                    "Resources": [mock_scim_user],
                    "totalResults": 1,
                    "itemsPerPage": 100,
                }
            elif "Groups" in url:
                response.json.return_value = {
                    "Resources": [mock_scim_group],
                    "totalResults": 1,
                    "itemsPerPage": 100,
                }
            return response

        def mock_connect_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "vaults" in url and "items" not in url:
                response.json.return_value = [mock_vault]
            elif "items" in url:
                response.json.return_value = [mock_item]
            return response

        def mock_events_post(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = {
                "items": [mock_audit_event],
                "cursor": None,
            }
            return response

        with patch.object(collector_all.scim_session, "request", side_effect=mock_scim_request):
            with patch.object(collector_all.connect_session, "request", side_effect=mock_connect_request):
                with patch.object(collector_all.events_session, "post", side_effect=mock_events_post):
                    result = collector_all.collect_evidence()

                    assert result.platform == "onepassword"
                    assert len(result.evidence_items) > 0
                    assert result.started_at is not None
                    assert result.completed_at is not None

    def test_collect_specific_evidence_types(self, collector_scim, mock_scim_user):
        """Test collecting specific evidence types."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "Resources": [mock_scim_user],
            "totalResults": 1,
            "itemsPerPage": 100,
        }

        with patch.object(collector_scim.scim_session, "request", return_value=mock_response):
            result = collector_scim.collect_evidence(evidence_types=["users"])

            assert result.platform == "onepassword"
            assert len(result.evidence_items) == 1
            assert result.evidence_items[0].evidence_type == "users"

    def test_collect_evidence_invalid_type(self, collector_all):
        """Test collecting invalid evidence type."""
        with pytest.raises(CollectionError, match="Unsupported evidence types"):
            collector_all.collect_evidence(evidence_types=["invalid_type"])

    def test_collect_users_evidence(self, collector_scim, mock_scim_user, mock_scim_admin_user, mock_scim_inactive_user):
        """Test collecting users evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "Resources": [mock_scim_user, mock_scim_admin_user, mock_scim_inactive_user],
            "totalResults": 3,
            "itemsPerPage": 100,
        }

        with patch.object(collector_scim.scim_session, "request", return_value=mock_response):
            result = collector_scim.collect_evidence(evidence_types=["users"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "users"
            assert evidence.platform == "onepassword"
            assert evidence.raw_data["total_count"] == 3
            assert evidence.raw_data["active_count"] == 2
            assert evidence.raw_data["admin_count"] == 1
            assert evidence.raw_data["inactive_count"] == 1
            assert "compliance_controls" in evidence.metadata

    def test_collect_groups_evidence(self, collector_scim, mock_scim_group):
        """Test collecting groups evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "Resources": [mock_scim_group],
            "totalResults": 1,
            "itemsPerPage": 100,
        }

        with patch.object(collector_scim.scim_session, "request", return_value=mock_response):
            result = collector_scim.collect_evidence(evidence_types=["groups"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "groups"
            assert evidence.raw_data["total_count"] == 1
            assert evidence.raw_data["groups"][0]["display_name"] == "Engineering Team"
            assert evidence.raw_data["groups"][0]["member_count"] == 2

    def test_collect_vaults_evidence(self, collector_connect, mock_vault, mock_personal_vault):
        """Test collecting vaults evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = [mock_vault, mock_personal_vault]

        with patch.object(collector_connect.connect_session, "request", return_value=mock_response):
            result = collector_connect.collect_evidence(evidence_types=["vaults"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "vaults"
            assert evidence.raw_data["total_count"] == 2
            assert evidence.raw_data["shared_count"] == 1
            assert evidence.raw_data["private_count"] == 1

    def test_collect_items_evidence(self, collector_connect, mock_vault, mock_item, mock_old_item):
        """Test collecting items evidence."""
        call_count = [0]

        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            call_count[0] += 1

            if "vaults" in url and "items" not in url:
                response.json.return_value = [mock_vault]
            elif "items" in url:
                response.json.return_value = [mock_item, mock_old_item]
            return response

        with patch.object(collector_connect.connect_session, "request", side_effect=mock_request):
            result = collector_connect.collect_evidence(evidence_types=["items"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "items"
            assert evidence.raw_data["total_count"] == 2
            assert "LOGIN" in evidence.raw_data["items_by_category"]
            assert evidence.raw_data["old_items_count"] == 1

    def test_collect_audit_events_evidence(self, collector_events, mock_audit_event, mock_security_event):
        """Test collecting audit events evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "items": [mock_audit_event, mock_security_event],
            "cursor": None,
        }

        with patch.object(collector_events.events_session, "post", return_value=mock_response):
            result = collector_events.collect_evidence(evidence_types=["audit_events"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "audit_events"
            assert evidence.raw_data["total_count"] == 2
            assert "signin" in evidence.raw_data["event_types"]
            assert "vault_access" in evidence.raw_data["event_types"]
            assert evidence.raw_data["security_events_count"] == 2

    def test_collect_users_without_scim(self, collector_connect):
        """Test collecting users evidence without SCIM configured."""
        result = collector_connect.collect_evidence(evidence_types=["users"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "users"
        assert evidence.raw_data["total_count"] == 0
        assert evidence.metadata["api"] == "none"


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestCollectResources:
    """Tests for resource collection."""

    def test_collect_all_resource_types(self, collector_all, mock_scim_user, mock_scim_group, mock_vault):
        """Test collecting all resource types."""
        def mock_scim_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "Users" in url:
                response.json.return_value = {
                    "Resources": [mock_scim_user],
                    "totalResults": 1,
                    "itemsPerPage": 100,
                }
            elif "Groups" in url:
                response.json.return_value = {
                    "Resources": [mock_scim_group],
                    "totalResults": 1,
                    "itemsPerPage": 100,
                }
            return response

        def mock_connect_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = [mock_vault]
            return response

        with patch.object(collector_all.scim_session, "request", side_effect=mock_scim_request):
            with patch.object(collector_all.connect_session, "request", side_effect=mock_connect_request):
                resources = collector_all.collect_resources()

                assert len(resources) == 3
                types = {r.type for r in resources}
                assert "onepassword_user" in types
                assert "onepassword_group" in types
                assert "onepassword_vault" in types

    def test_collect_specific_resource_types(self, collector_scim, mock_scim_user):
        """Test collecting specific resource types."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "Resources": [mock_scim_user],
            "totalResults": 1,
            "itemsPerPage": 100,
        }

        with patch.object(collector_scim.scim_session, "request", return_value=mock_response):
            resources = collector_scim.collect_resources(resource_types=["onepassword_user"])

            assert len(resources) == 1
            assert resources[0].type == "onepassword_user"

    def test_collect_resources_invalid_type(self, collector_all):
        """Test collecting invalid resource type."""
        with pytest.raises(CollectionError, match="Unsupported resource types"):
            collector_all.collect_resources(resource_types=["invalid_type"])

    def test_collect_user_resources(self, collector_scim, mock_scim_user, mock_scim_admin_user):
        """Test collecting user resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "Resources": [mock_scim_user, mock_scim_admin_user],
            "totalResults": 2,
            "itemsPerPage": 100,
        }

        with patch.object(collector_scim.scim_session, "request", return_value=mock_response):
            resources = collector_scim.collect_resources(resource_types=["onepassword_user"])

            assert len(resources) == 2

            # Check regular user
            user_resource = next(r for r in resources if r.id == "user-uuid-123")
            assert user_resource.type == "onepassword_user"
            assert user_resource.provider == "onepassword"
            assert user_resource.name == "John Doe"
            assert user_resource.tags["role"] == "member"
            assert user_resource.tags["active"] == "true"
            assert user_resource.tags["is_admin"] == "false"

            # Check admin user
            admin_resource = next(r for r in resources if r.id == "admin-uuid-456")
            assert admin_resource.tags["role"] == "admin"
            assert admin_resource.tags["is_admin"] == "true"

    def test_collect_group_resources(self, collector_scim, mock_scim_group):
        """Test collecting group resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "Resources": [mock_scim_group],
            "totalResults": 1,
            "itemsPerPage": 100,
        }

        with patch.object(collector_scim.scim_session, "request", return_value=mock_response):
            resources = collector_scim.collect_resources(resource_types=["onepassword_group"])

            assert len(resources) == 1
            assert resources[0].type == "onepassword_group"
            assert resources[0].id == "group-uuid-123"
            assert resources[0].name == "Engineering Team"
            assert resources[0].tags["member_count"] == "2"

    def test_collect_vault_resources(self, collector_connect, mock_vault, mock_personal_vault):
        """Test collecting vault resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = [mock_vault, mock_personal_vault]

        with patch.object(collector_connect.connect_session, "request", return_value=mock_response):
            resources = collector_connect.collect_resources(resource_types=["onepassword_vault"])

            assert len(resources) == 2

            # Check shared vault
            shared_vault = next(r for r in resources if r.id == "vault-uuid-123")
            assert shared_vault.type == "onepassword_vault"
            assert shared_vault.name == "Shared Vault"
            assert shared_vault.tags["type"] == "USER_CREATED"
            assert shared_vault.tags["is_shared"] == "true"

            # Check personal vault
            personal_vault = next(r for r in resources if r.id == "vault-uuid-456")
            assert personal_vault.tags["type"] == "PERSONAL"
            assert personal_vault.tags["is_shared"] == "false"


# =============================================================================
# Pagination Tests
# =============================================================================


class TestPagination:
    """Tests for API pagination."""

    def test_scim_pagination_multiple_pages(self, collector_scim, mock_scim_user):
        """Test SCIM pagination across multiple pages."""
        page2_user = mock_scim_user.copy()
        page2_user["id"] = "user-uuid-page2"
        page2_user["displayName"] = "Page 2 User"

        call_count = [0]

        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            call_count[0] += 1

            params = kwargs.get("params", {})
            start_index = params.get("startIndex", 1)

            if start_index == 1:
                response.json.return_value = {
                    "Resources": [mock_scim_user],
                    "totalResults": 2,
                    "itemsPerPage": 1,
                }
            else:
                response.json.return_value = {
                    "Resources": [page2_user],
                    "totalResults": 2,
                    "itemsPerPage": 1,
                }
            return response

        with patch.object(collector_scim.scim_session, "request", side_effect=mock_request):
            result = collector_scim.collect_evidence(evidence_types=["users"])

            evidence = result.evidence_items[0]
            assert evidence.raw_data["total_count"] == 2
            user_ids = [u["id"] for u in evidence.raw_data["users"]]
            assert "user-uuid-123" in user_ids
            assert "user-uuid-page2" in user_ids

    def test_events_pagination_with_cursor(self, collector_events, mock_audit_event):
        """Test Events API pagination with cursor."""
        event2 = mock_audit_event.copy()
        event2["uuid"] = "event-uuid-page2"

        call_count = [0]

        def mock_post(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            call_count[0] += 1

            json_data = kwargs.get("json", {})
            cursor = json_data.get("cursor")

            if not cursor:
                response.json.return_value = {
                    "items": [mock_audit_event],
                    "cursor": "next-page-cursor",
                }
            else:
                response.json.return_value = {
                    "items": [event2],
                    "cursor": None,
                }
            return response

        with patch.object(collector_events.events_session, "post", side_effect=mock_post):
            result = collector_events.collect_evidence(evidence_types=["audit_events"])

            evidence = result.evidence_items[0]
            assert evidence.raw_data["total_count"] == 2


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    def test_evidence_collection_error(self, collector_scim):
        """Test graceful handling of evidence collection errors."""
        with patch.object(
            collector_scim.scim_session,
            "request",
            side_effect=requests.RequestException("API error"),
        ):
            result = collector_scim.collect_evidence(evidence_types=["users"])

            # Should still have an evidence item with empty data
            assert len(result.evidence_items) == 1
            assert result.evidence_items[0].raw_data["total_count"] == 0

    def test_partial_evidence_collection(self, collector_all, mock_scim_user):
        """Test partial evidence collection when some APIs fail."""
        def mock_scim_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = {
                "Resources": [mock_scim_user],
                "totalResults": 1,
                "itemsPerPage": 100,
            }
            return response

        def mock_connect_request(method, url, **kwargs):
            raise requests.RequestException("Connect API error")

        with patch.object(collector_all.scim_session, "request", side_effect=mock_scim_request):
            with patch.object(collector_all.connect_session, "request", side_effect=mock_connect_request):
                result = collector_all.collect_evidence(evidence_types=["users", "vaults"])

                # Should have evidence items (users with data, vaults with empty data)
                assert len(result.evidence_items) == 2
                users_evidence = next(e for e in result.evidence_items if e.evidence_type == "users")
                vaults_evidence = next(e for e in result.evidence_items if e.evidence_type == "vaults")
                assert users_evidence.raw_data["total_count"] == 1
                assert vaults_evidence.raw_data["total_count"] == 0

    def test_resource_collection_error(self, collector_scim):
        """Test graceful handling of resource collection errors."""
        with patch.object(
            collector_scim.scim_session,
            "request",
            side_effect=requests.RequestException("API error"),
        ):
            resources = collector_scim.collect_resources(resource_types=["onepassword_user"])

            # Should return empty list
            assert resources == []

    def test_connect_request_requires_url(self, collector_events):
        """Test Connect API request requires URL configuration."""
        with pytest.raises(ConfigurationError, match="Connect URL not configured"):
            collector_events._make_connect_request("GET", "vaults")

    def test_scim_request_requires_url(self, collector_events):
        """Test SCIM API request requires URL configuration."""
        with pytest.raises(ConfigurationError, match="SCIM URL not configured"):
            collector_events._make_scim_request("GET", "Users")


# =============================================================================
# Compliance Control Mapping Tests
# =============================================================================


class TestComplianceControls:
    """Tests for compliance control mappings."""

    def test_users_evidence_has_controls(self, collector_scim, mock_scim_user):
        """Test users evidence has compliance controls."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "Resources": [mock_scim_user],
            "totalResults": 1,
            "itemsPerPage": 100,
        }

        with patch.object(collector_scim.scim_session, "request", return_value=mock_response):
            result = collector_scim.collect_evidence(evidence_types=["users"])

            evidence = result.evidence_items[0]
            controls = evidence.metadata["compliance_controls"]
            assert "soc2" in controls
            assert "nist_800_53" in controls
            assert "iso_27001" in controls
            assert "hitrust" in controls

    def test_vaults_evidence_has_controls(self, collector_connect, mock_vault):
        """Test vaults evidence has compliance controls."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = [mock_vault]

        with patch.object(collector_connect.connect_session, "request", return_value=mock_response):
            result = collector_connect.collect_evidence(evidence_types=["vaults"])

            evidence = result.evidence_items[0]
            controls = evidence.metadata["compliance_controls"]
            assert "CC6.1" in controls["soc2"]
            assert "AC-3" in controls["nist_800_53"]

    def test_all_evidence_types_have_mappings(self, collector_all):
        """Test all evidence types have compliance mappings."""
        for evidence_type in collector_all.SUPPORTED_EVIDENCE_TYPES:
            assert evidence_type in collector_all.EVIDENCE_CONTROL_MAPPINGS
            mappings = collector_all.EVIDENCE_CONTROL_MAPPINGS[evidence_type]
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
        """Test that the onepassword CLI command exists."""
        from attestful.cli.main import collect

        commands = [cmd for cmd in collect.commands]
        assert "onepassword" in commands

    def test_cli_command_options(self):
        """Test that the onepassword CLI command has correct options."""
        from attestful.cli.main import collect_onepassword

        param_names = [p.name for p in collect_onepassword.params]
        assert "connect_url" in param_names
        assert "connect_token" in param_names
        assert "scim_url" in param_names
        assert "scim_token" in param_names
        assert "events_token" in param_names
        assert "types" in param_names
        assert "days" in param_names
        assert "output" in param_names

    def test_cli_in_collector_list(self):
        """Test that onepassword is in the collector list."""
        from attestful.cli.main import collect_list
        from click.testing import CliRunner

        runner = CliRunner()
        result = runner.invoke(collect_list, [])

        assert "onepassword" in result.output.lower()
