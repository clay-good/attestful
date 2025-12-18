"""
Tests for the Slack collector.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest
import requests

from attestful.collectors.platforms.slack import SlackCollector, SlackCollectorConfig
from attestful.core.exceptions import CollectionError, ConfigurationError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_user():
    """Create a mock Slack user."""
    return {
        "id": "U123456",
        "team_id": "T123456",
        "name": "jdoe",
        "real_name": "John Doe",
        "is_admin": False,
        "is_owner": False,
        "is_primary_owner": False,
        "is_restricted": False,
        "is_ultra_restricted": False,
        "is_bot": False,
        "is_app_user": False,
        "has_2fa": True,
        "deleted": False,
        "tz": "America/New_York",
        "updated": 1700000000,
        "profile": {
            "email": "jdoe@example.com",
            "real_name": "John Doe",
            "display_name": "John",
            "image_72": "https://example.com/avatar.png",
        },
    }


@pytest.fixture
def mock_admin_user():
    """Create a mock admin Slack user."""
    return {
        "id": "U789012",
        "team_id": "T123456",
        "name": "admin",
        "real_name": "Admin User",
        "is_admin": True,
        "is_owner": False,
        "is_primary_owner": False,
        "is_restricted": False,
        "is_ultra_restricted": False,
        "is_bot": False,
        "is_app_user": False,
        "has_2fa": True,
        "deleted": False,
        "tz": "America/Los_Angeles",
        "updated": 1700000000,
        "profile": {
            "email": "admin@example.com",
            "real_name": "Admin User",
        },
    }


@pytest.fixture
def mock_bot_user():
    """Create a mock bot user."""
    return {
        "id": "B123456",
        "team_id": "T123456",
        "name": "testbot",
        "real_name": "Test Bot",
        "is_admin": False,
        "is_owner": False,
        "is_primary_owner": False,
        "is_restricted": False,
        "is_ultra_restricted": False,
        "is_bot": True,
        "is_app_user": False,
        "has_2fa": False,
        "deleted": False,
        "profile": {
            "real_name": "Test Bot",
        },
    }


@pytest.fixture
def mock_channel():
    """Create a mock Slack channel."""
    return {
        "id": "C123456",
        "name": "general",
        "is_channel": True,
        "is_private": False,
        "is_archived": False,
        "is_general": True,
        "is_shared": False,
        "is_ext_shared": False,
        "is_org_shared": False,
        "creator": "U123456",
        "created": 1600000000,
        "num_members": 50,
        "topic": {
            "value": "Company-wide announcements",
            "creator": "U123456",
            "last_set": 1600000000,
        },
        "purpose": {
            "value": "General discussion channel",
            "creator": "U123456",
            "last_set": 1600000000,
        },
    }


@pytest.fixture
def mock_private_channel():
    """Create a mock private Slack channel."""
    return {
        "id": "C789012",
        "name": "secret-project",
        "is_channel": True,
        "is_private": True,
        "is_archived": False,
        "is_general": False,
        "is_shared": False,
        "is_ext_shared": False,
        "is_org_shared": False,
        "creator": "U789012",
        "created": 1650000000,
        "num_members": 5,
        "topic": {
            "value": "Secret project discussion",
            "creator": "U789012",
            "last_set": 1650000000,
        },
        "purpose": {
            "value": "Confidential project planning",
            "creator": "U789012",
            "last_set": 1650000000,
        },
    }


@pytest.fixture
def mock_user_group():
    """Create a mock Slack user group."""
    return {
        "id": "S123456",
        "team_id": "T123456",
        "name": "Engineering Team",
        "handle": "engineering",
        "description": "Engineering team members",
        "is_external": False,
        "user_count": 10,
        "users": ["U123456", "U789012"],
        "created_by": "U123456",
        "date_create": 1600000000,
        "date_update": 1700000000,
    }


@pytest.fixture
def mock_team_info():
    """Create mock team info."""
    return {
        "id": "T123456",
        "name": "Example Company",
        "domain": "example",
        "email_domain": "example.com",
        "enterprise_id": None,
        "enterprise_name": None,
        "is_verified": True,
        "icon": {
            "image_original": "https://example.com/team-icon.png",
        },
    }


@pytest.fixture
def mock_app():
    """Create a mock Slack app."""
    return {
        "id": "A123456",
        "name": "Test App",
        "description": "A test application",
        "is_internal": False,
        "is_active": True,
        "scopes": ["users:read", "channels:read"],
        "date_created": 1600000000,
        "date_updated": 1700000000,
    }


@pytest.fixture
def mock_access_log():
    """Create a mock access log entry."""
    now = datetime.now(timezone.utc)
    return {
        "user_id": "U123456",
        "username": "jdoe",
        "date_first": int(now.timestamp()) - 3600,
        "date_last": int(now.timestamp()),
        "count": 5,
        "ip": "192.168.1.100",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "isp": "Example ISP",
        "country": "US",
        "region": "California",
    }


@pytest.fixture
def collector():
    """Create a SlackCollector instance."""
    config = SlackCollectorConfig(
        bot_token="xoxb-test-token-12345",
        user_token="xoxp-user-token-67890",
        days_of_history=90,
    )
    return SlackCollector(config=config)


@pytest.fixture
def collector_bot_only():
    """Create a SlackCollector instance with bot token only."""
    config = SlackCollectorConfig(
        bot_token="xoxb-test-token-12345",
        days_of_history=90,
    )
    return SlackCollector(config=config)


# =============================================================================
# Initialization Tests
# =============================================================================


class TestSlackCollectorInit:
    """Tests for SlackCollector initialization."""

    def test_init_with_config(self, collector):
        """Test initialization with config."""
        assert collector.config.bot_token == "xoxb-test-token-12345"
        assert collector.config.user_token == "xoxp-user-token-67890"
        assert collector.config.days_of_history == 90

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = SlackCollector()
        assert collector.config.bot_token == ""
        assert collector.config.user_token == ""
        assert collector.config.timeout == 30
        assert collector.config.max_retries == 3
        assert collector.config.page_size == 200
        assert collector.config.days_of_history == 90

    def test_metadata(self, collector):
        """Test collector metadata."""
        assert collector.metadata.name == "SlackCollector"
        assert collector.metadata.platform == "slack"
        assert "slack_user" in collector.metadata.resource_types
        assert "slack_channel" in collector.metadata.resource_types
        assert "users" in collector.metadata.evidence_types
        assert "channels" in collector.metadata.evidence_types

    def test_platform(self, collector):
        """Test platform attribute."""
        assert collector.PLATFORM == "slack"

    def test_api_url(self, collector):
        """Test API URL property."""
        assert collector.api_url == "https://slack.com/api"


# =============================================================================
# Session Tests
# =============================================================================


class TestSlackSession:
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


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestValidateCredentials:
    """Tests for credential validation."""

    def test_validate_credentials_success(self, collector):
        """Test successful credential validation."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "ok": True,
            "team": "Example Company",
            "user": "testbot",
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.validate_credentials()
            assert result is True

    def test_validate_credentials_no_token(self):
        """Test validation fails without token."""
        collector = SlackCollector(config=SlackCollectorConfig(bot_token=""))
        with pytest.raises(ConfigurationError, match="bot_token is required"):
            collector.validate_credentials()

    def test_validate_credentials_invalid_token(self, collector):
        """Test validation fails with invalid token."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "ok": False,
            "error": "invalid_auth",
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(collector.session, "get", return_value=mock_response):
            with pytest.raises(ConfigurationError, match="Invalid Slack token"):
                collector.validate_credentials()

    def test_validate_credentials_api_error(self, collector):
        """Test validation handles API errors."""
        with patch.object(
            collector.session,
            "get",
            side_effect=requests.RequestException("Connection error"),
        ):
            with pytest.raises(ConfigurationError, match="Failed to validate"):
                collector.validate_credentials()


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestCollectEvidence:
    """Tests for evidence collection."""

    def test_collect_all_evidence_types(self, collector, mock_user, mock_channel, mock_user_group, mock_team_info):
        """Test collecting all evidence types."""
        # Mock all API responses
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "users.list" in url:
                response.json.return_value = {
                    "ok": True,
                    "members": [mock_user],
                    "response_metadata": {"next_cursor": ""},
                }
            elif "conversations.list" in url:
                response.json.return_value = {
                    "ok": True,
                    "channels": [mock_channel],
                    "response_metadata": {"next_cursor": ""},
                }
            elif "usergroups.list" in url:
                response.json.return_value = {
                    "ok": True,
                    "usergroups": [mock_user_group],
                }
            elif "team.info" in url:
                response.json.return_value = {
                    "ok": True,
                    "team": mock_team_info,
                }
            elif "team.preferences.list" in url:
                response.json.return_value = {
                    "ok": False,
                    "error": "missing_scope",
                }
            elif "apps.list" in url:
                response.json.return_value = {
                    "ok": False,
                    "error": "missing_scope",
                }
            elif "team.accessLogs" in url:
                response.json.return_value = {
                    "ok": False,
                    "error": "missing_scope",
                }
            else:
                response.json.return_value = {"ok": True}

            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence()

            assert result.platform == "slack"
            assert len(result.evidence_items) > 0
            assert result.started_at is not None
            assert result.completed_at is not None

    def test_collect_specific_evidence_types(self, collector, mock_user):
        """Test collecting specific evidence types."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "ok": True,
            "members": [mock_user],
            "response_metadata": {"next_cursor": ""},
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["users"])

            assert result.platform == "slack"
            assert len(result.evidence_items) == 1
            assert result.evidence_items[0].evidence_type == "users"

    def test_collect_evidence_invalid_type(self, collector):
        """Test collecting invalid evidence type."""
        with pytest.raises(CollectionError, match="Unsupported evidence types"):
            collector.collect_evidence(evidence_types=["invalid_type"])

    def test_collect_users_evidence(self, collector, mock_user, mock_admin_user, mock_bot_user):
        """Test collecting users evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "ok": True,
            "members": [mock_user, mock_admin_user, mock_bot_user],
            "response_metadata": {"next_cursor": ""},
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["users"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "users"
            assert evidence.platform == "slack"
            assert evidence.raw_data["total_count"] == 3
            assert evidence.raw_data["admin_count"] == 1
            assert evidence.raw_data["bot_count"] == 1
            assert "compliance_controls" in evidence.metadata

    def test_collect_users_excludes_deleted(self, collector, mock_user):
        """Test that deleted users are excluded."""
        deleted_user = mock_user.copy()
        deleted_user["id"] = "U999999"
        deleted_user["deleted"] = True

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "ok": True,
            "members": [mock_user, deleted_user],
            "response_metadata": {"next_cursor": ""},
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["users"])

            evidence = result.evidence_items[0]
            assert evidence.raw_data["total_count"] == 1

    def test_collect_channels_evidence(self, collector, mock_channel, mock_private_channel):
        """Test collecting channels evidence."""
        call_count = [0]

        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            params = kwargs.get("params", {})
            channel_type = params.get("types", "public_channel")

            if "public_channel" in channel_type:
                response.json.return_value = {
                    "ok": True,
                    "channels": [mock_channel],
                    "response_metadata": {"next_cursor": ""},
                }
            else:
                response.json.return_value = {
                    "ok": True,
                    "channels": [mock_private_channel],
                    "response_metadata": {"next_cursor": ""},
                }
            call_count[0] += 1
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["channels"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "channels"
            assert evidence.raw_data["total_count"] == 2
            assert evidence.raw_data["public_count"] == 1
            assert evidence.raw_data["private_count"] == 1

    def test_collect_user_groups_evidence(self, collector, mock_user_group):
        """Test collecting user groups evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "ok": True,
            "usergroups": [mock_user_group],
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["user_groups"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "user_groups"
            assert evidence.raw_data["total_count"] == 1
            assert evidence.raw_data["user_groups"][0]["name"] == "Engineering Team"

    def test_collect_team_info_evidence(self, collector, mock_team_info):
        """Test collecting team info evidence."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "team.info" in url:
                response.json.return_value = {
                    "ok": True,
                    "team": mock_team_info,
                }
            else:
                response.json.return_value = {
                    "ok": False,
                    "error": "missing_scope",
                }
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["team_info"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "team_info"
            assert evidence.raw_data["team_info"]["name"] == "Example Company"
            assert evidence.raw_data["team_info"]["domain"] == "example"

    def test_collect_apps_evidence(self, collector, mock_app):
        """Test collecting apps evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "ok": True,
            "apps": [mock_app],
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["apps"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "apps"
            assert evidence.raw_data["total_count"] == 1

    def test_collect_apps_fallback_to_bots(self, collector, mock_bot_user):
        """Test apps collection falls back to bot users."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "apps.list" in url:
                response.json.return_value = {
                    "ok": False,
                    "error": "missing_scope",
                }
            elif "users.list" in url:
                response.json.return_value = {
                    "ok": True,
                    "members": [mock_bot_user],
                    "response_metadata": {"next_cursor": ""},
                }
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["apps"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "apps"
            assert evidence.raw_data["total_count"] == 1

    def test_collect_access_logs_evidence(self, collector, mock_access_log):
        """Test collecting access logs evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "ok": True,
            "logins": [mock_access_log],
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["access_logs"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "access_logs"
            assert evidence.raw_data["total_count"] == 1

    def test_collect_access_logs_respects_date_filter(self, collector):
        """Test access logs respects date filter."""
        old_log = {
            "user_id": "U123456",
            "username": "jdoe",
            "date_first": 1000000000,  # Very old timestamp
            "date_last": 1000000001,
            "count": 1,
            "ip": "192.168.1.100",
        }

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "ok": True,
            "logins": [old_log],
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["access_logs"])

            evidence = result.evidence_items[0]
            assert evidence.raw_data["total_count"] == 0


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestCollectResources:
    """Tests for resource collection."""

    def test_collect_all_resource_types(self, collector, mock_user, mock_channel, mock_user_group, mock_bot_user):
        """Test collecting all resource types."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "users.list" in url:
                response.json.return_value = {
                    "ok": True,
                    "members": [mock_user, mock_bot_user],
                    "response_metadata": {"next_cursor": ""},
                }
            elif "conversations.list" in url:
                response.json.return_value = {
                    "ok": True,
                    "channels": [mock_channel],
                    "response_metadata": {"next_cursor": ""},
                }
            elif "usergroups.list" in url:
                response.json.return_value = {
                    "ok": True,
                    "usergroups": [mock_user_group],
                }
            else:
                response.json.return_value = {"ok": True}

            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            resources = collector.collect_resources()

            assert len(resources) > 0
            types = {r.type for r in resources}
            assert "slack_user" in types
            assert "slack_channel" in types

    def test_collect_specific_resource_types(self, collector, mock_user):
        """Test collecting specific resource types."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "ok": True,
            "members": [mock_user],
            "response_metadata": {"next_cursor": ""},
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["slack_user"])

            assert len(resources) == 1
            assert resources[0].type == "slack_user"

    def test_collect_resources_invalid_type(self, collector):
        """Test collecting invalid resource type."""
        with pytest.raises(CollectionError, match="Unsupported resource types"):
            collector.collect_resources(resource_types=["invalid_type"])

    def test_collect_user_resources(self, collector, mock_user, mock_admin_user):
        """Test collecting user resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "ok": True,
            "members": [mock_user, mock_admin_user],
            "response_metadata": {"next_cursor": ""},
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["slack_user"])

            assert len(resources) == 2

            # Check first user
            user_resource = resources[0]
            assert user_resource.type == "slack_user"
            assert user_resource.provider == "slack"
            assert user_resource.id == "U123456"
            assert user_resource.name == "John Doe"
            assert user_resource.tags["role"] == "member"
            assert user_resource.tags["has_2fa"] == "true"

            # Check admin user
            admin_resource = resources[1]
            assert admin_resource.tags["role"] == "admin"
            assert admin_resource.tags["is_admin"] == "true"

    def test_collect_user_resources_excludes_deleted(self, collector, mock_user):
        """Test that deleted users are excluded from resources."""
        deleted_user = mock_user.copy()
        deleted_user["id"] = "U999999"
        deleted_user["deleted"] = True

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "ok": True,
            "members": [mock_user, deleted_user],
            "response_metadata": {"next_cursor": ""},
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["slack_user"])

            assert len(resources) == 1
            assert resources[0].id == "U123456"

    def test_collect_user_resources_role_detection(self, collector):
        """Test user role detection."""
        users = [
            {"id": "U1", "name": "owner", "is_primary_owner": True, "is_owner": True, "is_admin": True, "deleted": False, "profile": {}},
            {"id": "U2", "name": "owner2", "is_primary_owner": False, "is_owner": True, "is_admin": True, "deleted": False, "profile": {}},
            {"id": "U3", "name": "admin", "is_primary_owner": False, "is_owner": False, "is_admin": True, "deleted": False, "profile": {}},
            {"id": "U4", "name": "guest", "is_restricted": True, "deleted": False, "profile": {}},
            {"id": "U5", "name": "scguest", "is_ultra_restricted": True, "deleted": False, "profile": {}},
            {"id": "U6", "name": "bot", "is_bot": True, "deleted": False, "profile": {}},
            {"id": "U7", "name": "member", "deleted": False, "profile": {}},
        ]

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "ok": True,
            "members": users,
            "response_metadata": {"next_cursor": ""},
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["slack_user"])

            roles = {r.id: r.tags["role"] for r in resources}
            assert roles["U1"] == "primary_owner"
            assert roles["U2"] == "owner"
            assert roles["U3"] == "admin"
            assert roles["U4"] == "multi_channel_guest"
            assert roles["U5"] == "single_channel_guest"
            assert roles["U6"] == "bot"
            assert roles["U7"] == "member"

    def test_collect_channel_resources(self, collector, mock_channel, mock_private_channel):
        """Test collecting channel resources."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            params = kwargs.get("params", {})
            channel_type = params.get("types", "public_channel")

            if "public_channel" in channel_type:
                response.json.return_value = {
                    "ok": True,
                    "channels": [mock_channel],
                    "response_metadata": {"next_cursor": ""},
                }
            else:
                response.json.return_value = {
                    "ok": True,
                    "channels": [mock_private_channel],
                    "response_metadata": {"next_cursor": ""},
                }
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            resources = collector.collect_resources(resource_types=["slack_channel"])

            assert len(resources) == 2

            # Check public channel
            public_channel = next(r for r in resources if r.id == "C123456")
            assert public_channel.type == "slack_channel"
            assert public_channel.name == "general"
            assert public_channel.tags["is_private"] == "false"

            # Check private channel
            private_channel = next(r for r in resources if r.id == "C789012")
            assert private_channel.tags["is_private"] == "true"

    def test_collect_user_group_resources(self, collector, mock_user_group):
        """Test collecting user group resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "ok": True,
            "usergroups": [mock_user_group],
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["slack_user_group"])

            assert len(resources) == 1
            assert resources[0].type == "slack_user_group"
            assert resources[0].id == "S123456"
            assert resources[0].name == "Engineering Team"
            assert resources[0].tags["handle"] == "engineering"

    def test_collect_app_resources(self, collector, mock_bot_user):
        """Test collecting app resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "ok": True,
            "members": [mock_bot_user],
            "response_metadata": {"next_cursor": ""},
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["slack_app"])

            assert len(resources) == 1
            assert resources[0].type == "slack_app"
            assert resources[0].id == "B123456"
            assert resources[0].tags["is_bot"] == "true"


# =============================================================================
# Pagination Tests
# =============================================================================


class TestPagination:
    """Tests for API pagination."""

    def test_pagination_multiple_pages(self, collector, mock_user):
        """Test pagination across multiple pages."""
        page1_user = mock_user.copy()
        page1_user["id"] = "U111111"

        page2_user = mock_user.copy()
        page2_user["id"] = "U222222"

        call_count = [0]

        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            call_count[0] += 1

            params = kwargs.get("params", {})
            cursor = params.get("cursor")

            if not cursor:
                response.json.return_value = {
                    "ok": True,
                    "members": [page1_user],
                    "response_metadata": {"next_cursor": "cursor_page2"},
                }
            else:
                response.json.return_value = {
                    "ok": True,
                    "members": [page2_user],
                    "response_metadata": {"next_cursor": ""},
                }
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["users"])

            evidence = result.evidence_items[0]
            assert evidence.raw_data["total_count"] == 2
            user_ids = [u["id"] for u in evidence.raw_data["users"]]
            assert "U111111" in user_ids
            assert "U222222" in user_ids

    def test_pagination_stops_on_error(self, collector, mock_user):
        """Test pagination stops on API error."""
        call_count = [0]

        def mock_get(url, **kwargs):
            call_count[0] += 1

            if call_count[0] == 1:
                response = MagicMock()
                response.raise_for_status = MagicMock()
                response.json.return_value = {
                    "ok": True,
                    "members": [mock_user],
                    "response_metadata": {"next_cursor": "cursor_page2"},
                }
                return response
            else:
                raise requests.RequestException("API error")

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["users"])

            # Should still have results from first page
            evidence = result.evidence_items[0]
            assert evidence.raw_data["total_count"] == 1


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    def test_api_error_logged_but_continues(self, collector, mock_user):
        """Test that API errors are logged but collection continues."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "users.list" in url:
                response.json.return_value = {
                    "ok": True,
                    "members": [mock_user],
                    "response_metadata": {"next_cursor": ""},
                }
            else:
                response.json.return_value = {
                    "ok": False,
                    "error": "missing_scope",
                }
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence()

            # Should still have users evidence
            evidence_types = [e.evidence_type for e in result.evidence_items]
            assert "users" in evidence_types

    def test_collection_continues_on_error(self, collector):
        """Test that collection continues despite errors and returns empty results."""
        def mock_get(url, **kwargs):
            raise requests.RequestException("Network error")

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence()

            # Should still complete and return evidence items (with empty data)
            assert result.completed_at is not None
            # Evidence items are still returned, just with empty data
            assert len(result.evidence_items) > 0
            for evidence in result.evidence_items:
                # Data should be empty/zero due to errors
                if "total_count" in evidence.raw_data:
                    assert evidence.raw_data["total_count"] == 0


# =============================================================================
# Compliance Control Mapping Tests
# =============================================================================


class TestComplianceControls:
    """Tests for compliance control mappings."""

    def test_users_evidence_has_controls(self, collector, mock_user):
        """Test users evidence has compliance controls."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "ok": True,
            "members": [mock_user],
            "response_metadata": {"next_cursor": ""},
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["users"])

            evidence = result.evidence_items[0]
            controls = evidence.metadata["compliance_controls"]
            assert "soc2" in controls
            assert "nist_800_53" in controls
            assert "iso_27001" in controls
            assert "hitrust" in controls

    def test_channels_evidence_has_controls(self, collector, mock_channel):
        """Test channels evidence has compliance controls."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "ok": True,
            "channels": [mock_channel],
            "response_metadata": {"next_cursor": ""},
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["channels"])

            evidence = result.evidence_items[0]
            controls = evidence.metadata["compliance_controls"]
            assert "CC6.1" in controls["soc2"]
            assert "AC-3" in controls["nist_800_53"]

    def test_all_evidence_types_have_mappings(self, collector):
        """Test all evidence types have compliance mappings."""
        for evidence_type in collector.SUPPORTED_EVIDENCE_TYPES:
            assert evidence_type in collector.EVIDENCE_CONTROL_MAPPINGS
            mappings = collector.EVIDENCE_CONTROL_MAPPINGS[evidence_type]
            assert "soc2" in mappings
            assert "nist_800_53" in mappings
            assert "iso_27001" in mappings
            assert "hitrust" in mappings
