"""Unit tests for the Zoom collector."""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta

from attestful.collectors.platforms.zoom import ZoomCollector, ZoomCollectorConfig
from attestful.core.exceptions import CollectionError, ConfigurationError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_config():
    """Create a mock Zoom configuration."""
    return ZoomCollectorConfig(
        account_id="test-account-id",
        client_id="test-client-id",
        client_secret="test-client-secret",
    )


@pytest.fixture
def mock_user():
    """Create a mock user response."""
    return {
        "id": "user123",
        "email": "john@company.com",
        "first_name": "John",
        "last_name": "Doe",
        "display_name": "John Doe",
        "type": 2,  # Licensed
        "role_name": "Member",
        "role_id": "role123",
        "pmi": 1234567890,
        "timezone": "America/New_York",
        "verified": 1,
        "created_at": "2024-01-01T00:00:00Z",
        "last_login_time": "2024-01-15T00:00:00Z",
        "status": "active",
        "dept": "Engineering",
        "group_ids": ["group1", "group2"],
    }


@pytest.fixture
def mock_group():
    """Create a mock group response."""
    return {
        "id": "group123",
        "name": "Engineering Team",
        "total_members": 25,
    }


@pytest.fixture
def mock_role():
    """Create a mock role response."""
    return {
        "id": "role123",
        "name": "Admin",
        "description": "Administrator role",
        "total_members": 5,
    }


@pytest.fixture
def mock_room():
    """Create a mock Zoom Room response."""
    return {
        "id": "room123",
        "name": "Conference Room A",
        "type": "ZoomRoom",
        "status": "Available",
        "location_id": "loc123",
        "device_ip": "192.168.1.100",
        "camera": "Logitech Rally",
        "microphone": "Built-in",
        "speaker": "Built-in",
    }


@pytest.fixture
def mock_activity():
    """Create a mock sign-in activity response."""
    return {
        "email": "john@company.com",
        "time": "2024-01-15T10:00:00Z",
        "type": "Sign-in",
        "ip_address": "192.168.1.50",
        "client_type": "Browser",
        "version": "5.0.0",
    }


@pytest.fixture
def mock_account_settings():
    """Create a mock account settings response."""
    return {
        "schedule_meeting": {
            "require_password_for_scheduling_new_meetings": True,
            "require_password_for_instant_meetings": True,
            "require_password_for_pmi_meetings": "all",
            "waiting_room": True,
            "host_video": True,
            "participant_video": False,
            "join_before_host": False,
            "mute_upon_entry": True,
        },
        "in_meeting": {
            "e2e_encryption": True,
            "encryption_type": "enhanced",
            "screen_sharing": True,
            "who_can_share_screen": "host",
            "annotation": True,
            "whiteboard": True,
            "allow_participants_to_unmute": True,
            "chat": True,
            "private_chat": True,
            "file_transfer": False,
            "recording_consent": True,
        },
        "recording": {
            "cloud_recording": True,
            "local_recording": True,
            "auto_recording": "cloud",
            "host_delete_cloud_recording": True,
            "auto_delete_cmr": True,
            "auto_delete_cmr_days": 30,
        },
        "security": {
            "admin_change_name_pic": True,
            "sign_in_with_work_email": True,
            "sign_in_with_sso": True,
            "password_minimum_length": 10,
            "password_have_special_char": True,
            "password_have_number": True,
            "waiting_room": True,
        },
        "feature": {
            "zoom_phone": True,
            "webinar": True,
            "large_meeting": True,
        },
    }


@pytest.fixture
def cli_runner():
    """Create a CLI runner for testing."""
    from click.testing import CliRunner

    return CliRunner()


# =============================================================================
# Configuration Tests
# =============================================================================


class TestZoomCollectorConfig:
    """Tests for ZoomCollectorConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = ZoomCollectorConfig()
        assert config.account_id == ""
        assert config.client_id == ""
        assert config.client_secret == ""
        assert config.timeout == 30
        assert config.max_retries == 3
        assert config.page_size == 100
        assert config.days_of_history == 90

    def test_custom_config(self, mock_config):
        """Test custom configuration values."""
        assert mock_config.account_id == "test-account-id"
        assert mock_config.client_id == "test-client-id"
        assert mock_config.client_secret == "test-client-secret"


# =============================================================================
# Collector Initialization Tests
# =============================================================================


class TestZoomCollectorInit:
    """Tests for Zoom collector initialization."""

    def test_init_with_config(self, mock_config):
        """Test initialization with config."""
        collector = ZoomCollector(config=mock_config)
        assert collector.config == mock_config
        assert collector.PLATFORM == "zoom"

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = ZoomCollector()
        assert collector.config is not None
        assert collector.config.account_id == ""
        assert collector._session is None
        assert collector._access_token is None

    def test_supported_types(self, mock_config):
        """Test supported resource and evidence types."""
        collector = ZoomCollector(config=mock_config)
        assert "zoom_user" in collector.SUPPORTED_RESOURCE_TYPES
        assert "zoom_group" in collector.SUPPORTED_RESOURCE_TYPES
        assert "zoom_role" in collector.SUPPORTED_RESOURCE_TYPES
        assert "zoom_room" in collector.SUPPORTED_RESOURCE_TYPES

        assert "users" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "account_settings" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "meeting_settings" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "recording_settings" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "security_settings" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "groups" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "roles" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "signin_signout_activities" in collector.SUPPORTED_EVIDENCE_TYPES

    def test_api_url_property(self, mock_config):
        """Test API URL generation."""
        collector = ZoomCollector(config=mock_config)
        assert collector.api_url == "https://api.zoom.us/v2"


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestCredentialValidation:
    """Tests for credential validation."""

    @patch("attestful.collectors.platforms.zoom.requests.post")
    @patch("attestful.collectors.platforms.zoom.requests.Session")
    def test_validate_credentials_success(
        self, mock_session_class, mock_post, mock_config
    ):
        """Test successful credential validation."""
        # Mock OAuth token response
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "test-token", "expires_in": 3600}),
        )

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock users endpoint response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"users": []}
        mock_response.content = b'{"users": []}'
        mock_session.request.return_value = mock_response

        collector = ZoomCollector(config=mock_config)
        assert collector.validate_credentials() is True

    def test_validate_credentials_missing_account_id(self):
        """Test validation with missing account ID."""
        config = ZoomCollectorConfig(
            client_id="test-client-id",
            client_secret="test-client-secret",
        )
        collector = ZoomCollector(config=config)

        with pytest.raises(ConfigurationError, match="account_id is required"):
            collector.validate_credentials()

    def test_validate_credentials_missing_client_id(self):
        """Test validation with missing client ID."""
        config = ZoomCollectorConfig(
            account_id="test-account-id",
            client_secret="test-client-secret",
        )
        collector = ZoomCollector(config=config)

        with pytest.raises(ConfigurationError, match="client_id is required"):
            collector.validate_credentials()

    def test_validate_credentials_missing_client_secret(self):
        """Test validation with missing client secret."""
        config = ZoomCollectorConfig(
            account_id="test-account-id",
            client_id="test-client-id",
        )
        collector = ZoomCollector(config=config)

        with pytest.raises(ConfigurationError, match="client_secret is required"):
            collector.validate_credentials()

    @patch("attestful.collectors.platforms.zoom.requests.post")
    def test_validate_credentials_invalid_oauth(self, mock_post, mock_config):
        """Test invalid OAuth credential handling."""
        import requests

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            response=mock_response
        )
        mock_post.return_value = mock_response

        collector = ZoomCollector(config=mock_config)

        with pytest.raises(ConfigurationError, match="Invalid Zoom OAuth credentials"):
            collector.validate_credentials()


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestResourceCollection:
    """Tests for resource collection."""

    @patch("attestful.collectors.platforms.zoom.requests.post")
    @patch("attestful.collectors.platforms.zoom.requests.Session")
    def test_collect_user_resources(
        self, mock_session_class, mock_post, mock_config, mock_user
    ):
        """Test user resource collection."""
        # Mock OAuth token
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "test-token", "expires_in": 3600}),
        )

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {"users": [mock_user], "next_page_token": ""}
        mock_response.content = b'{"users": []}'
        mock_session.request.return_value = mock_response

        collector = ZoomCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["zoom_user"])

        assert len(resources) == 1
        assert resources[0].type == "zoom_user"
        assert resources[0].name == "john@company.com"
        assert resources[0].tags["type"] == "licensed"
        assert resources[0].tags["status"] == "active"

    @patch("attestful.collectors.platforms.zoom.requests.post")
    @patch("attestful.collectors.platforms.zoom.requests.Session")
    def test_collect_group_resources(
        self, mock_session_class, mock_post, mock_config, mock_group
    ):
        """Test group resource collection."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "test-token", "expires_in": 3600}),
        )

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {"groups": [mock_group], "next_page_token": ""}
        mock_response.content = b'{"groups": []}'
        mock_session.request.return_value = mock_response

        collector = ZoomCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["zoom_group"])

        assert len(resources) == 1
        assert resources[0].type == "zoom_group"
        assert resources[0].name == "Engineering Team"

    @patch("attestful.collectors.platforms.zoom.requests.post")
    @patch("attestful.collectors.platforms.zoom.requests.Session")
    def test_collect_role_resources(
        self, mock_session_class, mock_post, mock_config, mock_role
    ):
        """Test role resource collection."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "test-token", "expires_in": 3600}),
        )

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {"roles": [mock_role], "next_page_token": ""}
        mock_response.content = b'{"roles": []}'
        mock_session.request.return_value = mock_response

        collector = ZoomCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["zoom_role"])

        assert len(resources) == 1
        assert resources[0].type == "zoom_role"
        assert resources[0].name == "Admin"
        assert resources[0].tags["is_admin"] == "true"

    def test_collect_invalid_resource_type(self, mock_config):
        """Test error on invalid resource type."""
        collector = ZoomCollector(config=mock_config)

        with pytest.raises(CollectionError, match="Unsupported resource types"):
            collector.collect_resources(resource_types=["invalid_type"])


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestEvidenceCollection:
    """Tests for evidence collection."""

    @patch("attestful.collectors.platforms.zoom.requests.post")
    @patch("attestful.collectors.platforms.zoom.requests.Session")
    def test_collect_users_evidence(
        self, mock_session_class, mock_post, mock_config, mock_user
    ):
        """Test users evidence collection."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "test-token", "expires_in": 3600}),
        )

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {"users": [mock_user], "next_page_token": ""}
        mock_response.content = b'{"users": []}'
        mock_session.request.return_value = mock_response

        collector = ZoomCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["users"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "users"
        assert result.evidence_items[0].raw_data["total_count"] == 1
        assert result.evidence_items[0].raw_data["by_type"]["licensed"] == 1

    @patch("attestful.collectors.platforms.zoom.requests.post")
    @patch("attestful.collectors.platforms.zoom.requests.Session")
    def test_collect_account_settings_evidence(
        self, mock_session_class, mock_post, mock_config, mock_account_settings
    ):
        """Test account settings evidence collection."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "test-token", "expires_in": 3600}),
        )

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = mock_account_settings
        mock_response.content = b'{}'
        mock_session.request.return_value = mock_response

        collector = ZoomCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["account_settings"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "account_settings"
        assert "security_summary" in result.evidence_items[0].raw_data

    @patch("attestful.collectors.platforms.zoom.requests.post")
    @patch("attestful.collectors.platforms.zoom.requests.Session")
    def test_collect_meeting_settings_evidence(
        self, mock_session_class, mock_post, mock_config, mock_account_settings
    ):
        """Test meeting settings evidence collection."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "test-token", "expires_in": 3600}),
        )

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = mock_account_settings
        mock_response.content = b'{}'
        mock_session.request.return_value = mock_response

        collector = ZoomCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["meeting_settings"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "meeting_settings"
        assert "security_configuration" in result.evidence_items[0].raw_data

    @patch("attestful.collectors.platforms.zoom.requests.post")
    @patch("attestful.collectors.platforms.zoom.requests.Session")
    def test_collect_groups_evidence(
        self, mock_session_class, mock_post, mock_config, mock_group
    ):
        """Test groups evidence collection."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "test-token", "expires_in": 3600}),
        )

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # First call: groups list, second call: group members
        mock_response = MagicMock()
        mock_response.json.side_effect = [
            {"groups": [mock_group], "next_page_token": ""},
            {"total_records": 25},
        ]
        mock_response.content = b'{}'
        mock_session.request.return_value = mock_response

        collector = ZoomCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["groups"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "groups"
        assert result.evidence_items[0].raw_data["total_count"] == 1

    @patch("attestful.collectors.platforms.zoom.requests.post")
    @patch("attestful.collectors.platforms.zoom.requests.Session")
    def test_collect_roles_evidence(
        self, mock_session_class, mock_post, mock_config, mock_role
    ):
        """Test roles evidence collection."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "test-token", "expires_in": 3600}),
        )

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # First call: roles list, second call: role details
        mock_response = MagicMock()
        mock_response.json.side_effect = [
            {"roles": [mock_role], "next_page_token": ""},
            {"privileges": ["user:read", "user:write"]},
        ]
        mock_response.content = b'{}'
        mock_session.request.return_value = mock_response

        collector = ZoomCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["roles"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "roles"
        assert result.evidence_items[0].raw_data["admin_roles_count"] == 1

    @patch("attestful.collectors.platforms.zoom.requests.post")
    @patch("attestful.collectors.platforms.zoom.requests.Session")
    def test_collect_signin_activities_evidence(
        self, mock_session_class, mock_post, mock_config, mock_activity
    ):
        """Test sign-in activities evidence collection."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "test-token", "expires_in": 3600}),
        )

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "activity_logs": [mock_activity],
            "next_page_token": "",
        }
        mock_response.content = b'{}'
        mock_session.request.return_value = mock_response

        collector = ZoomCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["signin_signout_activities"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "signin_signout_activities"
        assert result.evidence_items[0].raw_data["by_type"]["Sign-in"] == 1

    def test_collect_invalid_evidence_type(self, mock_config):
        """Test error on invalid evidence type."""
        collector = ZoomCollector(config=mock_config)

        with pytest.raises(CollectionError, match="Unsupported evidence types"):
            collector.collect_evidence(evidence_types=["invalid_type"])


# =============================================================================
# Compliance Control Mapping Tests
# =============================================================================


class TestComplianceMetadata:
    """Tests for compliance control mappings."""

    def test_evidence_control_mappings_exist(self):
        """Test that all evidence types have control mappings."""
        collector = ZoomCollector()

        for evidence_type in collector.SUPPORTED_EVIDENCE_TYPES:
            assert evidence_type in collector.EVIDENCE_CONTROL_MAPPINGS
            mappings = collector.EVIDENCE_CONTROL_MAPPINGS[evidence_type]
            assert "soc2" in mappings
            assert "nist_800_53" in mappings
            assert "iso_27001" in mappings
            assert "hitrust" in mappings

    def test_users_compliance_controls(self):
        """Test users evidence compliance controls."""
        collector = ZoomCollector()
        controls = collector.EVIDENCE_CONTROL_MAPPINGS["users"]

        # SOC 2 - Access Control
        assert "CC6.1" in controls["soc2"]
        assert "CC6.2" in controls["soc2"]

        # NIST 800-53 - Access Control and Identity
        assert "AC-2" in controls["nist_800_53"]
        assert "IA-2" in controls["nist_800_53"]

        # ISO 27001
        assert "A.9.2.1" in controls["iso_27001"]

    def test_meeting_settings_compliance_controls(self):
        """Test meeting settings evidence compliance controls."""
        collector = ZoomCollector()
        controls = collector.EVIDENCE_CONTROL_MAPPINGS["meeting_settings"]

        # SOC 2 - Communication Security
        assert "CC6.6" in controls["soc2"]
        assert "CC6.7" in controls["soc2"]

        # NIST 800-53
        assert "AC-17" in controls["nist_800_53"]
        assert "SC-8" in controls["nist_800_53"]

    def test_signin_activities_compliance_controls(self):
        """Test sign-in activities evidence compliance controls."""
        collector = ZoomCollector()
        controls = collector.EVIDENCE_CONTROL_MAPPINGS["signin_signout_activities"]

        # SOC 2 - Audit Logging
        assert "CC7.2" in controls["soc2"]
        assert "CC7.3" in controls["soc2"]

        # NIST 800-53 - Audit
        assert "AU-2" in controls["nist_800_53"]
        assert "AU-3" in controls["nist_800_53"]
        assert "AU-6" in controls["nist_800_53"]
        assert "AU-12" in controls["nist_800_53"]

        # ISO 27001
        assert "A.12.4.1" in controls["iso_27001"]

    def test_security_settings_compliance_controls(self):
        """Test security settings evidence compliance controls."""
        collector = ZoomCollector()
        controls = collector.EVIDENCE_CONTROL_MAPPINGS["security_settings"]

        # SOC 2 - Authentication
        assert "CC6.1" in controls["soc2"]
        assert "CC6.2" in controls["soc2"]

        # NIST 800-53 - Password and Authentication
        assert "IA-5" in controls["nist_800_53"]
        assert "AC-7" in controls["nist_800_53"]


# =============================================================================
# CLI Tests
# =============================================================================


class TestZoomCLI:
    """Tests for Zoom CLI commands."""

    def test_collect_zoom_missing_account_id(self, cli_runner):
        """Test collect zoom command with missing account ID."""
        from attestful.cli.main import cli

        result = cli_runner.invoke(
            cli,
            [
                "collect",
                "zoom",
                "--client-id",
                "test-client-id",
                "--client-secret",
                "test-client-secret",
            ],
        )

        assert "account id is required" in result.output.lower()

    def test_collect_zoom_missing_client_id(self, cli_runner):
        """Test collect zoom command with missing client ID."""
        from attestful.cli.main import cli

        result = cli_runner.invoke(
            cli,
            [
                "collect",
                "zoom",
                "--account-id",
                "test-account-id",
                "--client-secret",
                "test-client-secret",
            ],
        )

        assert "client id is required" in result.output.lower()

    def test_collect_zoom_missing_client_secret(self, cli_runner):
        """Test collect zoom command with missing client secret."""
        from attestful.cli.main import cli

        result = cli_runner.invoke(
            cli,
            [
                "collect",
                "zoom",
                "--account-id",
                "test-account-id",
                "--client-id",
                "test-client-id",
            ],
        )

        assert "client secret is required" in result.output.lower()

    def test_collect_zoom_help(self, cli_runner):
        """Test collect zoom command help."""
        from attestful.cli.main import cli

        result = cli_runner.invoke(cli, ["collect", "zoom", "--help"])

        assert result.exit_code == 0
        assert "Collect evidence from Zoom" in result.output
        assert "--account-id" in result.output
        assert "--client-id" in result.output
        assert "--client-secret" in result.output
        assert "--types" in result.output
        assert "--days" in result.output

    def test_collect_list_shows_zoom(self, cli_runner):
        """Test that collect list shows Zoom as available."""
        from attestful.cli.main import cli

        result = cli_runner.invoke(cli, ["collect", "list"])

        assert result.exit_code == 0
        assert "zoom" in result.output.lower()
        # Zoom should be marked as available in Both mode
        assert "Both" in result.output


# =============================================================================
# OAuth Token Tests
# =============================================================================


class TestOAuthToken:
    """Tests for OAuth token handling."""

    @patch("attestful.collectors.platforms.zoom.requests.post")
    def test_token_caching(self, mock_post, mock_config):
        """Test that OAuth token is cached."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "test-token", "expires_in": 3600}),
        )

        collector = ZoomCollector(config=mock_config)

        # First call gets token
        token1 = collector._get_access_token()
        assert token1 == "test-token"
        assert mock_post.call_count == 1

        # Second call uses cached token
        token2 = collector._get_access_token()
        assert token2 == "test-token"
        assert mock_post.call_count == 1  # No additional call

    @patch("attestful.collectors.platforms.zoom.requests.post")
    def test_token_refresh_when_expired(self, mock_post, mock_config):
        """Test that expired token is refreshed."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "new-token", "expires_in": 3600}),
        )

        collector = ZoomCollector(config=mock_config)

        # Set an expired token
        collector._access_token = "old-token"
        collector._token_expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

        # Should get new token
        token = collector._get_access_token()
        assert token == "new-token"
        assert mock_post.call_count == 1


# =============================================================================
# User Type Mapping Tests
# =============================================================================


class TestUserTypeMapping:
    """Tests for user type mapping."""

    @patch("attestful.collectors.platforms.zoom.requests.post")
    @patch("attestful.collectors.platforms.zoom.requests.Session")
    def test_user_type_names(self, mock_session_class, mock_post, mock_config):
        """Test that user types are properly mapped to names."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"access_token": "test-token", "expires_in": 3600}),
        )

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        users = [
            {"id": "1", "email": "basic@test.com", "type": 1, "status": "active"},
            {"id": "2", "email": "licensed@test.com", "type": 2, "status": "active"},
            {"id": "3", "email": "onprem@test.com", "type": 3, "status": "active"},
            {"id": "4", "email": "none@test.com", "type": 99, "status": "active"},
        ]

        mock_response = MagicMock()
        mock_response.json.return_value = {"users": users, "next_page_token": ""}
        mock_response.content = b'{}'
        mock_session.request.return_value = mock_response

        collector = ZoomCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["zoom_user"])

        assert len(resources) == 4
        assert resources[0].tags["type"] == "basic"
        assert resources[1].tags["type"] == "licensed"
        assert resources[2].tags["type"] == "on_prem"
        assert resources[3].tags["type"] == "none"
