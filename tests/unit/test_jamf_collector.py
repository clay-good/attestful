"""Tests for Jamf collector."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
import requests

from attestful.collectors.platforms.jamf import (
    JamfCollector,
    JamfCollectorConfig,
)
from attestful.core.exceptions import CollectionError, ConfigurationError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def config():
    """Create a test configuration."""
    return JamfCollectorConfig(
        url="https://company.jamfcloud.com",
        username="testuser",
        password="testpass",
    )


@pytest.fixture
def oauth_config():
    """Create an OAuth test configuration."""
    return JamfCollectorConfig(
        url="https://company.jamfcloud.com",
        client_id="test_client_id",
        client_secret="test_client_secret",
    )


@pytest.fixture
def collector(config):
    """Create a collector instance."""
    return JamfCollector(config=config)


@pytest.fixture
def oauth_collector(oauth_config):
    """Create an OAuth collector instance."""
    return JamfCollector(config=oauth_config)


@pytest.fixture
def mock_computer():
    """Create a mock computer response."""
    return {
        "id": 1,
        "general": {
            "name": "MacBook Pro",
            "operatingSystemVersion": "14.0",
            "operatingSystemBuild": "23A344",
            "managed": True,
            "supervised": False,
            "lastContactTime": "2024-12-01T10:00:00Z",
            "lastEnrolledDate": "2024-01-01T00:00:00Z",
        },
        "hardware": {
            "serialNumber": "C02ABC123DEF",
            "model": "MacBook Pro (16-inch, 2023)",
        },
        "diskEncryption": {
            "fileVault2Status": "Enabled",
        },
        "security": {
            "sipStatus": "Enabled",
            "gatekeeperStatus": "App Store and Identified Developers",
            "firewallStatus": "Enabled",
        },
        "userAndLocation": {
            "username": "jdoe",
            "department": "Engineering",
        },
    }


@pytest.fixture
def mock_unencrypted_computer():
    """Create a mock unencrypted computer response."""
    return {
        "id": 2,
        "general": {
            "name": "Mac Mini",
            "operatingSystemVersion": "13.0",
            "operatingSystemBuild": "22A380",
            "managed": False,
            "supervised": False,
            "lastContactTime": "2024-11-01T10:00:00Z",
        },
        "hardware": {
            "serialNumber": "D02DEF456GHI",
            "model": "Mac Mini (2023)",
        },
        "diskEncryption": {
            "fileVault2Status": "Not Enabled",
        },
        "security": {
            "sipStatus": "Disabled",
        },
        "userAndLocation": {
            "username": "guest",
        },
    }


@pytest.fixture
def mock_mobile_device():
    """Create a mock mobile device response."""
    return {
        "id": 1,
        "name": "John's iPhone",
        "serialNumber": "ABCD12345678",
        "model": "iPhone 15 Pro",
        "osVersion": "17.0",
        "managed": True,
        "supervised": True,
        "lastInventoryUpdateDate": "2024-12-01T10:00:00Z",
        "username": "jdoe",
    }


@pytest.fixture
def mock_policy():
    """Create a mock policy response."""
    return {
        "id": 1,
        "name": "FileVault Enforcement",
        "enabled": True,
        "category": {"id": 1, "name": "Security"},
        "trigger": "recurring check-in",
        "frequency": "Once per computer",
    }


@pytest.fixture
def mock_configuration_profile():
    """Create a mock configuration profile response."""
    return {
        "id": 1,
        "name": "Security Profile",
        "scope": {"allComputers": True},
        "general": {"distributionMethod": "Install Automatically"},
    }


@pytest.fixture
def mock_user():
    """Create a mock user response."""
    return {
        "id": 1,
        "name": "jdoe",
        "email": "jdoe@example.com",
        "fullName": "John Doe",
        "phoneNumber": "555-1234",
        "position": "Engineer",
        "department": "Engineering",
        "building": "HQ",
        "ldapServer": {"id": 1, "name": "Corporate LDAP"},
    }


@pytest.fixture
def mock_extension_attribute():
    """Create a mock extension attribute response."""
    return {
        "id": 1,
        "name": "Compliance Status",
        "dataType": "STRING",
        "inputType": {"type": "script"},
        "enabled": True,
    }


@pytest.fixture
def mock_computer_group():
    """Create a mock computer group response."""
    return {
        "id": 1,
        "name": "All Managed Computers",
        "smartGroup": True,
        "memberCount": 150,
    }


# =============================================================================
# Initialization Tests
# =============================================================================


class TestJamfCollectorInit:
    """Test collector initialization."""

    def test_init_with_config(self, config):
        """Test initialization with config."""
        collector = JamfCollector(config=config)
        assert collector.config.url == "https://company.jamfcloud.com"
        assert collector.config.username == "testuser"
        assert collector.config.password == "testpass"

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = JamfCollector()
        assert collector.config.url == ""
        assert collector.config.username == ""
        assert collector.config.password == ""
        assert collector.config.timeout == 30
        assert collector.config.page_size == 100

    def test_init_oauth_config(self, oauth_config):
        """Test initialization with OAuth config."""
        collector = JamfCollector(config=oauth_config)
        assert collector.config.client_id == "test_client_id"
        assert collector.config.client_secret == "test_client_secret"

    def test_metadata(self, collector):
        """Test metadata property."""
        metadata = collector.metadata
        assert metadata.name == "Jamf Collector"
        assert metadata.platform == "jamf"
        assert "endpoint" in metadata.description.lower()
        assert metadata.version == "1.0.0"
        assert len(metadata.resource_types) == 5
        assert len(metadata.evidence_types) == 7

    def test_platform(self, collector):
        """Test platform constant."""
        assert collector.PLATFORM == "jamf"

    def test_api_url(self, collector):
        """Test API URL property."""
        assert collector.api_url == "https://company.jamfcloud.com"

    def test_api_url_strips_trailing_slash(self, config):
        """Test API URL removes trailing slash."""
        config.url = "https://company.jamfcloud.com/"
        collector = JamfCollector(config=config)
        assert collector.api_url == "https://company.jamfcloud.com"


# =============================================================================
# Session Tests
# =============================================================================


class TestJamfSession:
    """Test HTTP session handling."""

    def test_session_creation(self, collector):
        """Test session is created on first access."""
        session = collector.session
        assert session is not None
        assert "Accept" in session.headers

    def test_session_cached(self, collector):
        """Test session is cached."""
        session1 = collector.session
        session2 = collector.session
        assert session1 is session2


# =============================================================================
# Token Tests
# =============================================================================


class TestTokenManagement:
    """Test token management."""

    def test_get_token_basic_auth(self, collector):
        """Test token retrieval with basic auth."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"token": "test_token_123"}

        with patch("requests.post", return_value=mock_response) as mock_post:
            token = collector._get_token()
            assert token == "test_token_123"
            mock_post.assert_called_once()
            assert "auth/token" in mock_post.call_args[0][0]

    def test_get_token_oauth(self, oauth_collector):
        """Test token retrieval with OAuth."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "access_token": "oauth_token_456",
            "expires_in": 3600,
        }

        with patch("requests.post", return_value=mock_response) as mock_post:
            token = oauth_collector._get_token()
            assert token == "oauth_token_456"
            mock_post.assert_called_once()
            assert "oauth/token" in mock_post.call_args[0][0]

    def test_token_cached(self, collector):
        """Test token is cached."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"token": "cached_token"}

        with patch("requests.post", return_value=mock_response) as mock_post:
            token1 = collector._get_token()
            token2 = collector._get_token()
            assert token1 == token2
            assert mock_post.call_count == 1  # Only called once


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestValidateCredentials:
    """Test credential validation."""

    def test_validate_credentials_success(self, collector):
        """Test successful credential validation."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"token": "valid_token"}

        with patch("requests.post", return_value=mock_response):
            assert collector.validate_credentials() is True

    def test_validate_credentials_no_url(self):
        """Test validation fails without URL."""
        collector = JamfCollector(config=JamfCollectorConfig())
        with pytest.raises(ConfigurationError, match="url is required"):
            collector.validate_credentials()

    def test_validate_credentials_no_creds(self):
        """Test validation fails without credentials."""
        config = JamfCollectorConfig(url="https://company.jamfcloud.com")
        collector = JamfCollector(config=config)
        with pytest.raises(ConfigurationError, match="credentials required"):
            collector.validate_credentials()

    def test_validate_credentials_invalid(self, collector):
        """Test validation fails with invalid credentials."""
        with patch("requests.post", side_effect=requests.HTTPError("401 Unauthorized")):
            with pytest.raises(ConfigurationError, match="Invalid Jamf credentials"):
                collector.validate_credentials()


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestCollectEvidence:
    """Test evidence collection."""

    def _setup_mock_with_token(self, collector, mock_data_func):
        """Helper to setup mocks with token and data."""
        token_response = MagicMock()
        token_response.raise_for_status = MagicMock()
        token_response.json.return_value = {"token": "test_token"}

        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = mock_data_func(url)
            return response

        return token_response, mock_request

    def test_collect_all_evidence_types(self, collector, mock_computer, mock_mobile_device, mock_policy, mock_configuration_profile, mock_user, mock_extension_attribute, mock_computer_group):
        """Test collecting all evidence types."""
        def mock_data(url):
            if "computers-inventory" in url:
                return {"results": [mock_computer], "totalCount": 1}
            elif "mobile-devices" in url:
                return {"results": [mock_mobile_device], "totalCount": 1}
            elif "policies" in url:
                return {"results": [mock_policy], "totalCount": 1}
            elif "os-x-configuration-profiles" in url:
                return {"results": [mock_configuration_profile], "totalCount": 1}
            elif "mobile-device-configuration-profiles" in url:
                return {"results": [], "totalCount": 0}
            elif "users" in url and "extension" not in url:
                return {"results": [mock_user], "totalCount": 1}
            elif "computer-extension-attributes" in url:
                return {"results": [mock_extension_attribute], "totalCount": 1}
            elif "mobile-device-extension-attributes" in url:
                return {"results": [], "totalCount": 0}
            elif "computer-groups" in url:
                return {"results": [mock_computer_group], "totalCount": 1}
            return {"results": [], "totalCount": 0}

        token_response, mock_request = self._setup_mock_with_token(collector, mock_data)

        with patch("requests.post", return_value=token_response):
            with patch.object(collector.session, "request", side_effect=mock_request):
                result = collector.collect_evidence()

                assert result.success
                assert len(result.evidence_items) == 7
                evidence_types = [e.evidence_type for e in result.evidence_items]
                assert "computers" in evidence_types
                assert "mobile_devices" in evidence_types
                assert "policies" in evidence_types
                assert "configuration_profiles" in evidence_types
                assert "users" in evidence_types
                assert "extension_attributes" in evidence_types
                assert "computer_groups" in evidence_types

    def test_collect_specific_evidence_types(self, collector, mock_computer):
        """Test collecting specific evidence types."""
        def mock_data(url):
            return {"results": [mock_computer], "totalCount": 1}

        token_response, mock_request = self._setup_mock_with_token(collector, mock_data)

        with patch("requests.post", return_value=token_response):
            with patch.object(collector.session, "request", side_effect=mock_request):
                result = collector.collect_evidence(evidence_types=["computers"])

                assert len(result.evidence_items) == 1
                assert result.evidence_items[0].evidence_type == "computers"

    def test_collect_evidence_invalid_type(self, collector):
        """Test collecting invalid evidence type."""
        with pytest.raises(CollectionError, match="Unsupported evidence types"):
            collector.collect_evidence(evidence_types=["invalid_type"])

    def test_collect_computers_evidence(self, collector, mock_computer, mock_unencrypted_computer):
        """Test computers evidence collection."""
        def mock_data(url):
            return {"results": [mock_computer, mock_unencrypted_computer], "totalCount": 2}

        token_response, mock_request = self._setup_mock_with_token(collector, mock_data)

        with patch("requests.post", return_value=token_response):
            with patch.object(collector.session, "request", side_effect=mock_request):
                result = collector.collect_evidence(evidence_types=["computers"])

                assert len(result.evidence_items) == 1
                evidence = result.evidence_items[0]
                assert evidence.evidence_type == "computers"
                assert evidence.raw_data["total_count"] == 2
                assert evidence.raw_data["managed_count"] == 1
                assert evidence.raw_data["unmanaged_count"] == 1
                assert evidence.raw_data["encrypted_count"] == 1
                assert evidence.raw_data["unencrypted_count"] == 1
                assert evidence.raw_data["compliant_count"] == 1
                assert evidence.raw_data["compliance_rate"] == 50.0

    def test_collect_mobile_devices_evidence(self, collector, mock_mobile_device):
        """Test mobile devices evidence collection."""
        def mock_data(url):
            return {"results": [mock_mobile_device], "totalCount": 1}

        token_response, mock_request = self._setup_mock_with_token(collector, mock_data)

        with patch("requests.post", return_value=token_response):
            with patch.object(collector.session, "request", side_effect=mock_request):
                result = collector.collect_evidence(evidence_types=["mobile_devices"])

                assert len(result.evidence_items) == 1
                evidence = result.evidence_items[0]
                assert evidence.evidence_type == "mobile_devices"
                assert evidence.raw_data["total_count"] == 1
                assert evidence.raw_data["managed_count"] == 1
                assert evidence.raw_data["supervised_count"] == 1

    def test_collect_policies_evidence(self, collector, mock_policy):
        """Test policies evidence collection."""
        def mock_data(url):
            return {"results": [mock_policy], "totalCount": 1}

        token_response, mock_request = self._setup_mock_with_token(collector, mock_data)

        with patch("requests.post", return_value=token_response):
            with patch.object(collector.session, "request", side_effect=mock_request):
                result = collector.collect_evidence(evidence_types=["policies"])

                assert len(result.evidence_items) == 1
                evidence = result.evidence_items[0]
                assert evidence.evidence_type == "policies"
                assert evidence.raw_data["total_count"] == 1
                assert evidence.raw_data["enabled_count"] == 1

    def test_collect_users_evidence(self, collector, mock_user):
        """Test users evidence collection."""
        def mock_data(url):
            return {"results": [mock_user], "totalCount": 1}

        token_response, mock_request = self._setup_mock_with_token(collector, mock_data)

        with patch("requests.post", return_value=token_response):
            with patch.object(collector.session, "request", side_effect=mock_request):
                result = collector.collect_evidence(evidence_types=["users"])

                assert len(result.evidence_items) == 1
                evidence = result.evidence_items[0]
                assert evidence.evidence_type == "users"
                assert evidence.raw_data["total_count"] == 1
                assert evidence.raw_data["ldap_users"] == 1

    def test_collect_computer_groups_evidence(self, collector, mock_computer_group):
        """Test computer groups evidence collection."""
        static_group = {"id": 2, "name": "Manual Group", "smartGroup": False, "memberCount": 10}

        def mock_data(url):
            return {"results": [mock_computer_group, static_group], "totalCount": 2}

        token_response, mock_request = self._setup_mock_with_token(collector, mock_data)

        with patch("requests.post", return_value=token_response):
            with patch.object(collector.session, "request", side_effect=mock_request):
                result = collector.collect_evidence(evidence_types=["computer_groups"])

                assert len(result.evidence_items) == 1
                evidence = result.evidence_items[0]
                assert evidence.evidence_type == "computer_groups"
                assert evidence.raw_data["total_count"] == 2
                assert evidence.raw_data["smart_groups"] == 1
                assert evidence.raw_data["static_groups"] == 1


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestCollectResources:
    """Test resource collection."""

    def _setup_mock_with_token(self, collector, mock_data_func):
        """Helper to setup mocks with token and data."""
        token_response = MagicMock()
        token_response.raise_for_status = MagicMock()
        token_response.json.return_value = {"token": "test_token"}

        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = mock_data_func(url)
            return response

        return token_response, mock_request

    def test_collect_all_resource_types(self, collector, mock_computer, mock_mobile_device, mock_policy, mock_configuration_profile, mock_user):
        """Test collecting all resource types."""
        def mock_data(url):
            if "computers-inventory" in url:
                return {"results": [mock_computer], "totalCount": 1}
            elif "mobile-devices" in url:
                return {"results": [mock_mobile_device], "totalCount": 1}
            elif "policies" in url:
                return {"results": [mock_policy], "totalCount": 1}
            elif "os-x-configuration-profiles" in url:
                return {"results": [mock_configuration_profile], "totalCount": 1}
            elif "mobile-device-configuration-profiles" in url:
                return {"results": [], "totalCount": 0}
            elif "/users" in url:
                return {"results": [mock_user], "totalCount": 1}
            return {"results": [], "totalCount": 0}

        token_response, mock_request = self._setup_mock_with_token(collector, mock_data)

        with patch("requests.post", return_value=token_response):
            with patch.object(collector.session, "request", side_effect=mock_request):
                resources = collector.collect_resources()

                assert len(resources) == 5
                resource_types = [r.type for r in resources]
                assert "jamf_computer" in resource_types
                assert "jamf_mobile_device" in resource_types
                assert "jamf_policy" in resource_types
                assert "jamf_configuration_profile" in resource_types
                assert "jamf_user" in resource_types

    def test_collect_specific_resource_types(self, collector, mock_computer):
        """Test collecting specific resource types."""
        def mock_data(url):
            return {"results": [mock_computer], "totalCount": 1}

        token_response, mock_request = self._setup_mock_with_token(collector, mock_data)

        with patch("requests.post", return_value=token_response):
            with patch.object(collector.session, "request", side_effect=mock_request):
                resources = collector.collect_resources(resource_types=["jamf_computer"])

                assert len(resources) == 1
                assert resources[0].type == "jamf_computer"

    def test_collect_resources_invalid_type(self, collector):
        """Test collecting invalid resource type."""
        with pytest.raises(CollectionError, match="Unsupported resource types"):
            collector.collect_resources(resource_types=["invalid_type"])

    def test_collect_computer_resources(self, collector, mock_computer):
        """Test computer resource collection."""
        def mock_data(url):
            return {"results": [mock_computer], "totalCount": 1}

        token_response, mock_request = self._setup_mock_with_token(collector, mock_data)

        with patch("requests.post", return_value=token_response):
            with patch.object(collector.session, "request", side_effect=mock_request):
                resources = collector.collect_resources(resource_types=["jamf_computer"])

                assert len(resources) == 1
                resource = resources[0]
                assert resource.type == "jamf_computer"
                assert resource.id == "1"
                assert resource.name == "MacBook Pro"
                assert resource.provider == "jamf"
                assert resource.metadata["managed"] is True
                assert resource.metadata["filevault_enabled"] is True


# =============================================================================
# Pagination Tests
# =============================================================================


class TestPagination:
    """Test pagination handling."""

    def test_pagination_multiple_pages(self, collector, mock_computer):
        """Test pagination across multiple pages."""
        page1_computer = {**mock_computer, "id": 1}
        page2_computer = {**mock_computer, "id": 2}

        call_count = [0]

        def mock_data(url):
            call_count[0] += 1
            if call_count[0] == 1:
                return {"results": [page1_computer], "totalCount": 2}
            else:
                return {"results": [page2_computer], "totalCount": 2}

        token_response = MagicMock()
        token_response.raise_for_status = MagicMock()
        token_response.json.return_value = {"token": "test_token"}

        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = mock_data(url)
            return response

        with patch("requests.post", return_value=token_response):
            with patch.object(collector.session, "request", side_effect=mock_request):
                collector.config.page_size = 1
                result = collector.collect_evidence(evidence_types=["computers"])

                assert len(result.evidence_items) == 1
                evidence = result.evidence_items[0]
                assert evidence.raw_data["total_count"] == 2


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Test error handling."""

    def test_api_error_logged_but_continues(self, collector, mock_policy):
        """Test that API errors for one type don't stop other collections."""
        call_count = [0]

        def mock_data(url):
            if "computers-inventory" in url:
                raise requests.RequestException("API error")
            return {"results": [mock_policy], "totalCount": 1}

        token_response = MagicMock()
        token_response.raise_for_status = MagicMock()
        token_response.json.return_value = {"token": "test_token"}

        def mock_request(method, url, **kwargs):
            result = mock_data(url)
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = result
            return response

        with patch("requests.post", return_value=token_response):
            with patch.object(collector.session, "request", side_effect=mock_request):
                result = collector.collect_evidence(evidence_types=["computers", "policies"])

                # Should still have policies evidence
                evidence_types = [e.evidence_type for e in result.evidence_items]
                assert "policies" in evidence_types
                # Should have error for computers
                assert len(result.errors) > 0


# =============================================================================
# Compliance Control Mapping Tests
# =============================================================================


class TestComplianceControls:
    """Test compliance control mappings."""

    def test_computers_evidence_has_controls(self, collector, mock_computer):
        """Test computers evidence has compliance controls."""
        def mock_data(url):
            return {"results": [mock_computer], "totalCount": 1}

        token_response = MagicMock()
        token_response.raise_for_status = MagicMock()
        token_response.json.return_value = {"token": "test_token"}

        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = mock_data(url)
            return response

        with patch("requests.post", return_value=token_response):
            with patch.object(collector.session, "request", side_effect=mock_request):
                result = collector.collect_evidence(evidence_types=["computers"])

                evidence = result.evidence_items[0]
                controls = evidence.metadata["compliance_controls"]
                assert "soc2" in controls
                assert "nist_800_53" in controls
                assert "iso_27001" in controls
                assert "hitrust" in controls
                assert "CM-8" in controls["nist_800_53"]
                assert "A.8.1.1" in controls["iso_27001"]

    def test_all_evidence_types_have_mappings(self, collector):
        """Test all evidence types have compliance mappings."""
        for evidence_type in collector.SUPPORTED_EVIDENCE_TYPES:
            assert evidence_type in collector.EVIDENCE_CONTROL_MAPPINGS
            mappings = collector.EVIDENCE_CONTROL_MAPPINGS[evidence_type]
            assert "soc2" in mappings
            assert "nist_800_53" in mappings
            assert "iso_27001" in mappings
            assert "hitrust" in mappings


# =============================================================================
# CLI Tests
# =============================================================================


class TestJamfCLI:
    """Test CLI commands."""

    def test_collect_jamf_missing_url(self):
        """Test collect jamf fails without URL."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "jamf"])

        assert result.exit_code == 0
        assert "URL is required" in result.output

    def test_collect_jamf_missing_credentials(self):
        """Test collect jamf fails without credentials."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "jamf", "--url", "https://test.jamfcloud.com"])

        assert result.exit_code == 0
        assert "credentials required" in result.output

    def test_collect_jamf_help(self):
        """Test collect jamf help."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "jamf", "--help"])

        assert result.exit_code == 0
        assert "Jamf Pro" in result.output
        assert "--url" in result.output
        assert "--username" in result.output
        assert "--client-id" in result.output

    def test_collect_list_shows_jamf(self):
        """Test collect list shows jamf."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "list"])

        assert result.exit_code == 0
        assert "jamf" in result.output


# =============================================================================
# Compliance Calculation Tests
# =============================================================================


class TestComplianceCalculations:
    """Test compliance calculations."""

    def test_compliance_rate_calculation(self, collector):
        """Test compliance rate is calculated correctly."""
        computers = [
            {
                "id": 1,
                "general": {"managed": True, "operatingSystemVersion": "14.0"},
                "hardware": {},
                "diskEncryption": {"fileVault2Status": "Enabled"},
                "security": {},
                "userAndLocation": {},
            },
            {
                "id": 2,
                "general": {"managed": True, "operatingSystemVersion": "14.0"},
                "hardware": {},
                "diskEncryption": {"fileVault2Status": "Enabled"},
                "security": {},
                "userAndLocation": {},
            },
            {
                "id": 3,
                "general": {"managed": False, "operatingSystemVersion": "13.0"},
                "hardware": {},
                "diskEncryption": {"fileVault2Status": "Not Enabled"},
                "security": {},
                "userAndLocation": {},
            },
        ]

        def mock_data(url):
            return {"results": computers, "totalCount": 3}

        token_response = MagicMock()
        token_response.raise_for_status = MagicMock()
        token_response.json.return_value = {"token": "test_token"}

        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = mock_data(url)
            return response

        with patch("requests.post", return_value=token_response):
            with patch.object(collector.session, "request", side_effect=mock_request):
                result = collector.collect_evidence(evidence_types=["computers"])

                evidence = result.evidence_items[0]
                # 2 out of 3 computers are compliant (managed + encrypted)
                assert evidence.raw_data["compliance_rate"] == 66.7

    def test_os_version_distribution(self, collector):
        """Test OS version distribution is calculated correctly."""
        computers = [
            {"id": 1, "general": {"operatingSystemVersion": "14.0", "managed": True}, "hardware": {}, "diskEncryption": {}, "security": {}, "userAndLocation": {}},
            {"id": 2, "general": {"operatingSystemVersion": "14.0", "managed": True}, "hardware": {}, "diskEncryption": {}, "security": {}, "userAndLocation": {}},
            {"id": 3, "general": {"operatingSystemVersion": "13.0", "managed": True}, "hardware": {}, "diskEncryption": {}, "security": {}, "userAndLocation": {}},
        ]

        def mock_data(url):
            return {"results": computers, "totalCount": 3}

        token_response = MagicMock()
        token_response.raise_for_status = MagicMock()
        token_response.json.return_value = {"token": "test_token"}

        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = mock_data(url)
            return response

        with patch("requests.post", return_value=token_response):
            with patch.object(collector.session, "request", side_effect=mock_request):
                result = collector.collect_evidence(evidence_types=["computers"])

                evidence = result.evidence_items[0]
                assert evidence.raw_data["os_versions"]["14.0"] == 2
                assert evidence.raw_data["os_versions"]["13.0"] == 1
