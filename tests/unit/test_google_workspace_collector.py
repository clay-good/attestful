"""Tests for Google Workspace collector."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from attestful.collectors.platforms.google_workspace import (
    GoogleWorkspaceCollector,
    GoogleWorkspaceCollectorConfig,
)
from attestful.core.exceptions import CollectionError, ConfigurationError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def config():
    """Create a test configuration."""
    return GoogleWorkspaceCollectorConfig(
        credentials_file="/path/to/credentials.json",
        delegated_user="admin@example.com",
        customer_id="C12345",
        domain="example.com",
    )


@pytest.fixture
def collector(config):
    """Create a collector instance."""
    return GoogleWorkspaceCollector(config=config)


@pytest.fixture
def mock_user():
    """Create a mock user response."""
    return {
        "id": "user-123",
        "primaryEmail": "john.doe@example.com",
        "name": {"fullName": "John Doe", "givenName": "John", "familyName": "Doe"},
        "suspended": False,
        "isAdmin": False,
        "isDelegatedAdmin": False,
        "isEnforcedIn2Sv": True,
        "isEnrolledIn2Sv": True,
        "creationTime": "2024-01-01T00:00:00Z",
        "lastLoginTime": "2024-12-01T10:00:00Z",
        "orgUnitPath": "/Engineering",
        "recoveryEmail": "john.personal@gmail.com",
        "recoveryPhone": "+1234567890",
    }


@pytest.fixture
def mock_admin_user():
    """Create a mock admin user response."""
    return {
        "id": "admin-123",
        "primaryEmail": "admin@example.com",
        "name": {"fullName": "Admin User"},
        "suspended": False,
        "isAdmin": True,
        "isDelegatedAdmin": False,
        "isEnforcedIn2Sv": True,
        "isEnrolledIn2Sv": True,
        "creationTime": "2023-01-01T00:00:00Z",
        "lastLoginTime": "2024-12-01T10:00:00Z",
        "orgUnitPath": "/",
    }


@pytest.fixture
def mock_suspended_user():
    """Create a mock suspended user response."""
    return {
        "id": "suspended-123",
        "primaryEmail": "former@example.com",
        "name": {"fullName": "Former Employee"},
        "suspended": True,
        "isAdmin": False,
        "isEnrolledIn2Sv": False,
        "orgUnitPath": "/Former",
    }


@pytest.fixture
def mock_group():
    """Create a mock group response."""
    return {
        "id": "group-123",
        "email": "engineering@example.com",
        "name": "Engineering Team",
        "description": "Engineering department group",
        "directMembersCount": "25",
        "adminCreated": True,
    }


@pytest.fixture
def mock_chrome_device():
    """Create a mock Chrome OS device response."""
    return {
        "deviceId": "device-123",
        "serialNumber": "ABC123",
        "model": "Chromebook 14",
        "osVersion": "120.0.6099.0",
        "status": "ACTIVE",
        "lastSync": "2024-12-01T10:00:00Z",
        "orgUnitPath": "/Devices",
        "annotatedUser": "john.doe@example.com",
    }


@pytest.fixture
def mock_mobile_device():
    """Create a mock mobile device response."""
    return {
        "deviceId": "mobile-123",
        "serialNumber": "XYZ789",
        "model": "iPhone 15",
        "os": "iOS 17.0",
        "type": "IOS",
        "status": "APPROVED",
        "lastSync": "2024-12-01T10:00:00Z",
        "email": ["john.doe@example.com"],
    }


@pytest.fixture
def mock_login_activity():
    """Create a mock login activity response."""
    return {
        "id": {"uniqueQualifier": "activity-123", "time": "2024-12-01T10:00:00Z"},
        "actor": {"email": "john.doe@example.com"},
        "ipAddress": "192.168.1.1",
        "events": [{"name": "login_success", "type": "LOGIN"}],
    }


@pytest.fixture
def mock_org_unit():
    """Create a mock org unit response."""
    return {
        "orgUnitId": "ou-123",
        "name": "Engineering",
        "orgUnitPath": "/Engineering",
        "parentOrgUnitPath": "/",
        "description": "Engineering department",
        "blockInheritance": False,
    }


@pytest.fixture
def mock_token():
    """Create a mock OAuth token response."""
    return {
        "clientId": "client-123",
        "displayText": "Third Party App",
        "scopes": ["https://www.googleapis.com/auth/drive.readonly"],
        "nativeApp": False,
    }


@pytest.fixture
def mock_alert():
    """Create a mock security alert response."""
    return {
        "alertId": "alert-123",
        "type": "Suspicious login",
        "source": "Security Center",
        "createTime": "2024-12-01T10:00:00Z",
        "startTime": "2024-12-01T09:00:00Z",
        "endTime": "2024-12-01T11:00:00Z",
        "metadata": {"status": "NOT_STARTED", "severity": "HIGH"},
    }


# =============================================================================
# Initialization Tests
# =============================================================================


class TestGoogleWorkspaceCollectorInit:
    """Test collector initialization."""

    def test_init_with_config(self, config):
        """Test initialization with config."""
        collector = GoogleWorkspaceCollector(config=config)
        assert collector.config.credentials_file == "/path/to/credentials.json"
        assert collector.config.delegated_user == "admin@example.com"
        assert collector.config.customer_id == "C12345"

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = GoogleWorkspaceCollector()
        assert collector.config.credentials_file == ""
        assert collector.config.delegated_user == ""
        assert collector.config.customer_id == "my_customer"
        assert collector.config.timeout == 30
        assert collector.config.page_size == 100
        assert collector.config.days_of_history == 90

    def test_metadata(self, collector):
        """Test metadata property."""
        metadata = collector.metadata
        assert metadata.name == "Google Workspace Collector"
        assert metadata.platform == "google_workspace"
        assert "productivity" in metadata.description.lower()
        assert metadata.version == "1.0.0"
        assert len(metadata.resource_types) == 4
        assert len(metadata.evidence_types) == 7

    def test_platform(self, collector):
        """Test platform constant."""
        assert collector.PLATFORM == "google_workspace"


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestValidateCredentials:
    """Test credential validation."""

    def test_validate_credentials_no_creds_file(self):
        """Test validation fails without credentials file."""
        collector = GoogleWorkspaceCollector(config=GoogleWorkspaceCollectorConfig())
        with pytest.raises(ConfigurationError, match="credentials_file is required"):
            collector.validate_credentials()

    def test_validate_credentials_no_delegated_user(self):
        """Test validation fails without delegated user."""
        config = GoogleWorkspaceCollectorConfig(credentials_file="/path/to/creds.json")
        collector = GoogleWorkspaceCollector(config=config)
        with pytest.raises(ConfigurationError, match="delegated_user.*is required"):
            collector.validate_credentials()

    def test_validate_credentials_success(self, collector):
        """Test successful credential validation."""
        mock_service = MagicMock()
        mock_service.users().list().execute.return_value = {"users": []}

        with patch.object(collector, "_get_admin_service", return_value=mock_service):
            assert collector.validate_credentials() is True

    def test_validate_credentials_invalid(self, collector):
        """Test validation fails with invalid credentials."""
        mock_service = MagicMock()
        mock_service.users().list().execute.side_effect = Exception("401 unauthorized")

        with patch.object(collector, "_get_admin_service", return_value=mock_service):
            with pytest.raises(ConfigurationError, match="Invalid Google Workspace credentials"):
                collector.validate_credentials()


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestCollectEvidence:
    """Test evidence collection."""

    def test_collect_all_evidence_types(self, collector, mock_user, mock_group, mock_chrome_device, mock_mobile_device, mock_login_activity, mock_org_unit, mock_token, mock_alert):
        """Test collecting all evidence types."""
        mock_admin_service = MagicMock()
        mock_reports_service = MagicMock()
        mock_alerts_service = MagicMock()

        # Setup users mock
        mock_admin_service.users().list().execute.return_value = {"users": [mock_user]}
        # Setup groups mock
        mock_admin_service.groups().list().execute.return_value = {"groups": [mock_group]}
        mock_admin_service.members().list().execute.return_value = {"members": []}
        # Setup devices mocks
        mock_admin_service.chromeosdevices().list().execute.return_value = {"chromeosdevices": [mock_chrome_device]}
        mock_admin_service.mobiledevices().list().execute.return_value = {"mobiledevices": [mock_mobile_device]}
        # Setup org units mock
        mock_admin_service.orgunits().list().execute.return_value = {"organizationUnits": [mock_org_unit]}
        # Setup tokens mock
        mock_admin_service.tokens().list().execute.return_value = {"items": [mock_token]}
        # Setup login activity mock
        mock_reports_service.activities().list().execute.return_value = {"items": [mock_login_activity]}
        # Setup alerts mock
        mock_alerts_service.alerts().list().execute.return_value = {"alerts": [mock_alert]}

        with patch.object(collector, "_get_admin_service", return_value=mock_admin_service):
            with patch.object(collector, "_get_reports_service", return_value=mock_reports_service):
                with patch.object(collector, "_get_alerts_service", return_value=mock_alerts_service):
                    result = collector.collect_evidence()

                    assert result.success
                    assert len(result.evidence_items) == 7
                    evidence_types = [e.evidence_type for e in result.evidence_items]
                    assert "users" in evidence_types
                    assert "groups" in evidence_types
                    assert "devices" in evidence_types
                    assert "login_activity" in evidence_types
                    assert "org_units" in evidence_types
                    assert "tokens" in evidence_types
                    assert "security_alerts" in evidence_types

    def test_collect_specific_evidence_types(self, collector, mock_user):
        """Test collecting specific evidence types."""
        mock_admin_service = MagicMock()
        mock_admin_service.users().list().execute.return_value = {"users": [mock_user]}

        with patch.object(collector, "_get_admin_service", return_value=mock_admin_service):
            result = collector.collect_evidence(evidence_types=["users"])

            assert len(result.evidence_items) == 1
            assert result.evidence_items[0].evidence_type == "users"

    def test_collect_evidence_invalid_type(self, collector):
        """Test collecting invalid evidence type."""
        with pytest.raises(CollectionError, match="Unsupported evidence types"):
            collector.collect_evidence(evidence_types=["invalid_type"])

    def test_collect_users_evidence(self, collector, mock_user, mock_admin_user, mock_suspended_user):
        """Test users evidence collection."""
        mock_admin_service = MagicMock()
        mock_admin_service.users().list().execute.return_value = {
            "users": [mock_user, mock_admin_user, mock_suspended_user]
        }

        with patch.object(collector, "_get_admin_service", return_value=mock_admin_service):
            result = collector.collect_evidence(evidence_types=["users"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "users"
            assert evidence.raw_data["total_count"] == 3
            assert evidence.raw_data["active_count"] == 2
            assert evidence.raw_data["suspended_count"] == 1
            assert evidence.raw_data["admin_count"] == 1
            assert evidence.raw_data["mfa_enabled_count"] == 2
            assert evidence.raw_data["mfa_rate"] == 66.7

    def test_collect_groups_evidence(self, collector, mock_group):
        """Test groups evidence collection."""
        mock_admin_service = MagicMock()
        mock_admin_service.groups().list().execute.return_value = {"groups": [mock_group]}
        mock_admin_service.members().list().execute.return_value = {"members": []}

        with patch.object(collector, "_get_admin_service", return_value=mock_admin_service):
            result = collector.collect_evidence(evidence_types=["groups"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "groups"
            assert evidence.raw_data["total_count"] == 1
            assert evidence.raw_data["admin_created_count"] == 1

    def test_collect_devices_evidence(self, collector, mock_chrome_device, mock_mobile_device):
        """Test devices evidence collection."""
        mock_admin_service = MagicMock()
        mock_admin_service.chromeosdevices().list().execute.return_value = {"chromeosdevices": [mock_chrome_device]}
        mock_admin_service.mobiledevices().list().execute.return_value = {"mobiledevices": [mock_mobile_device]}

        with patch.object(collector, "_get_admin_service", return_value=mock_admin_service):
            result = collector.collect_evidence(evidence_types=["devices"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "devices"
            assert evidence.raw_data["chrome_device_count"] == 1
            assert evidence.raw_data["mobile_device_count"] == 1
            assert evidence.raw_data["total_count"] == 2

    def test_collect_login_activity_evidence(self, collector, mock_login_activity):
        """Test login activity evidence collection."""
        mock_reports_service = MagicMock()
        mock_reports_service.activities().list().execute.return_value = {"items": [mock_login_activity]}

        with patch.object(collector, "_get_reports_service", return_value=mock_reports_service):
            result = collector.collect_evidence(evidence_types=["login_activity"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "login_activity"
            assert evidence.raw_data["total_count"] == 1
            assert evidence.raw_data["success_count"] == 1

    def test_collect_org_units_evidence(self, collector, mock_org_unit):
        """Test org units evidence collection."""
        mock_admin_service = MagicMock()
        mock_admin_service.orgunits().list().execute.return_value = {"organizationUnits": [mock_org_unit]}

        with patch.object(collector, "_get_admin_service", return_value=mock_admin_service):
            result = collector.collect_evidence(evidence_types=["org_units"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "org_units"
            assert evidence.raw_data["total_count"] == 1

    def test_collect_tokens_evidence(self, collector, mock_user, mock_token):
        """Test tokens evidence collection."""
        mock_admin_service = MagicMock()
        mock_admin_service.users().list().execute.return_value = {"users": [mock_user]}
        mock_admin_service.tokens().list().execute.return_value = {"items": [mock_token]}

        with patch.object(collector, "_get_admin_service", return_value=mock_admin_service):
            result = collector.collect_evidence(evidence_types=["tokens"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "tokens"
            assert evidence.raw_data["total_count"] == 1
            assert evidence.raw_data["unique_apps"] == 1

    def test_collect_security_alerts_evidence(self, collector, mock_alert):
        """Test security alerts evidence collection."""
        mock_alerts_service = MagicMock()
        mock_alerts_service.alerts().list().execute.return_value = {"alerts": [mock_alert]}

        with patch.object(collector, "_get_alerts_service", return_value=mock_alerts_service):
            result = collector.collect_evidence(evidence_types=["security_alerts"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "security_alerts"
            assert evidence.raw_data["total_count"] == 1


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestCollectResources:
    """Test resource collection."""

    def test_collect_all_resource_types(self, collector, mock_user, mock_group, mock_chrome_device, mock_org_unit):
        """Test collecting all resource types."""
        mock_admin_service = MagicMock()
        mock_admin_service.users().list().execute.return_value = {"users": [mock_user]}
        mock_admin_service.groups().list().execute.return_value = {"groups": [mock_group]}
        mock_admin_service.chromeosdevices().list().execute.return_value = {"chromeosdevices": [mock_chrome_device]}
        mock_admin_service.mobiledevices().list().execute.return_value = {"mobiledevices": []}
        mock_admin_service.orgunits().list().execute.return_value = {"organizationUnits": [mock_org_unit]}

        with patch.object(collector, "_get_admin_service", return_value=mock_admin_service):
            resources = collector.collect_resources()

            assert len(resources) == 4
            resource_types = [r.type for r in resources]
            assert "gws_user" in resource_types
            assert "gws_group" in resource_types
            assert "gws_device" in resource_types
            assert "gws_org_unit" in resource_types

    def test_collect_specific_resource_types(self, collector, mock_user):
        """Test collecting specific resource types."""
        mock_admin_service = MagicMock()
        mock_admin_service.users().list().execute.return_value = {"users": [mock_user]}

        with patch.object(collector, "_get_admin_service", return_value=mock_admin_service):
            resources = collector.collect_resources(resource_types=["gws_user"])

            assert len(resources) == 1
            assert resources[0].type == "gws_user"

    def test_collect_resources_invalid_type(self, collector):
        """Test collecting invalid resource type."""
        with pytest.raises(CollectionError, match="Unsupported resource types"):
            collector.collect_resources(resource_types=["invalid_type"])

    def test_collect_user_resources(self, collector, mock_user):
        """Test user resource collection."""
        mock_admin_service = MagicMock()
        mock_admin_service.users().list().execute.return_value = {"users": [mock_user]}

        with patch.object(collector, "_get_admin_service", return_value=mock_admin_service):
            resources = collector.collect_resources(resource_types=["gws_user"])

            assert len(resources) == 1
            resource = resources[0]
            assert resource.type == "gws_user"
            assert resource.id == "user-123"
            assert resource.name == "john.doe@example.com"
            assert resource.provider == "google_workspace"
            assert resource.metadata["is_enrolled_in_2sv"] is True


# =============================================================================
# Pagination Tests
# =============================================================================


class TestPagination:
    """Test pagination handling."""

    def test_pagination_multiple_pages(self, collector, mock_user):
        """Test pagination across multiple pages."""
        page1_user = {**mock_user, "id": "user-1"}
        page2_user = {**mock_user, "id": "user-2"}

        mock_admin_service = MagicMock()
        mock_admin_service.users().list().execute.side_effect = [
            {"users": [page1_user], "nextPageToken": "token123"},
            {"users": [page2_user]},
        ]

        with patch.object(collector, "_get_admin_service", return_value=mock_admin_service):
            result = collector.collect_evidence(evidence_types=["users"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.raw_data["total_count"] == 2


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Test error handling."""

    def test_api_error_logged_but_continues(self, collector, mock_group):
        """Test that API errors for one type don't stop other collections."""
        mock_admin_service = MagicMock()
        mock_admin_service.users().list().execute.side_effect = Exception("API error")
        mock_admin_service.groups().list().execute.return_value = {"groups": [mock_group]}
        mock_admin_service.members().list().execute.return_value = {"members": []}

        with patch.object(collector, "_get_admin_service", return_value=mock_admin_service):
            result = collector.collect_evidence(evidence_types=["users", "groups"])

            # Should still have groups evidence
            evidence_types = [e.evidence_type for e in result.evidence_items]
            assert "groups" in evidence_types
            # Should have error for users
            assert len(result.errors) > 0


# =============================================================================
# Compliance Control Mapping Tests
# =============================================================================


class TestComplianceControls:
    """Test compliance control mappings."""

    def test_users_evidence_has_controls(self, collector, mock_user):
        """Test users evidence has compliance controls."""
        mock_admin_service = MagicMock()
        mock_admin_service.users().list().execute.return_value = {"users": [mock_user]}

        with patch.object(collector, "_get_admin_service", return_value=mock_admin_service):
            result = collector.collect_evidence(evidence_types=["users"])

            evidence = result.evidence_items[0]
            controls = evidence.metadata["compliance_controls"]
            assert "soc2" in controls
            assert "nist_800_53" in controls
            assert "iso_27001" in controls
            assert "hitrust" in controls
            assert "AC-2" in controls["nist_800_53"]
            assert "A.9.2.1" in controls["iso_27001"]

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


class TestGoogleWorkspaceCLI:
    """Test CLI commands."""

    def test_collect_google_workspace_missing_creds(self):
        """Test collect google-workspace fails without credentials."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "google-workspace"])

        assert result.exit_code == 0
        assert "credentials file is required" in result.output

    def test_collect_google_workspace_missing_delegated_user(self):
        """Test collect google-workspace fails without delegated user."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "google-workspace", "--credentials-file", "/path/to/creds.json"])

        assert result.exit_code == 0
        assert "Delegated admin user" in result.output

    def test_collect_google_workspace_help(self):
        """Test collect google-workspace help."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "google-workspace", "--help"])

        assert result.exit_code == 0
        assert "Google Workspace" in result.output
        assert "--credentials-file" in result.output
        assert "--delegated-user" in result.output

    def test_collect_list_shows_google_workspace(self):
        """Test collect list shows google-workspace."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "list"])

        assert result.exit_code == 0
        assert "google-workspace" in result.output


# =============================================================================
# MFA Rate Calculation Tests
# =============================================================================


class TestMFACalculations:
    """Test MFA rate calculations."""

    def test_mfa_rate_calculation(self, collector):
        """Test MFA rate is calculated correctly."""
        users = [
            {"id": "1", "primaryEmail": "a@test.com", "name": {}, "suspended": False, "isAdmin": False, "isEnrolledIn2Sv": True, "orgUnitPath": "/"},
            {"id": "2", "primaryEmail": "b@test.com", "name": {}, "suspended": False, "isAdmin": False, "isEnrolledIn2Sv": True, "orgUnitPath": "/"},
            {"id": "3", "primaryEmail": "c@test.com", "name": {}, "suspended": False, "isAdmin": False, "isEnrolledIn2Sv": False, "orgUnitPath": "/"},
            {"id": "4", "primaryEmail": "d@test.com", "name": {}, "suspended": False, "isAdmin": False, "isEnrolledIn2Sv": False, "orgUnitPath": "/"},
        ]

        mock_admin_service = MagicMock()
        mock_admin_service.users().list().execute.return_value = {"users": users}

        with patch.object(collector, "_get_admin_service", return_value=mock_admin_service):
            result = collector.collect_evidence(evidence_types=["users"])

            evidence = result.evidence_items[0]
            # 2 out of 4 users have MFA
            assert evidence.raw_data["mfa_rate"] == 50.0
            assert evidence.raw_data["mfa_enabled_count"] == 2

    def test_org_unit_distribution(self, collector):
        """Test org unit distribution is calculated correctly."""
        users = [
            {"id": "1", "primaryEmail": "a@test.com", "name": {}, "suspended": False, "isAdmin": False, "orgUnitPath": "/Engineering"},
            {"id": "2", "primaryEmail": "b@test.com", "name": {}, "suspended": False, "isAdmin": False, "orgUnitPath": "/Engineering"},
            {"id": "3", "primaryEmail": "c@test.com", "name": {}, "suspended": False, "isAdmin": False, "orgUnitPath": "/Sales"},
        ]

        mock_admin_service = MagicMock()
        mock_admin_service.users().list().execute.return_value = {"users": users}

        with patch.object(collector, "_get_admin_service", return_value=mock_admin_service):
            result = collector.collect_evidence(evidence_types=["users"])

            evidence = result.evidence_items[0]
            assert evidence.raw_data["org_unit_distribution"]["/Engineering"] == 2
            assert evidence.raw_data["org_unit_distribution"]["/Sales"] == 1
