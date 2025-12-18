"""
Unit tests for Microsoft 365 collector.
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta

from attestful.collectors.platforms.microsoft365 import (
    Microsoft365Collector,
    Microsoft365CollectorConfig,
    EVIDENCE_CONTROL_MAPPINGS,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_config():
    """Create a mock Microsoft 365 configuration."""
    return Microsoft365CollectorConfig(
        tenant_id="test-tenant-id",
        client_id="test-client-id",
        client_secret="test-client-secret",
        timeout=30,
        max_retries=3,
        page_size=100,
        days_of_history=30,
    )


@pytest.fixture
def mock_user():
    """Create a mock user response."""
    return {
        "id": "user-123",
        "displayName": "Admin User",
        "userPrincipalName": "admin@example.com",
        "mail": "admin@example.com",
        "accountEnabled": True,
        "createdDateTime": "2024-01-01T10:00:00Z",
        "userType": "Member",
        "assignedLicenses": [{"skuId": "license-1"}],
    }


@pytest.fixture
def mock_guest_user():
    """Create a mock guest user."""
    return {
        "id": "guest-123",
        "displayName": "External User",
        "userPrincipalName": "external_example.com#EXT#@example.onmicrosoft.com",
        "mail": "external@example.com",
        "accountEnabled": True,
        "createdDateTime": "2024-02-01T10:00:00Z",
        "userType": "Guest",
        "assignedLicenses": [],
    }


@pytest.fixture
def mock_group():
    """Create a mock group response."""
    return {
        "id": "group-123",
        "displayName": "Security Team",
        "description": "Security team members",
        "groupTypes": [],
        "securityEnabled": True,
        "mailEnabled": False,
        "mail": None,
        "createdDateTime": "2024-01-01T08:00:00Z",
    }


@pytest.fixture
def mock_m365_group():
    """Create a mock Microsoft 365 group."""
    return {
        "id": "m365-group-123",
        "displayName": "Project Alpha",
        "description": "Project Alpha team",
        "groupTypes": ["Unified"],
        "securityEnabled": False,
        "mailEnabled": True,
        "mail": "project-alpha@example.com",
        "createdDateTime": "2024-01-15T10:00:00Z",
    }


@pytest.fixture
def mock_device():
    """Create a mock managed device."""
    return {
        "id": "device-123",
        "deviceName": "LAPTOP-001",
        "managedDeviceOwnerType": "company",
        "operatingSystem": "Windows",
        "osVersion": "10.0.19044.1234",
        "complianceState": "compliant",
        "lastSyncDateTime": "2024-03-15T12:00:00Z",
        "enrolledDateTime": "2024-01-01T10:00:00Z",
        "manufacturer": "Dell",
        "model": "Latitude 5520",
    }


@pytest.fixture
def mock_sign_in():
    """Create a mock sign-in event."""
    return {
        "id": "signin-123",
        "createdDateTime": "2024-03-15T14:30:00Z",
        "userPrincipalName": "admin@example.com",
        "appDisplayName": "Microsoft Teams",
        "ipAddress": "192.168.1.100",
        "clientAppUsed": "Browser",
        "status": {
            "errorCode": 0,
            "failureReason": None,
        },
        "riskState": "none",
        "riskLevelAggregated": "none",
    }


@pytest.fixture
def mock_failed_sign_in():
    """Create a mock failed sign-in event."""
    return {
        "id": "signin-456",
        "createdDateTime": "2024-03-15T15:00:00Z",
        "userPrincipalName": "user@example.com",
        "appDisplayName": "Microsoft Office 365",
        "ipAddress": "10.0.0.50",
        "clientAppUsed": "Browser",
        "status": {
            "errorCode": 50126,
            "failureReason": "Invalid username or password",
        },
        "riskState": "none",
        "riskLevelAggregated": "none",
    }


@pytest.fixture
def mock_risky_user():
    """Create a mock risky user."""
    return {
        "id": "risky-123",
        "userPrincipalName": "risky@example.com",
        "riskState": "atRisk",
        "riskLevel": "high",
        "riskDetail": "unfamiliarFeatures",
        "riskLastUpdatedDateTime": "2024-03-15T10:00:00Z",
    }


@pytest.fixture
def mock_conditional_access_policy():
    """Create a mock conditional access policy."""
    return {
        "id": "policy-123",
        "displayName": "Require MFA for admins",
        "state": "enabled",
        "createdDateTime": "2024-01-01T08:00:00Z",
        "modifiedDateTime": "2024-02-15T10:00:00Z",
        "conditions": {
            "userRiskLevels": [],
            "signInRiskLevels": [],
            "platforms": {},
            "locations": {},
            "clientAppTypes": ["all"],
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": ["mfa"],
        },
        "sessionControls": {},
    }


@pytest.fixture
def mock_directory_role():
    """Create a mock directory role."""
    return {
        "id": "role-123",
        "displayName": "Global Administrator",
        "description": "Can manage all aspects of Azure AD and Microsoft services",
        "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10",
    }


@pytest.fixture
def mock_application():
    """Create a mock application."""
    return {
        "id": "app-123",
        "displayName": "Custom App",
        "appId": "app-id-123",
        "createdDateTime": "2024-01-01T10:00:00Z",
        "signInAudience": "AzureADMyOrg",
        "requiredResourceAccess": [],
    }


# =============================================================================
# Configuration Tests
# =============================================================================


class TestMicrosoft365CollectorConfig:
    """Tests for Microsoft 365 collector configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        config = Microsoft365CollectorConfig()
        assert config.tenant_id == ""
        assert config.client_id == ""
        assert config.client_secret == ""
        assert config.timeout == 30
        assert config.max_retries == 3
        assert config.page_size == 100
        assert config.days_of_history == 30

    def test_custom_config(self, mock_config):
        """Test custom configuration values."""
        assert mock_config.tenant_id == "test-tenant-id"
        assert mock_config.client_id == "test-client-id"
        assert mock_config.client_secret == "test-client-secret"


# =============================================================================
# Collector Initialization Tests
# =============================================================================


class TestMicrosoft365CollectorInit:
    """Tests for Microsoft 365 collector initialization."""

    def test_init_with_config(self, mock_config):
        """Test initialization with config."""
        collector = Microsoft365Collector(config=mock_config)
        assert collector.config == mock_config
        assert collector.PLATFORM == "microsoft365"

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = Microsoft365Collector()
        assert collector.config is not None
        assert collector.config.tenant_id == ""

    def test_base_url(self, mock_config):
        """Test base URL."""
        collector = Microsoft365Collector(config=mock_config)
        assert collector.base_url == "https://graph.microsoft.com/v1.0"

    def test_beta_url(self, mock_config):
        """Test beta URL."""
        collector = Microsoft365Collector(config=mock_config)
        assert collector.beta_url == "https://graph.microsoft.com/beta"

    def test_supported_resource_types(self, mock_config):
        """Test supported resource types."""
        collector = Microsoft365Collector(config=mock_config)
        assert "m365_user" in collector.SUPPORTED_RESOURCE_TYPES
        assert "m365_group" in collector.SUPPORTED_RESOURCE_TYPES
        assert "m365_device" in collector.SUPPORTED_RESOURCE_TYPES
        assert "m365_application" in collector.SUPPORTED_RESOURCE_TYPES

    def test_supported_evidence_types(self, mock_config):
        """Test supported evidence types."""
        collector = Microsoft365Collector(config=mock_config)
        assert "users" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "groups" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "devices" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "sign_ins" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "security_alerts" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "conditional_access" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "directory_roles" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "applications" in collector.SUPPORTED_EVIDENCE_TYPES


# =============================================================================
# Metadata Tests
# =============================================================================


class TestMetadata:
    """Tests for collector metadata."""

    def test_get_metadata(self, mock_config):
        """Test getting collector metadata."""
        collector = Microsoft365Collector(config=mock_config)
        metadata = collector.get_metadata()

        assert metadata.name == "Microsoft 365 Collector"
        assert metadata.platform == "microsoft365"
        assert "m365_user" in metadata.resource_types
        assert "users" in metadata.evidence_types
        assert metadata.version == "1.0.0"


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestCredentialValidation:
    """Tests for credential validation."""

    @patch("attestful.collectors.platforms.microsoft365.requests.post")
    @patch("attestful.collectors.platforms.microsoft365.Microsoft365Collector._request")
    def test_validate_credentials_success(self, mock_request, mock_post, mock_config):
        """Test successful credential validation."""
        # Mock token response
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"access_token": "test-token", "expires_in": 3600},
        )
        mock_post.return_value.raise_for_status = MagicMock()

        # Mock organization response
        mock_request.return_value = MagicMock(
            json=lambda: {"value": [{"displayName": "Test Org"}]},
        )

        collector = Microsoft365Collector(config=mock_config)
        result = collector.validate_credentials()

        assert result is True

    @patch("attestful.collectors.platforms.microsoft365.requests.post")
    def test_validate_credentials_failure(self, mock_post, mock_config):
        """Test failed credential validation."""
        mock_post.side_effect = Exception("Authentication failed")

        collector = Microsoft365Collector(config=mock_config)
        result = collector.validate_credentials()

        assert result is False


# =============================================================================
# Token Management Tests
# =============================================================================


class TestTokenManagement:
    """Tests for OAuth token management."""

    @patch("attestful.collectors.platforms.microsoft365.requests.post")
    def test_get_access_token(self, mock_post, mock_config):
        """Test getting access token."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"access_token": "new-token", "expires_in": 3600},
        )
        mock_post.return_value.raise_for_status = MagicMock()

        collector = Microsoft365Collector(config=mock_config)
        token = collector._get_access_token()

        assert token == "new-token"
        assert collector._access_token == "new-token"
        assert collector._token_expires_at is not None

    @patch("attestful.collectors.platforms.microsoft365.requests.post")
    def test_token_caching(self, mock_post, mock_config):
        """Test that tokens are cached."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"access_token": "cached-token", "expires_in": 3600},
        )
        mock_post.return_value.raise_for_status = MagicMock()

        collector = Microsoft365Collector(config=mock_config)

        # First call should get token
        token1 = collector._get_access_token()
        # Second call should use cached token
        token2 = collector._get_access_token()

        assert token1 == token2
        assert mock_post.call_count == 1


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestResourceCollection:
    """Tests for resource collection."""

    @patch("attestful.collectors.platforms.microsoft365.Microsoft365Collector._paginate")
    def test_collect_users(self, mock_paginate, mock_config, mock_user):
        """Test collecting user resources."""
        mock_paginate.return_value = iter([mock_user])

        collector = Microsoft365Collector(config=mock_config)
        resources = collector.collect_resources(resource_types=["m365_user"])

        assert len(resources) == 1
        assert resources[0].type == "m365_user"
        assert resources[0].name == "admin@example.com"
        assert resources[0].tags["account_enabled"] == "True"

    @patch("attestful.collectors.platforms.microsoft365.Microsoft365Collector._paginate")
    def test_collect_groups(self, mock_paginate, mock_config, mock_group):
        """Test collecting group resources."""
        mock_paginate.return_value = iter([mock_group])

        collector = Microsoft365Collector(config=mock_config)
        resources = collector.collect_resources(resource_types=["m365_group"])

        assert len(resources) == 1
        assert resources[0].type == "m365_group"
        assert resources[0].name == "Security Team"
        assert resources[0].tags["security_enabled"] == "True"

    @patch("attestful.collectors.platforms.microsoft365.Microsoft365Collector._paginate")
    def test_collect_devices(self, mock_paginate, mock_config, mock_device):
        """Test collecting device resources."""
        mock_paginate.return_value = iter([mock_device])

        collector = Microsoft365Collector(config=mock_config)
        resources = collector.collect_resources(resource_types=["m365_device"])

        assert len(resources) == 1
        assert resources[0].type == "m365_device"
        assert resources[0].name == "LAPTOP-001"
        assert resources[0].tags["compliance_state"] == "compliant"

    @patch("attestful.collectors.platforms.microsoft365.Microsoft365Collector._paginate")
    def test_collect_applications(self, mock_paginate, mock_config, mock_application):
        """Test collecting application resources."""
        mock_paginate.return_value = iter([mock_application])

        collector = Microsoft365Collector(config=mock_config)
        resources = collector.collect_resources(resource_types=["m365_application"])

        assert len(resources) == 1
        assert resources[0].type == "m365_application"
        assert resources[0].name == "Custom App"


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestEvidenceCollection:
    """Tests for evidence collection."""

    @patch("attestful.collectors.platforms.microsoft365.Microsoft365Collector._request")
    @patch("attestful.collectors.platforms.microsoft365.Microsoft365Collector._paginate")
    def test_collect_users_evidence(self, mock_paginate, mock_request, mock_config, mock_user, mock_guest_user):
        """Test collecting users evidence."""
        mock_paginate.return_value = iter([mock_user, mock_guest_user])
        mock_request.return_value = MagicMock(json=lambda: {"value": []})

        collector = Microsoft365Collector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["users"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "users"
        assert evidence.raw_data["total_count"] == 2
        assert evidence.raw_data["summary"]["guest_users"] == 1
        assert evidence.raw_data["summary"]["licensed_users"] == 1

    @patch("attestful.collectors.platforms.microsoft365.Microsoft365Collector._request")
    @patch("attestful.collectors.platforms.microsoft365.Microsoft365Collector._paginate")
    def test_collect_groups_evidence(self, mock_paginate, mock_request, mock_config, mock_group, mock_m365_group):
        """Test collecting groups evidence."""
        mock_paginate.return_value = iter([mock_group, mock_m365_group])
        mock_request.return_value = MagicMock(text="5")

        collector = Microsoft365Collector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["groups"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "groups"
        assert evidence.raw_data["total_count"] == 2
        assert evidence.raw_data["summary"]["security_groups"] == 1
        assert evidence.raw_data["summary"]["m365_groups"] == 1

    @patch("attestful.collectors.platforms.microsoft365.Microsoft365Collector._paginate")
    def test_collect_devices_evidence(self, mock_paginate, mock_config, mock_device):
        """Test collecting devices evidence."""
        noncompliant_device = mock_device.copy()
        noncompliant_device["id"] = "device-456"
        noncompliant_device["complianceState"] = "noncompliant"

        mock_paginate.return_value = iter([mock_device, noncompliant_device])

        collector = Microsoft365Collector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["devices"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "devices"
        assert evidence.raw_data["total_count"] == 2
        assert evidence.raw_data["summary"]["compliant_devices"] == 1
        assert evidence.raw_data["summary"]["noncompliant_devices"] == 1
        assert evidence.raw_data["summary"]["compliance_rate_percent"] == 50.0

    @patch("attestful.collectors.platforms.microsoft365.Microsoft365Collector._paginate")
    def test_collect_sign_ins_evidence(self, mock_paginate, mock_config, mock_sign_in, mock_failed_sign_in):
        """Test collecting sign-ins evidence."""
        mock_paginate.return_value = iter([mock_sign_in, mock_failed_sign_in])

        collector = Microsoft365Collector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["sign_ins"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "sign_ins"
        assert evidence.raw_data["total_count"] == 2
        assert evidence.raw_data["summary"]["successful"] == 1
        assert evidence.raw_data["summary"]["failed"] == 1
        assert evidence.raw_data["summary"]["success_rate_percent"] == 50.0

    @patch("attestful.collectors.platforms.microsoft365.Microsoft365Collector._paginate")
    def test_collect_security_alerts_evidence(self, mock_paginate, mock_config, mock_risky_user):
        """Test collecting security alerts evidence."""
        mock_paginate.side_effect = [
            iter([mock_risky_user]),  # risky users
            iter([]),  # risk detections
        ]

        collector = Microsoft365Collector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["security_alerts"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "security_alerts"
        assert evidence.raw_data["summary"]["total_risky_users"] == 1
        assert evidence.raw_data["summary"]["high_severity"] == 1

    @patch("attestful.collectors.platforms.microsoft365.Microsoft365Collector._paginate")
    def test_collect_conditional_access_evidence(self, mock_paginate, mock_config, mock_conditional_access_policy):
        """Test collecting conditional access evidence."""
        mock_paginate.side_effect = [
            iter([mock_conditional_access_policy]),  # policies
            iter([]),  # named locations
        ]

        collector = Microsoft365Collector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["conditional_access"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "conditional_access"
        assert evidence.raw_data["total_count"] == 1
        assert evidence.raw_data["summary"]["enabled_policies"] == 1

    @patch("attestful.collectors.platforms.microsoft365.Microsoft365Collector._paginate")
    def test_collect_directory_roles_evidence(self, mock_paginate, mock_config, mock_directory_role, mock_user):
        """Test collecting directory roles evidence."""
        mock_paginate.side_effect = [
            iter([mock_directory_role]),  # roles
            iter([mock_user]),  # role members
        ]

        collector = Microsoft365Collector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["directory_roles"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "directory_roles"
        assert evidence.raw_data["total_count"] == 1
        assert evidence.raw_data["summary"]["global_admins"] == 1

    @patch("attestful.collectors.platforms.microsoft365.Microsoft365Collector._paginate")
    def test_collect_applications_evidence(self, mock_paginate, mock_config, mock_application):
        """Test collecting applications evidence."""
        mock_paginate.side_effect = [
            iter([]),  # service principals
            iter([mock_application]),  # app registrations
        ]

        collector = Microsoft365Collector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["applications"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "applications"
        assert evidence.raw_data["summary"]["app_registrations"] == 1


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    @patch("attestful.collectors.platforms.microsoft365.Microsoft365Collector._paginate")
    def test_resource_collection_error(self, mock_paginate, mock_config):
        """Test handling errors during resource collection."""
        mock_paginate.side_effect = Exception("API error")

        collector = Microsoft365Collector(config=mock_config)
        resources = collector.collect_resources(resource_types=["m365_user"])

        # Should return empty list, not raise
        assert resources == []

    @patch("attestful.collectors.platforms.microsoft365.Microsoft365Collector._paginate")
    def test_evidence_collection_error(self, mock_paginate, mock_config):
        """Test handling errors during evidence collection.

        Microsoft 365 collector handles API errors gracefully - individual evidence
        methods catch exceptions and return empty data rather than failing
        completely. This ensures partial collection still works.
        """
        mock_paginate.side_effect = Exception("API error")

        collector = Microsoft365Collector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["users"])

        # Should still return evidence (with empty data), not fail
        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "users"
        # Data should be empty due to error
        assert result.evidence_items[0].raw_data["total_count"] == 0

    def test_unknown_resource_type(self, mock_config):
        """Test handling unknown resource types."""
        collector = Microsoft365Collector(config=mock_config)
        resources = collector.collect_resources(resource_types=["unknown_type"])
        assert resources == []

    def test_unknown_evidence_type(self, mock_config):
        """Test handling unknown evidence types."""
        collector = Microsoft365Collector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["unknown_type"])
        assert len(result.evidence_items) == 0


# =============================================================================
# Compliance Metadata Tests
# =============================================================================


class TestComplianceMetadata:
    """Tests for compliance-related metadata in evidence."""

    def test_evidence_control_mappings(self):
        """Test evidence control mappings are defined."""
        assert "users" in EVIDENCE_CONTROL_MAPPINGS
        assert "groups" in EVIDENCE_CONTROL_MAPPINGS
        assert "devices" in EVIDENCE_CONTROL_MAPPINGS
        assert "sign_ins" in EVIDENCE_CONTROL_MAPPINGS
        assert "security_alerts" in EVIDENCE_CONTROL_MAPPINGS
        assert "conditional_access" in EVIDENCE_CONTROL_MAPPINGS
        assert "directory_roles" in EVIDENCE_CONTROL_MAPPINGS
        assert "applications" in EVIDENCE_CONTROL_MAPPINGS

    def test_users_compliance_controls(self):
        """Test compliance controls for users evidence."""
        controls = EVIDENCE_CONTROL_MAPPINGS["users"]
        assert "SOC2:CC6.1" in controls
        assert "NIST:AC-2" in controls
        assert "ISO27001:A.9.2" in controls
        assert "HITRUST:01.b" in controls

    def test_sign_ins_compliance_controls(self):
        """Test compliance controls for sign-ins evidence."""
        controls = EVIDENCE_CONTROL_MAPPINGS["sign_ins"]
        assert "SOC2:CC7.2" in controls
        assert "NIST:AU-2" in controls
        assert "ISO27001:A.12.4" in controls
        assert "HITRUST:09.ab" in controls

    @patch("attestful.collectors.platforms.microsoft365.Microsoft365Collector._request")
    @patch("attestful.collectors.platforms.microsoft365.Microsoft365Collector._paginate")
    def test_evidence_contains_compliance_controls(self, mock_paginate, mock_request, mock_config, mock_user):
        """Test that evidence contains compliance controls."""
        mock_paginate.return_value = iter([mock_user])
        mock_request.return_value = MagicMock(json=lambda: {"value": []})

        collector = Microsoft365Collector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["users"])

        evidence = result.evidence_items[0]
        assert "compliance_controls" in evidence.metadata
        assert "SOC2:CC6.1" in evidence.metadata["compliance_controls"]


# =============================================================================
# CLI Tests
# =============================================================================


class TestMicrosoft365CLI:
    """Tests for Microsoft 365 CLI commands."""

    def test_microsoft365_help(self):
        """Test microsoft365 collect help."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "microsoft365", "--help"])
        assert result.exit_code == 0
        assert "Collect evidence from Microsoft 365" in result.output
        assert "--tenant-id" in result.output
        assert "--client-id" in result.output
        assert "--client-secret" in result.output

    def test_microsoft365_evidence_types_in_help(self):
        """Test evidence types are documented in help."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "microsoft365", "--help"])
        assert result.exit_code == 0
        assert "users" in result.output
        assert "groups" in result.output
        assert "devices" in result.output
        assert "sign_ins" in result.output
        assert "security_alerts" in result.output
        assert "conditional_access" in result.output
        assert "directory_roles" in result.output
        assert "applications" in result.output

    def test_microsoft365_missing_tenant_id(self):
        """Test error when tenant ID is missing."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "microsoft365"])
        assert result.exit_code == 0
        assert "Error" in result.output
        assert "tenant" in result.output.lower()

    def test_microsoft365_missing_client_id(self):
        """Test error when client ID is missing."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "microsoft365", "--tenant-id", "test"])
        assert result.exit_code == 0
        assert "Error" in result.output
        assert "client" in result.output.lower()

    def test_microsoft365_missing_client_secret(self):
        """Test error when client secret is missing."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["collect", "microsoft365", "--tenant-id", "test", "--client-id", "test"],
        )
        assert result.exit_code == 0
        assert "Error" in result.output
        assert "secret" in result.output.lower()

    def test_collect_list_shows_microsoft365(self):
        """Test collect list shows microsoft365 as available."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "list"])
        assert result.exit_code == 0
        assert "microsoft365" in result.output
        assert "Available" in result.output


# =============================================================================
# Import Tests
# =============================================================================


class TestImports:
    """Tests for module imports."""

    def test_import_from_platforms(self):
        """Test importing from platforms package."""
        from attestful.collectors.platforms import (
            Microsoft365Collector,
            Microsoft365CollectorConfig,
        )

        assert Microsoft365Collector is not None
        assert Microsoft365CollectorConfig is not None
