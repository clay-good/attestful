"""
Unit tests for Datadog collector.
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from attestful.collectors.platforms.datadog import (
    DatadogCollector,
    DatadogCollectorConfig,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_config():
    """Create a mock Datadog configuration."""
    return DatadogCollectorConfig(
        api_key="test-api-key",
        app_key="test-app-key",
        site="datadoghq.com",
        timeout=30,
        max_retries=3,
        page_size=100,
        days_of_history=30,
    )


@pytest.fixture
def mock_monitor():
    """Create a mock monitor response."""
    return {
        "id": 12345,
        "name": "High CPU Usage",
        "type": "metric alert",
        "query": "avg(last_5m):avg:system.cpu.user{*} > 90",
        "message": "CPU usage is too high",
        "overall_state": "OK",
        "priority": 2,
        "created": "2024-01-15T10:00:00Z",
        "modified": "2024-03-01T14:30:00Z",
        "multi": False,
        "restricted_roles": [],
        "tags": ["team:platform", "env:production"],
    }


@pytest.fixture
def mock_dashboard():
    """Create a mock dashboard response."""
    return {
        "id": "abc-123-def",
        "title": "Production Overview",
        "description": "Main production dashboard",
        "layout_type": "ordered",
        "is_read_only": False,
        "author_handle": "user@example.com",
        "created_at": "2024-02-01T08:00:00Z",
        "modified_at": "2024-03-15T16:45:00Z",
        "url": "/dashboard/abc-123-def/production-overview",
    }


@pytest.fixture
def mock_user():
    """Create a mock user response."""
    return {
        "id": "user-123",
        "type": "users",
        "attributes": {
            "email": "admin@example.com",
            "name": "Admin User",
            "status": "Active",
            "disabled": False,
            "verified": True,
            "service_account": False,
            "created_at": "2023-06-01T10:00:00Z",
            "modified_at": "2024-01-15T09:30:00Z",
            "mfa_enabled": True,
            "title": "Platform Engineer",
        },
        "relationships": {
            "roles": {
                "data": [
                    {"id": "role-admin", "type": "roles"}
                ]
            }
        },
    }


@pytest.fixture
def mock_slo():
    """Create a mock SLO response."""
    return {
        "id": "slo-123",
        "name": "API Availability",
        "description": "99.9% availability for API endpoints",
        "type": "metric",
        "target_threshold": 99.9,
        "timeframe": "30d",
        "tags": ["service:api", "team:platform"],
        "created_at": "2024-01-01T00:00:00Z",
        "modified_at": "2024-02-15T12:00:00Z",
        "monitor_ids": [12345, 67890],
        "groups": [],
        "overall_status": [{"sli_value": 99.95, "status": "OK"}],
    }


@pytest.fixture
def mock_synthetic():
    """Create a mock synthetic test response."""
    return {
        "public_id": "syn-abc-123",
        "name": "API Health Check",
        "type": "api",
        "status": "live",
        "tags": ["team:platform", "env:production"],
        "locations": ["aws:us-east-1", "aws:eu-west-1"],
        "message": "API health check failed",
        "created_at": "2024-01-10T08:00:00Z",
        "modified_at": "2024-03-01T10:00:00Z",
        "created_by": {"name": "Admin", "email": "admin@example.com"},
        "config": {
            "request": {"url": "https://api.example.com/health", "method": "GET"},
            "assertions": [{"type": "statusCode", "target": 200}],
        },
        "options": {
            "tick_every": 60,
            "min_failure_duration": 0,
            "min_location_failed": 1,
        },
        "overall_state": 0,  # 0 = OK
    }


@pytest.fixture
def mock_api_key():
    """Create a mock API key response."""
    return {
        "id": "key-123",
        "type": "api_keys",
        "attributes": {
            "name": "Production API Key",
            "key": "abcd1234efgh5678ijkl",
            "created_at": "2024-01-01T00:00:00Z",
            "modified_at": "2024-02-01T00:00:00Z",
            "last_used_at": "2024-03-15T12:00:00Z",
        },
    }


@pytest.fixture
def mock_security_rule():
    """Create a mock security rule response."""
    return {
        "id": "rule-123",
        "type": "security_rules",
        "attributes": {
            "name": "Impossible Travel Detection",
            "type": "log_detection",
            "isEnabled": True,
            "isDefault": False,
            "message": "User logged in from impossible locations",
            "tags": ["security", "authentication"],
            "cases": [{"status": "high"}],
            "queries": [{"query": "service:auth"}],
            "options": {"detectionMethod": "anomaly"},
            "createdAt": "2024-01-15T10:00:00Z",
            "updateAuthor": "admin@example.com",
        },
    }


@pytest.fixture
def mock_audit_event():
    """Create a mock audit event response."""
    return {
        "id": "event-123",
        "type": "audit",
        "attributes": {
            "timestamp": "2024-03-15T14:30:00Z",
            "type": {"name": "user.login", "category": "authentication"},
            "actor": {
                "type": "user",
                "id": "user-123",
                "name": "admin@example.com",
            },
            "target": {"type": "session", "id": "session-456"},
            "outcome": "success",
            "service": "authentication",
            "attributes": {"message": "User logged in successfully"},
        },
    }


# =============================================================================
# Configuration Tests
# =============================================================================


class TestDatadogCollectorConfig:
    """Tests for Datadog collector configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        config = DatadogCollectorConfig()
        assert config.api_key == ""
        assert config.app_key == ""
        assert config.site == "datadoghq.com"
        assert config.timeout == 30
        assert config.max_retries == 3
        assert config.page_size == 100
        assert config.days_of_history == 30

    def test_custom_config(self, mock_config):
        """Test custom configuration values."""
        assert mock_config.api_key == "test-api-key"
        assert mock_config.app_key == "test-app-key"
        assert mock_config.site == "datadoghq.com"

    def test_eu_site_config(self):
        """Test EU site configuration."""
        config = DatadogCollectorConfig(
            api_key="key",
            app_key="app",
            site="datadoghq.eu",
        )
        assert config.site == "datadoghq.eu"


# =============================================================================
# Collector Initialization Tests
# =============================================================================


class TestDatadogCollectorInit:
    """Tests for Datadog collector initialization."""

    def test_init_with_config(self, mock_config):
        """Test initialization with config."""
        collector = DatadogCollector(config=mock_config)
        assert collector.config == mock_config
        assert collector.PLATFORM == "datadog"

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = DatadogCollector()
        assert collector.config is not None
        assert collector.config.api_key == ""

    def test_base_url(self, mock_config):
        """Test base URL generation."""
        collector = DatadogCollector(config=mock_config)
        assert collector.base_url == "https://api.datadoghq.com/api"

    def test_base_url_eu(self):
        """Test EU base URL generation."""
        config = DatadogCollectorConfig(site="datadoghq.eu")
        collector = DatadogCollector(config=config)
        assert collector.base_url == "https://api.datadoghq.eu/api"

    def test_supported_types(self, mock_config):
        """Test supported resource and evidence types."""
        collector = DatadogCollector(config=mock_config)
        assert "datadog_monitor" in collector.SUPPORTED_RESOURCE_TYPES
        assert "datadog_dashboard" in collector.SUPPORTED_RESOURCE_TYPES
        assert "datadog_user" in collector.SUPPORTED_RESOURCE_TYPES
        assert "datadog_slo" in collector.SUPPORTED_RESOURCE_TYPES

        assert "monitors" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "dashboards" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "users" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "api_keys" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "audit_logs" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "security_rules" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "slos" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "synthetics" in collector.SUPPORTED_EVIDENCE_TYPES


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestCredentialValidation:
    """Tests for credential validation."""

    @patch("attestful.collectors.platforms.datadog.requests.Session")
    def test_validate_credentials_success(self, mock_session_class, mock_config):
        """Test successful credential validation."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"valid": True}
        mock_session.request.return_value = mock_response

        collector = DatadogCollector(config=mock_config)
        assert collector.validate_credentials() is True

    @patch("attestful.collectors.platforms.datadog.requests.Session")
    def test_validate_credentials_invalid(self, mock_session_class, mock_config):
        """Test invalid credentials."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"valid": False}
        mock_session.request.return_value = mock_response

        collector = DatadogCollector(config=mock_config)
        assert collector.validate_credentials() is False

    @patch("attestful.collectors.platforms.datadog.requests.Session")
    def test_validate_credentials_error(self, mock_session_class, mock_config):
        """Test credential validation error."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_session.request.side_effect = Exception("Connection error")

        collector = DatadogCollector(config=mock_config)
        assert collector.validate_credentials() is False


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestResourceCollection:
    """Tests for resource collection."""

    @patch("attestful.collectors.platforms.datadog.requests.Session")
    def test_collect_monitors(self, mock_session_class, mock_config, mock_monitor):
        """Test collecting monitor resources."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [mock_monitor]
        mock_session.request.return_value = mock_response

        collector = DatadogCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["datadog_monitor"])

        assert len(resources) == 1
        assert resources[0].type == "datadog_monitor"
        assert resources[0].name == "High CPU Usage"
        assert resources[0].tags["overall_state"] == "OK"

    @patch("attestful.collectors.platforms.datadog.requests.Session")
    def test_collect_dashboards(self, mock_session_class, mock_config, mock_dashboard):
        """Test collecting dashboard resources."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"dashboards": [mock_dashboard]}
        mock_session.request.return_value = mock_response

        collector = DatadogCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["datadog_dashboard"])

        assert len(resources) == 1
        assert resources[0].type == "datadog_dashboard"
        assert resources[0].name == "Production Overview"

    @patch("attestful.collectors.platforms.datadog.requests.Session")
    def test_collect_users(self, mock_session_class, mock_config, mock_user):
        """Test collecting user resources."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [mock_user], "meta": {}}
        mock_session.request.return_value = mock_response

        collector = DatadogCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["datadog_user"])

        assert len(resources) == 1
        assert resources[0].type == "datadog_user"
        assert resources[0].name == "admin@example.com"
        assert resources[0].tags["status"] == "Active"

    @patch("attestful.collectors.platforms.datadog.requests.Session")
    def test_collect_slos(self, mock_session_class, mock_config, mock_slo):
        """Test collecting SLO resources."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [mock_slo]}
        mock_session.request.return_value = mock_response

        collector = DatadogCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["datadog_slo"])

        assert len(resources) == 1
        assert resources[0].type == "datadog_slo"
        assert resources[0].name == "API Availability"


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestEvidenceCollection:
    """Tests for evidence collection."""

    @patch("attestful.collectors.platforms.datadog.requests.Session")
    def test_collect_monitors_evidence(self, mock_session_class, mock_config, mock_monitor):
        """Test collecting monitors evidence."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [mock_monitor]
        mock_session.request.return_value = mock_response

        collector = DatadogCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["monitors"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "monitors"
        assert result.evidence_items[0].raw_data["total_count"] == 1
        assert "status_breakdown" in result.evidence_items[0].raw_data

    @patch("attestful.collectors.platforms.datadog.requests.Session")
    def test_collect_dashboards_evidence(self, mock_session_class, mock_config, mock_dashboard):
        """Test collecting dashboards evidence."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"dashboards": [mock_dashboard]}
        mock_session.request.return_value = mock_response

        collector = DatadogCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["dashboards"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "dashboards"
        assert result.evidence_items[0].raw_data["total_count"] == 1

    @patch("attestful.collectors.platforms.datadog.requests.Session")
    def test_collect_users_evidence(self, mock_session_class, mock_config, mock_user):
        """Test collecting users evidence."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [mock_user], "meta": {}}
        mock_session.request.return_value = mock_response

        collector = DatadogCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["users"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "users"
        assert result.evidence_items[0].raw_data["total_count"] == 1
        assert "summary" in result.evidence_items[0].raw_data

    @patch("attestful.collectors.platforms.datadog.requests.Session")
    def test_collect_api_keys_evidence(self, mock_session_class, mock_config, mock_api_key):
        """Test collecting API keys evidence."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [mock_api_key], "meta": {}}
        mock_session.request.return_value = mock_response

        collector = DatadogCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["api_keys"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "api_keys"
        # Verify key is masked
        api_keys = result.evidence_items[0].raw_data["api_keys"]
        assert api_keys[0]["key_prefix"].endswith("...")

    @patch("attestful.collectors.platforms.datadog.requests.Session")
    def test_collect_security_rules_evidence(self, mock_session_class, mock_config, mock_security_rule):
        """Test collecting security rules evidence."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [mock_security_rule], "meta": {}}
        mock_session.request.return_value = mock_response

        collector = DatadogCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["security_rules"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "security_rules"
        assert result.evidence_items[0].raw_data["total_rules"] == 1
        assert result.evidence_items[0].raw_data["enabled_rules"] == 1

    @patch("attestful.collectors.platforms.datadog.requests.Session")
    def test_collect_slos_evidence(self, mock_session_class, mock_config, mock_slo):
        """Test collecting SLOs evidence."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [mock_slo]}
        mock_session.request.return_value = mock_response

        collector = DatadogCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["slos"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "slos"
        assert result.evidence_items[0].raw_data["total_slos"] == 1
        assert "summary" in result.evidence_items[0].raw_data

    @patch("attestful.collectors.platforms.datadog.requests.Session")
    def test_collect_synthetics_evidence(self, mock_session_class, mock_config, mock_synthetic):
        """Test collecting synthetics evidence."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"tests": [mock_synthetic]}
        mock_session.request.return_value = mock_response

        collector = DatadogCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["synthetics"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "synthetics"
        assert result.evidence_items[0].raw_data["total_tests"] == 1
        assert "summary" in result.evidence_items[0].raw_data

    @patch("attestful.collectors.platforms.datadog.requests.Session")
    def test_collect_audit_logs_evidence(self, mock_session_class, mock_config, mock_audit_event):
        """Test collecting audit logs evidence."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [mock_audit_event], "meta": {}}
        mock_session.request.return_value = mock_response

        collector = DatadogCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["audit_logs"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "audit_logs"
        assert result.evidence_items[0].raw_data["total_events"] == 1
        assert "security_events" in result.evidence_items[0].raw_data


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    @patch("attestful.collectors.platforms.datadog.requests.Session")
    def test_resource_collection_error(self, mock_session_class, mock_config):
        """Test handling errors during resource collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_session.request.side_effect = Exception("API error")

        collector = DatadogCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["datadog_monitor"])

        # Should return empty list, not raise
        assert resources == []

    @patch("attestful.collectors.platforms.datadog.requests.Session")
    def test_evidence_collection_graceful_degradation(self, mock_session_class, mock_config):
        """Test graceful degradation when API errors occur.

        Datadog collector handles API errors gracefully - individual evidence
        methods catch exceptions and return empty data rather than failing
        completely. This ensures partial collection still works.
        """
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_session.request.side_effect = Exception("API error")

        collector = DatadogCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["monitors"])

        # Should still return evidence (with empty data), not fail
        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "monitors"
        # Data should be empty due to error
        assert result.evidence_items[0].raw_data["total_count"] == 0

    def test_unknown_resource_type(self, mock_config):
        """Test handling unknown resource types."""
        collector = DatadogCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["unknown_type"])
        assert resources == []

    def test_unknown_evidence_type(self, mock_config):
        """Test handling unknown evidence types."""
        collector = DatadogCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["unknown_type"])
        assert len(result.evidence_items) == 0


# =============================================================================
# Compliance Metadata Tests
# =============================================================================


class TestComplianceMetadata:
    """Tests for compliance-related metadata in evidence."""

    @patch("attestful.collectors.platforms.datadog.requests.Session")
    def test_monitors_compliance_controls(self, mock_session_class, mock_config, mock_monitor):
        """Test compliance controls in monitors evidence."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [mock_monitor]
        mock_session.request.return_value = mock_response

        collector = DatadogCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["monitors"])

        metadata = result.evidence_items[0].metadata
        assert "compliance_controls" in metadata
        assert "SOC2:CC7.1" in metadata["compliance_controls"]
        assert "NIST:SI-4" in metadata["compliance_controls"]

    @patch("attestful.collectors.platforms.datadog.requests.Session")
    def test_users_compliance_controls(self, mock_session_class, mock_config, mock_user):
        """Test compliance controls in users evidence."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [mock_user], "meta": {}}
        mock_session.request.return_value = mock_response

        collector = DatadogCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["users"])

        metadata = result.evidence_items[0].metadata
        assert "compliance_controls" in metadata
        assert "SOC2:CC6.1" in metadata["compliance_controls"]
        assert "NIST:AC-2" in metadata["compliance_controls"]


# =============================================================================
# CLI Tests
# =============================================================================


class TestDatadogCLI:
    """Tests for Datadog CLI commands."""

    def test_datadog_help(self):
        """Test datadog collect help."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "datadog", "--help"])
        assert result.exit_code == 0
        assert "Collect evidence from Datadog" in result.output
        assert "--types" in result.output
        assert "--site" in result.output
        assert "--days" in result.output

    def test_datadog_evidence_types_in_help(self):
        """Test evidence types are documented in help."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "datadog", "--help"])
        assert result.exit_code == 0
        assert "monitors" in result.output
        assert "dashboards" in result.output
        assert "users" in result.output
        assert "audit_logs" in result.output
        assert "security_rules" in result.output
        assert "slos" in result.output
        assert "synthetics" in result.output

    def test_datadog_examples_in_help(self):
        """Test examples are in help output."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "datadog", "--help"])
        assert result.exit_code == 0
        assert "Examples:" in result.output

    def test_collect_list_shows_datadog(self):
        """Test collect list shows datadog as available."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "list"])
        assert result.exit_code == 0
        assert "datadog" in result.output
        assert "Available" in result.output
