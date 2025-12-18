"""Unit tests for the Zendesk collector."""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from attestful.collectors.platforms.zendesk import ZendeskCollector, ZendeskCollectorConfig
from attestful.core.exceptions import CollectionError, ConfigurationError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_config():
    """Create a mock Zendesk configuration."""
    return ZendeskCollectorConfig(
        email="admin@company.com",
        api_token="test-token",
        subdomain="company",
    )


@pytest.fixture
def mock_ticket():
    """Create a mock ticket response."""
    return {
        "id": 12345,
        "result_type": "ticket",
        "subject": "Test Support Ticket",
        "description": "This is a test ticket description",
        "status": "open",
        "priority": "high",
        "type": "incident",
        "via": {"channel": "email"},
        "requester_id": 100,
        "assignee_id": 200,
        "group_id": 300,
        "organization_id": 400,
        "tags": ["urgent", "production"],
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-02T00:00:00Z",
        "solved_at": None,
    }


@pytest.fixture
def mock_user():
    """Create a mock user response."""
    return {
        "id": 12345,
        "name": "John Doe",
        "email": "john@company.com",
        "role": "agent",
        "active": True,
        "suspended": False,
        "verified": True,
        "two_factor_auth_enabled": True,
        "default_group_id": 300,
        "created_at": "2024-01-01T00:00:00Z",
        "last_login_at": "2024-01-15T00:00:00Z",
    }


@pytest.fixture
def mock_group():
    """Create a mock group response."""
    return {
        "id": 12345,
        "name": "Support Team",
        "description": "Primary support team",
        "default": True,
        "deleted": False,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-02T00:00:00Z",
    }


@pytest.fixture
def mock_organization():
    """Create a mock organization response."""
    return {
        "id": 12345,
        "name": "Acme Corp",
        "domain_names": ["acme.com"],
        "shared_tickets": True,
        "shared_comments": True,
        "group_id": 300,
        "tags": ["enterprise"],
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-02T00:00:00Z",
    }


@pytest.fixture
def mock_macro():
    """Create a mock macro response."""
    return {
        "id": 12345,
        "title": "Close and Resolve",
        "description": "Macro to close and resolve tickets",
        "active": True,
        "restriction": None,
        "actions": [{"field": "status", "value": "solved"}],
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-02T00:00:00Z",
    }


@pytest.fixture
def mock_trigger():
    """Create a mock trigger response."""
    return {
        "id": 12345,
        "title": "Auto-assign Urgent Tickets",
        "description": "Auto-assign tickets with urgent priority",
        "active": True,
        "category_id": 1,
        "conditions": {
            "all": [{"field": "priority", "operator": "is", "value": "urgent"}],
            "any": [],
        },
        "actions": [{"field": "assignee_id", "value": "100"}],
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-02T00:00:00Z",
    }


@pytest.fixture
def mock_audit_log():
    """Create a mock audit log response."""
    return {
        "id": 12345,
        "action": "login",
        "actor_id": 100,
        "actor_name": "John Doe",
        "source_type": "user",
        "source_id": 100,
        "source_label": "John Doe",
        "ip_address": "192.168.1.1",
        "created_at": "2024-01-15T00:00:00Z",
    }


@pytest.fixture
def cli_runner():
    """Create a CLI runner for testing."""
    from click.testing import CliRunner

    return CliRunner()


# =============================================================================
# Configuration Tests
# =============================================================================


class TestZendeskCollectorConfig:
    """Tests for ZendeskCollectorConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = ZendeskCollectorConfig()
        assert config.email == ""
        assert config.api_token == ""
        assert config.subdomain == ""
        assert config.timeout == 30
        assert config.max_retries == 3
        assert config.page_size == 100
        assert config.days_of_history == 90

    def test_custom_config(self, mock_config):
        """Test custom configuration values."""
        assert mock_config.email == "admin@company.com"
        assert mock_config.api_token == "test-token"
        assert mock_config.subdomain == "company"


# =============================================================================
# Collector Initialization Tests
# =============================================================================


class TestZendeskCollectorInit:
    """Tests for Zendesk collector initialization."""

    def test_init_with_config(self, mock_config):
        """Test initialization with config."""
        collector = ZendeskCollector(config=mock_config)
        assert collector.config == mock_config
        assert collector.PLATFORM == "zendesk"

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = ZendeskCollector()
        assert collector.config is not None
        assert collector.config.email == ""
        assert collector._session is None

    def test_supported_types(self, mock_config):
        """Test supported resource and evidence types."""
        collector = ZendeskCollector(config=mock_config)
        assert "zendesk_ticket" in collector.SUPPORTED_RESOURCE_TYPES
        assert "zendesk_user" in collector.SUPPORTED_RESOURCE_TYPES
        assert "zendesk_group" in collector.SUPPORTED_RESOURCE_TYPES
        assert "zendesk_organization" in collector.SUPPORTED_RESOURCE_TYPES

        assert "tickets" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "ticket_metrics" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "users" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "groups" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "organizations" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "macros" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "triggers" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "audit_logs" in collector.SUPPORTED_EVIDENCE_TYPES

    def test_api_url_property(self, mock_config):
        """Test API URL generation."""
        collector = ZendeskCollector(config=mock_config)
        assert collector.api_url == "https://company.zendesk.com/api/v2"


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestCredentialValidation:
    """Tests for credential validation."""

    @patch("attestful.collectors.platforms.zendesk.requests.Session")
    def test_validate_credentials_success(self, mock_session_class, mock_config):
        """Test successful credential validation."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"user": {"name": "Test User"}}
        mock_session.get.return_value = mock_response

        collector = ZendeskCollector(config=mock_config)
        assert collector.validate_credentials() is True

    @patch("attestful.collectors.platforms.zendesk.requests.Session")
    def test_validate_credentials_invalid(self, mock_session_class, mock_config):
        """Test invalid credential handling."""
        import requests

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            response=mock_response
        )
        mock_session.get.return_value = mock_response

        collector = ZendeskCollector(config=mock_config)

        with pytest.raises(ConfigurationError, match="Invalid Zendesk credentials"):
            collector.validate_credentials()

    def test_validate_credentials_missing_subdomain(self):
        """Test validation with missing subdomain."""
        config = ZendeskCollectorConfig(
            email="admin@company.com",
            api_token="test-token",
        )
        collector = ZendeskCollector(config=config)

        with pytest.raises(ConfigurationError, match="subdomain is required"):
            collector.validate_credentials()

    def test_validate_credentials_missing_email(self):
        """Test validation with missing email."""
        config = ZendeskCollectorConfig(
            api_token="test-token",
            subdomain="company",
        )
        collector = ZendeskCollector(config=config)

        with pytest.raises(ConfigurationError, match="email is required"):
            collector.validate_credentials()

    def test_validate_credentials_missing_token(self):
        """Test validation with missing token."""
        config = ZendeskCollectorConfig(
            email="admin@company.com",
            subdomain="company",
        )
        collector = ZendeskCollector(config=config)

        with pytest.raises(ConfigurationError, match="api_token is required"):
            collector.validate_credentials()


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestResourceCollection:
    """Tests for resource collection."""

    @patch("attestful.collectors.platforms.zendesk.requests.Session")
    def test_collect_ticket_resources(self, mock_session_class, mock_config, mock_ticket):
        """Test ticket resource collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "results": [mock_ticket],
            "meta": {"has_more": False},
        }
        mock_response.ok = True
        mock_session.get.return_value = mock_response

        collector = ZendeskCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["zendesk_ticket"])

        assert len(resources) == 1
        assert resources[0].type == "zendesk_ticket"
        assert resources[0].name == "Test Support Ticket"
        assert resources[0].metadata["status"] == "open"
        assert resources[0].metadata["priority"] == "high"

    @patch("attestful.collectors.platforms.zendesk.requests.Session")
    def test_collect_user_resources(self, mock_session_class, mock_config, mock_user):
        """Test user resource collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # First call returns users, second returns empty to stop pagination
        mock_response = MagicMock()
        mock_response.json.side_effect = [{"users": [mock_user]}, {"users": []}]
        mock_response.ok = True
        mock_session.get.return_value = mock_response

        collector = ZendeskCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["zendesk_user"])

        assert len(resources) == 1
        assert resources[0].type == "zendesk_user"
        assert resources[0].name == "John Doe"
        assert resources[0].tags["role"] == "agent"
        assert resources[0].tags["mfa_enabled"] == "true"

    @patch("attestful.collectors.platforms.zendesk.requests.Session")
    def test_collect_group_resources(self, mock_session_class, mock_config, mock_group):
        """Test group resource collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.side_effect = [{"groups": [mock_group]}, {"groups": []}]
        mock_response.ok = True
        mock_session.get.return_value = mock_response

        collector = ZendeskCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["zendesk_group"])

        assert len(resources) == 1
        assert resources[0].type == "zendesk_group"
        assert resources[0].name == "Support Team"
        assert resources[0].tags["default"] == "true"

    @patch("attestful.collectors.platforms.zendesk.requests.Session")
    def test_collect_organization_resources(
        self, mock_session_class, mock_config, mock_organization
    ):
        """Test organization resource collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.side_effect = [
            {"organizations": [mock_organization]},
            {"organizations": []},
        ]
        mock_response.ok = True
        mock_session.get.return_value = mock_response

        collector = ZendeskCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["zendesk_organization"])

        assert len(resources) == 1
        assert resources[0].type == "zendesk_organization"
        assert resources[0].name == "Acme Corp"
        assert resources[0].tags["shared_tickets"] == "true"

    def test_collect_invalid_resource_type(self, mock_config):
        """Test error on invalid resource type."""
        collector = ZendeskCollector(config=mock_config)

        with pytest.raises(CollectionError, match="Unsupported resource types"):
            collector.collect_resources(resource_types=["invalid_type"])


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestEvidenceCollection:
    """Tests for evidence collection."""

    @patch("attestful.collectors.platforms.zendesk.requests.Session")
    def test_collect_tickets_evidence(self, mock_session_class, mock_config, mock_ticket):
        """Test tickets evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "results": [mock_ticket],
            "meta": {"has_more": False},
        }
        mock_response.ok = True
        mock_session.get.return_value = mock_response

        collector = ZendeskCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["tickets"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "tickets"
        assert result.evidence_items[0].raw_data["total_count"] == 1
        assert result.evidence_items[0].raw_data["by_status"]["open"] == 1
        assert result.evidence_items[0].raw_data["by_priority"]["high"] == 1

    @patch("attestful.collectors.platforms.zendesk.requests.Session")
    def test_collect_ticket_metrics_evidence(
        self, mock_session_class, mock_config, mock_ticket
    ):
        """Test ticket metrics evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_search_response = MagicMock()
        mock_search_response.json.return_value = {
            "results": [mock_ticket],
            "meta": {"has_more": False},
        }
        mock_search_response.ok = True

        mock_metrics_response = MagicMock()
        mock_metrics_response.json.return_value = {
            "tickets": [
                {
                    "id": 12345,
                    "metric_set": {
                        "reply_time_in_minutes": {"calendar": 30},
                        "first_resolution_time_in_minutes": {"calendar": 60},
                        "full_resolution_time_in_minutes": {"calendar": 120},
                        "agent_wait_time_in_minutes": {"calendar": 15},
                        "requester_wait_time_in_minutes": {"calendar": 45},
                        "reopens": 0,
                        "replies": 3,
                    },
                }
            ]
        }
        mock_metrics_response.ok = True

        mock_session.get.side_effect = [mock_search_response, mock_metrics_response]

        collector = ZendeskCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["ticket_metrics"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "ticket_metrics"
        assert result.evidence_items[0].raw_data["total_count"] == 1
        assert result.evidence_items[0].raw_data["average_reply_time_minutes"] == 30.0

    @patch("attestful.collectors.platforms.zendesk.requests.Session")
    def test_collect_users_evidence(self, mock_session_class, mock_config, mock_user):
        """Test users evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.side_effect = [{"users": [mock_user]}, {"users": []}]
        mock_response.ok = True
        mock_session.get.return_value = mock_response

        collector = ZendeskCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["users"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "users"
        assert result.evidence_items[0].raw_data["total_count"] == 1
        assert result.evidence_items[0].raw_data["active_count"] == 1
        assert result.evidence_items[0].raw_data["mfa_enabled_count"] == 1

    @patch("attestful.collectors.platforms.zendesk.requests.Session")
    def test_collect_groups_evidence(self, mock_session_class, mock_config, mock_group):
        """Test groups evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.side_effect = [{"groups": [mock_group]}, {"groups": []}]
        mock_response.ok = True
        mock_session.get.return_value = mock_response

        collector = ZendeskCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["groups"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "groups"
        assert result.evidence_items[0].raw_data["total_count"] == 1
        assert result.evidence_items[0].raw_data["active_count"] == 1

    @patch("attestful.collectors.platforms.zendesk.requests.Session")
    def test_collect_organizations_evidence(
        self, mock_session_class, mock_config, mock_organization
    ):
        """Test organizations evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.side_effect = [
            {"organizations": [mock_organization]},
            {"organizations": []},
        ]
        mock_response.ok = True
        mock_session.get.return_value = mock_response

        collector = ZendeskCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["organizations"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "organizations"
        assert result.evidence_items[0].raw_data["total_count"] == 1

    @patch("attestful.collectors.platforms.zendesk.requests.Session")
    def test_collect_macros_evidence(self, mock_session_class, mock_config, mock_macro):
        """Test macros evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.side_effect = [{"macros": [mock_macro]}, {"macros": []}]
        mock_response.ok = True
        mock_session.get.return_value = mock_response

        collector = ZendeskCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["macros"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "macros"
        assert result.evidence_items[0].raw_data["total_count"] == 1
        assert result.evidence_items[0].raw_data["active_count"] == 1

    @patch("attestful.collectors.platforms.zendesk.requests.Session")
    def test_collect_triggers_evidence(
        self, mock_session_class, mock_config, mock_trigger
    ):
        """Test triggers evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.side_effect = [{"triggers": [mock_trigger]}, {"triggers": []}]
        mock_response.ok = True
        mock_session.get.return_value = mock_response

        collector = ZendeskCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["triggers"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "triggers"
        assert result.evidence_items[0].raw_data["total_count"] == 1
        assert result.evidence_items[0].raw_data["active_count"] == 1

    @patch("attestful.collectors.platforms.zendesk.requests.Session")
    def test_collect_audit_logs_evidence(
        self, mock_session_class, mock_config, mock_audit_log
    ):
        """Test audit logs evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "audit_logs": [mock_audit_log],
            "meta": {"has_more": False},
        }
        mock_response.ok = True
        mock_session.get.return_value = mock_response

        collector = ZendeskCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["audit_logs"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "audit_logs"
        assert result.evidence_items[0].raw_data["by_action"]["login"] == 1

    @patch("attestful.collectors.platforms.zendesk.requests.Session")
    def test_collect_audit_logs_enterprise_only(self, mock_session_class, mock_config):
        """Test audit logs returns empty for non-Enterprise plans."""
        import requests

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.ok = False
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            response=mock_response
        )
        mock_session.get.return_value = mock_response

        collector = ZendeskCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["audit_logs"])

        # Should return evidence with note about Enterprise requirement
        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "audit_logs"
        assert result.evidence_items[0].raw_data["total_count"] == 0

    def test_collect_invalid_evidence_type(self, mock_config):
        """Test error on invalid evidence type."""
        collector = ZendeskCollector(config=mock_config)

        with pytest.raises(CollectionError, match="Unsupported evidence types"):
            collector.collect_evidence(evidence_types=["invalid_type"])


# =============================================================================
# Compliance Control Mapping Tests
# =============================================================================


class TestComplianceMetadata:
    """Tests for compliance control mappings."""

    def test_evidence_control_mappings_exist(self):
        """Test that all evidence types have control mappings."""
        collector = ZendeskCollector()

        for evidence_type in collector.SUPPORTED_EVIDENCE_TYPES:
            assert evidence_type in collector.EVIDENCE_CONTROL_MAPPINGS
            mappings = collector.EVIDENCE_CONTROL_MAPPINGS[evidence_type]
            assert "soc2" in mappings
            assert "nist_800_53" in mappings
            assert "iso_27001" in mappings
            assert "hitrust" in mappings

    def test_tickets_compliance_controls(self):
        """Test tickets evidence compliance controls."""
        collector = ZendeskCollector()
        controls = collector.EVIDENCE_CONTROL_MAPPINGS["tickets"]

        # SOC 2 - Incident Response
        assert "CC3.2" in controls["soc2"]
        assert "CC7.4" in controls["soc2"]
        assert "CC7.5" in controls["soc2"]

        # NIST 800-53 - Incident Response
        assert "IR-4" in controls["nist_800_53"]
        assert "IR-5" in controls["nist_800_53"]
        assert "IR-6" in controls["nist_800_53"]

    def test_users_compliance_controls(self):
        """Test users evidence compliance controls."""
        collector = ZendeskCollector()
        controls = collector.EVIDENCE_CONTROL_MAPPINGS["users"]

        # SOC 2 - Access Control
        assert "CC6.1" in controls["soc2"]
        assert "CC6.2" in controls["soc2"]
        assert "CC6.3" in controls["soc2"]

        # NIST 800-53 - Access Control
        assert "AC-2" in controls["nist_800_53"]
        assert "AC-3" in controls["nist_800_53"]
        assert "IA-2" in controls["nist_800_53"]

        # ISO 27001
        assert "A.9.2.1" in controls["iso_27001"]
        assert "A.9.2.2" in controls["iso_27001"]

    def test_audit_logs_compliance_controls(self):
        """Test audit logs evidence compliance controls."""
        collector = ZendeskCollector()
        controls = collector.EVIDENCE_CONTROL_MAPPINGS["audit_logs"]

        # SOC 2 - Logging
        assert "CC7.2" in controls["soc2"]
        assert "CC7.3" in controls["soc2"]

        # NIST 800-53 - Audit
        assert "AU-2" in controls["nist_800_53"]
        assert "AU-3" in controls["nist_800_53"]
        assert "AU-6" in controls["nist_800_53"]

        # ISO 27001
        assert "A.12.4.1" in controls["iso_27001"]
        assert "A.12.4.3" in controls["iso_27001"]

    def test_ticket_metrics_compliance_controls(self):
        """Test ticket metrics evidence compliance controls."""
        collector = ZendeskCollector()
        controls = collector.EVIDENCE_CONTROL_MAPPINGS["ticket_metrics"]

        # SOC 2 - Response metrics
        assert "CC3.2" in controls["soc2"]
        assert "CC7.3" in controls["soc2"]
        assert "CC7.4" in controls["soc2"]

        # NIST 800-53
        assert "IR-4" in controls["nist_800_53"]
        assert "IR-8" in controls["nist_800_53"]


# =============================================================================
# CLI Tests
# =============================================================================


class TestZendeskCLI:
    """Tests for Zendesk CLI commands."""

    def test_collect_zendesk_missing_subdomain(self, cli_runner):
        """Test collect zendesk command with missing subdomain."""
        from attestful.cli.main import cli

        result = cli_runner.invoke(
            cli,
            [
                "collect",
                "zendesk",
                "--email",
                "admin@company.com",
                "--token",
                "test-token",
            ],
        )

        assert "subdomain is required" in result.output.lower()

    def test_collect_zendesk_missing_token(self, cli_runner):
        """Test collect zendesk command with missing token."""
        from attestful.cli.main import cli

        result = cli_runner.invoke(
            cli,
            [
                "collect",
                "zendesk",
                "--email",
                "admin@company.com",
                "--subdomain",
                "company",
            ],
        )

        assert "api token is required" in result.output.lower()

    def test_collect_zendesk_missing_email(self, cli_runner):
        """Test collect zendesk command with missing email."""
        from attestful.cli.main import cli

        result = cli_runner.invoke(
            cli,
            [
                "collect",
                "zendesk",
                "--token",
                "test-token",
                "--subdomain",
                "company",
            ],
        )

        assert "email is required" in result.output.lower()

    def test_collect_zendesk_help(self, cli_runner):
        """Test collect zendesk command help."""
        from attestful.cli.main import cli

        result = cli_runner.invoke(cli, ["collect", "zendesk", "--help"])

        assert result.exit_code == 0
        assert "Collect evidence from Zendesk" in result.output
        assert "--email" in result.output
        assert "--token" in result.output
        assert "--subdomain" in result.output
        assert "--types" in result.output
        assert "--days" in result.output

    def test_collect_list_shows_zendesk(self, cli_runner):
        """Test that collect list shows Zendesk as available."""
        from attestful.cli.main import cli

        result = cli_runner.invoke(cli, ["collect", "list"])

        assert result.exit_code == 0
        assert "zendesk" in result.output.lower()
        # Zendesk should be marked as available in Both mode
        assert "Both" in result.output


# =============================================================================
# Pagination Tests
# =============================================================================


class TestPagination:
    """Tests for pagination functionality."""

    @patch("attestful.collectors.platforms.zendesk.requests.Session")
    def test_cursor_pagination(self, mock_session_class, mock_config, mock_ticket):
        """Test cursor-based pagination."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # First page with more
        first_response = MagicMock()
        first_response.json.return_value = {
            "results": [mock_ticket],
            "meta": {"has_more": True, "after_cursor": "cursor123"},
        }
        first_response.ok = True

        # Second page without more
        second_response = MagicMock()
        second_response.json.return_value = {
            "results": [{**mock_ticket, "id": 12346}],
            "meta": {"has_more": False},
        }
        second_response.ok = True

        mock_session.get.side_effect = [first_response, second_response]

        collector = ZendeskCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["tickets"])

        assert result.evidence_items[0].raw_data["total_count"] == 2

    @patch("attestful.collectors.platforms.zendesk.requests.Session")
    def test_offset_pagination(self, mock_session_class, mock_config, mock_user):
        """Test offset-based pagination."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # First page with 100 users
        first_response = MagicMock()
        first_response.json.return_value = {"users": [mock_user]}
        first_response.ok = True

        # Second page empty (stops pagination)
        second_response = MagicMock()
        second_response.json.return_value = {"users": []}
        second_response.ok = True

        mock_session.get.side_effect = [first_response, second_response]

        collector = ZendeskCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["users"])

        assert result.evidence_items[0].raw_data["total_count"] == 1


# =============================================================================
# Ticket Normalization Tests
# =============================================================================


class TestTicketNormalization:
    """Tests for ticket data normalization."""

    def test_normalize_ticket(self, mock_config, mock_ticket):
        """Test ticket normalization."""
        collector = ZendeskCollector(config=mock_config)
        normalized = collector._normalize_ticket(mock_ticket)

        assert normalized["id"] == 12345
        assert normalized["subject"] == "Test Support Ticket"
        assert normalized["status"] == "open"
        assert normalized["priority"] == "high"
        assert normalized["type"] == "incident"
        assert normalized["channel"] == "email"
        assert normalized["tags"] == ["urgent", "production"]

    def test_normalize_ticket_missing_fields(self, mock_config):
        """Test ticket normalization with missing fields."""
        collector = ZendeskCollector(config=mock_config)
        minimal_ticket = {"id": 12345, "subject": "Minimal Ticket"}
        normalized = collector._normalize_ticket(minimal_ticket)

        assert normalized["id"] == 12345
        assert normalized["subject"] == "Minimal Ticket"
        assert normalized["status"] is None
        assert normalized["priority"] is None
        assert normalized["channel"] is None

    def test_normalize_ticket_long_description(self, mock_config):
        """Test ticket normalization truncates long descriptions."""
        collector = ZendeskCollector(config=mock_config)
        long_ticket = {
            "id": 12345,
            "subject": "Long Description Ticket",
            "description": "x" * 1000,  # Long description
        }
        normalized = collector._normalize_ticket(long_ticket)

        assert len(normalized["description"]) == 500  # Truncated to 500 chars
