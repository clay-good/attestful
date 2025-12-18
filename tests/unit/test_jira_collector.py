"""Unit tests for the Jira collector."""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from attestful.collectors.platforms.jira import JiraCollector, JiraCollectorConfig
from attestful.core.exceptions import CollectionError, ConfigurationError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_config():
    """Create a mock Jira configuration."""
    return JiraCollectorConfig(
        email="user@company.com",
        api_token="test-token",
        base_url="https://company.atlassian.net",
    )


@pytest.fixture
def mock_server_config():
    """Create a mock Jira Server configuration."""
    return JiraCollectorConfig(
        api_token="test-token",
        base_url="https://jira.company.com",
        is_cloud=False,
    )


@pytest.fixture
def mock_project():
    """Create a mock project response."""
    return {
        "id": "10001",
        "key": "PROJ1",
        "name": "Project One",
        "projectTypeKey": "software",
        "simplified": False,
        "style": "classic",
        "isPrivate": False,
    }


@pytest.fixture
def mock_user():
    """Create a mock user response."""
    return {
        "accountId": "12345",
        "displayName": "John Doe",
        "emailAddress": "john@company.com",
        "active": True,
        "accountType": "atlassian",
        "timeZone": "America/New_York",
    }


@pytest.fixture
def mock_issue():
    """Create a mock issue response."""
    return {
        "id": "10001",
        "key": "PROJ-1",
        "fields": {
            "summary": "Test Issue",
            "status": {"name": "Open"},
            "issuetype": {"name": "Bug"},
            "priority": {"name": "High"},
            "assignee": {"displayName": "John Doe"},
            "reporter": {"displayName": "Jane Smith"},
            "created": "2024-01-01T00:00:00.000Z",
            "updated": "2024-01-02T00:00:00.000Z",
            "resolution": None,
            "labels": ["bug", "urgent"],
            "components": [{"name": "Backend"}],
            "fixVersions": [{"name": "1.0.0"}],
            "project": {"key": "PROJ1"},
        },
        "changelog": {
            "histories": [
                {
                    "author": {"displayName": "John Doe"},
                    "created": "2024-01-02T00:00:00.000Z",
                    "items": [
                        {"field": "status", "fromString": "Open", "toString": "In Progress"},
                    ],
                },
            ],
        },
    }


@pytest.fixture
def mock_workflow():
    """Create a mock workflow response."""
    return {
        "id": {"name": "Default Workflow", "entityId": "wf-123"},
        "description": "Default workflow",
        "isDefault": True,
        "statuses": [{"name": "Open"}, {"name": "In Progress"}, {"name": "Done"}],
        "transitions": [{"name": "Start"}, {"name": "Done"}],
    }


@pytest.fixture
def cli_runner():
    """Create a CLI runner for testing."""
    from click.testing import CliRunner
    return CliRunner()


# =============================================================================
# Configuration Tests
# =============================================================================


class TestJiraCollectorConfig:
    """Tests for JiraCollectorConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = JiraCollectorConfig()
        assert config.email == ""
        assert config.api_token == ""
        assert config.base_url == ""
        assert config.project_keys == []
        assert config.timeout == 30
        assert config.max_retries == 3
        assert config.page_size == 100
        assert config.days_of_history == 90
        assert config.is_cloud is True

    def test_custom_config(self, mock_config):
        """Test custom configuration values."""
        assert mock_config.email == "user@company.com"
        assert mock_config.api_token == "test-token"
        assert mock_config.base_url == "https://company.atlassian.net"

    def test_server_config(self, mock_server_config):
        """Test server/datacenter configuration."""
        assert mock_server_config.is_cloud is False
        assert mock_server_config.base_url == "https://jira.company.com"


# =============================================================================
# Collector Initialization Tests
# =============================================================================


class TestJiraCollectorInit:
    """Tests for Jira collector initialization."""

    def test_init_with_config(self, mock_config):
        """Test initialization with config."""
        collector = JiraCollector(config=mock_config)
        assert collector.config == mock_config
        assert collector.PLATFORM == "jira"

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = JiraCollector()
        assert collector.config is not None
        assert collector.config.email == ""
        assert collector._session is None

    def test_supported_types(self, mock_config):
        """Test supported resource and evidence types."""
        collector = JiraCollector(config=mock_config)
        assert "jira_project" in collector.SUPPORTED_RESOURCE_TYPES
        assert "jira_user" in collector.SUPPORTED_RESOURCE_TYPES
        assert "jira_workflow" in collector.SUPPORTED_RESOURCE_TYPES
        assert "jira_issue" in collector.SUPPORTED_RESOURCE_TYPES

        assert "projects" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "issues" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "workflows" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "users" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "audit_log" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "security_schemes" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "permission_schemes" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "components" in collector.SUPPORTED_EVIDENCE_TYPES


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestCredentialValidation:
    """Tests for credential validation."""

    @patch("attestful.collectors.platforms.jira.requests.Session")
    def test_validate_credentials_success(self, mock_session_class, mock_config):
        """Test successful credential validation."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"displayName": "Test User"}
        mock_session.get.return_value = mock_response

        collector = JiraCollector(config=mock_config)
        assert collector.validate_credentials() is True

    @patch("attestful.collectors.platforms.jira.requests.Session")
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

        collector = JiraCollector(config=mock_config)

        with pytest.raises(ConfigurationError, match="Invalid Jira credentials"):
            collector.validate_credentials()

    def test_validate_credentials_missing_url(self):
        """Test validation with missing URL."""
        config = JiraCollectorConfig(
            email="user@company.com",
            api_token="test-token",
        )
        collector = JiraCollector(config=config)

        with pytest.raises(ConfigurationError, match="base_url is required"):
            collector.validate_credentials()

    def test_validate_credentials_missing_token(self):
        """Test validation with missing token."""
        config = JiraCollectorConfig(
            email="user@company.com",
            base_url="https://company.atlassian.net",
        )
        collector = JiraCollector(config=config)

        with pytest.raises(ConfigurationError, match="api_token is required"):
            collector.validate_credentials()

    def test_validate_credentials_missing_email_for_cloud(self):
        """Test validation with missing email for cloud."""
        config = JiraCollectorConfig(
            api_token="test-token",
            base_url="https://company.atlassian.net",
            is_cloud=True,
        )
        collector = JiraCollector(config=config)

        with pytest.raises(ConfigurationError, match="email is required"):
            collector.validate_credentials()

    @patch("attestful.collectors.platforms.jira.requests.Session")
    def test_validate_credentials_server_no_email(self, mock_session_class, mock_server_config):
        """Test validation succeeds for server without email."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"displayName": "Test User"}
        mock_session.get.return_value = mock_response

        collector = JiraCollector(config=mock_server_config)
        assert collector.validate_credentials() is True


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestResourceCollection:
    """Tests for resource collection."""

    @patch("attestful.collectors.platforms.jira.requests.Session")
    def test_collect_project_resources(self, mock_session_class, mock_config, mock_project):
        """Test project resource collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "values": [mock_project],
            "total": 1,
        }
        mock_session.get.return_value = mock_response

        collector = JiraCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["jira_project"])

        assert len(resources) == 1
        assert resources[0].type == "jira_project"
        assert resources[0].metadata["key"] == "PROJ1"

    @patch("attestful.collectors.platforms.jira.requests.Session")
    def test_collect_user_resources(self, mock_session_class, mock_config, mock_user):
        """Test user resource collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # First call returns users, second returns empty to stop pagination
        mock_response = MagicMock()
        mock_response.json.side_effect = [[mock_user], []]
        mock_session.get.return_value = mock_response

        collector = JiraCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["jira_user"])

        assert len(resources) == 1
        assert resources[0].type == "jira_user"
        assert resources[0].name == "John Doe"
        assert resources[0].metadata["active"] is True

    @patch("attestful.collectors.platforms.jira.requests.Session")
    def test_collect_workflow_resources(self, mock_session_class, mock_config, mock_workflow):
        """Test workflow resource collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {"values": [mock_workflow]}
        mock_session.get.return_value = mock_response

        collector = JiraCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["jira_workflow"])

        assert len(resources) == 1
        assert resources[0].type == "jira_workflow"
        assert resources[0].name == "Default Workflow"
        assert resources[0].metadata["is_default"] is True

    def test_collect_invalid_resource_type(self, mock_config):
        """Test error on invalid resource type."""
        collector = JiraCollector(config=mock_config)

        with pytest.raises(CollectionError, match="Unsupported resource types"):
            collector.collect_resources(resource_types=["invalid_type"])


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestEvidenceCollection:
    """Tests for evidence collection."""

    @patch("attestful.collectors.platforms.jira.requests.Session")
    def test_collect_projects_evidence(self, mock_session_class, mock_config, mock_project):
        """Test projects evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "values": [mock_project],
            "total": 1,
        }
        mock_session.get.return_value = mock_response

        collector = JiraCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["projects"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "projects"
        assert result.evidence_items[0].raw_data["total_count"] == 1

    @patch("attestful.collectors.platforms.jira.requests.Session")
    def test_collect_issues_evidence(self, mock_session_class, mock_config, mock_issue):
        """Test issues evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "issues": [mock_issue],
            "total": 1,
        }
        mock_session.get.return_value = mock_response

        collector = JiraCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["issues"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "issues"
        assert result.evidence_items[0].raw_data["total_count"] == 1

    @patch("attestful.collectors.platforms.jira.requests.Session")
    def test_collect_workflows_evidence(self, mock_session_class, mock_config, mock_workflow):
        """Test workflows evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {"values": [mock_workflow]}
        mock_session.get.return_value = mock_response

        collector = JiraCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["workflows"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "workflows"

    @patch("attestful.collectors.platforms.jira.requests.Session")
    def test_collect_users_evidence(self, mock_session_class, mock_config, mock_user):
        """Test users evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.side_effect = [[mock_user], []]
        mock_session.get.return_value = mock_response

        collector = JiraCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["users"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "users"
        assert result.evidence_items[0].raw_data["active_count"] == 1

    @patch("attestful.collectors.platforms.jira.requests.Session")
    def test_collect_audit_log_evidence_cloud(self, mock_session_class, mock_config):
        """Test audit log evidence collection for Cloud."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "records": [
                {
                    "id": "audit-1",
                    "summary": "Project created",
                    "category": "project",
                    "created": "2024-01-01T00:00:00.000Z",
                },
            ],
        }
        mock_session.get.return_value = mock_response

        collector = JiraCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["audit_log"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "audit_log"

    def test_collect_audit_log_evidence_server(self, mock_server_config):
        """Test audit log evidence collection for Server/Data Center."""
        collector = JiraCollector(config=mock_server_config)
        result = collector.collect_evidence(evidence_types=["audit_log"])

        # Server doesn't support audit log via REST API
        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "audit_log"
        assert "not available" in result.evidence_items[0].raw_data.get("note", "").lower()

    @patch("attestful.collectors.platforms.jira.requests.Session")
    def test_collect_security_schemes_evidence(self, mock_session_class, mock_config):
        """Test security schemes evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "issueSecuritySchemes": [
                {"id": "10001", "name": "Default Security Scheme"},
            ],
        }
        mock_session.get.return_value = mock_response

        collector = JiraCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["security_schemes"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "security_schemes"

    @patch("attestful.collectors.platforms.jira.requests.Session")
    def test_collect_permission_schemes_evidence(self, mock_session_class, mock_config):
        """Test permission schemes evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "permissionSchemes": [
                {"id": "10001", "name": "Default Permission Scheme"},
            ],
        }
        mock_session.get.return_value = mock_response

        collector = JiraCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["permission_schemes"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "permission_schemes"

    @patch("attestful.collectors.platforms.jira.requests.Session")
    def test_collect_components_evidence(self, mock_session_class, mock_config, mock_project):
        """Test components evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # First call: project search, second call: components
        mock_response = MagicMock()
        mock_response.json.side_effect = [
            {"values": [mock_project], "total": 1},
            [{"id": "10001", "name": "Backend", "lead": {"displayName": "John"}}],
        ]
        mock_session.get.return_value = mock_response

        collector = JiraCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["components"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "components"

    def test_collect_invalid_evidence_type(self, mock_config):
        """Test error on invalid evidence type."""
        collector = JiraCollector(config=mock_config)

        with pytest.raises(CollectionError, match="Unsupported evidence types"):
            collector.collect_evidence(evidence_types=["invalid_type"])

    @patch("attestful.collectors.platforms.jira.requests.Session")
    def test_evidence_collection_graceful_degradation(self, mock_session_class, mock_config):
        """Test graceful degradation when API errors occur."""
        import requests

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {"values": []}
        mock_response.raise_for_status.side_effect = requests.RequestException("API Error")
        mock_session.get.return_value = mock_response

        collector = JiraCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["workflows"])

        # Should handle error gracefully - return empty workflows
        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "workflows"


# =============================================================================
# Compliance Control Mapping Tests
# =============================================================================


class TestComplianceMetadata:
    """Tests for compliance control mappings."""

    def test_evidence_control_mappings_exist(self):
        """Test that all evidence types have control mappings."""
        collector = JiraCollector()

        for evidence_type in collector.SUPPORTED_EVIDENCE_TYPES:
            assert evidence_type in collector.EVIDENCE_CONTROL_MAPPINGS
            mappings = collector.EVIDENCE_CONTROL_MAPPINGS[evidence_type]
            assert "soc2" in mappings
            assert "nist_800_53" in mappings
            assert "iso_27001" in mappings
            assert "hitrust" in mappings

    def test_projects_compliance_controls(self):
        """Test projects evidence compliance controls."""
        collector = JiraCollector()
        controls = collector.EVIDENCE_CONTROL_MAPPINGS["projects"]

        # SOC 2 Trust Services Criteria
        assert "CC6.1" in controls["soc2"]
        assert "CC8.1" in controls["soc2"]

        # NIST 800-53
        assert "CM-3" in controls["nist_800_53"]
        assert "SA-10" in controls["nist_800_53"]

    def test_issues_compliance_controls(self):
        """Test issues evidence compliance controls."""
        collector = JiraCollector()
        controls = collector.EVIDENCE_CONTROL_MAPPINGS["issues"]

        # SOC 2 - Change Management
        assert "CC8.1" in controls["soc2"]

        # NIST 800-53 - Configuration Management
        assert "CM-3" in controls["nist_800_53"]

        # ISO 27001
        assert "A.12.1.2" in controls["iso_27001"]

    def test_audit_log_compliance_controls(self):
        """Test audit log evidence compliance controls."""
        collector = JiraCollector()
        controls = collector.EVIDENCE_CONTROL_MAPPINGS["audit_log"]

        # SOC 2 - Logging
        assert "CC7.2" in controls["soc2"]

        # NIST 800-53 - Audit
        assert "AU-2" in controls["nist_800_53"]
        assert "AU-3" in controls["nist_800_53"]

        # ISO 27001
        assert "A.12.4.1" in controls["iso_27001"]


# =============================================================================
# CLI Tests
# =============================================================================


class TestJiraCLI:
    """Tests for Jira CLI commands."""

    def test_collect_jira_missing_url(self, cli_runner):
        """Test collect jira command with missing URL."""
        from attestful.cli.main import cli

        result = cli_runner.invoke(cli, [
            "collect", "jira",
            "--email", "user@company.com",
            "--token", "test-token",
        ])

        assert "Jira URL is required" in result.output

    def test_collect_jira_missing_token(self, cli_runner):
        """Test collect jira command with missing token."""
        from attestful.cli.main import cli

        result = cli_runner.invoke(cli, [
            "collect", "jira",
            "--url", "https://company.atlassian.net",
            "--email", "user@company.com",
        ])

        assert "API token is required" in result.output

    def test_collect_jira_missing_email_cloud(self, cli_runner):
        """Test collect jira command with missing email for cloud."""
        from attestful.cli.main import cli

        result = cli_runner.invoke(cli, [
            "collect", "jira",
            "--url", "https://company.atlassian.net",
            "--token", "test-token",
        ])

        assert "Email is required for Jira Cloud" in result.output

    def test_collect_jira_server_no_email_required(self, cli_runner):
        """Test collect jira command for server doesn't require email."""
        from attestful.cli.main import cli

        # This should NOT show "email required" error for server mode
        result = cli_runner.invoke(cli, [
            "collect", "jira",
            "--url", "https://jira.company.com",
            "--token", "test-token",
            "--server",
        ])

        # Should proceed to validation (which will fail without real credentials)
        assert "Email is required" not in result.output

    def test_collect_jira_help(self, cli_runner):
        """Test collect jira command help."""
        from attestful.cli.main import cli

        result = cli_runner.invoke(cli, ["collect", "jira", "--help"])

        assert result.exit_code == 0
        assert "Collect evidence from Jira" in result.output
        assert "--email" in result.output
        assert "--token" in result.output
        assert "--url" in result.output
        assert "--project" in result.output
        assert "--types" in result.output
        assert "--cloud" in result.output
        assert "--server" in result.output

    def test_collect_list_shows_jira(self, cli_runner):
        """Test that collect list shows Jira as available."""
        from attestful.cli.main import cli

        result = cli_runner.invoke(cli, ["collect", "list"])

        assert result.exit_code == 0
        assert "jira" in result.output.lower()
        # Jira should be marked as available
        assert "Both" in result.output
