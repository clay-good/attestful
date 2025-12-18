"""Unit tests for the Notion collector."""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from attestful.collectors.platforms.notion import NotionCollector, NotionCollectorConfig
from attestful.core.exceptions import CollectionError, ConfigurationError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_config():
    """Create a mock Notion configuration."""
    return NotionCollectorConfig(
        api_token="secret_test_token_xxx",
    )


@pytest.fixture
def mock_page():
    """Create a mock page response."""
    # Use recent dates to pass the cutoff filter
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    return {
        "object": "page",
        "id": "page-123",
        "created_time": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "last_edited_time": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "created_by": {"id": "user-123"},
        "last_edited_by": {"id": "user-456"},
        "archived": False,
        "url": "https://www.notion.so/Test-Page-123",
        "properties": {
            "title": {
                "title": [{"plain_text": "Test Page"}]
            }
        },
        "parent": {
            "type": "workspace",
            "workspace": True,
        },
        "icon": {"type": "emoji", "emoji": "📄"},
        "cover": None,
        "public_url": None,
    }


@pytest.fixture
def mock_database():
    """Create a mock database response."""
    return {
        "object": "database",
        "id": "db-123",
        "created_time": "2024-01-01T00:00:00.000Z",
        "last_edited_time": "2024-01-15T00:00:00.000Z",
        "archived": False,
        "is_inline": False,
        "url": "https://www.notion.so/Test-Database-123",
        "title": [{"plain_text": "Test Database"}],
        "properties": {
            "Name": {"id": "title", "type": "title", "title": {}},
            "Status": {"id": "status", "type": "status", "status": {}},
            "Priority": {"id": "priority", "type": "select", "select": {}},
        },
        "parent": {
            "type": "page_id",
            "page_id": "parent-page-123",
        },
        "public_url": None,
    }


@pytest.fixture
def mock_user():
    """Create a mock user response."""
    return {
        "object": "user",
        "id": "user-123",
        "type": "person",
        "name": "John Doe",
        "avatar_url": "https://example.com/avatar.png",
        "person": {
            "email": "john@company.com",
        },
    }


@pytest.fixture
def mock_bot_user():
    """Create a mock bot user response."""
    return {
        "object": "user",
        "id": "bot-123",
        "type": "bot",
        "name": "Test Integration",
        "avatar_url": None,
        "bot": {
            "owner": {
                "type": "workspace",
                "workspace": True,
            }
        },
    }


@pytest.fixture
def mock_comment():
    """Create a mock comment response."""
    return {
        "object": "comment",
        "id": "comment-123",
        "discussion_id": "discussion-123",
        "created_time": "2024-01-10T00:00:00.000Z",
        "created_by": {"id": "user-123"},
        "rich_text": [{"plain_text": "This is a test comment"}],
    }


@pytest.fixture
def cli_runner():
    """Create a CLI runner for testing."""
    from click.testing import CliRunner

    return CliRunner()


# =============================================================================
# Configuration Tests
# =============================================================================


class TestNotionCollectorConfig:
    """Tests for NotionCollectorConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = NotionCollectorConfig()
        assert config.api_token == ""
        assert config.timeout == 30
        assert config.max_retries == 3
        assert config.page_size == 100
        assert config.days_of_history == 90
        assert config.root_page_id == ""

    def test_custom_config(self, mock_config):
        """Test custom configuration values."""
        assert mock_config.api_token == "secret_test_token_xxx"


# =============================================================================
# Collector Initialization Tests
# =============================================================================


class TestNotionCollectorInit:
    """Tests for Notion collector initialization."""

    def test_init_with_config(self, mock_config):
        """Test initialization with config."""
        collector = NotionCollector(config=mock_config)
        assert collector.config == mock_config
        assert collector.PLATFORM == "notion"

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = NotionCollector()
        assert collector.config is not None
        assert collector.config.api_token == ""
        assert collector._session is None

    def test_supported_types(self, mock_config):
        """Test supported resource and evidence types."""
        collector = NotionCollector(config=mock_config)
        assert "notion_page" in collector.SUPPORTED_RESOURCE_TYPES
        assert "notion_database" in collector.SUPPORTED_RESOURCE_TYPES
        assert "notion_user" in collector.SUPPORTED_RESOURCE_TYPES

        assert "pages" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "databases" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "users" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "comments" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "permissions" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "audit_logs" in collector.SUPPORTED_EVIDENCE_TYPES

    def test_api_url_property(self, mock_config):
        """Test API URL generation."""
        collector = NotionCollector(config=mock_config)
        assert collector.api_url == "https://api.notion.com/v1"

    def test_notion_version(self, mock_config):
        """Test Notion API version."""
        collector = NotionCollector(config=mock_config)
        assert collector.NOTION_VERSION == "2022-06-28"


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestCredentialValidation:
    """Tests for credential validation."""

    @patch("attestful.collectors.platforms.notion.requests.Session")
    def test_validate_credentials_success(self, mock_session_class, mock_config):
        """Test successful credential validation."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"name": "Test Bot"}
        mock_response.content = b'{"name": "Test Bot"}'
        mock_session.request.return_value = mock_response

        collector = NotionCollector(config=mock_config)
        assert collector.validate_credentials() is True

    @patch("attestful.collectors.platforms.notion.requests.Session")
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
        mock_session.request.return_value = mock_response

        collector = NotionCollector(config=mock_config)

        with pytest.raises(ConfigurationError, match="Invalid Notion API token"):
            collector.validate_credentials()

    def test_validate_credentials_missing_token(self):
        """Test validation with missing token."""
        config = NotionCollectorConfig()
        collector = NotionCollector(config=config)

        with pytest.raises(ConfigurationError, match="api_token is required"):
            collector.validate_credentials()


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestResourceCollection:
    """Tests for resource collection."""

    @patch("attestful.collectors.platforms.notion.requests.Session")
    def test_collect_page_resources(self, mock_session_class, mock_config, mock_page):
        """Test page resource collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "results": [mock_page],
            "has_more": False,
        }
        mock_response.content = b'{}'
        mock_session.request.return_value = mock_response

        collector = NotionCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["notion_page"])

        assert len(resources) == 1
        assert resources[0].type == "notion_page"
        assert resources[0].name == "Test Page"
        assert resources[0].tags["archived"] == "false"
        assert resources[0].tags["parent_type"] == "workspace"

    @patch("attestful.collectors.platforms.notion.requests.Session")
    def test_collect_database_resources(
        self, mock_session_class, mock_config, mock_database
    ):
        """Test database resource collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "results": [mock_database],
            "has_more": False,
        }
        mock_response.content = b'{}'
        mock_session.request.return_value = mock_response

        collector = NotionCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["notion_database"])

        assert len(resources) == 1
        assert resources[0].type == "notion_database"
        assert resources[0].name == "Test Database"
        assert resources[0].metadata["property_count"] == 3

    @patch("attestful.collectors.platforms.notion.requests.Session")
    def test_collect_user_resources(self, mock_session_class, mock_config, mock_user):
        """Test user resource collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "results": [mock_user],
            "has_more": False,
        }
        mock_response.content = b'{}'
        mock_session.request.return_value = mock_response

        collector = NotionCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["notion_user"])

        assert len(resources) == 1
        assert resources[0].type == "notion_user"
        assert resources[0].name == "John Doe"
        assert resources[0].tags["type"] == "person"
        assert resources[0].metadata["email"] == "john@company.com"

    def test_collect_invalid_resource_type(self, mock_config):
        """Test error on invalid resource type."""
        collector = NotionCollector(config=mock_config)

        with pytest.raises(CollectionError, match="Unsupported resource types"):
            collector.collect_resources(resource_types=["invalid_type"])


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestEvidenceCollection:
    """Tests for evidence collection."""

    @patch("attestful.collectors.platforms.notion.requests.Session")
    def test_collect_pages_evidence(self, mock_session_class, mock_config, mock_page):
        """Test pages evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "results": [mock_page],
            "has_more": False,
        }
        mock_response.content = b'{}'
        mock_session.request.return_value = mock_response

        collector = NotionCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["pages"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "pages"
        assert result.evidence_items[0].raw_data["total_count"] == 1
        assert result.evidence_items[0].raw_data["by_parent_type"]["workspace"] == 1

    @patch("attestful.collectors.platforms.notion.requests.Session")
    def test_collect_databases_evidence(
        self, mock_session_class, mock_config, mock_database
    ):
        """Test databases evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "results": [mock_database],
            "has_more": False,
        }
        mock_response.content = b'{}'
        mock_session.request.return_value = mock_response

        collector = NotionCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["databases"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "databases"
        assert result.evidence_items[0].raw_data["total_count"] == 1

    @patch("attestful.collectors.platforms.notion.requests.Session")
    def test_collect_users_evidence(
        self, mock_session_class, mock_config, mock_user, mock_bot_user
    ):
        """Test users evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "results": [mock_user, mock_bot_user],
            "has_more": False,
        }
        mock_response.content = b'{}'
        mock_session.request.return_value = mock_response

        collector = NotionCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["users"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "users"
        assert result.evidence_items[0].raw_data["total_count"] == 2
        assert result.evidence_items[0].raw_data["person_count"] == 1
        assert result.evidence_items[0].raw_data["bot_count"] == 1

    @patch("attestful.collectors.platforms.notion.requests.Session")
    def test_collect_comments_evidence(
        self, mock_session_class, mock_config, mock_page, mock_comment
    ):
        """Test comments evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # First call: search for pages, second call: get comments
        mock_response = MagicMock()
        mock_response.json.side_effect = [
            {"results": [mock_page], "has_more": False},  # Search pages
            {"results": [mock_comment]},  # Get comments
        ]
        mock_response.content = b'{}'
        mock_session.request.return_value = mock_response

        collector = NotionCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["comments"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "comments"

    @patch("attestful.collectors.platforms.notion.requests.Session")
    def test_collect_permissions_evidence(
        self, mock_session_class, mock_config, mock_page, mock_database
    ):
        """Test permissions evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock different search results for pages and databases
        mock_response = MagicMock()
        mock_response.json.side_effect = [
            {"results": [mock_page], "has_more": False},  # Search pages
            {"results": [mock_database], "has_more": False},  # Search databases
        ]
        mock_response.content = b'{}'
        mock_session.request.return_value = mock_response

        collector = NotionCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["permissions"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "permissions"
        assert result.evidence_items[0].raw_data["public_count"] == 0  # Neither is public

    @patch("attestful.collectors.platforms.notion.requests.Session")
    def test_collect_audit_logs_evidence(self, mock_session_class, mock_config):
        """Test audit logs evidence collection (Enterprise only)."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        collector = NotionCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["audit_logs"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "audit_logs"
        assert "note" in result.evidence_items[0].raw_data
        assert "Enterprise" in result.evidence_items[0].raw_data["note"]

    def test_collect_invalid_evidence_type(self, mock_config):
        """Test error on invalid evidence type."""
        collector = NotionCollector(config=mock_config)

        with pytest.raises(CollectionError, match="Unsupported evidence types"):
            collector.collect_evidence(evidence_types=["invalid_type"])


# =============================================================================
# Compliance Control Mapping Tests
# =============================================================================


class TestComplianceMetadata:
    """Tests for compliance control mappings."""

    def test_evidence_control_mappings_exist(self):
        """Test that all evidence types have control mappings."""
        collector = NotionCollector()

        for evidence_type in collector.SUPPORTED_EVIDENCE_TYPES:
            assert evidence_type in collector.EVIDENCE_CONTROL_MAPPINGS
            mappings = collector.EVIDENCE_CONTROL_MAPPINGS[evidence_type]
            assert "soc2" in mappings
            assert "nist_800_53" in mappings
            assert "iso_27001" in mappings
            assert "hitrust" in mappings

    def test_pages_compliance_controls(self):
        """Test pages evidence compliance controls."""
        collector = NotionCollector()
        controls = collector.EVIDENCE_CONTROL_MAPPINGS["pages"]

        # SOC 2 - Documentation
        assert "CC2.2" in controls["soc2"]
        assert "CC2.3" in controls["soc2"]

        # NIST 800-53
        assert "AT-3" in controls["nist_800_53"]
        assert "SA-5" in controls["nist_800_53"]

    def test_users_compliance_controls(self):
        """Test users evidence compliance controls."""
        collector = NotionCollector()
        controls = collector.EVIDENCE_CONTROL_MAPPINGS["users"]

        # SOC 2 - Access Control
        assert "CC6.1" in controls["soc2"]
        assert "CC6.2" in controls["soc2"]

        # NIST 800-53
        assert "AC-2" in controls["nist_800_53"]
        assert "IA-2" in controls["nist_800_53"]

    def test_permissions_compliance_controls(self):
        """Test permissions evidence compliance controls."""
        collector = NotionCollector()
        controls = collector.EVIDENCE_CONTROL_MAPPINGS["permissions"]

        # SOC 2 - Access Control
        assert "CC6.1" in controls["soc2"]
        assert "CC6.3" in controls["soc2"]

        # NIST 800-53
        assert "AC-3" in controls["nist_800_53"]
        assert "AC-6" in controls["nist_800_53"]

        # ISO 27001
        assert "A.9.4.1" in controls["iso_27001"]

    def test_audit_logs_compliance_controls(self):
        """Test audit logs evidence compliance controls."""
        collector = NotionCollector()
        controls = collector.EVIDENCE_CONTROL_MAPPINGS["audit_logs"]

        # SOC 2 - Audit
        assert "CC7.2" in controls["soc2"]
        assert "CC7.3" in controls["soc2"]

        # NIST 800-53
        assert "AU-2" in controls["nist_800_53"]
        assert "AU-3" in controls["nist_800_53"]
        assert "AU-12" in controls["nist_800_53"]


# =============================================================================
# CLI Tests
# =============================================================================


class TestNotionCLI:
    """Tests for Notion CLI commands."""

    def test_collect_notion_missing_token(self, cli_runner):
        """Test collect notion command with missing token."""
        from attestful.cli.main import cli

        result = cli_runner.invoke(cli, ["collect", "notion"])

        assert "api token is required" in result.output.lower()

    def test_collect_notion_help(self, cli_runner):
        """Test collect notion command help."""
        from attestful.cli.main import cli

        result = cli_runner.invoke(cli, ["collect", "notion", "--help"])

        assert result.exit_code == 0
        assert "Collect evidence from Notion" in result.output
        assert "--token" in result.output
        assert "--types" in result.output
        assert "--days" in result.output

    def test_collect_list_shows_notion(self, cli_runner):
        """Test that collect list shows Notion as available."""
        from attestful.cli.main import cli

        result = cli_runner.invoke(cli, ["collect", "list"])

        assert result.exit_code == 0
        assert "notion" in result.output.lower()
        # Notion should be marked as available in Both mode
        assert "Both" in result.output


# =============================================================================
# Normalization Tests
# =============================================================================


class TestNormalization:
    """Tests for data normalization."""

    def test_normalize_page(self, mock_config, mock_page):
        """Test page normalization."""
        collector = NotionCollector(config=mock_config)
        normalized = collector._normalize_page(mock_page)

        assert normalized["id"] == "page-123"
        assert normalized["title"] == "Test Page"
        assert normalized["archived"] is False
        assert normalized["parent_type"] == "workspace"

    def test_normalize_page_missing_title(self, mock_config):
        """Test page normalization with missing title."""
        collector = NotionCollector(config=mock_config)
        page_without_title = {
            "id": "page-123",
            "properties": {},
            "parent": {"type": "workspace"},
            "archived": False,
        }
        normalized = collector._normalize_page(page_without_title)

        assert normalized["id"] == "page-123"
        assert normalized["title"] == ""

    def test_normalize_database(self, mock_config, mock_database):
        """Test database normalization."""
        collector = NotionCollector(config=mock_config)
        normalized = collector._normalize_database(mock_database)

        assert normalized["id"] == "db-123"
        assert normalized["title"] == "Test Database"
        assert normalized["property_count"] == 3
        assert normalized["is_inline"] is False
        assert normalized["parent_type"] == "page_id"

    def test_get_page_title(self, mock_config, mock_page):
        """Test page title extraction."""
        collector = NotionCollector(config=mock_config)
        title = collector._get_page_title(mock_page)
        assert title == "Test Page"

    def test_get_page_title_with_name_property(self, mock_config):
        """Test page title extraction with Name property."""
        collector = NotionCollector(config=mock_config)
        page = {
            "properties": {
                "Name": {"title": [{"plain_text": "Named Page"}]}
            }
        }
        title = collector._get_page_title(page)
        assert title == "Named Page"


# =============================================================================
# Pagination Tests
# =============================================================================


class TestPagination:
    """Tests for pagination functionality."""

    @patch("attestful.collectors.platforms.notion.requests.Session")
    def test_pagination_multiple_pages(self, mock_session_class, mock_config, mock_page):
        """Test pagination with multiple pages."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        page_1 = {**mock_page, "id": "page-1"}
        page_2 = {**mock_page, "id": "page-2"}

        mock_response = MagicMock()
        mock_response.json.side_effect = [
            {"results": [page_1], "has_more": True, "next_cursor": "cursor123"},
            {"results": [page_2], "has_more": False},
        ]
        mock_response.content = b'{}'
        mock_session.request.return_value = mock_response

        collector = NotionCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["pages"])

        assert result.evidence_items[0].raw_data["total_count"] == 2


# =============================================================================
# User Type Tests
# =============================================================================


class TestUserTypes:
    """Tests for user type handling."""

    @patch("attestful.collectors.platforms.notion.requests.Session")
    def test_person_user_email(self, mock_session_class, mock_config, mock_user):
        """Test that person users have email extracted."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {"results": [mock_user], "has_more": False}
        mock_response.content = b'{}'
        mock_session.request.return_value = mock_response

        collector = NotionCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["users"])

        users = result.evidence_items[0].raw_data["users"]
        assert users[0]["email"] == "john@company.com"

    @patch("attestful.collectors.platforms.notion.requests.Session")
    def test_bot_user_no_email(self, mock_session_class, mock_config, mock_bot_user):
        """Test that bot users have no email."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.json.return_value = {"results": [mock_bot_user], "has_more": False}
        mock_response.content = b'{}'
        mock_session.request.return_value = mock_response

        collector = NotionCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["users"])

        users = result.evidence_items[0].raw_data["users"]
        assert users[0]["email"] is None
        assert users[0]["bot_owner_type"] == "workspace"
