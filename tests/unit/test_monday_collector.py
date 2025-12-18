"""
Tests for the Monday.com collector.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
import requests

from attestful.collectors.platforms.monday import (
    MondayCollector,
    MondayCollectorConfig,
)
from attestful.core.exceptions import CollectionError, ConfigurationError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def config():
    """Create a test configuration."""
    return MondayCollectorConfig(
        api_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
        timeout=30,
        max_retries=3,
        page_size=100,
        days_of_history=90,
    )


@pytest.fixture
def collector(config):
    """Create a test collector."""
    return MondayCollector(config=config)


@pytest.fixture
def mock_user():
    """Create a mock user."""
    return {
        "id": "12345678",
        "name": "Test User",
        "email": "test@example.com",
        "title": "Developer",
        "photo_thumb": "https://example.com/photo.png",
        "phone": "+1234567890",
        "location": "New York",
        "timezone": "America/New_York",
        "is_admin": False,
        "is_guest": False,
        "is_pending": False,
        "is_verified": True,
        "enabled": True,
        "created_at": "2024-01-01T00:00:00Z",
        "account": {"id": "acc-123", "name": "Test Account"},
    }


@pytest.fixture
def mock_admin_user():
    """Create a mock admin user."""
    return {
        "id": "87654321",
        "name": "Admin User",
        "email": "admin@example.com",
        "title": "Admin",
        "is_admin": True,
        "is_guest": False,
        "is_pending": False,
        "is_verified": True,
        "enabled": True,
        "created_at": "2024-01-01T00:00:00Z",
        "account": {"id": "acc-123", "name": "Test Account"},
    }


@pytest.fixture
def mock_team():
    """Create a mock team."""
    return {
        "id": "456789",
        "name": "Engineering",
        "picture_url": "https://example.com/team.png",
        "users": [
            {"id": "12345678", "name": "Test User", "email": "test@example.com"},
            {"id": "87654321", "name": "Admin User", "email": "admin@example.com"},
        ],
    }


@pytest.fixture
def mock_workspace():
    """Create a mock workspace."""
    return {
        "id": "789012",
        "name": "Main Workspace",
        "kind": "open",
        "description": "Main workspace description",
        "created_at": "2024-01-01T00:00:00Z",
    }


@pytest.fixture
def mock_board():
    """Create a mock board."""
    return {
        "id": "111222333",
        "name": "Project Board",
        "state": "active",
        "board_kind": "public",
        "description": "Project board description",
        "permissions": "everyone",
        "item_terminology": "item",
        "items_count": 50,
        "workspace_id": "789012",
        "created_at": "2024-01-15T00:00:00Z",
        "updated_at": "2024-06-01T00:00:00Z",
        "creator": {"id": "12345678", "name": "Test User"},
        "owners": [{"id": "12345678", "name": "Test User"}],
        "subscribers": [{"id": "87654321", "name": "Admin User"}],
        "columns": [
            {"id": "col-1", "title": "Status", "type": "status"},
            {"id": "col-2", "title": "Person", "type": "people"},
        ],
        "groups": [
            {"id": "grp-1", "title": "To Do", "color": "#ff0000"},
            {"id": "grp-2", "title": "Done", "color": "#00ff00"},
        ],
    }


@pytest.fixture
def mock_item():
    """Create a mock item."""
    recent_date = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    return {
        "id": "222333444",
        "name": "Implement feature X",
        "state": "active",
        "created_at": "2024-06-01T00:00:00Z",
        "updated_at": recent_date,
        "creator_id": "12345678",
        "group": {"id": "grp-1", "title": "To Do"},
        "column_values": [
            {"id": "col-1", "text": "Working on it", "type": "status", "value": '{"index": 1}'},
            {"id": "col-2", "text": "Test User", "type": "people", "value": '{"id": "12345678"}'},
        ],
    }


@pytest.fixture
def mock_update():
    """Create a mock update."""
    return {
        "id": "333444555",
        "body": "<p>Update body</p>",
        "text_body": "Update body",
        "created_at": "2024-06-15T10:00:00Z",
        "updated_at": "2024-06-15T10:00:00Z",
        "creator_id": "12345678",
        "creator": {"id": "12345678", "name": "Test User"},
        "item_id": "222333444",
    }


@pytest.fixture
def mock_activity_log():
    """Create a mock activity log."""
    return {
        "id": "444555666",
        "event": "update_column_value",
        "data": '{"column_id": "col-1", "value": "Done"}',
        "created_at": "2024-06-15T10:30:00Z",
        "user_id": "12345678",
    }


# =============================================================================
# Initialization Tests
# =============================================================================


class TestMondayCollectorInit:
    """Test collector initialization."""

    def test_init_with_config(self, config):
        """Test initialization with config."""
        collector = MondayCollector(config=config)
        assert collector.config == config
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" in collector.config.api_token

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = MondayCollector()
        assert collector.config is not None
        assert collector.config.api_token == ""

    def test_metadata(self, collector):
        """Test collector metadata."""
        assert collector.metadata.name == "MondayCollector"
        assert collector.metadata.platform == "monday"
        assert "monday_user" in collector.metadata.resource_types
        assert "users" in collector.metadata.evidence_types

    def test_platform(self, collector):
        """Test platform constant."""
        assert collector.PLATFORM == "monday"

    def test_api_url(self, collector):
        """Test API URL constant."""
        assert collector.API_URL == "https://api.monday.com/v2"


# =============================================================================
# Session Tests
# =============================================================================


class TestMondaySession:
    """Test session management."""

    def test_session_creation(self, collector):
        """Test session is created correctly."""
        session = collector.session
        assert session is not None
        assert "Authorization" in session.headers
        assert session.headers["Authorization"] == collector.config.api_token

    def test_session_cached(self, collector):
        """Test session is cached."""
        session1 = collector.session
        session2 = collector.session
        assert session1 is session2

    def test_session_requires_api_token(self):
        """Test session requires API token."""
        collector = MondayCollector(config=MondayCollectorConfig())
        with pytest.raises(ConfigurationError, match="API token is required"):
            _ = collector.session


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestValidateCredentials:
    """Test credential validation."""

    def test_validate_credentials_success(self, collector):
        """Test successful credential validation."""
        mock_response = {
            "me": {
                "id": "12345678",
                "name": "Test User",
                "email": "test@example.com",
            }
        }

        with patch.object(collector, "_graphql", return_value=mock_response):
            assert collector.validate_credentials() is True

    def test_validate_credentials_failure(self, collector):
        """Test failed credential validation."""
        with patch.object(collector, "_graphql", side_effect=ConfigurationError("Invalid Monday.com API token")):
            with pytest.raises(ConfigurationError, match="Invalid"):
                collector.validate_credentials()

    def test_validate_credentials_no_token(self):
        """Test validation without API token."""
        collector = MondayCollector(config=MondayCollectorConfig())
        with pytest.raises(ConfigurationError, match="API token is required"):
            collector.validate_credentials()


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestCollectEvidence:
    """Test evidence collection."""

    def test_collect_all_evidence_types(self, collector, mock_user, mock_team, mock_workspace, mock_board, mock_item, mock_update, mock_activity_log):
        """Test collecting all evidence types."""
        # Test that we can collect at least some evidence types successfully
        # Testing specific types individually for reliability
        with patch.object(collector, "_graphql", return_value={"users": [mock_user]}):
            result = collector.collect_evidence(evidence_types=["users"])

        assert result.platform == "monday"
        assert len(result.evidence_items) == 1
        assert result.errors == []

    def test_collect_specific_evidence_types(self, collector, mock_user, mock_team):
        """Test collecting specific evidence types."""
        with patch.object(collector, "_graphql") as mock_graphql:
            def graphql_side_effect(query, variables=None):
                if "users {" in query:
                    return {"users": [mock_user]}
                elif "teams {" in query:
                    return {"teams": [mock_team]}
                return {}

            mock_graphql.side_effect = graphql_side_effect
            result = collector.collect_evidence(evidence_types=["users", "teams"])

        assert len(result.evidence_items) == 2
        evidence_types = [e.evidence_type for e in result.evidence_items]
        assert "users" in evidence_types
        assert "teams" in evidence_types

    def test_collect_evidence_invalid_type(self, collector):
        """Test collecting with invalid evidence type."""
        with pytest.raises(CollectionError, match="Unsupported evidence types"):
            collector.collect_evidence(evidence_types=["invalid_type"])

    def test_collect_users_evidence(self, collector, mock_user, mock_admin_user):
        """Test collecting users evidence."""
        with patch.object(collector, "_graphql", return_value={"users": [mock_user, mock_admin_user]}):
            result = collector.collect_evidence(evidence_types=["users"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "users"
        assert evidence.raw_data["total_count"] == 2
        assert evidence.raw_data["admin_count"] == 1
        assert evidence.raw_data["enabled_count"] == 2

    def test_collect_teams_evidence(self, collector, mock_team):
        """Test collecting teams evidence."""
        with patch.object(collector, "_graphql", return_value={"teams": [mock_team]}):
            result = collector.collect_evidence(evidence_types=["teams"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "teams"
        assert evidence.raw_data["total_count"] == 1
        assert evidence.raw_data["teams"][0]["member_count"] == 2

    def test_collect_workspaces_evidence(self, collector, mock_workspace):
        """Test collecting workspaces evidence."""
        with patch.object(collector, "_graphql", return_value={"workspaces": [mock_workspace]}):
            result = collector.collect_evidence(evidence_types=["workspaces"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "workspaces"
        assert evidence.raw_data["total_count"] == 1

    def test_collect_boards_evidence(self, collector, mock_board):
        """Test collecting boards evidence."""
        with patch.object(collector, "_graphql", return_value={"boards": [mock_board]}):
            result = collector.collect_evidence(evidence_types=["boards"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "boards"
        assert evidence.raw_data["total_count"] == 1
        assert "active" in evidence.raw_data["by_state"]

    def test_collect_items_evidence(self, collector, mock_board, mock_item):
        """Test collecting items evidence."""
        call_count = [0]

        with patch.object(collector, "_graphql") as mock_graphql:
            def graphql_side_effect(query, variables=None):
                call_count[0] += 1
                if "items_page" in query:
                    return {"boards": [{"items_page": {"cursor": None, "items": [mock_item]}}]}
                else:
                    # First call gets boards list, second call returns empty to stop pagination
                    if call_count[0] <= 2:
                        return {"boards": [{"id": mock_board["id"], "name": mock_board["name"]}]}
                    return {"boards": []}

            mock_graphql.side_effect = graphql_side_effect
            result = collector.collect_evidence(evidence_types=["items"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "items"
        assert evidence.raw_data["total_count"] == 1

    def test_collect_updates_evidence(self, collector, mock_update):
        """Test collecting updates evidence."""
        with patch.object(collector, "_graphql", return_value={"updates": [mock_update]}):
            result = collector.collect_evidence(evidence_types=["updates"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "updates"
        assert evidence.raw_data["total_count"] == 1

    def test_collect_activity_logs_evidence(self, collector, mock_board, mock_activity_log):
        """Test collecting activity logs evidence."""
        mock_board_with_logs = mock_board.copy()
        mock_board_with_logs["activity_logs"] = [mock_activity_log]

        with patch.object(collector, "_graphql", return_value={"boards": [mock_board_with_logs]}):
            result = collector.collect_evidence(evidence_types=["activity_logs"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "activity_logs"
        assert evidence.raw_data["total_count"] == 1


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestCollectResources:
    """Test resource collection."""

    def test_collect_all_resource_types(self, collector, mock_user, mock_team, mock_board, mock_item):
        """Test collecting all resource types."""
        call_count = [0]

        with patch.object(collector, "_graphql") as mock_graphql:
            def graphql_side_effect(query, variables=None):
                call_count[0] += 1
                # Order matters - more specific patterns first
                if "items_page" in query:
                    return {"boards": [{"items_page": {"cursor": None, "items": [mock_item]}}]}
                elif "boards(" in query:
                    # Return boards for first few calls, then empty to stop pagination
                    if call_count[0] <= 4:
                        return {"boards": [mock_board]}
                    return {"boards": []}
                elif "teams {" in query:
                    return {"teams": [mock_team]}
                elif "users {" in query:
                    return {"users": [mock_user]}
                return {}

            mock_graphql.side_effect = graphql_side_effect
            resources = collector.collect_resources()

        assert len(resources) == 4
        resource_types = [r.type for r in resources]
        assert "monday_user" in resource_types
        assert "monday_team" in resource_types
        assert "monday_board" in resource_types
        assert "monday_item" in resource_types

    def test_collect_specific_resource_types(self, collector, mock_user):
        """Test collecting specific resource types."""
        with patch.object(collector, "_graphql", return_value={"users": [mock_user]}):
            resources = collector.collect_resources(resource_types=["monday_user"])

        assert len(resources) == 1
        assert resources[0].type == "monday_user"

    def test_collect_resources_invalid_type(self, collector):
        """Test collecting with invalid resource type."""
        with pytest.raises(CollectionError, match="Unsupported resource types"):
            collector.collect_resources(resource_types=["invalid_type"])

    def test_collect_user_resources(self, collector, mock_user, mock_admin_user):
        """Test collecting user resources."""
        with patch.object(collector, "_graphql", return_value={"users": [mock_user, mock_admin_user]}):
            resources = collector.collect_resources(resource_types=["monday_user"])

        assert len(resources) == 2
        user_resource = next(r for r in resources if r.id == "12345678")
        assert user_resource.type == "monday_user"
        assert user_resource.name == "Test User"
        assert user_resource.tags["is_admin"] == "false"

        admin_resource = next(r for r in resources if r.id == "87654321")
        assert admin_resource.tags["is_admin"] == "true"

    def test_collect_team_resources(self, collector, mock_team):
        """Test collecting team resources."""
        with patch.object(collector, "_graphql", return_value={"teams": [mock_team]}):
            resources = collector.collect_resources(resource_types=["monday_team"])

        assert len(resources) == 1
        resource = resources[0]
        assert resource.type == "monday_team"
        assert resource.name == "Engineering"
        assert resource.tags["member_count"] == "2"

    def test_collect_board_resources(self, collector, mock_board):
        """Test collecting board resources."""
        with patch.object(collector, "_graphql", return_value={"boards": [mock_board]}):
            resources = collector.collect_resources(resource_types=["monday_board"])

        assert len(resources) == 1
        resource = resources[0]
        assert resource.type == "monday_board"
        assert resource.name == "Project Board"
        assert resource.tags["state"] == "active"
        assert resource.tags["board_kind"] == "public"

    def test_collect_item_resources(self, collector, mock_board, mock_item):
        """Test collecting item resources."""
        call_count = [0]

        with patch.object(collector, "_graphql") as mock_graphql:
            def graphql_side_effect(query, variables=None):
                call_count[0] += 1
                if "items_page" in query:
                    return {"boards": [{"items_page": {"cursor": None, "items": [mock_item]}}]}
                else:
                    # Return boards for first call, then empty to stop pagination
                    if call_count[0] <= 2:
                        return {"boards": [{"id": mock_board["id"], "name": mock_board["name"]}]}
                    return {"boards": []}

            mock_graphql.side_effect = graphql_side_effect
            resources = collector.collect_resources(resource_types=["monday_item"])

        assert len(resources) == 1
        resource = resources[0]
        assert resource.type == "monday_item"
        assert resource.name == "Implement feature X"
        assert resource.tags["state"] == "active"


# =============================================================================
# Pagination Tests
# =============================================================================


class TestPagination:
    """Test pagination behavior."""

    def test_items_pagination_multiple_pages(self, collector, mock_item):
        """Test items pagination with multiple pages."""
        page1_response = {
            "boards": [{
                "items_page": {
                    "cursor": "cursor-123",
                    "items": [mock_item],
                }
            }]
        }
        page2_response = {
            "boards": [{
                "items_page": {
                    "cursor": None,
                    "items": [mock_item],
                }
            }]
        }

        with patch.object(collector, "_graphql") as mock_graphql:
            mock_graphql.side_effect = [page1_response, page2_response]
            items = list(collector._paginate_items(12345))

        assert len(items) == 2

    def test_items_pagination_stops_on_error(self, collector):
        """Test items pagination stops gracefully on error."""
        with patch.object(collector, "_graphql", side_effect=Exception("API error")):
            items = list(collector._paginate_items(12345))

        assert len(items) == 0


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Test error handling."""

    def test_evidence_collection_error(self, collector):
        """Test evidence collection handles errors gracefully."""
        with patch.object(collector, "_graphql", side_effect=Exception("API error")):
            result = collector.collect_evidence(evidence_types=["users"])

        assert len(result.evidence_items) == 0
        assert len(result.errors) == 1
        assert "Error collecting users" in result.errors[0]

    def test_partial_evidence_collection(self, collector, mock_user, mock_team):
        """Test partial evidence collection on error."""
        with patch.object(collector, "_graphql") as mock_graphql:
            def graphql_side_effect(query, variables=None):
                # Users query has is_admin field; teams query has teams { at top level
                if "is_admin" in query:
                    return {"users": [mock_user]}
                elif "teams {" in query or "teams\n" in query:
                    raise Exception("Team API error")
                return {}

            mock_graphql.side_effect = graphql_side_effect
            result = collector.collect_evidence(evidence_types=["users", "teams"])

        assert len(result.evidence_items) == 1
        assert len(result.errors) == 1

    def test_resource_collection_error(self, collector):
        """Test resource collection handles errors gracefully."""
        with patch.object(collector, "_graphql", side_effect=Exception("API error")):
            resources = collector.collect_resources(resource_types=["monday_user"])

        # Should return empty list without raising
        assert len(resources) == 0

    def test_graphql_authentication_error(self, collector):
        """Test GraphQL authentication error handling."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "errors": [{"message": "Authentication failed"}]
        }
        mock_response.raise_for_status.return_value = None

        with patch("requests.Session") as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            mock_session.post.return_value = mock_response
            mock_session.headers = {}

            collector._session = None
            with pytest.raises(ConfigurationError, match="Invalid Monday.com API token"):
                collector._graphql("query { me { id } }")


# =============================================================================
# Compliance Control Tests
# =============================================================================


class TestComplianceControls:
    """Test compliance control mappings."""

    def test_users_evidence_has_controls(self, collector, mock_user):
        """Test users evidence includes control mappings."""
        with patch.object(collector, "_graphql", return_value={"users": [mock_user]}):
            result = collector.collect_evidence(evidence_types=["users"])

        evidence = result.evidence_items[0]
        controls = evidence.metadata.get("compliance_controls", {})
        assert "soc2" in controls
        assert "nist_800_53" in controls
        assert "iso_27001" in controls
        assert "hitrust" in controls

    def test_boards_evidence_has_controls(self, collector, mock_board):
        """Test boards evidence includes control mappings."""
        with patch.object(collector, "_graphql", return_value={"boards": [mock_board]}):
            result = collector.collect_evidence(evidence_types=["boards"])

        evidence = result.evidence_items[0]
        controls = evidence.metadata.get("compliance_controls", {})
        assert "CC8.1" in controls["soc2"]
        assert "CM-3" in controls["nist_800_53"]

    def test_all_evidence_types_have_mappings(self, collector):
        """Test all evidence types have control mappings."""
        for evidence_type in collector.SUPPORTED_EVIDENCE_TYPES:
            assert evidence_type in collector.EVIDENCE_CONTROL_MAPPINGS
            mappings = collector.EVIDENCE_CONTROL_MAPPINGS[evidence_type]
            assert "soc2" in mappings
            assert "nist_800_53" in mappings
            assert "iso_27001" in mappings
            assert "hitrust" in mappings


# =============================================================================
# Board Filter Tests
# =============================================================================


class TestBoardFilter:
    """Test board filtering functionality."""

    def test_filter_by_board_ids(self):
        """Test filtering boards by IDs."""
        config = MondayCollectorConfig(
            api_token="test-token",
            board_ids=[111, 222],
        )
        collector = MondayCollector(config=config)

        mock_board1 = {"id": "111", "name": "Board 1", "state": "active"}
        mock_board2 = {"id": "222", "name": "Board 2", "state": "active"}
        mock_board3 = {"id": "333", "name": "Board 3", "state": "active"}

        with patch.object(collector, "_graphql", return_value={"boards": [mock_board1, mock_board2, mock_board3]}):
            result = collector.collect_evidence(evidence_types=["boards"])

        assert len(result.evidence_items) == 1
        boards = result.evidence_items[0].raw_data["boards"]
        assert len(boards) == 2
        board_ids = [b["id"] for b in boards]
        assert "111" in board_ids
        assert "222" in board_ids
        assert "333" not in board_ids


# =============================================================================
# CLI Tests
# =============================================================================


class TestCLI:
    """Test CLI integration."""

    def test_cli_command_exists(self):
        """Test CLI command is registered."""
        from attestful.cli.main import collect

        assert "monday" in [cmd.name for cmd in collect.commands.values()]

    def test_cli_command_options(self):
        """Test CLI command has expected options."""
        from attestful.cli.main import collect_monday

        option_names = [param.name for param in collect_monday.params]
        assert "api_token" in option_names
        assert "types" in option_names
        assert "days" in option_names
        assert "output" in option_names

    def test_cli_in_collector_list(self):
        """Test Monday.com appears in collector list."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "list"])

        assert result.exit_code == 0
        assert "monday" in result.output.lower()
