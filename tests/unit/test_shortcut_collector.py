"""
Tests for the Shortcut collector.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch, PropertyMock
import requests

from attestful.collectors.platforms.shortcut import (
    ShortcutCollector,
    ShortcutCollectorConfig,
)
from attestful.core.exceptions import CollectionError, ConfigurationError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def config():
    """Create a test configuration."""
    return ShortcutCollectorConfig(
        api_token="test-api-token-xxx",
        timeout=30,
        max_retries=3,
        page_size=100,
        days_of_history=90,
    )


@pytest.fixture
def collector(config):
    """Create a test collector."""
    return ShortcutCollector(config=config)


@pytest.fixture
def mock_member():
    """Create a mock member."""
    return {
        "id": "12345678-1234-1234-1234-123456789012",
        "profile": {
            "name": "Test User",
            "email_address": "test@example.com",
            "mention_name": "testuser",
            "two_factor_auth_activated": True,
        },
        "role": "owner",
        "state": "active",
        "disabled": False,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-06-01T00:00:00Z",
    }


@pytest.fixture
def mock_team():
    """Create a mock team (group)."""
    return {
        "id": "team-123",
        "name": "Engineering",
        "description": "Engineering team",
        "mention_name": "engineering",
        "color": "#0000ff",
        "member_ids": ["member-1", "member-2"],
        "workflow_ids": ["workflow-1"],
        "num_stories_started": 42,
        "archived": False,
    }


@pytest.fixture
def mock_project():
    """Create a mock project."""
    return {
        "id": 12345,
        "name": "Platform",
        "description": "Platform project",
        "abbreviation": "PLT",
        "color": "#ff0000",
        "team_id": "team-123",
        "iteration_length": 2,
        "start_time": "2024-01-01T00:00:00Z",
        "archived": False,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-06-01T00:00:00Z",
        "follower_ids": ["member-1"],
        "stats": {"num_stories": 100},
    }


@pytest.fixture
def mock_story():
    """Create a mock story."""
    recent_date = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat().replace("+00:00", "Z")
    return {
        "id": 67890,
        "name": "Implement feature X",
        "story_type": "feature",
        "workflow_state_id": 500000001,
        "workflow_state": {"name": "In Progress"},
        "epic_id": 11111,
        "project_id": 12345,
        "iteration_id": 22222,
        "estimate": 3,
        "started": True,
        "completed": False,
        "blocked": False,
        "blocker": False,
        "archived": False,
        "owner_ids": ["member-1"],
        "follower_ids": ["member-2"],
        "requested_by_id": "member-3",
        "labels": [{"name": "priority:high"}, {"name": "type:feature"}],
        "created_at": "2024-05-01T00:00:00Z",
        "updated_at": recent_date,
        "started_at": "2024-05-15T00:00:00Z",
        "completed_at": None,
        "deadline": "2024-07-01T00:00:00Z",
    }


@pytest.fixture
def mock_epic():
    """Create a mock epic."""
    return {
        "id": 11111,
        "name": "Epic Feature",
        "description": "A large feature",
        "state": "in progress",
        "milestone_id": 33333,
        "group_ids": ["team-123"],
        "owner_ids": ["member-1"],
        "follower_ids": ["member-2"],
        "planned_start_date": "2024-05-01",
        "deadline": "2024-08-01",
        "started": True,
        "completed": False,
        "archived": False,
        "created_at": "2024-04-01T00:00:00Z",
        "updated_at": "2024-06-01T00:00:00Z",
        "completed_at": None,
        "stats": {"num_stories_total": 10},
        "labels": [{"name": "epic-label"}],
    }


@pytest.fixture
def mock_iteration():
    """Create a mock iteration."""
    return {
        "id": 22222,
        "name": "Sprint 42",
        "description": "Sprint 42 description",
        "status": "started",
        "group_ids": ["team-123"],
        "follower_ids": ["member-1"],
        "start_date": "2024-06-01",
        "end_date": "2024-06-14",
        "created_at": "2024-05-28T00:00:00Z",
        "updated_at": "2024-06-01T00:00:00Z",
        "stats": {"num_stories": 15},
        "labels": [],
    }


@pytest.fixture
def mock_workflow():
    """Create a mock workflow."""
    return {
        "id": 500000000,
        "name": "Development",
        "description": "Standard development workflow",
        "team_id": "team-123",
        "default_state_id": 500000001,
        "auto_assign_owner": False,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z",
        "states": [
            {
                "id": 500000001,
                "name": "Ready for Development",
                "description": "Ready to be worked on",
                "type": "unstarted",
                "position": 1,
                "color": "#cccccc",
                "num_stories": 10,
            },
            {
                "id": 500000002,
                "name": "In Progress",
                "description": "Currently being worked on",
                "type": "started",
                "position": 2,
                "color": "#0000ff",
                "num_stories": 5,
            },
            {
                "id": 500000003,
                "name": "Done",
                "description": "Completed",
                "type": "done",
                "position": 3,
                "color": "#00ff00",
                "num_stories": 100,
            },
        ],
    }


# =============================================================================
# Initialization Tests
# =============================================================================


class TestShortcutCollectorInit:
    """Test collector initialization."""

    def test_init_with_config(self, config):
        """Test initialization with config."""
        collector = ShortcutCollector(config=config)
        assert collector.config == config
        assert collector.config.api_token == "test-api-token-xxx"

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = ShortcutCollector()
        assert collector.config is not None
        assert collector.config.api_token == ""

    def test_metadata(self, collector):
        """Test collector metadata."""
        assert collector.metadata.name == "ShortcutCollector"
        assert collector.metadata.platform == "shortcut"
        assert "shortcut_member" in collector.metadata.resource_types
        assert "members" in collector.metadata.evidence_types

    def test_platform(self, collector):
        """Test platform constant."""
        assert collector.PLATFORM == "shortcut"

    def test_api_url(self, collector):
        """Test API URL constant."""
        assert collector.API_URL == "https://api.app.shortcut.com/api/v3"


# =============================================================================
# Session Tests
# =============================================================================


class TestShortcutSession:
    """Test session management."""

    def test_session_creation(self, collector):
        """Test session is created correctly."""
        session = collector.session
        assert session is not None
        assert "Shortcut-Token" in session.headers
        assert session.headers["Shortcut-Token"] == "test-api-token-xxx"

    def test_session_cached(self, collector):
        """Test session is cached."""
        session1 = collector.session
        session2 = collector.session
        assert session1 is session2

    def test_session_requires_api_token(self):
        """Test session requires API token."""
        collector = ShortcutCollector(config=ShortcutCollectorConfig())
        with pytest.raises(ConfigurationError, match="API token is required"):
            _ = collector.session


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestValidateCredentials:
    """Test credential validation."""

    def test_validate_credentials_success(self, collector):
        """Test successful credential validation."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "id": "member-123",
            "profile": {"name": "Test User"},
        }
        mock_response.raise_for_status.return_value = None

        with patch.object(collector, "_get", return_value=mock_response.json.return_value):
            assert collector.validate_credentials() is True

    def test_validate_credentials_failure(self, collector):
        """Test failed credential validation."""
        with patch.object(collector, "_get", side_effect=ConfigurationError("Invalid Shortcut API token")):
            with pytest.raises(ConfigurationError, match="Invalid"):
                collector.validate_credentials()

    def test_validate_credentials_no_token(self):
        """Test validation without API token."""
        collector = ShortcutCollector(config=ShortcutCollectorConfig())
        with pytest.raises(ConfigurationError, match="API token is required"):
            collector.validate_credentials()


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestCollectEvidence:
    """Test evidence collection."""

    def test_collect_all_evidence_types(self, collector, mock_member, mock_team, mock_project, mock_story, mock_epic, mock_iteration, mock_workflow):
        """Test collecting all evidence types."""
        with patch.object(collector, "_get") as mock_get:
            mock_get.side_effect = [
                [mock_member],  # members
                [mock_team],  # teams (groups)
                [mock_project],  # projects
                [mock_epic],  # epics
                [mock_iteration],  # iterations
                [mock_workflow],  # workflows
            ]
            with patch.object(collector, "_search_stories", return_value=iter([mock_story])):
                result = collector.collect_evidence()

        assert result.platform == "shortcut"
        assert len(result.evidence_items) == 7
        assert result.errors == []

    def test_collect_specific_evidence_types(self, collector, mock_member, mock_team):
        """Test collecting specific evidence types."""
        with patch.object(collector, "_get") as mock_get:
            mock_get.side_effect = [
                [mock_member],  # members
                [mock_team],  # teams (groups)
            ]
            result = collector.collect_evidence(evidence_types=["members", "teams"])

        assert len(result.evidence_items) == 2
        evidence_types = [e.evidence_type for e in result.evidence_items]
        assert "members" in evidence_types
        assert "teams" in evidence_types

    def test_collect_evidence_invalid_type(self, collector):
        """Test collecting with invalid evidence type."""
        with pytest.raises(CollectionError, match="Unsupported evidence types"):
            collector.collect_evidence(evidence_types=["invalid_type"])

    def test_collect_members_evidence(self, collector, mock_member):
        """Test collecting members evidence."""
        with patch.object(collector, "_get", return_value=[mock_member]):
            result = collector.collect_evidence(evidence_types=["members"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "members"
        assert evidence.raw_data["total_count"] == 1
        assert evidence.raw_data["active_count"] == 1
        assert evidence.raw_data["mfa_enabled_count"] == 1

    def test_collect_teams_evidence(self, collector, mock_team):
        """Test collecting teams evidence."""
        with patch.object(collector, "_get", return_value=[mock_team]):
            result = collector.collect_evidence(evidence_types=["teams"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "teams"
        assert evidence.raw_data["total_count"] == 1
        assert evidence.raw_data["active_count"] == 1

    def test_collect_projects_evidence(self, collector, mock_project):
        """Test collecting projects evidence."""
        with patch.object(collector, "_get", return_value=[mock_project]):
            result = collector.collect_evidence(evidence_types=["projects"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "projects"
        assert evidence.raw_data["total_count"] == 1

    def test_collect_stories_evidence(self, collector, mock_story):
        """Test collecting stories evidence."""
        with patch.object(collector, "_search_stories", return_value=iter([mock_story])):
            result = collector.collect_evidence(evidence_types=["stories"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "stories"
        assert evidence.raw_data["total_count"] == 1
        assert "feature" in evidence.raw_data["by_type"]

    def test_collect_epics_evidence(self, collector, mock_epic):
        """Test collecting epics evidence."""
        with patch.object(collector, "_get", return_value=[mock_epic]):
            result = collector.collect_evidence(evidence_types=["epics"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "epics"
        assert evidence.raw_data["total_count"] == 1
        assert "in progress" in evidence.raw_data["by_state"]

    def test_collect_iterations_evidence(self, collector, mock_iteration):
        """Test collecting iterations evidence."""
        with patch.object(collector, "_get", return_value=[mock_iteration]):
            result = collector.collect_evidence(evidence_types=["iterations"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "iterations"
        assert evidence.raw_data["total_count"] == 1
        assert "started" in evidence.raw_data["by_status"]

    def test_collect_workflows_evidence(self, collector, mock_workflow):
        """Test collecting workflows evidence."""
        with patch.object(collector, "_get", return_value=[mock_workflow]):
            result = collector.collect_evidence(evidence_types=["workflows"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "workflows"
        assert evidence.raw_data["total_count"] == 1
        assert len(evidence.raw_data["workflows"][0]["states"]) == 3


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestCollectResources:
    """Test resource collection."""

    def test_collect_all_resource_types(self, collector, mock_member, mock_team, mock_project, mock_story):
        """Test collecting all resource types."""
        with patch.object(collector, "_get") as mock_get:
            mock_get.side_effect = [
                [mock_member],  # members
                [mock_team],  # teams (groups)
                [mock_project],  # projects
            ]
            with patch.object(collector, "_search_stories", return_value=iter([mock_story])):
                resources = collector.collect_resources()

        assert len(resources) == 4
        resource_types = [r.type for r in resources]
        assert "shortcut_member" in resource_types
        assert "shortcut_team" in resource_types
        assert "shortcut_project" in resource_types
        assert "shortcut_story" in resource_types

    def test_collect_specific_resource_types(self, collector, mock_member):
        """Test collecting specific resource types."""
        with patch.object(collector, "_get", return_value=[mock_member]):
            resources = collector.collect_resources(resource_types=["shortcut_member"])

        assert len(resources) == 1
        assert resources[0].type == "shortcut_member"

    def test_collect_resources_invalid_type(self, collector):
        """Test collecting with invalid resource type."""
        with pytest.raises(CollectionError, match="Unsupported resource types"):
            collector.collect_resources(resource_types=["invalid_type"])

    def test_collect_member_resources(self, collector, mock_member):
        """Test collecting member resources."""
        with patch.object(collector, "_get", return_value=[mock_member]):
            resources = collector.collect_resources(resource_types=["shortcut_member"])

        assert len(resources) == 1
        resource = resources[0]
        assert resource.type == "shortcut_member"
        assert resource.name == "Test User"
        assert resource.tags["role"] == "owner"
        assert resource.tags["mfa_enabled"] == "true"

    def test_collect_team_resources(self, collector, mock_team):
        """Test collecting team resources."""
        with patch.object(collector, "_get", return_value=[mock_team]):
            resources = collector.collect_resources(resource_types=["shortcut_team"])

        assert len(resources) == 1
        resource = resources[0]
        assert resource.type == "shortcut_team"
        assert resource.name == "Engineering"
        assert resource.tags["member_count"] == "2"

    def test_collect_project_resources(self, collector, mock_project):
        """Test collecting project resources."""
        with patch.object(collector, "_get", return_value=[mock_project]):
            resources = collector.collect_resources(resource_types=["shortcut_project"])

        assert len(resources) == 1
        resource = resources[0]
        assert resource.type == "shortcut_project"
        assert resource.name == "Platform"
        assert resource.tags["abbreviation"] == "PLT"

    def test_collect_story_resources(self, collector, mock_story):
        """Test collecting story resources."""
        with patch.object(collector, "_search_stories", return_value=iter([mock_story])):
            resources = collector.collect_resources(resource_types=["shortcut_story"])

        assert len(resources) == 1
        resource = resources[0]
        assert resource.type == "shortcut_story"
        assert resource.name == "Implement feature X"
        assert resource.tags["story_type"] == "feature"
        assert resource.tags["started"] == "true"
        assert resource.tags["completed"] == "false"


# =============================================================================
# Pagination Tests
# =============================================================================


class TestPagination:
    """Test pagination behavior."""

    def test_story_search_pagination(self, collector, mock_story):
        """Test story search pagination."""
        mock_response1 = MagicMock()
        mock_response1.json.return_value = {
            "data": [mock_story],
            "next": "cursor-123",
        }
        mock_response1.raise_for_status.return_value = None

        mock_response2 = MagicMock()
        mock_response2.json.return_value = {
            "data": [mock_story],
            "next": None,
        }
        mock_response2.raise_for_status.return_value = None

        with patch("requests.Session") as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            mock_session.post.side_effect = [mock_response1, mock_response2]
            mock_session.headers = {}

            # Reset session to use patched version
            collector._session = None
            stories = list(collector._search_stories("test query"))

        assert len(stories) == 2

    def test_story_search_stops_on_error(self, collector):
        """Test story search stops gracefully on error."""
        with patch("requests.Session") as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            mock_session.post.side_effect = requests.RequestException("Connection error")
            mock_session.headers = {}

            # Reset session to use patched version
            collector._session = None
            stories = list(collector._search_stories("test query"))

        assert len(stories) == 0


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Test error handling."""

    def test_evidence_collection_error(self, collector):
        """Test evidence collection handles errors gracefully."""
        with patch.object(collector, "_get", side_effect=Exception("API error")):
            result = collector.collect_evidence(evidence_types=["members"])

        assert len(result.evidence_items) == 0
        assert len(result.errors) == 1
        assert "Error collecting members" in result.errors[0]

    def test_partial_evidence_collection(self, collector, mock_member, mock_team):
        """Test partial evidence collection on error."""
        def side_effect(endpoint, *args, **kwargs):
            if endpoint == "members":
                return [mock_member]
            elif endpoint == "groups":
                raise Exception("Team API error")
            return []

        with patch.object(collector, "_get", side_effect=side_effect):
            result = collector.collect_evidence(evidence_types=["members", "teams"])

        assert len(result.evidence_items) == 1
        assert len(result.errors) == 1

    def test_resource_collection_error(self, collector):
        """Test resource collection handles errors gracefully."""
        with patch.object(collector, "_get", side_effect=Exception("API error")):
            resources = collector.collect_resources(resource_types=["shortcut_member"])

        # Should return empty list without raising
        assert len(resources) == 0


# =============================================================================
# Compliance Control Tests
# =============================================================================


class TestComplianceControls:
    """Test compliance control mappings."""

    def test_members_evidence_has_controls(self, collector, mock_member):
        """Test members evidence includes control mappings."""
        with patch.object(collector, "_get", return_value=[mock_member]):
            result = collector.collect_evidence(evidence_types=["members"])

        evidence = result.evidence_items[0]
        controls = evidence.metadata.get("compliance_controls", {})
        assert "soc2" in controls
        assert "nist_800_53" in controls
        assert "iso_27001" in controls
        assert "hitrust" in controls

    def test_stories_evidence_has_controls(self, collector, mock_story):
        """Test stories evidence includes control mappings."""
        with patch.object(collector, "_search_stories", return_value=iter([mock_story])):
            result = collector.collect_evidence(evidence_types=["stories"])

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
# CLI Tests
# =============================================================================


class TestCLI:
    """Test CLI integration."""

    def test_cli_command_exists(self):
        """Test CLI command is registered."""
        from attestful.cli.main import collect

        assert "shortcut" in [cmd.name for cmd in collect.commands.values()]

    def test_cli_command_options(self):
        """Test CLI command has expected options."""
        from attestful.cli.main import collect_shortcut

        option_names = [param.name for param in collect_shortcut.params]
        assert "api_token" in option_names
        assert "types" in option_names
        assert "days" in option_names
        assert "output" in option_names

    def test_cli_in_collector_list(self):
        """Test Shortcut appears in collector list."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "list"])

        assert result.exit_code == 0
        assert "shortcut" in result.output.lower()
