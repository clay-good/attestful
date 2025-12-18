"""
Tests for the Asana collector.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
import requests

from attestful.collectors.platforms.asana import (
    AsanaCollector,
    AsanaCollectorConfig,
)
from attestful.core.exceptions import CollectionError, ConfigurationError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def config():
    """Create a test configuration."""
    return AsanaCollectorConfig(
        access_token="1/1234567890:abcdef123456",
        workspace_gid="",
        timeout=30,
        max_retries=3,
        page_size=100,
        days_of_history=90,
    )


@pytest.fixture
def config_with_workspace():
    """Create a test configuration with workspace."""
    return AsanaCollectorConfig(
        access_token="1/1234567890:abcdef123456",
        workspace_gid="1234567890",
        timeout=30,
        max_retries=3,
        page_size=100,
        days_of_history=90,
    )


@pytest.fixture
def collector(config):
    """Create a test collector."""
    return AsanaCollector(config=config)


@pytest.fixture
def mock_workspace():
    """Create a mock workspace."""
    return {
        "gid": "1234567890",
        "name": "Test Workspace",
        "is_organization": True,
        "email_domains": ["example.com"],
    }


@pytest.fixture
def mock_user():
    """Create a mock user."""
    return {
        "gid": "user-123",
        "name": "Test User",
        "email": "test@example.com",
        "photo": {"image_128x128": "https://example.com/photo.png"},
        "resource_type": "user",
    }


@pytest.fixture
def mock_team():
    """Create a mock team."""
    return {
        "gid": "team-456",
        "name": "Engineering",
        "description": "Engineering team",
        "permalink_url": "https://app.asana.com/0/team/456",
        "visibility": "public",
    }


@pytest.fixture
def mock_project():
    """Create a mock project."""
    return {
        "gid": "project-789",
        "name": "Platform Project",
        "archived": False,
        "color": "dark-blue",
        "created_at": "2024-01-01T00:00:00.000Z",
        "modified_at": "2024-06-15T12:00:00.000Z",
        "notes": "Platform development project",
        "owner": {"gid": "user-123", "name": "Test User"},
        "public": True,
        "team": {"gid": "team-456", "name": "Engineering"},
        "current_status": {"text": "On track"},
        "due_on": "2024-12-31",
        "start_on": "2024-01-01",
        "permalink_url": "https://app.asana.com/0/789",
        "default_view": "board",
    }


@pytest.fixture
def mock_task():
    """Create a mock task."""
    recent_date = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    return {
        "gid": "task-111",
        "name": "Implement feature X",
        "assignee": {"gid": "user-123", "name": "Test User"},
        "assignee_status": "inbox",
        "completed": False,
        "completed_at": None,
        "created_at": "2024-06-01T00:00:00.000Z",
        "modified_at": recent_date,
        "due_on": "2024-07-15",
        "due_at": None,
        "start_on": "2024-06-15",
        "start_at": None,
        "notes": "Implement the new feature",
        "num_subtasks": 3,
        "parent": None,
        "permalink_url": "https://app.asana.com/0/789/111",
        "resource_subtype": "default_task",
        "tags": [{"name": "priority:high"}, {"name": "sprint:42"}],
        "custom_fields": [],
    }


@pytest.fixture
def mock_portfolio():
    """Create a mock portfolio."""
    return {
        "gid": "portfolio-222",
        "name": "Q3 Initiatives",
        "color": "light-green",
        "created_at": "2024-04-01T00:00:00.000Z",
        "owner": {"gid": "user-123", "name": "Test User"},
        "public": True,
        "permalink_url": "https://app.asana.com/0/portfolio/222",
        "members": [{"gid": "user-123", "name": "Test User"}],
    }


@pytest.fixture
def mock_goal():
    """Create a mock goal."""
    return {
        "gid": "goal-333",
        "name": "Increase customer satisfaction",
        "owner": {"gid": "user-123", "name": "Test User"},
        "team": {"gid": "team-456", "name": "Engineering"},
        "time_period": {"display_name": "Q3 2024"},
        "due_on": "2024-09-30",
        "start_on": "2024-07-01",
        "status": "on_track",
        "is_workspace_level": False,
        "num_likes": 5,
    }


@pytest.fixture
def mock_iteration():
    """Create a mock iteration."""
    return {
        "gid": "iteration-444",
        "name": "Sprint 42",
    }


# =============================================================================
# Initialization Tests
# =============================================================================


class TestAsanaCollectorInit:
    """Test collector initialization."""

    def test_init_with_config(self, config):
        """Test initialization with config."""
        collector = AsanaCollector(config=config)
        assert collector.config == config
        assert collector.config.access_token == "1/1234567890:abcdef123456"

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = AsanaCollector()
        assert collector.config is not None
        assert collector.config.access_token == ""

    def test_init_with_workspace(self, config_with_workspace):
        """Test initialization with workspace specified."""
        collector = AsanaCollector(config=config_with_workspace)
        assert collector.config.workspace_gid == "1234567890"

    def test_metadata(self, collector):
        """Test collector metadata."""
        assert collector.metadata.name == "AsanaCollector"
        assert collector.metadata.platform == "asana"
        assert "asana_user" in collector.metadata.resource_types
        assert "users" in collector.metadata.evidence_types

    def test_platform(self, collector):
        """Test platform constant."""
        assert collector.PLATFORM == "asana"

    def test_api_url(self, collector):
        """Test API URL constant."""
        assert collector.API_URL == "https://app.asana.com/api/1.0"


# =============================================================================
# Session Tests
# =============================================================================


class TestAsanaSession:
    """Test session management."""

    def test_session_creation(self, collector):
        """Test session is created correctly."""
        session = collector.session
        assert session is not None
        assert "Authorization" in session.headers
        assert session.headers["Authorization"] == "Bearer 1/1234567890:abcdef123456"

    def test_session_cached(self, collector):
        """Test session is cached."""
        session1 = collector.session
        session2 = collector.session
        assert session1 is session2

    def test_session_requires_access_token(self):
        """Test session requires access token."""
        collector = AsanaCollector(config=AsanaCollectorConfig())
        with pytest.raises(ConfigurationError, match="access token is required"):
            _ = collector.session


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestValidateCredentials:
    """Test credential validation."""

    def test_validate_credentials_success(self, collector):
        """Test successful credential validation."""
        mock_response = {
            "data": {
                "gid": "user-123",
                "name": "Test User",
                "email": "test@example.com",
            }
        }

        with patch.object(collector, "_get", return_value=mock_response):
            assert collector.validate_credentials() is True

    def test_validate_credentials_failure(self, collector):
        """Test failed credential validation."""
        with patch.object(collector, "_get", side_effect=ConfigurationError("Invalid Asana access token")):
            with pytest.raises(ConfigurationError, match="Invalid"):
                collector.validate_credentials()

    def test_validate_credentials_no_token(self):
        """Test validation without access token."""
        collector = AsanaCollector(config=AsanaCollectorConfig())
        with pytest.raises(ConfigurationError, match="access token is required"):
            collector.validate_credentials()


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestCollectEvidence:
    """Test evidence collection."""

    def test_collect_all_evidence_types(self, collector, mock_workspace, mock_user, mock_team, mock_project, mock_task, mock_portfolio, mock_goal):
        """Test collecting all evidence types."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            with patch.object(collector, "_paginate") as mock_paginate:
                def paginate_side_effect(endpoint, params=None):
                    if "users" in endpoint:
                        return iter([mock_user])
                    elif "teams" in endpoint:
                        if "/users" in endpoint:
                            return iter([mock_user])
                        return iter([mock_team])
                    elif "projects" in endpoint:
                        return iter([mock_project])
                    elif "tasks" in endpoint:
                        return iter([mock_task])
                    elif "portfolios" in endpoint:
                        if "/items" in endpoint:
                            return iter([{"gid": "project-789", "name": "Platform Project", "resource_type": "project"}])
                        return iter([mock_portfolio])
                    elif "goals" in endpoint:
                        return iter([mock_goal])
                    return iter([])

                mock_paginate.side_effect = paginate_side_effect

                with patch.object(collector, "_get") as mock_get:
                    mock_get.return_value = {"data": mock_workspace}
                    result = collector.collect_evidence()

        assert result.platform == "asana"
        assert len(result.evidence_items) == 7
        assert result.errors == []

    def test_collect_specific_evidence_types(self, collector, mock_workspace, mock_user, mock_team):
        """Test collecting specific evidence types."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            with patch.object(collector, "_paginate") as mock_paginate:
                def paginate_side_effect(endpoint, params=None):
                    if "users" in endpoint:
                        return iter([mock_user])
                    elif "teams" in endpoint:
                        if "/users" in endpoint:
                            return iter([mock_user])
                        return iter([mock_team])
                    return iter([])

                mock_paginate.side_effect = paginate_side_effect
                result = collector.collect_evidence(evidence_types=["users", "teams"])

        assert len(result.evidence_items) == 2
        evidence_types = [e.evidence_type for e in result.evidence_items]
        assert "users" in evidence_types
        assert "teams" in evidence_types

    def test_collect_evidence_invalid_type(self, collector):
        """Test collecting with invalid evidence type."""
        with pytest.raises(CollectionError, match="Unsupported evidence types"):
            collector.collect_evidence(evidence_types=["invalid_type"])

    def test_collect_users_evidence(self, collector, mock_workspace, mock_user):
        """Test collecting users evidence."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            with patch.object(collector, "_paginate", return_value=iter([mock_user])):
                result = collector.collect_evidence(evidence_types=["users"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "users"
        assert evidence.raw_data["total_count"] == 1

    def test_collect_teams_evidence(self, collector, mock_workspace, mock_team, mock_user):
        """Test collecting teams evidence."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            with patch.object(collector, "_paginate") as mock_paginate:
                def paginate_side_effect(endpoint, params=None):
                    if "/users" in endpoint:
                        return iter([mock_user])
                    return iter([mock_team])

                mock_paginate.side_effect = paginate_side_effect
                result = collector.collect_evidence(evidence_types=["teams"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "teams"
        assert evidence.raw_data["total_count"] == 1

    def test_collect_projects_evidence(self, collector, mock_workspace, mock_project):
        """Test collecting projects evidence."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            with patch.object(collector, "_paginate", return_value=iter([mock_project])):
                result = collector.collect_evidence(evidence_types=["projects"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "projects"
        assert evidence.raw_data["total_count"] == 1
        assert evidence.raw_data["public_count"] == 1

    def test_collect_tasks_evidence(self, collector, mock_workspace, mock_project, mock_task):
        """Test collecting tasks evidence."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            with patch.object(collector, "_paginate") as mock_paginate:
                def paginate_side_effect(endpoint, params=None):
                    if "projects" in endpoint and "tasks" not in endpoint:
                        return iter([mock_project])
                    elif "tasks" in endpoint:
                        return iter([mock_task])
                    return iter([])

                mock_paginate.side_effect = paginate_side_effect
                result = collector.collect_evidence(evidence_types=["tasks"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "tasks"
        assert evidence.raw_data["total_count"] == 1
        assert evidence.raw_data["by_status"]["incomplete"] == 1

    def test_collect_portfolios_evidence(self, collector, mock_workspace, mock_portfolio):
        """Test collecting portfolios evidence."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            with patch.object(collector, "_paginate") as mock_paginate:
                def paginate_side_effect(endpoint, params=None):
                    if "/items" in endpoint:
                        return iter([{"gid": "project-789", "name": "Project", "resource_type": "project"}])
                    return iter([mock_portfolio])

                mock_paginate.side_effect = paginate_side_effect
                result = collector.collect_evidence(evidence_types=["portfolios"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "portfolios"
        assert evidence.raw_data["total_count"] == 1

    def test_collect_goals_evidence(self, collector, mock_workspace, mock_goal):
        """Test collecting goals evidence."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            with patch.object(collector, "_paginate", return_value=iter([mock_goal])):
                result = collector.collect_evidence(evidence_types=["goals"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "goals"
        assert evidence.raw_data["total_count"] == 1
        assert "on_track" in evidence.raw_data["by_status"]

    def test_collect_workspaces_evidence(self, collector, mock_workspace):
        """Test collecting workspaces evidence."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            with patch.object(collector, "_get", return_value={"data": mock_workspace}):
                result = collector.collect_evidence(evidence_types=["workspaces"])

        assert len(result.evidence_items) == 1
        evidence = result.evidence_items[0]
        assert evidence.evidence_type == "workspaces"
        assert evidence.raw_data["total_count"] == 1
        assert evidence.raw_data["organization_count"] == 1


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestCollectResources:
    """Test resource collection."""

    def test_collect_all_resource_types(self, collector, mock_workspace, mock_user, mock_team, mock_project, mock_task):
        """Test collecting all resource types."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            with patch.object(collector, "_paginate") as mock_paginate:
                def paginate_side_effect(endpoint, params=None):
                    if "users" in endpoint:
                        return iter([mock_user])
                    elif "teams" in endpoint:
                        return iter([mock_team])
                    elif "projects" in endpoint and "tasks" not in endpoint:
                        return iter([mock_project])
                    elif "tasks" in endpoint:
                        return iter([mock_task])
                    return iter([])

                mock_paginate.side_effect = paginate_side_effect
                resources = collector.collect_resources()

        assert len(resources) == 4
        resource_types = [r.type for r in resources]
        assert "asana_user" in resource_types
        assert "asana_team" in resource_types
        assert "asana_project" in resource_types
        assert "asana_task" in resource_types

    def test_collect_specific_resource_types(self, collector, mock_workspace, mock_user):
        """Test collecting specific resource types."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            with patch.object(collector, "_paginate", return_value=iter([mock_user])):
                resources = collector.collect_resources(resource_types=["asana_user"])

        assert len(resources) == 1
        assert resources[0].type == "asana_user"

    def test_collect_resources_invalid_type(self, collector):
        """Test collecting with invalid resource type."""
        with pytest.raises(CollectionError, match="Unsupported resource types"):
            collector.collect_resources(resource_types=["invalid_type"])

    def test_collect_user_resources(self, collector, mock_workspace, mock_user):
        """Test collecting user resources."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            with patch.object(collector, "_paginate", return_value=iter([mock_user])):
                resources = collector.collect_resources(resource_types=["asana_user"])

        assert len(resources) == 1
        resource = resources[0]
        assert resource.type == "asana_user"
        assert resource.name == "Test User"
        assert resource.tags["has_email"] == "true"

    def test_collect_team_resources(self, collector, mock_workspace, mock_team):
        """Test collecting team resources."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            with patch.object(collector, "_paginate", return_value=iter([mock_team])):
                resources = collector.collect_resources(resource_types=["asana_team"])

        assert len(resources) == 1
        resource = resources[0]
        assert resource.type == "asana_team"
        assert resource.name == "Engineering"
        assert resource.tags["visibility"] == "public"

    def test_collect_project_resources(self, collector, mock_workspace, mock_project):
        """Test collecting project resources."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            with patch.object(collector, "_paginate", return_value=iter([mock_project])):
                resources = collector.collect_resources(resource_types=["asana_project"])

        assert len(resources) == 1
        resource = resources[0]
        assert resource.type == "asana_project"
        assert resource.name == "Platform Project"
        assert resource.tags["public"] == "true"
        assert resource.tags["archived"] == "false"

    def test_collect_task_resources(self, collector, mock_workspace, mock_project, mock_task):
        """Test collecting task resources."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            with patch.object(collector, "_paginate") as mock_paginate:
                def paginate_side_effect(endpoint, params=None):
                    if "projects" in endpoint and "tasks" not in endpoint:
                        return iter([mock_project])
                    elif "tasks" in endpoint:
                        return iter([mock_task])
                    return iter([])

                mock_paginate.side_effect = paginate_side_effect
                resources = collector.collect_resources(resource_types=["asana_task"])

        assert len(resources) == 1
        resource = resources[0]
        assert resource.type == "asana_task"
        assert resource.name == "Implement feature X"
        assert resource.tags["completed"] == "false"
        assert resource.tags["has_assignee"] == "true"


# =============================================================================
# Pagination Tests
# =============================================================================


class TestPagination:
    """Test pagination behavior."""

    def test_pagination_multiple_pages(self, collector, mock_user):
        """Test pagination with multiple pages."""
        mock_response1 = MagicMock()
        mock_response1.json.return_value = {
            "data": [mock_user],
            "next_page": {"offset": "cursor-123"},
        }
        mock_response1.raise_for_status.return_value = None

        mock_response2 = MagicMock()
        mock_response2.json.return_value = {
            "data": [mock_user],
            "next_page": None,
        }
        mock_response2.raise_for_status.return_value = None

        with patch("requests.Session") as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            mock_session.get.side_effect = [mock_response1, mock_response2]
            mock_session.headers = {}

            collector._session = None
            users = list(collector._paginate("users"))

        assert len(users) == 2

    def test_pagination_stops_on_error(self, collector):
        """Test pagination stops gracefully on error."""
        with patch("requests.Session") as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            mock_session.get.side_effect = requests.RequestException("Connection error")
            mock_session.headers = {}

            collector._session = None
            users = list(collector._paginate("users"))

        assert len(users) == 0


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Test error handling."""

    def test_evidence_collection_error(self, collector, mock_workspace):
        """Test evidence collection handles errors gracefully."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            with patch.object(collector, "_paginate", side_effect=Exception("API error")):
                result = collector.collect_evidence(evidence_types=["users"])

        assert len(result.evidence_items) == 0
        assert len(result.errors) == 1
        assert "Error collecting users" in result.errors[0]

    def test_partial_evidence_collection(self, collector, mock_workspace, mock_user):
        """Test partial evidence collection on error."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            call_count = [0]

            def paginate_side_effect(endpoint, params=None):
                call_count[0] += 1
                if "users" in endpoint:
                    return iter([mock_user])
                elif "teams" in endpoint:
                    raise Exception("Team API error")
                return iter([])

            with patch.object(collector, "_paginate", side_effect=paginate_side_effect):
                result = collector.collect_evidence(evidence_types=["users", "teams"])

        assert len(result.evidence_items) == 1
        assert len(result.errors) == 1

    def test_resource_collection_error(self, collector, mock_workspace):
        """Test resource collection handles errors gracefully."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            with patch.object(collector, "_paginate", side_effect=Exception("API error")):
                resources = collector.collect_resources(resource_types=["asana_user"])

        # Should return empty list without raising
        assert len(resources) == 0


# =============================================================================
# Compliance Control Tests
# =============================================================================


class TestComplianceControls:
    """Test compliance control mappings."""

    def test_users_evidence_has_controls(self, collector, mock_workspace, mock_user):
        """Test users evidence includes control mappings."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            with patch.object(collector, "_paginate", return_value=iter([mock_user])):
                result = collector.collect_evidence(evidence_types=["users"])

        evidence = result.evidence_items[0]
        controls = evidence.metadata.get("compliance_controls", {})
        assert "soc2" in controls
        assert "nist_800_53" in controls
        assert "iso_27001" in controls
        assert "hitrust" in controls

    def test_tasks_evidence_has_controls(self, collector, mock_workspace, mock_project, mock_task):
        """Test tasks evidence includes control mappings."""
        with patch.object(collector, "_get_workspaces", return_value=[mock_workspace]):
            with patch.object(collector, "_paginate") as mock_paginate:
                def paginate_side_effect(endpoint, params=None):
                    if "projects" in endpoint and "tasks" not in endpoint:
                        return iter([mock_project])
                    elif "tasks" in endpoint:
                        return iter([mock_task])
                    return iter([])

                mock_paginate.side_effect = paginate_side_effect
                result = collector.collect_evidence(evidence_types=["tasks"])

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
# Workspace Tests
# =============================================================================


class TestWorkspaces:
    """Test workspace handling."""

    def test_get_all_workspaces(self, collector, mock_workspace):
        """Test getting all workspaces when none specified."""
        with patch.object(collector, "_paginate", return_value=iter([mock_workspace])):
            workspaces = collector._get_workspaces()

        assert len(workspaces) == 1
        assert workspaces[0]["gid"] == "1234567890"

    def test_get_specific_workspace(self, config_with_workspace, mock_workspace):
        """Test getting specific workspace when GID provided."""
        collector = AsanaCollector(config=config_with_workspace)

        mock_response = {"data": mock_workspace}
        with patch.object(collector, "_get", return_value=mock_response):
            workspaces = collector._get_workspaces()

        assert len(workspaces) == 1
        assert workspaces[0]["gid"] == "1234567890"

    def test_workspaces_cached(self, collector, mock_workspace):
        """Test workspaces are cached."""
        with patch.object(collector, "_paginate", return_value=iter([mock_workspace])) as mock_paginate:
            _ = collector._get_workspaces()
            _ = collector._get_workspaces()

        # Should only call paginate once
        assert mock_paginate.call_count == 1


# =============================================================================
# CLI Tests
# =============================================================================


class TestCLI:
    """Test CLI integration."""

    def test_cli_command_exists(self):
        """Test CLI command is registered."""
        from attestful.cli.main import collect

        assert "asana" in [cmd.name for cmd in collect.commands.values()]

    def test_cli_command_options(self):
        """Test CLI command has expected options."""
        from attestful.cli.main import collect_asana

        option_names = [param.name for param in collect_asana.params]
        assert "access_token" in option_names
        assert "workspace_gid" in option_names
        assert "types" in option_names
        assert "days" in option_names
        assert "output" in option_names

    def test_cli_in_collector_list(self):
        """Test Asana appears in collector list."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "list"])

        assert result.exit_code == 0
        assert "asana" in result.output.lower()
