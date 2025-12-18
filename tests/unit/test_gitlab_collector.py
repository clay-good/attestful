"""
Unit tests for GitLab collector.
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from attestful.collectors.platforms.gitlab import (
    GitLabCollector,
    GitLabCollectorConfig,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_config():
    """Create a mock GitLab configuration."""
    return GitLabCollectorConfig(
        token="test-token",
        base_url="https://gitlab.com",
        group_id="my-group",
        include_subgroups=True,
        timeout=30,
        max_retries=3,
        page_size=100,
        days_of_history=90,
    )


@pytest.fixture
def mock_project():
    """Create a mock project response."""
    return {
        "id": 12345,
        "name": "my-project",
        "path_with_namespace": "my-group/my-project",
        "description": "Test project",
        "visibility": "private",
        "archived": False,
        "default_branch": "main",
        "web_url": "https://gitlab.com/my-group/my-project",
        "created_at": "2024-01-15T10:00:00Z",
        "last_activity_at": "2024-03-01T14:30:00Z",
        "namespace": {"full_path": "my-group"},
        "merge_requests_enabled": True,
        "issues_enabled": True,
        "wiki_enabled": True,
        "jobs_enabled": True,
        "container_registry_enabled": True,
    }


@pytest.fixture
def mock_user():
    """Create a mock user/member response."""
    return {
        "id": 100,
        "username": "testuser",
        "name": "Test User",
        "state": "active",
        "access_level": 40,  # Maintainer
        "email": "test@example.com",
        "web_url": "https://gitlab.com/testuser",
        "expires_at": None,
    }


@pytest.fixture
def mock_group():
    """Create a mock group response."""
    return {
        "id": 50,
        "name": "my-group",
        "full_path": "my-group",
        "description": "Test group",
        "visibility": "private",
        "web_url": "https://gitlab.com/groups/my-group",
        "created_at": "2023-01-01T00:00:00Z",
    }


@pytest.fixture
def mock_protected_branch():
    """Create a mock protected branch response."""
    return {
        "name": "main",
        "push_access_levels": [{"access_level": 40}],
        "merge_access_levels": [{"access_level": 40}],
        "allow_force_push": False,
        "code_owner_approval_required": True,
    }


@pytest.fixture
def mock_merge_request():
    """Create a mock merge request response."""
    return {
        "id": 1000,
        "iid": 42,
        "title": "Add new feature",
        "state": "merged",
        "source_branch": "feature/new-feature",
        "target_branch": "main",
        "author": {"username": "developer"},
        "merged_by": {"username": "maintainer"},
        "created_at": "2024-03-01T10:00:00Z",
        "merged_at": "2024-03-02T14:00:00Z",
        "has_conflicts": False,
        "user_notes_count": 5,
        "upvotes": 2,
        "downvotes": 0,
    }


@pytest.fixture
def mock_pipeline():
    """Create a mock pipeline response."""
    return {
        "id": 5000,
        "ref": "main",
        "status": "success",
        "source": "push",
        "created_at": "2024-03-01T10:00:00Z",
        "updated_at": "2024-03-01T10:30:00Z",
        "web_url": "https://gitlab.com/my-group/my-project/-/pipelines/5000",
    }


@pytest.fixture
def mock_vulnerability():
    """Create a mock vulnerability response."""
    return {
        "id": 8000,
        "title": "SQL Injection vulnerability",
        "severity": "high",
        "state": "detected",
        "scanner": {"name": "sast"},
        "created_at": "2024-02-15T08:00:00Z",
        "dismissed_at": None,
        "resolved_at": None,
        "location": {"file": "app/models/user.py", "line": 42},
    }


@pytest.fixture
def mock_deploy_key():
    """Create a mock deploy key response."""
    return {
        "id": 9000,
        "title": "Production Deploy Key",
        "can_push": False,
        "created_at": "2024-01-01T00:00:00Z",
        "expires_at": None,
        "fingerprint": "SHA256:abc123...",
    }


@pytest.fixture
def mock_runner():
    """Create a mock runner response."""
    return {
        "id": 7000,
        "description": "Docker Runner",
        "status": "online",
        "runner_type": "group_type",
        "is_shared": False,
        "active": True,
        "ip_address": "10.0.0.1",
        "contacted_at": "2024-03-15T12:00:00Z",
        "tag_list": ["docker", "linux"],
        "version": "16.8.0",
        "online": True,
    }


@pytest.fixture
def mock_audit_event():
    """Create a mock audit event response."""
    return {
        "id": 6000,
        "author_id": 100,
        "author": {"name": "Admin User"},
        "entity_id": 50,
        "entity_type": "Group",
        "entity_path": "my-group",
        "event_type": "member_added",
        "details": {"add": "user", "as": "Developer"},
        "created_at": "2024-03-15T10:00:00Z",
        "ip_address": "192.168.1.1",
    }


# =============================================================================
# Configuration Tests
# =============================================================================


class TestGitLabCollectorConfig:
    """Tests for GitLab collector configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        config = GitLabCollectorConfig()
        assert config.token == ""
        assert config.base_url == "https://gitlab.com"
        assert config.group_id == ""
        assert config.include_subgroups is True
        assert config.timeout == 30
        assert config.max_retries == 3
        assert config.page_size == 100
        assert config.days_of_history == 90

    def test_custom_config(self, mock_config):
        """Test custom configuration values."""
        assert mock_config.token == "test-token"
        assert mock_config.base_url == "https://gitlab.com"
        assert mock_config.group_id == "my-group"

    def test_self_hosted_config(self):
        """Test self-hosted GitLab configuration."""
        config = GitLabCollectorConfig(
            token="token",
            base_url="https://gitlab.mycompany.com",
        )
        assert config.base_url == "https://gitlab.mycompany.com"


# =============================================================================
# Collector Initialization Tests
# =============================================================================


class TestGitLabCollectorInit:
    """Tests for GitLab collector initialization."""

    def test_init_with_config(self, mock_config):
        """Test initialization with config."""
        collector = GitLabCollector(config=mock_config)
        assert collector.config == mock_config
        assert collector.PLATFORM == "gitlab"

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = GitLabCollector()
        assert collector.config is not None
        assert collector.config.token == ""

    def test_api_url(self, mock_config):
        """Test API URL generation."""
        collector = GitLabCollector(config=mock_config)
        assert collector.api_url == "https://gitlab.com/api/v4"

    def test_api_url_self_hosted(self):
        """Test self-hosted API URL generation."""
        config = GitLabCollectorConfig(base_url="https://gitlab.mycompany.com")
        collector = GitLabCollector(config=config)
        assert collector.api_url == "https://gitlab.mycompany.com/api/v4"

    def test_supported_types(self, mock_config):
        """Test supported resource and evidence types."""
        collector = GitLabCollector(config=mock_config)
        assert "gitlab_project" in collector.SUPPORTED_RESOURCE_TYPES
        assert "gitlab_user" in collector.SUPPORTED_RESOURCE_TYPES
        assert "gitlab_group" in collector.SUPPORTED_RESOURCE_TYPES
        assert "gitlab_runner" in collector.SUPPORTED_RESOURCE_TYPES

        assert "projects" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "protected_branches" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "merge_requests" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "pipelines" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "members" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "vulnerabilities" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "audit_events" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "deploy_keys" in collector.SUPPORTED_EVIDENCE_TYPES


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestCredentialValidation:
    """Tests for credential validation."""

    @patch("attestful.collectors.platforms.gitlab.requests.Session")
    def test_validate_credentials_success(self, mock_session_class, mock_config):
        """Test successful credential validation."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"username": "testuser", "id": 100}
        mock_session.request.return_value = mock_response

        collector = GitLabCollector(config=mock_config)
        assert collector.validate_credentials() is True

    @patch("attestful.collectors.platforms.gitlab.requests.Session")
    def test_validate_credentials_error(self, mock_session_class, mock_config):
        """Test credential validation error."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_session.request.side_effect = Exception("Unauthorized")

        collector = GitLabCollector(config=mock_config)
        assert collector.validate_credentials() is False


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestResourceCollection:
    """Tests for resource collection."""

    @patch("attestful.collectors.platforms.gitlab.requests.Session")
    def test_collect_projects(self, mock_session_class, mock_config, mock_project):
        """Test collecting project resources."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [mock_project]
        mock_response.headers = {"X-Total-Pages": "1"}
        mock_session.request.return_value = mock_response

        collector = GitLabCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["gitlab_project"])

        assert len(resources) == 1
        assert resources[0].type == "gitlab_project"
        assert resources[0].name == "my-group/my-project"
        assert resources[0].tags["visibility"] == "private"

    @patch("attestful.collectors.platforms.gitlab.requests.Session")
    def test_collect_users(self, mock_session_class, mock_config, mock_user):
        """Test collecting user resources."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [mock_user]
        mock_response.headers = {"X-Total-Pages": "1"}
        mock_session.request.return_value = mock_response

        collector = GitLabCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["gitlab_user"])

        assert len(resources) == 1
        assert resources[0].type == "gitlab_user"
        assert resources[0].name == "testuser"
        assert resources[0].tags["access_level"] == "40"

    @patch("attestful.collectors.platforms.gitlab.requests.Session")
    def test_collect_groups(self, mock_session_class, mock_config, mock_group):
        """Test collecting group resources."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_group
        mock_response.headers = {"X-Total-Pages": "1"}
        mock_session.request.return_value = mock_response

        collector = GitLabCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["gitlab_group"])

        assert len(resources) >= 1
        assert resources[0].type == "gitlab_group"

    @patch("attestful.collectors.platforms.gitlab.requests.Session")
    def test_collect_runners(self, mock_session_class, mock_config, mock_runner):
        """Test collecting runner resources."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [mock_runner]
        mock_response.headers = {"X-Total-Pages": "1"}
        mock_session.request.return_value = mock_response

        collector = GitLabCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["gitlab_runner"])

        assert len(resources) == 1
        assert resources[0].type == "gitlab_runner"
        assert resources[0].name == "Docker Runner"


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestEvidenceCollection:
    """Tests for evidence collection."""

    @patch("attestful.collectors.platforms.gitlab.requests.Session")
    def test_collect_projects_evidence(self, mock_session_class, mock_config, mock_project):
        """Test collecting projects evidence."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [mock_project]
        mock_response.headers = {"X-Total-Pages": "1"}
        mock_session.request.return_value = mock_response

        collector = GitLabCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["projects"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "projects"
        assert result.evidence_items[0].raw_data["total_count"] == 1

    @patch("attestful.collectors.platforms.gitlab.requests.Session")
    def test_collect_protected_branches_evidence(self, mock_session_class, mock_config, mock_project, mock_protected_branch):
        """Test collecting protected branches evidence."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        def mock_request(*args, **kwargs):
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"X-Total-Pages": "1"}
            url = args[1] if len(args) > 1 else kwargs.get("url", "")
            if "protected_branches" in url:
                mock_response.json.return_value = [mock_protected_branch]
            else:
                mock_response.json.return_value = [mock_project]
            return mock_response

        mock_session.request.side_effect = mock_request

        collector = GitLabCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["protected_branches"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "protected_branches"
        assert result.evidence_items[0].raw_data["total_protected"] >= 0

    @patch("attestful.collectors.platforms.gitlab.requests.Session")
    def test_collect_merge_requests_evidence(self, mock_session_class, mock_config, mock_project, mock_merge_request):
        """Test collecting merge requests evidence."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        def mock_request(*args, **kwargs):
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"X-Total-Pages": "1"}
            url = args[1] if len(args) > 1 else kwargs.get("url", "")
            if "merge_requests" in url:
                mock_response.json.return_value = [mock_merge_request]
            else:
                mock_response.json.return_value = [mock_project]
            return mock_response

        mock_session.request.side_effect = mock_request

        collector = GitLabCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["merge_requests"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "merge_requests"
        assert "by_state" in result.evidence_items[0].raw_data

    @patch("attestful.collectors.platforms.gitlab.requests.Session")
    def test_collect_pipelines_evidence(self, mock_session_class, mock_config, mock_project, mock_pipeline):
        """Test collecting pipelines evidence."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        def mock_request(*args, **kwargs):
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"X-Total-Pages": "1"}
            url = args[1] if len(args) > 1 else kwargs.get("url", "")
            if "/pipelines/" in url and "/jobs" in url:
                mock_response.json.return_value = []
            elif "pipelines" in url:
                mock_response.json.return_value = [mock_pipeline]
            else:
                mock_response.json.return_value = [mock_project]
            return mock_response

        mock_session.request.side_effect = mock_request

        collector = GitLabCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["pipelines"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "pipelines"
        assert "by_status" in result.evidence_items[0].raw_data

    @patch("attestful.collectors.platforms.gitlab.requests.Session")
    def test_collect_members_evidence(self, mock_session_class, mock_config, mock_user):
        """Test collecting members evidence."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [mock_user]
        mock_response.headers = {"X-Total-Pages": "1"}
        mock_session.request.return_value = mock_response

        collector = GitLabCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["members"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "members"
        assert "by_access_level" in result.evidence_items[0].raw_data
        assert "high_privilege_users" in result.evidence_items[0].raw_data

    @patch("attestful.collectors.platforms.gitlab.requests.Session")
    def test_collect_deploy_keys_evidence(self, mock_session_class, mock_config, mock_project, mock_deploy_key):
        """Test collecting deploy keys evidence."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        def mock_request(*args, **kwargs):
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"X-Total-Pages": "1"}
            url = args[1] if len(args) > 1 else kwargs.get("url", "")
            if "deploy_keys" in url:
                mock_response.json.return_value = [mock_deploy_key]
            else:
                mock_response.json.return_value = [mock_project]
            return mock_response

        mock_session.request.side_effect = mock_request

        collector = GitLabCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["deploy_keys"])

        assert len(result.evidence_items) == 1
        assert result.evidence_items[0].evidence_type == "deploy_keys"
        assert result.evidence_items[0].raw_data["total_count"] >= 0


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    @patch("attestful.collectors.platforms.gitlab.requests.Session")
    def test_resource_collection_error(self, mock_session_class, mock_config):
        """Test handling errors during resource collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_session.request.side_effect = Exception("API error")

        collector = GitLabCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["gitlab_project"])

        # Should return empty list, not raise
        assert resources == []

    @patch("attestful.collectors.platforms.gitlab.requests.Session")
    def test_evidence_collection_error(self, mock_session_class, mock_config):
        """Test handling errors during evidence collection."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_session.request.side_effect = Exception("API error")

        collector = GitLabCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["projects"])

        # Should return result with errors, not raise
        assert len(result.errors) > 0
        assert "projects" in result.errors[0]

    def test_unknown_resource_type(self, mock_config):
        """Test handling unknown resource types."""
        collector = GitLabCollector(config=mock_config)
        resources = collector.collect_resources(resource_types=["unknown_type"])
        assert resources == []

    def test_unknown_evidence_type(self, mock_config):
        """Test handling unknown evidence types."""
        collector = GitLabCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["unknown_type"])
        assert len(result.evidence_items) == 0


# =============================================================================
# Compliance Metadata Tests
# =============================================================================


class TestComplianceMetadata:
    """Tests for compliance-related metadata in evidence."""

    @patch("attestful.collectors.platforms.gitlab.requests.Session")
    def test_projects_compliance_controls(self, mock_session_class, mock_config, mock_project):
        """Test compliance controls in projects evidence."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [mock_project]
        mock_response.headers = {"X-Total-Pages": "1"}
        mock_session.request.return_value = mock_response

        collector = GitLabCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["projects"])

        metadata = result.evidence_items[0].metadata
        assert "compliance_controls" in metadata
        assert "SOC2:CC8.1" in metadata["compliance_controls"]
        assert "NIST:CM-3" in metadata["compliance_controls"]

    @patch("attestful.collectors.platforms.gitlab.requests.Session")
    def test_members_compliance_controls(self, mock_session_class, mock_config, mock_user):
        """Test compliance controls in members evidence."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [mock_user]
        mock_response.headers = {"X-Total-Pages": "1"}
        mock_session.request.return_value = mock_response

        collector = GitLabCollector(config=mock_config)
        result = collector.collect_evidence(evidence_types=["members"])

        metadata = result.evidence_items[0].metadata
        assert "compliance_controls" in metadata
        assert "SOC2:CC6.1" in metadata["compliance_controls"]
        assert "NIST:AC-2" in metadata["compliance_controls"]


# =============================================================================
# CLI Tests
# =============================================================================


class TestGitLabCLI:
    """Tests for GitLab CLI commands."""

    def test_gitlab_help(self):
        """Test gitlab collect help."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "gitlab", "--help"])
        assert result.exit_code == 0
        assert "Collect evidence from GitLab" in result.output
        assert "--types" in result.output
        assert "--group" in result.output
        assert "--url" in result.output
        assert "--days" in result.output

    def test_gitlab_evidence_types_in_help(self):
        """Test evidence types are documented in help."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "gitlab", "--help"])
        assert result.exit_code == 0
        assert "projects" in result.output
        assert "protected_branches" in result.output
        assert "merge_requests" in result.output
        assert "pipelines" in result.output
        assert "vulnerabilities" in result.output
        assert "audit_events" in result.output

    def test_gitlab_examples_in_help(self):
        """Test examples are in help output."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "gitlab", "--help"])
        assert result.exit_code == 0
        assert "Examples:" in result.output

    def test_collect_list_shows_gitlab(self):
        """Test collect list shows gitlab as available."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "list"])
        assert result.exit_code == 0
        assert "gitlab" in result.output
        assert "Available" in result.output
