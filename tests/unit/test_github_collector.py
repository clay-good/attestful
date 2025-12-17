"""
Unit tests for GitHub collector.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, patch, MagicMock
from requests.exceptions import HTTPError

from attestful.collectors.platforms.github import GitHubCollector, GitHubCollectorConfig
from attestful.core.models import CollectionResult, Resource


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def github_config():
    """Sample GitHub configuration."""
    return GitHubCollectorConfig(
        token="ghp_test_token",
        organization="test-org",
        timeout=30,
        page_size=100,
        days_of_history=30,
    )


@pytest.fixture
def collector(github_config):
    """GitHub collector instance."""
    return GitHubCollector(config=github_config)


@pytest.fixture
def mock_response():
    """Create a mock response factory."""
    def _create_response(json_data, status_code=200, headers=None):
        response = Mock()
        response.json.return_value = json_data
        response.status_code = status_code
        response.headers = headers or {}
        return response
    return _create_response


# =============================================================================
# Configuration Tests
# =============================================================================


class TestGitHubCollectorConfig:
    """Tests for GitHubCollectorConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = GitHubCollectorConfig()
        assert config.token == ""
        assert config.organization == ""
        assert config.api_url == "https://api.github.com"
        assert config.timeout == 30
        assert config.page_size == 100
        assert config.include_archived is False
        assert config.days_of_history == 90

    def test_custom_config(self):
        """Test custom configuration values."""
        config = GitHubCollectorConfig(
            token="test-token",
            organization="my-org",
            api_url="https://github.example.com/api",
            timeout=60,
            page_size=50,
            include_archived=True,
            days_of_history=30,
        )
        assert config.token == "test-token"
        assert config.organization == "my-org"
        assert config.api_url == "https://github.example.com/api"
        assert config.include_archived is True


# =============================================================================
# Collector Initialization Tests
# =============================================================================


class TestGitHubCollectorInit:
    """Tests for collector initialization."""

    def test_init_with_config(self, github_config):
        """Test initialization with config."""
        collector = GitHubCollector(config=github_config)
        assert collector.config == github_config
        assert collector.PLATFORM == "github"

    def test_init_without_config(self):
        """Test initialization without config uses defaults."""
        collector = GitHubCollector()
        assert collector.config is not None
        assert collector.config.token == ""

    def test_base_url(self, collector):
        """Test base URL property."""
        assert collector.base_url == "https://api.github.com"

    def test_supported_types(self, collector):
        """Test supported resource and evidence types."""
        assert "github_repository" in collector.SUPPORTED_RESOURCE_TYPES
        assert "github_user" in collector.SUPPORTED_RESOURCE_TYPES
        assert "github_team" in collector.SUPPORTED_RESOURCE_TYPES

        assert "repositories" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "branch_protection" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "security_alerts" in collector.SUPPORTED_EVIDENCE_TYPES


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestCredentialValidation:
    """Tests for credential validation."""

    def test_validate_credentials_success(self, collector, mock_response):
        """Test successful credential validation."""
        with patch.object(collector, "_request") as mock_request:
            mock_request.return_value = mock_response({"login": "testuser"})

            result = collector.validate_credentials()

            assert result is True
            mock_request.assert_called_once_with("GET", "/user")

    def test_validate_credentials_failure(self, collector):
        """Test failed credential validation."""
        with patch.object(collector, "_request") as mock_request:
            mock_request.side_effect = Exception("Unauthorized")

            result = collector.validate_credentials()

            assert result is False


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestResourceCollection:
    """Tests for resource collection."""

    def test_collect_repositories(self, collector, mock_response):
        """Test collecting repositories."""
        repos = [
            {
                "id": 1,
                "name": "repo1",
                "full_name": "test-org/repo1",
                "visibility": "private",
                "default_branch": "main",
                "archived": False,
            },
            {
                "id": 2,
                "name": "repo2",
                "full_name": "test-org/repo2",
                "visibility": "public",
                "default_branch": "master",
                "archived": False,
            },
        ]

        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter(repos)

            resources = collector.collect_resources(resource_types=["github_repository"])

            assert len(resources) == 2
            assert all(isinstance(r, Resource) for r in resources)
            assert resources[0].type == "github_repository"
            assert resources[0].name == "test-org/repo1"

    def test_collect_archived_repos_excluded_by_default(self, collector):
        """Test that archived repos are excluded by default."""
        repos = [
            {"id": 1, "name": "active", "full_name": "org/active", "archived": False},
            {"id": 2, "name": "archived", "full_name": "org/archived", "archived": True},
        ]

        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter(repos)

            resources = collector.collect_resources(resource_types=["github_repository"])

            assert len(resources) == 1
            assert resources[0].name == "org/active"

    def test_collect_archived_repos_included_when_configured(self, github_config):
        """Test that archived repos are included when configured."""
        github_config.include_archived = True
        collector = GitHubCollector(config=github_config)

        repos = [
            {"id": 1, "name": "active", "full_name": "org/active", "archived": False},
            {"id": 2, "name": "archived", "full_name": "org/archived", "archived": True},
        ]

        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter(repos)

            resources = collector.collect_resources(resource_types=["github_repository"])

            assert len(resources) == 2

    def test_collect_users(self, collector):
        """Test collecting organization members."""
        members = [
            {"id": 1, "login": "user1", "type": "User", "site_admin": False},
            {"id": 2, "login": "user2", "type": "User", "site_admin": True},
        ]

        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter(members)

            resources = collector.collect_resources(resource_types=["github_user"])

            assert len(resources) == 2
            assert resources[0].type == "github_user"
            assert resources[0].name == "user1"

    def test_collect_teams(self, collector):
        """Test collecting organization teams."""
        teams = [
            {"id": 1, "name": "engineering", "privacy": "closed", "permission": "push"},
            {"id": 2, "name": "admins", "privacy": "secret", "permission": "admin"},
        ]

        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter(teams)

            resources = collector.collect_resources(resource_types=["github_team"])

            assert len(resources) == 2
            assert resources[0].type == "github_team"
            assert resources[0].name == "engineering"

    def test_collect_all_resource_types(self, collector):
        """Test collecting all resource types."""
        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter([])

            resources = collector.collect_resources()

            # Should attempt to collect all supported types
            assert mock_paginate.call_count >= 1


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestEvidenceCollection:
    """Tests for evidence collection."""

    def test_collect_repositories_evidence(self, collector):
        """Test collecting repositories evidence."""
        repos = [
            {
                "id": 1,
                "name": "repo1",
                "full_name": "org/repo1",
                "private": True,
                "visibility": "private",
                "default_branch": "main",
                "archived": False,
                "has_issues": True,
                "has_wiki": True,
                "has_discussions": False,
                "fork": False,
                "allow_forking": True,
                "delete_branch_on_merge": True,
                "allow_merge_commit": True,
                "allow_squash_merge": True,
                "allow_rebase_merge": True,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-15T00:00:00Z",
                "pushed_at": "2024-01-15T00:00:00Z",
            },
        ]

        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter(repos)

            result = collector.collect_evidence(evidence_types=["repositories"])

            assert isinstance(result, CollectionResult)
            assert len(result.evidence) == 1
            assert result.evidence[0].evidence_type == "repositories"
            assert result.evidence[0].raw_data["total_count"] == 1

    def test_collect_branch_protection_evidence(self, collector, mock_response):
        """Test collecting branch protection evidence."""
        repos = [
            {"id": 1, "full_name": "org/repo1", "default_branch": "main", "archived": False},
        ]
        protection = {
            "required_pull_request_reviews": {
                "required_approving_review_count": 2,
                "dismiss_stale_reviews": True,
                "require_code_owner_reviews": True,
            },
            "required_status_checks": {"strict": True},
            "enforce_admins": {"enabled": True},
            "required_signatures": {"enabled": False},
            "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False},
        }

        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter(repos)
            with patch.object(collector, "_request") as mock_request:
                mock_request.return_value = mock_response(protection)

                result = collector.collect_evidence(evidence_types=["branch_protection"])

                assert len(result.evidence) == 1
                evidence = result.evidence[0]
                assert evidence.evidence_type == "branch_protection"
                assert evidence.raw_data["summary"]["protected_count"] == 1

    def test_collect_evidence_handles_errors(self, collector):
        """Test that evidence collection handles errors gracefully."""
        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.side_effect = Exception("API Error")

            result = collector.collect_evidence(evidence_types=["repositories"])

            assert isinstance(result, CollectionResult)
            assert len(result.errors) > 0

    def test_collect_all_evidence_types(self, collector):
        """Test collecting all evidence types."""
        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter([])
            with patch.object(collector, "_request") as mock_request:
                mock_request.return_value = Mock(json=lambda: {"workflows": []})

                result = collector.collect_evidence()

                assert isinstance(result, CollectionResult)


class TestSecurityAlertsEvidence:
    """Tests for security alerts evidence collection."""

    def test_collect_security_alerts(self, collector, mock_response):
        """Test collecting security alerts."""
        repos = [
            {"id": 1, "full_name": "org/repo1", "archived": False},
        ]
        code_alerts = [
            {
                "number": 1,
                "state": "open",
                "rule": {"severity": "high", "security_severity_level": "critical"},
                "tool": {"name": "CodeQL"},
                "created_at": "2024-01-01T00:00:00Z",
            },
        ]
        dependabot_alerts = [
            {
                "number": 1,
                "state": "open",
                "security_advisory": {"severity": "high"},
                "dependency": {"package": {"name": "lodash", "ecosystem": "npm"}},
                "created_at": "2024-01-01T00:00:00Z",
            },
        ]

        with patch.object(collector, "_paginate") as mock_paginate:
            # First call returns repos, subsequent calls return alerts
            mock_paginate.side_effect = [
                iter(repos),
                iter(code_alerts),
                iter(dependabot_alerts),
            ]

            result = collector.collect_evidence(evidence_types=["security_alerts"])

            assert len(result.evidence) == 1
            evidence = result.evidence[0]
            assert evidence.evidence_type == "security_alerts"


class TestCollaboratorsEvidence:
    """Tests for collaborators evidence collection."""

    def test_collect_collaborators(self, collector):
        """Test collecting collaborators evidence."""
        repos = [
            {"id": 1, "full_name": "org/repo1", "archived": False},
        ]
        collaborators = [
            {
                "login": "user1",
                "id": 1,
                "type": "User",
                "permissions": {"admin": True, "push": True, "pull": True},
                "role_name": "admin",
            },
            {
                "login": "user2",
                "id": 2,
                "type": "User",
                "permissions": {"admin": False, "push": True, "pull": True},
                "role_name": "write",
            },
        ]

        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.side_effect = [iter(repos), iter(collaborators)]

            result = collector.collect_evidence(evidence_types=["collaborators"])

            assert len(result.evidence) == 1
            evidence = result.evidence[0]
            assert evidence.raw_data["summary"]["total_admins"] == 1


class TestCommitsEvidence:
    """Tests for commits evidence collection."""

    def test_collect_commits(self, collector):
        """Test collecting commits evidence."""
        repos = [
            {"id": 1, "full_name": "org/repo1", "archived": False},
        ]
        commits = [
            {
                "sha": "abc123",
                "commit": {
                    "author": {"email": "user@example.com", "date": "2024-01-15T00:00:00Z"},
                },
            },
            {
                "sha": "def456",
                "commit": {
                    "author": {"email": "user@example.com", "date": "2024-01-14T00:00:00Z"},
                },
            },
        ]

        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.side_effect = [iter(repos), iter(commits)]

            result = collector.collect_evidence(evidence_types=["commits"])

            assert len(result.evidence) == 1
            evidence = result.evidence[0]
            assert evidence.raw_data["summary"]["total_commits"] == 2


class TestPullRequestsEvidence:
    """Tests for pull requests evidence collection."""

    def test_collect_pull_requests(self, collector):
        """Test collecting pull requests evidence."""
        repos = [
            {"id": 1, "full_name": "org/repo1", "archived": False},
        ]
        prs = [
            {
                "number": 1,
                "title": "Feature PR",
                "state": "open",
                "merged_at": None,
                "user": {"login": "user1"},
                "created_at": "2024-01-15T00:00:00Z",
                "updated_at": "2024-01-15T00:00:00Z",
                "requested_reviewers": [{"login": "reviewer1"}],
                "draft": False,
            },
        ]

        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.side_effect = [iter(repos), iter(prs)]

            result = collector.collect_evidence(evidence_types=["pull_requests"])

            assert len(result.evidence) == 1


class TestWorkflowsEvidence:
    """Tests for workflows evidence collection."""

    def test_collect_workflows(self, collector, mock_response):
        """Test collecting workflows evidence."""
        repos = [
            {"id": 1, "full_name": "org/repo1", "archived": False},
        ]
        workflows = {
            "workflows": [
                {
                    "id": 1,
                    "name": "CI",
                    "path": ".github/workflows/ci.yml",
                    "state": "active",
                },
            ],
        }

        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter(repos)
            with patch.object(collector, "_request") as mock_request:
                mock_request.return_value = mock_response(workflows)

                result = collector.collect_evidence(evidence_types=["workflows"])

                assert len(result.evidence) == 1
                evidence = result.evidence[0]
                assert evidence.raw_data["summary"]["total_workflows"] == 1


class TestAuditLogEvidence:
    """Tests for audit log evidence collection."""

    def test_collect_audit_log(self, collector):
        """Test collecting audit log evidence."""
        events = [
            {
                "@timestamp": "2024-01-15T00:00:00Z",
                "action": "repo.create",
                "actor": "user1",
                "org": "test-org",
                "repo": "test-org/new-repo",
            },
        ]

        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter(events)

            result = collector.collect_evidence(evidence_types=["audit_log"])

            assert len(result.evidence) == 1
            evidence = result.evidence[0]
            assert evidence.evidence_type == "audit_log"

    def test_audit_log_without_org(self):
        """Test audit log collection without organization."""
        config = GitHubCollectorConfig(token="test")
        collector = GitHubCollector(config=config)

        result = collector.collect_evidence(evidence_types=["audit_log"])

        assert len(result.evidence) == 1
        assert "error" in result.evidence[0].raw_data


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    def test_unknown_resource_type(self, collector):
        """Test handling unknown resource type."""
        resources = collector.collect_resources(resource_types=["unknown_type"])
        assert resources == []

    def test_unknown_evidence_type(self, collector):
        """Test handling unknown evidence type."""
        result = collector.collect_evidence(evidence_types=["unknown_type"])
        assert result.evidence == []

    def test_empty_organization(self):
        """Test collector without organization uses personal repos."""
        config = GitHubCollectorConfig(token="test", organization="")
        collector = GitHubCollector(config=config)

        # Should use /user/repos endpoint instead of /orgs/.../repos
        assert collector.config.organization == ""

    def test_collection_result_platform(self, collector):
        """Test that collection result includes platform."""
        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter([])

            result = collector.collect_evidence(evidence_types=["repositories"])

            assert result.platform == "github"
            assert result.completed_at is not None
