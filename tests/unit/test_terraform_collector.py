"""
Tests for the Terraform Cloud collector.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
import pytest
import requests

from attestful.collectors.platforms.terraform import TerraformCloudCollector, TerraformCloudCollectorConfig
from attestful.core.exceptions import CollectionError, ConfigurationError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_workspace():
    """Create a mock Terraform Cloud workspace."""
    return {
        "id": "ws-abc123",
        "type": "workspaces",
        "attributes": {
            "name": "production",
            "description": "Production infrastructure",
            "auto-apply": False,
            "file-triggers-enabled": True,
            "queue-all-runs": False,
            "speculative-enabled": True,
            "terraform-version": "1.6.0",
            "working-directory": "",
            "execution-mode": "remote",
            "vcs-repo": {
                "identifier": "org/repo",
                "branch": "main",
            },
            "locked": False,
            "resource-count": 42,
            "created-at": "2024-01-01T00:00:00Z",
            "updated-at": "2024-06-01T00:00:00Z",
            "environment": "production",
        },
    }


@pytest.fixture
def mock_locked_workspace():
    """Create a mock locked workspace."""
    return {
        "id": "ws-def456",
        "type": "workspaces",
        "attributes": {
            "name": "staging",
            "description": "Staging infrastructure",
            "auto-apply": True,
            "locked": True,
            "terraform-version": "1.5.0",
            "execution-mode": "remote",
            "vcs-repo": None,
            "resource-count": 20,
            "created-at": "2024-01-01T00:00:00Z",
        },
    }


@pytest.fixture
def mock_run():
    """Create a mock Terraform Cloud run."""
    now = datetime.now(timezone.utc)
    return {
        "id": "run-abc123",
        "type": "runs",
        "attributes": {
            "status": "applied",
            "source": "tfe-api",
            "is-destroy": False,
            "message": "Scheduled apply",
            "has-changes": True,
            "auto-apply": False,
            "plan-only": False,
            "created-at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status-timestamps": {
                "planned-at": (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "applied-at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        },
    }


@pytest.fixture
def mock_errored_run():
    """Create a mock errored run."""
    now = datetime.now(timezone.utc)
    return {
        "id": "run-def456",
        "type": "runs",
        "attributes": {
            "status": "errored",
            "source": "tfe-ui",
            "is-destroy": False,
            "message": "Failed apply",
            "has-changes": True,
            "created-at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    }


@pytest.fixture
def mock_state_version():
    """Create a mock state version."""
    now = datetime.now(timezone.utc)
    return {
        "id": "sv-abc123",
        "type": "state-versions",
        "attributes": {
            "serial": 42,
            "created-at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "size": 12345,
            "hosted-state-download-url": "https://example.com/state",
            "resources-processed": True,
        },
    }


@pytest.fixture
def mock_policy_set():
    """Create a mock policy set."""
    return {
        "id": "polset-abc123",
        "type": "policy-sets",
        "attributes": {
            "name": "security-policies",
            "description": "Security policy checks",
            "global": True,
            "kind": "sentinel",
            "agent-enabled": False,
            "policy-count": 5,
            "workspace-count": 10,
            "created-at": "2024-01-01T00:00:00Z",
            "updated-at": "2024-06-01T00:00:00Z",
        },
    }


@pytest.fixture
def mock_policy():
    """Create a mock policy."""
    return {
        "id": "pol-abc123",
        "type": "policies",
        "attributes": {
            "name": "require-tags",
            "description": "Require all resources to have tags",
            "enforcement-level": "hard-mandatory",
        },
    }


@pytest.fixture
def mock_variable_set():
    """Create a mock variable set."""
    return {
        "id": "varset-abc123",
        "type": "varsets",
        "attributes": {
            "name": "common-vars",
            "description": "Common variables for all workspaces",
            "global": True,
        },
    }


@pytest.fixture
def mock_variable():
    """Create a mock variable."""
    return {
        "id": "var-abc123",
        "type": "vars",
        "attributes": {
            "key": "aws_region",
            "sensitive": False,
            "category": "terraform",
            "hcl": False,
        },
    }


@pytest.fixture
def mock_sensitive_variable():
    """Create a mock sensitive variable."""
    return {
        "id": "var-def456",
        "type": "vars",
        "attributes": {
            "key": "aws_secret_key",
            "sensitive": True,
            "category": "terraform",
            "hcl": False,
        },
    }


@pytest.fixture
def mock_team():
    """Create a mock team."""
    return {
        "id": "team-abc123",
        "type": "teams",
        "attributes": {
            "name": "platform-team",
            "visibility": "organization",
            "sso-team-id": None,
            "organization-access": {
                "manage-policies": True,
                "manage-workspaces": True,
                "manage-vcs-settings": False,
                "manage-providers": False,
                "manage-modules": True,
                "manage-run-tasks": False,
                "manage-membership": False,
            },
        },
    }


@pytest.fixture
def collector():
    """Create a TerraformCloudCollector instance."""
    config = TerraformCloudCollectorConfig(
        api_token="test-token-12345",
        organization="test-org",
        days_of_history=90,
    )
    return TerraformCloudCollector(config=config)


# =============================================================================
# Initialization Tests
# =============================================================================


class TestTerraformCloudCollectorInit:
    """Tests for TerraformCloudCollector initialization."""

    def test_init_with_config(self, collector):
        """Test initialization with config."""
        assert collector.config.api_token == "test-token-12345"
        assert collector.config.organization == "test-org"
        assert collector.config.days_of_history == 90

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = TerraformCloudCollector()
        assert collector.config.api_token == ""
        assert collector.config.organization == ""
        assert collector.config.timeout == 30
        assert collector.config.max_retries == 3
        assert collector.config.page_size == 100
        assert collector.config.days_of_history == 90

    def test_metadata(self, collector):
        """Test collector metadata."""
        assert collector.metadata.name == "TerraformCloudCollector"
        assert collector.metadata.platform == "terraform_cloud"
        assert "terraform_workspace" in collector.metadata.resource_types
        assert "terraform_run" in collector.metadata.resource_types
        assert "workspaces" in collector.metadata.evidence_types
        assert "runs" in collector.metadata.evidence_types

    def test_platform(self, collector):
        """Test platform attribute."""
        assert collector.PLATFORM == "terraform_cloud"

    def test_base_url(self, collector):
        """Test base URL property."""
        assert collector.base_url == "https://app.terraform.io/api/v2"


# =============================================================================
# Session Tests
# =============================================================================


class TestTerraformCloudSession:
    """Tests for session creation."""

    def test_session_creation(self, collector):
        """Test session is created on first access."""
        session = collector.session
        assert session is not None
        assert isinstance(session, requests.Session)

    def test_session_cached(self, collector):
        """Test session is cached."""
        session1 = collector.session
        session2 = collector.session
        assert session1 is session2

    def test_session_has_auth_header(self, collector):
        """Test session has authorization header."""
        session = collector.session
        assert "Authorization" in session.headers
        assert "Bearer " in session.headers["Authorization"]

    def test_session_has_json_api_header(self, collector):
        """Test session has JSON:API content type."""
        session = collector.session
        assert session.headers["Content-Type"] == "application/vnd.api+json"


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestValidateCredentials:
    """Tests for credential validation."""

    def test_validate_credentials_success(self, collector):
        """Test successful credential validation."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "name": "test-org",
                },
            },
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.validate_credentials()
            assert result is True

    def test_validate_credentials_no_token(self):
        """Test validation fails without token."""
        collector = TerraformCloudCollector(
            config=TerraformCloudCollectorConfig(api_token="", organization="test-org")
        )
        with pytest.raises(ConfigurationError, match="api_token is required"):
            collector.validate_credentials()

    def test_validate_credentials_no_organization(self):
        """Test validation fails without organization."""
        collector = TerraformCloudCollector(
            config=TerraformCloudCollectorConfig(api_token="test-token", organization="")
        )
        with pytest.raises(ConfigurationError, match="organization is required"):
            collector.validate_credentials()

    def test_validate_credentials_invalid_token(self, collector):
        """Test validation fails with invalid token."""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.HTTPError("401 Unauthorized")

        with patch.object(collector.session, "get", return_value=mock_response):
            mock_response.raise_for_status.side_effect = requests.HTTPError("401 Unauthorized")
            with pytest.raises(ConfigurationError, match="Invalid Terraform Cloud API token"):
                collector.validate_credentials()

    def test_validate_credentials_org_not_found(self, collector):
        """Test validation fails with invalid organization."""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.HTTPError("404 Not Found")

        with patch.object(collector.session, "get", return_value=mock_response):
            mock_response.raise_for_status.side_effect = requests.HTTPError("404 Not Found")
            with pytest.raises(ConfigurationError, match="Organization not found"):
                collector.validate_credentials()


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestCollectEvidence:
    """Tests for evidence collection."""

    def test_collect_all_evidence_types(self, collector, mock_workspace, mock_team):
        """Test collecting all evidence types."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "/workspaces" in url and "/runs" not in url and "/vars" not in url and "/state-versions" not in url:
                response.json.return_value = {
                    "data": [mock_workspace],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            elif "/runs" in url:
                response.json.return_value = {
                    "data": [],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            elif "/state-versions" in url:
                response.json.return_value = {
                    "data": [],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            elif "/policy-sets" in url:
                response.json.return_value = {
                    "data": [],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            elif "/varsets" in url:
                response.json.return_value = {
                    "data": [],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            elif "/vars" in url:
                response.json.return_value = {
                    "data": [],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            elif "/teams" in url:
                response.json.return_value = {
                    "data": [mock_team],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            else:
                response.json.return_value = {
                    "data": [],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }

            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence()

            assert result.platform == "terraform_cloud"
            assert len(result.evidence_items) > 0
            assert result.started_at is not None
            assert result.completed_at is not None

    def test_collect_specific_evidence_types(self, collector, mock_workspace):
        """Test collecting specific evidence types."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": [mock_workspace],
            "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["workspaces"])

            assert result.platform == "terraform_cloud"
            assert len(result.evidence_items) == 1
            assert result.evidence_items[0].evidence_type == "workspaces"

    def test_collect_evidence_invalid_type(self, collector):
        """Test collecting invalid evidence type."""
        with pytest.raises(CollectionError, match="Unsupported evidence types"):
            collector.collect_evidence(evidence_types=["invalid_type"])

    def test_collect_workspaces_evidence(self, collector, mock_workspace, mock_locked_workspace):
        """Test collecting workspaces evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": [mock_workspace, mock_locked_workspace],
            "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["workspaces"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "workspaces"
            assert evidence.platform == "terraform_cloud"
            assert evidence.raw_data["total_count"] == 2
            assert evidence.raw_data["auto_apply_count"] == 1
            assert evidence.raw_data["locked_count"] == 1
            assert evidence.raw_data["vcs_connected_count"] == 1

    def test_collect_runs_evidence(self, collector, mock_workspace, mock_run, mock_errored_run):
        """Test collecting runs evidence."""
        call_count = [0]

        def mock_get(url, **kwargs):
            call_count[0] += 1
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "/workspaces" in url and "/runs" not in url:
                response.json.return_value = {
                    "data": [mock_workspace],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            elif "/runs" in url:
                response.json.return_value = {
                    "data": [mock_run, mock_errored_run],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["runs"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "runs"
            assert evidence.raw_data["total_count"] == 2
            assert "applied" in evidence.raw_data["status_counts"]
            assert "errored" in evidence.raw_data["status_counts"]

    def test_collect_policies_evidence(self, collector, mock_policy_set, mock_policy):
        """Test collecting policies evidence."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "/policy-sets" in url and "/policies" not in url:
                response.json.return_value = {
                    "data": [mock_policy_set],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            elif "/policies" in url:
                response.json.return_value = {
                    "data": [mock_policy],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["policies"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "policies"
            assert evidence.raw_data["policy_set_count"] == 1
            assert evidence.raw_data["policy_count"] == 1
            assert evidence.raw_data["global_policy_sets"] == 1

    def test_collect_variables_evidence(self, collector, mock_workspace, mock_variable_set, mock_variable, mock_sensitive_variable):
        """Test collecting variables evidence."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            # Order matters - more specific patterns first
            if "/varsets/" in url and "/relationships/vars" in url:
                response.json.return_value = {
                    "data": [mock_variable],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            elif "/organizations/" in url and "/varsets" in url:
                response.json.return_value = {
                    "data": [mock_variable_set],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            elif "/workspaces/" in url and "/vars" in url:
                response.json.return_value = {
                    "data": [mock_variable, mock_sensitive_variable],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            elif "/workspaces" in url:
                response.json.return_value = {
                    "data": [mock_workspace],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            else:
                response.json.return_value = {
                    "data": [],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["variables"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "variables"
            assert evidence.raw_data["variable_set_count"] == 1
            assert evidence.raw_data["workspace_variable_count"] == 2
            assert evidence.raw_data["sensitive_workspace_vars"] == 1

    def test_collect_teams_evidence(self, collector, mock_team):
        """Test collecting teams evidence."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "/teams" in url and "/organization-memberships" not in url:
                response.json.return_value = {
                    "data": [mock_team],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            elif "/organization-memberships" in url:
                response.json.return_value = {
                    "data": [],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["teams"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "teams"
            assert evidence.raw_data["total_count"] == 1


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestCollectResources:
    """Tests for resource collection."""

    def test_collect_all_resource_types(self, collector, mock_workspace, mock_run, mock_policy_set, mock_team):
        """Test collecting all resource types."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "/workspaces" in url and "/runs" not in url:
                response.json.return_value = {
                    "data": [mock_workspace],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            elif "/runs" in url:
                response.json.return_value = {
                    "data": [mock_run],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            elif "/policy-sets" in url:
                response.json.return_value = {
                    "data": [mock_policy_set],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            elif "/teams" in url:
                response.json.return_value = {
                    "data": [mock_team],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            resources = collector.collect_resources()

            assert len(resources) > 0
            types = {r.type for r in resources}
            assert "terraform_workspace" in types
            assert "terraform_run" in types
            assert "terraform_policy_set" in types
            assert "terraform_team" in types

    def test_collect_specific_resource_types(self, collector, mock_workspace):
        """Test collecting specific resource types."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": [mock_workspace],
            "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["terraform_workspace"])

            assert len(resources) == 1
            assert resources[0].type == "terraform_workspace"

    def test_collect_resources_invalid_type(self, collector):
        """Test collecting invalid resource type."""
        with pytest.raises(CollectionError, match="Unsupported resource types"):
            collector.collect_resources(resource_types=["invalid_type"])

    def test_collect_workspace_resources(self, collector, mock_workspace):
        """Test collecting workspace resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": [mock_workspace],
            "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["terraform_workspace"])

            assert len(resources) == 1
            resource = resources[0]
            assert resource.type == "terraform_workspace"
            assert resource.provider == "terraform_cloud"
            assert resource.id == "ws-abc123"
            assert resource.name == "production"
            assert resource.tags["auto_apply"] == "false"
            assert resource.tags["locked"] == "false"
            assert resource.tags["vcs_connected"] == "true"

    def test_collect_run_resources(self, collector, mock_workspace, mock_run):
        """Test collecting run resources."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "/workspaces" in url and "/runs" not in url:
                response.json.return_value = {
                    "data": [mock_workspace],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            elif "/runs" in url:
                response.json.return_value = {
                    "data": [mock_run],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            resources = collector.collect_resources(resource_types=["terraform_run"])

            assert len(resources) == 1
            resource = resources[0]
            assert resource.type == "terraform_run"
            assert resource.id == "run-abc123"
            assert resource.tags["status"] == "applied"
            assert resource.tags["is_destroy"] == "false"

    def test_collect_policy_set_resources(self, collector, mock_policy_set):
        """Test collecting policy set resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": [mock_policy_set],
            "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["terraform_policy_set"])

            assert len(resources) == 1
            resource = resources[0]
            assert resource.type == "terraform_policy_set"
            assert resource.id == "polset-abc123"
            assert resource.tags["global"] == "true"
            assert resource.tags["kind"] == "sentinel"

    def test_collect_team_resources(self, collector, mock_team):
        """Test collecting team resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": [mock_team],
            "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["terraform_team"])

            assert len(resources) == 1
            resource = resources[0]
            assert resource.type == "terraform_team"
            assert resource.id == "team-abc123"
            assert resource.name == "platform-team"
            assert resource.tags["manage_workspaces"] == "true"


# =============================================================================
# Pagination Tests
# =============================================================================


class TestPagination:
    """Tests for API pagination."""

    def test_pagination_multiple_pages(self, collector, mock_workspace, mock_locked_workspace):
        """Test pagination across multiple pages."""
        call_count = [0]

        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            call_count[0] += 1

            params = kwargs.get("params", {})
            page_number = params.get("page[number]", 1)

            if page_number == 1:
                response.json.return_value = {
                    "data": [mock_workspace],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 2}},
                }
            else:
                response.json.return_value = {
                    "data": [mock_locked_workspace],
                    "meta": {"pagination": {"current-page": 2, "total-pages": 2}},
                }
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["workspaces"])

            evidence = result.evidence_items[0]
            assert evidence.raw_data["total_count"] == 2

    def test_pagination_stops_on_error(self, collector, mock_workspace):
        """Test pagination stops on API error."""
        call_count = [0]

        def mock_get(url, **kwargs):
            call_count[0] += 1

            if call_count[0] == 1:
                response = MagicMock()
                response.raise_for_status = MagicMock()
                response.json.return_value = {
                    "data": [mock_workspace],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 2}},
                }
                return response
            else:
                raise requests.RequestException("API error")

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["workspaces"])

            # Should still have results from first page
            evidence = result.evidence_items[0]
            assert evidence.raw_data["total_count"] == 1


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    def test_api_error_logged_but_continues(self, collector, mock_workspace):
        """Test that API errors are logged but collection continues."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "/workspaces" in url:
                response.json.return_value = {
                    "data": [mock_workspace],
                    "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
                }
            else:
                raise requests.RequestException("API error")
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["workspaces", "policies"])

            # Should still have workspaces evidence
            evidence_types = [e.evidence_type for e in result.evidence_items]
            assert "workspaces" in evidence_types

    def test_collection_continues_on_error(self, collector):
        """Test that collection continues despite errors."""
        def mock_get(url, **kwargs):
            raise requests.RequestException("Network error")

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence()

            # Should still complete
            assert result.completed_at is not None


# =============================================================================
# Compliance Control Mapping Tests
# =============================================================================


class TestComplianceControls:
    """Tests for compliance control mappings."""

    def test_workspaces_evidence_has_controls(self, collector, mock_workspace):
        """Test workspaces evidence has compliance controls."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": [mock_workspace],
            "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["workspaces"])

            evidence = result.evidence_items[0]
            controls = evidence.metadata["compliance_controls"]
            assert "soc2" in controls
            assert "nist_800_53" in controls
            assert "iso_27001" in controls
            assert "hitrust" in controls
            # Check specific IaC controls
            assert "CM-2" in controls["nist_800_53"]
            assert "SA-10" in controls["nist_800_53"]

    def test_policies_evidence_has_controls(self, collector, mock_policy_set):
        """Test policies evidence has compliance controls."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": [mock_policy_set],
            "meta": {"pagination": {"current-page": 1, "total-pages": 1}},
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["policies"])

            evidence = result.evidence_items[0]
            controls = evidence.metadata["compliance_controls"]
            assert "CC5.2" in controls["soc2"]
            assert "AC-3" in controls["nist_800_53"]

    def test_all_evidence_types_have_mappings(self, collector):
        """Test all evidence types have compliance mappings."""
        for evidence_type in collector.SUPPORTED_EVIDENCE_TYPES:
            assert evidence_type in collector.EVIDENCE_CONTROL_MAPPINGS
            mappings = collector.EVIDENCE_CONTROL_MAPPINGS[evidence_type]
            assert "soc2" in mappings
            assert "nist_800_53" in mappings
            assert "iso_27001" in mappings
            assert "hitrust" in mappings
