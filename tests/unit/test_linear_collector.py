"""
Tests for the Linear collector.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
import pytest
import requests

from attestful.collectors.platforms.linear import LinearCollector, LinearCollectorConfig
from attestful.core.exceptions import CollectionError, ConfigurationError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_user():
    """Create a mock Linear user."""
    return {
        "id": "user-123",
        "name": "John Doe",
        "displayName": "John D.",
        "email": "jdoe@example.com",
        "active": True,
        "admin": False,
        "guest": False,
        "createdAt": "2023-01-15T10:30:00Z",
        "lastSeen": "2024-06-20T14:00:00Z",
        "avatarUrl": "https://linear.app/avatars/user-123",
    }


@pytest.fixture
def mock_admin_user():
    """Create a mock admin user."""
    return {
        "id": "user-456",
        "name": "Admin User",
        "displayName": "Admin",
        "email": "admin@example.com",
        "active": True,
        "admin": True,
        "guest": False,
        "createdAt": "2022-06-01T08:00:00Z",
        "lastSeen": "2024-06-20T15:00:00Z",
        "avatarUrl": None,
    }


@pytest.fixture
def mock_guest_user():
    """Create a mock guest user."""
    return {
        "id": "user-789",
        "name": "Guest User",
        "displayName": "Guest",
        "email": "guest@external.com",
        "active": True,
        "admin": False,
        "guest": True,
        "createdAt": "2024-01-01T00:00:00Z",
        "lastSeen": "2024-06-20T12:00:00Z",
        "avatarUrl": None,
    }


@pytest.fixture
def mock_inactive_user():
    """Create a mock inactive user."""
    return {
        "id": "user-inactive",
        "name": "Former Employee",
        "displayName": "Former",
        "email": "former@example.com",
        "active": False,
        "admin": False,
        "guest": False,
        "createdAt": "2022-01-01T00:00:00Z",
        "lastSeen": "2023-06-01T00:00:00Z",
        "avatarUrl": None,
    }


@pytest.fixture
def mock_team():
    """Create a mock Linear team."""
    return {
        "id": "team-123",
        "name": "Engineering",
        "key": "ENG",
        "description": "Engineering team",
        "private": False,
        "createdAt": "2023-01-01T00:00:00Z",
        "members": {
            "nodes": [
                {"id": "user-123", "name": "John Doe", "email": "jdoe@example.com"},
                {"id": "user-456", "name": "Admin User", "email": "admin@example.com"},
            ],
        },
    }


@pytest.fixture
def mock_private_team():
    """Create a mock private team."""
    return {
        "id": "team-456",
        "name": "Security",
        "key": "SEC",
        "description": "Security team",
        "private": True,
        "createdAt": "2023-06-01T00:00:00Z",
        "members": {
            "nodes": [
                {"id": "user-456", "name": "Admin User", "email": "admin@example.com"},
            ],
        },
    }


@pytest.fixture
def mock_project():
    """Create a mock Linear project."""
    return {
        "id": "project-123",
        "name": "Q4 Release",
        "description": "Q4 product release",
        "state": "started",
        "progress": 0.45,
        "startDate": "2024-10-01",
        "targetDate": "2024-12-31",
        "createdAt": "2024-09-15T10:00:00Z",
        "updatedAt": "2024-06-20T14:00:00Z",
        "lead": {
            "id": "user-123",
            "name": "John Doe",
            "email": "jdoe@example.com",
        },
        "teams": {
            "nodes": [
                {"id": "team-123", "name": "Engineering"},
            ],
        },
    }


@pytest.fixture
def mock_completed_project():
    """Create a mock completed project."""
    return {
        "id": "project-456",
        "name": "Q3 Release",
        "description": "Q3 product release",
        "state": "completed",
        "progress": 1.0,
        "startDate": "2024-07-01",
        "targetDate": "2024-09-30",
        "createdAt": "2024-06-15T10:00:00Z",
        "updatedAt": "2024-09-30T18:00:00Z",
        "lead": None,
        "teams": {
            "nodes": [],
        },
    }


@pytest.fixture
def mock_issue():
    """Create a mock Linear issue."""
    return {
        "id": "issue-123",
        "identifier": "ENG-123",
        "title": "Fix authentication bug",
        "priority": 2,
        "state": {
            "id": "state-1",
            "name": "In Progress",
            "type": "started",
        },
        "assignee": {
            "id": "user-123",
            "name": "John Doe",
            "email": "jdoe@example.com",
        },
        "creator": {
            "id": "user-456",
            "name": "Admin User",
        },
        "team": {
            "id": "team-123",
            "name": "Engineering",
        },
        "project": {
            "id": "project-123",
            "name": "Q4 Release",
        },
        "createdAt": "2024-06-15T10:00:00Z",
        "updatedAt": "2024-06-20T14:00:00Z",
        "completedAt": None,
        "labels": {
            "nodes": [
                {"id": "label-1", "name": "bug"},
                {"id": "label-2", "name": "high-priority"},
            ],
        },
    }


@pytest.fixture
def mock_completed_issue():
    """Create a mock completed issue."""
    return {
        "id": "issue-456",
        "identifier": "ENG-124",
        "title": "Update documentation",
        "priority": 3,
        "state": {
            "id": "state-2",
            "name": "Done",
            "type": "completed",
        },
        "assignee": None,
        "creator": {
            "id": "user-123",
            "name": "John Doe",
        },
        "team": {
            "id": "team-123",
            "name": "Engineering",
        },
        "project": None,
        "createdAt": "2024-06-10T08:00:00Z",
        "updatedAt": "2024-06-18T16:00:00Z",
        "completedAt": "2024-06-18T16:00:00Z",
        "labels": {
            "nodes": [],
        },
    }


@pytest.fixture
def mock_cycle():
    """Create a mock Linear cycle."""
    return {
        "id": "cycle-123",
        "name": "Sprint 42",
        "number": 42,
        "startsAt": "2024-06-17T00:00:00Z",
        "endsAt": "2024-06-28T23:59:59Z",
        "completedAt": None,
        "progress": 0.6,
        "scopeHistory": [10, 12, 12],
        "completedScopeHistory": [0, 3, 7],
        "team": {
            "id": "team-123",
            "name": "Engineering",
        },
    }


@pytest.fixture
def mock_completed_cycle():
    """Create a mock completed cycle."""
    return {
        "id": "cycle-456",
        "name": "Sprint 41",
        "number": 41,
        "startsAt": "2024-06-03T00:00:00Z",
        "endsAt": "2024-06-14T23:59:59Z",
        "completedAt": "2024-06-14T18:00:00Z",
        "progress": 1.0,
        "scopeHistory": [15, 15, 15],
        "completedScopeHistory": [5, 10, 15],
        "team": {
            "id": "team-123",
            "name": "Engineering",
        },
    }


@pytest.fixture
def mock_issue_history():
    """Create mock issue history for audit logs."""
    return {
        "nodes": [
            {
                "id": "history-1",
                "createdAt": "2024-06-20T14:00:00Z",
                "actorId": "user-123",
                "fromState": {"id": "state-0", "name": "Todo"},
                "toState": {"id": "state-1", "name": "In Progress"},
                "fromAssignee": None,
                "toAssignee": None,
            },
            {
                "id": "history-2",
                "createdAt": "2024-06-18T10:00:00Z",
                "actorId": "user-456",
                "fromState": None,
                "toState": None,
                "fromAssignee": None,
                "toAssignee": {"id": "user-123", "name": "John Doe"},
            },
        ],
    }


@pytest.fixture
def collector():
    """Create a LinearCollector instance."""
    config = LinearCollectorConfig(
        api_key="lin_api_test_key_12345",
        days_of_history=90,
    )
    return LinearCollector(config=config)


# =============================================================================
# Initialization Tests
# =============================================================================


class TestLinearCollectorInit:
    """Tests for LinearCollector initialization."""

    def test_init_with_config(self, collector):
        """Test initialization with config."""
        assert collector.config.api_key == "lin_api_test_key_12345"
        assert collector.config.days_of_history == 90

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = LinearCollector()
        assert collector.config.api_key == ""
        assert collector.config.timeout == 30
        assert collector.config.max_retries == 3
        assert collector.config.page_size == 100
        assert collector.config.days_of_history == 90

    def test_metadata(self, collector):
        """Test collector metadata."""
        assert collector.metadata.name == "LinearCollector"
        assert collector.metadata.platform == "linear"
        assert "linear_user" in collector.metadata.resource_types
        assert "linear_team" in collector.metadata.resource_types
        assert "linear_issue" in collector.metadata.resource_types
        assert "users" in collector.metadata.evidence_types
        assert "teams" in collector.metadata.evidence_types
        assert "issues" in collector.metadata.evidence_types

    def test_platform(self, collector):
        """Test platform attribute."""
        assert collector.PLATFORM == "linear"

    def test_api_url(self, collector):
        """Test API URL constant."""
        assert collector.API_URL == "https://api.linear.app/graphql"


# =============================================================================
# Session Tests
# =============================================================================


class TestLinearSession:
    """Tests for session creation."""

    def test_session_creation(self, collector):
        """Test session is created on first access."""
        session = collector.session
        assert session is not None
        assert isinstance(session, requests.Session)
        assert collector.config.api_key in session.headers["Authorization"]

    def test_session_cached(self, collector):
        """Test session is cached."""
        session1 = collector.session
        session2 = collector.session
        assert session1 is session2

    def test_session_requires_api_key(self):
        """Test session requires API key."""
        collector = LinearCollector()
        with pytest.raises(ConfigurationError, match="API key not configured"):
            _ = collector.session


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
                "viewer": {
                    "id": "user-123",
                    "name": "Test User",
                    "email": "test@example.com",
                },
            },
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.validate_credentials()
            assert result is True

    def test_validate_credentials_failure(self, collector):
        """Test credential validation failure."""
        with patch.object(
            collector.session,
            "post",
            side_effect=requests.RequestException("Invalid API key"),
        ):
            with pytest.raises(ConfigurationError, match="Failed to validate"):
                collector.validate_credentials()

    def test_validate_credentials_graphql_error(self, collector):
        """Test credential validation with GraphQL error."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "errors": [{"message": "Authentication required"}],
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(collector.session, "post", return_value=mock_response):
            with pytest.raises(ConfigurationError, match="Failed to validate"):
                collector.validate_credentials()


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestCollectEvidence:
    """Tests for evidence collection."""

    def test_collect_all_evidence_types(self, collector, mock_user, mock_team, mock_project, mock_issue, mock_cycle):
        """Test collecting all evidence types."""
        def mock_post(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            query = kwargs.get("json", {}).get("query", "")

            if "users" in query:
                response.json.return_value = {
                    "data": {
                        "users": {
                            "nodes": [mock_user],
                            "pageInfo": {"hasNextPage": False},
                        },
                    },
                }
            elif "teams" in query:
                response.json.return_value = {
                    "data": {
                        "teams": {
                            "nodes": [mock_team],
                            "pageInfo": {"hasNextPage": False},
                        },
                    },
                }
            elif "projects" in query:
                response.json.return_value = {
                    "data": {
                        "projects": {
                            "nodes": [mock_project],
                            "pageInfo": {"hasNextPage": False},
                        },
                    },
                }
            elif "cycles" in query:
                response.json.return_value = {
                    "data": {
                        "cycles": {
                            "nodes": [mock_cycle],
                            "pageInfo": {"hasNextPage": False},
                        },
                    },
                }
            elif "issues" in query:
                issue_with_history = mock_issue.copy()
                issue_with_history["history"] = {"nodes": []}
                response.json.return_value = {
                    "data": {
                        "issues": {
                            "nodes": [issue_with_history],
                            "pageInfo": {"hasNextPage": False},
                        },
                    },
                }
            else:
                response.json.return_value = {"data": {}}

            return response

        with patch.object(collector.session, "post", side_effect=mock_post):
            result = collector.collect_evidence()

            assert result.platform == "linear"
            assert len(result.evidence_items) > 0
            assert result.started_at is not None
            assert result.completed_at is not None

    def test_collect_specific_evidence_types(self, collector, mock_user):
        """Test collecting specific evidence types."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "users": {
                    "nodes": [mock_user],
                    "pageInfo": {"hasNextPage": False},
                },
            },
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["users"])

            assert result.platform == "linear"
            assert len(result.evidence_items) == 1
            assert result.evidence_items[0].evidence_type == "users"

    def test_collect_evidence_invalid_type(self, collector):
        """Test collecting invalid evidence type."""
        with pytest.raises(CollectionError, match="Unsupported evidence types"):
            collector.collect_evidence(evidence_types=["invalid_type"])

    def test_collect_users_evidence(self, collector, mock_user, mock_admin_user, mock_guest_user, mock_inactive_user):
        """Test collecting users evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "users": {
                    "nodes": [mock_user, mock_admin_user, mock_guest_user, mock_inactive_user],
                    "pageInfo": {"hasNextPage": False},
                },
            },
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["users"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "users"
            assert evidence.platform == "linear"
            assert evidence.raw_data["total_count"] == 4
            assert evidence.raw_data["active_count"] == 3
            assert evidence.raw_data["admin_count"] == 1
            assert evidence.raw_data["guest_count"] == 1
            assert evidence.raw_data["inactive_count"] == 1
            assert "compliance_controls" in evidence.metadata

    def test_collect_teams_evidence(self, collector, mock_team, mock_private_team):
        """Test collecting teams evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "teams": {
                    "nodes": [mock_team, mock_private_team],
                    "pageInfo": {"hasNextPage": False},
                },
            },
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["teams"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "teams"
            assert evidence.raw_data["total_count"] == 2
            assert evidence.raw_data["private_count"] == 1
            assert evidence.raw_data["public_count"] == 1

    def test_collect_projects_evidence(self, collector, mock_project, mock_completed_project):
        """Test collecting projects evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "projects": {
                    "nodes": [mock_project, mock_completed_project],
                    "pageInfo": {"hasNextPage": False},
                },
            },
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["projects"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "projects"
            assert evidence.raw_data["total_count"] == 2
            assert "started" in evidence.raw_data["state_breakdown"]
            assert "completed" in evidence.raw_data["state_breakdown"]

    def test_collect_issues_evidence(self, collector, mock_issue, mock_completed_issue):
        """Test collecting issues evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "issues": {
                    "nodes": [mock_issue, mock_completed_issue],
                    "pageInfo": {"hasNextPage": False},
                },
            },
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["issues"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "issues"
            assert evidence.raw_data["total_count"] == 2
            assert evidence.raw_data["completed_count"] == 1
            assert evidence.raw_data["unassigned_count"] == 1

    def test_collect_cycles_evidence(self, collector, mock_cycle, mock_completed_cycle):
        """Test collecting cycles evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "cycles": {
                    "nodes": [mock_cycle, mock_completed_cycle],
                    "pageInfo": {"hasNextPage": False},
                },
            },
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["cycles"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "cycles"
            assert evidence.raw_data["total_count"] == 2
            assert evidence.raw_data["completed_count"] == 1
            assert evidence.raw_data["in_progress_count"] == 1

    def test_collect_audit_logs_evidence(self, collector, mock_issue, mock_issue_history):
        """Test collecting audit logs evidence."""
        issue_with_history = mock_issue.copy()
        issue_with_history["history"] = mock_issue_history

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "issues": {
                    "nodes": [issue_with_history],
                    "pageInfo": {"hasNextPage": False},
                },
            },
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["audit_logs"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "audit_logs"
            assert evidence.raw_data["total_count"] == 2
            assert "state_change" in evidence.raw_data["event_types"]
            assert "assignee_change" in evidence.raw_data["event_types"]


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestCollectResources:
    """Tests for resource collection."""

    def test_collect_all_resource_types(self, collector, mock_user, mock_team, mock_project, mock_issue):
        """Test collecting all resource types."""
        def mock_post(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            query = kwargs.get("json", {}).get("query", "")

            if "users" in query:
                response.json.return_value = {
                    "data": {
                        "users": {
                            "nodes": [mock_user],
                            "pageInfo": {"hasNextPage": False},
                        },
                    },
                }
            elif "teams" in query:
                response.json.return_value = {
                    "data": {
                        "teams": {
                            "nodes": [mock_team],
                            "pageInfo": {"hasNextPage": False},
                        },
                    },
                }
            elif "projects" in query:
                response.json.return_value = {
                    "data": {
                        "projects": {
                            "nodes": [mock_project],
                            "pageInfo": {"hasNextPage": False},
                        },
                    },
                }
            elif "issues" in query:
                response.json.return_value = {
                    "data": {
                        "issues": {
                            "nodes": [mock_issue],
                            "pageInfo": {"hasNextPage": False},
                        },
                    },
                }
            else:
                response.json.return_value = {"data": {}}

            return response

        with patch.object(collector.session, "post", side_effect=mock_post):
            resources = collector.collect_resources()

            assert len(resources) == 4
            types = {r.type for r in resources}
            assert "linear_user" in types
            assert "linear_team" in types
            assert "linear_project" in types
            assert "linear_issue" in types

    def test_collect_specific_resource_types(self, collector, mock_user):
        """Test collecting specific resource types."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "users": {
                    "nodes": [mock_user],
                    "pageInfo": {"hasNextPage": False},
                },
            },
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["linear_user"])

            assert len(resources) == 1
            assert resources[0].type == "linear_user"

    def test_collect_resources_invalid_type(self, collector):
        """Test collecting invalid resource type."""
        with pytest.raises(CollectionError, match="Unsupported resource types"):
            collector.collect_resources(resource_types=["invalid_type"])

    def test_collect_user_resources(self, collector, mock_user, mock_admin_user, mock_guest_user):
        """Test collecting user resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "users": {
                    "nodes": [mock_user, mock_admin_user, mock_guest_user],
                    "pageInfo": {"hasNextPage": False},
                },
            },
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["linear_user"])

            assert len(resources) == 3

            # Check member user
            member = next(r for r in resources if r.id == "user-123")
            assert member.type == "linear_user"
            assert member.provider == "linear"
            assert member.tags["role"] == "member"
            assert member.tags["active"] == "true"

            # Check admin user
            admin = next(r for r in resources if r.id == "user-456")
            assert admin.tags["role"] == "admin"

            # Check guest user
            guest = next(r for r in resources if r.id == "user-789")
            assert guest.tags["role"] == "guest"

    def test_collect_team_resources(self, collector, mock_team, mock_private_team):
        """Test collecting team resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "teams": {
                    "nodes": [mock_team, mock_private_team],
                    "pageInfo": {"hasNextPage": False},
                },
            },
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["linear_team"])

            assert len(resources) == 2

            public_team = next(r for r in resources if r.id == "team-123")
            assert public_team.name == "Engineering"
            assert public_team.tags["private"] == "false"
            assert public_team.tags["key"] == "ENG"

            private_team = next(r for r in resources if r.id == "team-456")
            assert private_team.tags["private"] == "true"

    def test_collect_project_resources(self, collector, mock_project):
        """Test collecting project resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "projects": {
                    "nodes": [mock_project],
                    "pageInfo": {"hasNextPage": False},
                },
            },
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["linear_project"])

            assert len(resources) == 1
            assert resources[0].type == "linear_project"
            assert resources[0].name == "Q4 Release"
            assert resources[0].tags["state"] == "started"
            assert resources[0].tags["has_lead"] == "true"

    def test_collect_issue_resources(self, collector, mock_issue):
        """Test collecting issue resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "issues": {
                    "nodes": [mock_issue],
                    "pageInfo": {"hasNextPage": False},
                },
            },
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["linear_issue"])

            assert len(resources) == 1
            assert resources[0].type == "linear_issue"
            assert "ENG-123" in resources[0].name
            assert resources[0].tags["state"] == "In Progress"
            assert resources[0].tags["has_assignee"] == "true"


# =============================================================================
# Pagination Tests
# =============================================================================


class TestPagination:
    """Tests for API pagination."""

    def test_pagination_multiple_pages(self, collector, mock_user):
        """Test pagination across multiple pages."""
        user2 = mock_user.copy()
        user2["id"] = "user-page2"
        user2["name"] = "Page 2 User"

        call_count = [0]

        def mock_post(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            call_count[0] += 1

            variables = kwargs.get("json", {}).get("variables", {})
            after = variables.get("after")

            if not after:
                response.json.return_value = {
                    "data": {
                        "users": {
                            "nodes": [mock_user],
                            "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
                        },
                    },
                }
            else:
                response.json.return_value = {
                    "data": {
                        "users": {
                            "nodes": [user2],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        },
                    },
                }
            return response

        with patch.object(collector.session, "post", side_effect=mock_post):
            result = collector.collect_evidence(evidence_types=["users"])

            evidence = result.evidence_items[0]
            assert evidence.raw_data["total_count"] == 2
            assert call_count[0] == 2

    def test_pagination_stops_on_error(self, collector, mock_user):
        """Test pagination stops on API error."""
        call_count = [0]

        def mock_post(url, **kwargs):
            call_count[0] += 1

            if call_count[0] == 1:
                response = MagicMock()
                response.raise_for_status = MagicMock()
                response.json.return_value = {
                    "data": {
                        "users": {
                            "nodes": [mock_user],
                            "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
                        },
                    },
                }
                return response
            else:
                raise requests.RequestException("API error")

        with patch.object(collector.session, "post", side_effect=mock_post):
            result = collector.collect_evidence(evidence_types=["users"])

            # Should still have results from first page
            evidence = result.evidence_items[0]
            assert evidence.raw_data["total_count"] == 1


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    def test_evidence_collection_error(self, collector):
        """Test graceful handling of evidence collection errors."""
        with patch.object(
            collector.session,
            "post",
            side_effect=requests.RequestException("API error"),
        ):
            result = collector.collect_evidence(evidence_types=["users"])

            # Should still have an evidence item with empty data
            assert len(result.evidence_items) == 1
            assert result.evidence_items[0].raw_data["total_count"] == 0

    def test_partial_evidence_collection(self, collector, mock_user):
        """Test partial evidence collection when some queries fail."""
        call_count = [0]

        def mock_post(url, **kwargs):
            call_count[0] += 1
            query = kwargs.get("json", {}).get("query", "")

            if "users" in query:
                response = MagicMock()
                response.raise_for_status = MagicMock()
                response.json.return_value = {
                    "data": {
                        "users": {
                            "nodes": [mock_user],
                            "pageInfo": {"hasNextPage": False},
                        },
                    },
                }
                return response
            else:
                raise requests.RequestException("API error")

        with patch.object(collector.session, "post", side_effect=mock_post):
            result = collector.collect_evidence(evidence_types=["users", "teams"])

            # Should have evidence for users (with data) and teams (with empty data)
            assert len(result.evidence_items) == 2

    def test_resource_collection_error(self, collector):
        """Test graceful handling of resource collection errors."""
        with patch.object(
            collector.session,
            "post",
            side_effect=requests.RequestException("API error"),
        ):
            resources = collector.collect_resources(resource_types=["linear_user"])

            # Should return empty list
            assert resources == []


# =============================================================================
# Compliance Control Mapping Tests
# =============================================================================


class TestComplianceControls:
    """Tests for compliance control mappings."""

    def test_users_evidence_has_controls(self, collector, mock_user):
        """Test users evidence has compliance controls."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "users": {
                    "nodes": [mock_user],
                    "pageInfo": {"hasNextPage": False},
                },
            },
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["users"])

            evidence = result.evidence_items[0]
            controls = evidence.metadata["compliance_controls"]
            assert "soc2" in controls
            assert "nist_800_53" in controls
            assert "iso_27001" in controls
            assert "hitrust" in controls

    def test_issues_evidence_has_controls(self, collector, mock_issue):
        """Test issues evidence has compliance controls."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "issues": {
                    "nodes": [mock_issue],
                    "pageInfo": {"hasNextPage": False},
                },
            },
        }

        with patch.object(collector.session, "post", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["issues"])

            evidence = result.evidence_items[0]
            controls = evidence.metadata["compliance_controls"]
            assert "CC5.2" in controls["soc2"]
            assert "CM-3" in controls["nist_800_53"]

    def test_all_evidence_types_have_mappings(self, collector):
        """Test all evidence types have compliance mappings."""
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
    """Tests for CLI integration."""

    def test_cli_command_exists(self):
        """Test that the linear CLI command exists."""
        from attestful.cli.main import collect

        commands = [cmd for cmd in collect.commands]
        assert "linear" in commands

    def test_cli_command_options(self):
        """Test that the linear CLI command has correct options."""
        from attestful.cli.main import collect_linear

        param_names = [p.name for p in collect_linear.params]
        assert "api_key" in param_names
        assert "types" in param_names
        assert "days" in param_names
        assert "output" in param_names

    def test_cli_in_collector_list(self):
        """Test that linear is in the collector list."""
        from attestful.cli.main import collect_list
        from click.testing import CliRunner

        runner = CliRunner()
        result = runner.invoke(collect_list, [])

        assert "linear" in result.output.lower()
