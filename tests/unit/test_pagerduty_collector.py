"""
Tests for the PagerDuty collector.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
import pytest
import requests

from attestful.collectors.platforms.pagerduty import PagerDutyCollector, PagerDutyCollectorConfig
from attestful.core.exceptions import CollectionError, ConfigurationError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_incident():
    """Create a mock PagerDuty incident."""
    now = datetime.now(timezone.utc)
    created_at = (now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ack_at = (now - timedelta(hours=1, minutes=45)).strftime("%Y-%m-%dT%H:%M:%SZ")
    resolved_at = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "id": "PINCIDENT1",
        "incident_number": 1234,
        "title": "High CPU usage on prod-server-01",
        "status": "resolved",
        "urgency": "high",
        "priority": {"id": "P1", "name": "P1"},
        "service": {
            "id": "PSERVICE1",
            "type": "service_reference",
            "summary": "Production API",
        },
        "escalation_policy": {
            "id": "PPOLICY1",
            "type": "escalation_policy_reference",
            "summary": "Production On-Call",
        },
        "created_at": created_at,
        "last_status_change_at": resolved_at,
        "resolved_at": resolved_at,
        "assignments": [
            {
                "at": created_at,
                "assignee": {
                    "id": "PUSER1",
                    "type": "user_reference",
                    "summary": "John Doe",
                },
            }
        ],
        "acknowledgements": [
            {
                "at": ack_at,
                "acknowledger": {
                    "id": "PUSER1",
                    "type": "user_reference",
                    "summary": "John Doe",
                },
            }
        ],
    }


@pytest.fixture
def mock_triggered_incident():
    """Create a mock triggered incident."""
    now = datetime.now(timezone.utc)
    return {
        "id": "PINCIDENT2",
        "incident_number": 1235,
        "title": "Database connection failure",
        "status": "triggered",
        "urgency": "high",
        "service": {"id": "PSERVICE2", "summary": "Database"},
        "escalation_policy": {"id": "PPOLICY1", "summary": "Production On-Call"},
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "assignments": [],
        "acknowledgements": [],
    }


@pytest.fixture
def mock_service():
    """Create a mock PagerDuty service."""
    return {
        "id": "PSERVICE1",
        "name": "Production API",
        "description": "Main production API service",
        "status": "active",
        "escalation_policy": {
            "id": "PPOLICY1",
            "type": "escalation_policy_reference",
            "summary": "Production On-Call",
        },
        "auto_resolve_timeout": 14400,
        "acknowledgement_timeout": 1800,
        "alert_creation": "create_alerts_and_incidents",
        "alert_grouping": "intelligent",
        "alert_grouping_timeout": None,
        "teams": [
            {"id": "PTEAM1", "type": "team_reference", "summary": "Platform Team"},
        ],
        "created_at": "2024-01-01T00:00:00Z",
    }


@pytest.fixture
def mock_schedule():
    """Create a mock PagerDuty schedule."""
    return {
        "id": "PSCHEDULE1",
        "name": "Production On-Call",
        "description": "24/7 on-call rotation for production",
        "time_zone": "America/New_York",
        "users": [
            {"id": "PUSER1", "type": "user_reference", "summary": "John Doe"},
            {"id": "PUSER2", "type": "user_reference", "summary": "Jane Smith"},
        ],
        "escalation_policies": [
            {"id": "PPOLICY1", "type": "escalation_policy_reference", "summary": "Production On-Call"},
        ],
        "teams": [
            {"id": "PTEAM1", "type": "team_reference", "summary": "Platform Team"},
        ],
    }


@pytest.fixture
def mock_escalation_policy():
    """Create a mock PagerDuty escalation policy."""
    return {
        "id": "PPOLICY1",
        "name": "Production On-Call",
        "description": "Escalation for production incidents",
        "num_loops": 2,
        "on_call_handoff_notifications": "if_has_services",
        "escalation_rules": [
            {
                "escalation_delay_in_minutes": 5,
                "targets": [
                    {"id": "PSCHEDULE1", "type": "schedule_reference", "summary": "Production On-Call"},
                ],
            },
            {
                "escalation_delay_in_minutes": 10,
                "targets": [
                    {"id": "PUSER3", "type": "user_reference", "summary": "Manager"},
                ],
            },
        ],
        "services": [
            {"id": "PSERVICE1", "type": "service_reference", "summary": "Production API"},
        ],
        "teams": [],
    }


@pytest.fixture
def mock_user():
    """Create a mock PagerDuty user."""
    return {
        "id": "PUSER1",
        "name": "John Doe",
        "email": "john.doe@example.com",
        "role": "user",
        "job_title": "Senior Engineer",
        "time_zone": "America/New_York",
        "invitation_sent": True,
        "teams": [
            {"id": "PTEAM1", "type": "team_reference", "summary": "Platform Team"},
        ],
    }


@pytest.fixture
def mock_admin_user():
    """Create a mock admin user."""
    return {
        "id": "PUSER3",
        "name": "Admin User",
        "email": "admin@example.com",
        "role": "admin",
        "job_title": "Engineering Manager",
        "time_zone": "America/New_York",
        "invitation_sent": True,
        "teams": [],
    }


@pytest.fixture
def mock_team():
    """Create a mock PagerDuty team."""
    return {
        "id": "PTEAM1",
        "name": "Platform Team",
        "description": "Platform engineering team",
    }


@pytest.fixture
def mock_contact_method():
    """Create a mock contact method."""
    return {
        "id": "PCONTACT1",
        "type": "email_contact_method",
        "address": "john.doe@example.com",
    }


@pytest.fixture
def mock_integration():
    """Create a mock service integration."""
    return {
        "id": "PINTEG1",
        "type": "aws_cloudwatch_inbound_integration",
        "name": "AWS CloudWatch",
    }


@pytest.fixture
def collector():
    """Create a PagerDutyCollector instance."""
    config = PagerDutyCollectorConfig(
        api_token="test-api-token-12345",
        days_of_history=90,
    )
    return PagerDutyCollector(config=config)


# =============================================================================
# Initialization Tests
# =============================================================================


class TestPagerDutyCollectorInit:
    """Tests for PagerDutyCollector initialization."""

    def test_init_with_config(self, collector):
        """Test initialization with config."""
        assert collector.config.api_token == "test-api-token-12345"
        assert collector.config.days_of_history == 90

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = PagerDutyCollector()
        assert collector.config.api_token == ""
        assert collector.config.timeout == 30
        assert collector.config.max_retries == 3
        assert collector.config.page_size == 100
        assert collector.config.days_of_history == 90

    def test_metadata(self, collector):
        """Test collector metadata."""
        assert collector.metadata.name == "PagerDutyCollector"
        assert collector.metadata.platform == "pagerduty"
        assert "pagerduty_incident" in collector.metadata.resource_types
        assert "pagerduty_service" in collector.metadata.resource_types
        assert "incidents" in collector.metadata.evidence_types
        assert "services" in collector.metadata.evidence_types

    def test_platform(self, collector):
        """Test platform attribute."""
        assert collector.PLATFORM == "pagerduty"

    def test_api_url(self, collector):
        """Test API URL property."""
        assert collector.api_url == "https://api.pagerduty.com"


# =============================================================================
# Session Tests
# =============================================================================


class TestPagerDutySession:
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
        assert "Token token=" in session.headers["Authorization"]


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestValidateCredentials:
    """Tests for credential validation."""

    def test_validate_credentials_success(self, collector):
        """Test successful credential validation."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "abilities": ["read_access", "write_access"],
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.validate_credentials()
            assert result is True

    def test_validate_credentials_no_token(self):
        """Test validation fails without token."""
        collector = PagerDutyCollector(config=PagerDutyCollectorConfig(api_token=""))
        with pytest.raises(ConfigurationError, match="api_token is required"):
            collector.validate_credentials()

    def test_validate_credentials_invalid_token(self, collector):
        """Test validation fails with invalid token."""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.HTTPError("401 Unauthorized")

        with patch.object(collector.session, "get", return_value=mock_response):
            mock_response.raise_for_status.side_effect = requests.HTTPError("401 Unauthorized")
            with pytest.raises(ConfigurationError, match="Invalid PagerDuty API token"):
                collector.validate_credentials()

    def test_validate_credentials_api_error(self, collector):
        """Test validation handles API errors."""
        with patch.object(
            collector.session,
            "get",
            side_effect=requests.RequestException("Connection error"),
        ):
            with pytest.raises(ConfigurationError, match="Failed to validate"):
                collector.validate_credentials()


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestCollectEvidence:
    """Tests for evidence collection."""

    def test_collect_all_evidence_types(self, collector, mock_incident, mock_service, mock_schedule, mock_user, mock_team):
        """Test collecting all evidence types."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "/incidents" in url:
                response.json.return_value = {
                    "incidents": [mock_incident],
                    "more": False,
                }
            elif "/services" in url and "/integrations" not in url:
                response.json.return_value = {
                    "services": [mock_service],
                    "more": False,
                }
            elif "/integrations" in url:
                response.json.return_value = {
                    "integrations": [],
                }
            elif "/schedules" in url:
                response.json.return_value = {
                    "schedules": [mock_schedule],
                    "schedule": mock_schedule,
                    "more": False,
                }
            elif "/escalation_policies" in url:
                response.json.return_value = {
                    "escalation_policies": [],
                    "more": False,
                }
            elif "/users" in url and "/contact_methods" not in url:
                response.json.return_value = {
                    "users": [mock_user],
                    "more": False,
                }
            elif "/contact_methods" in url:
                response.json.return_value = {
                    "contact_methods": [],
                }
            elif "/teams" in url and "/members" not in url:
                response.json.return_value = {
                    "teams": [mock_team],
                    "more": False,
                }
            elif "/members" in url:
                response.json.return_value = {
                    "members": [],
                }
            else:
                response.json.return_value = {}

            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence()

            assert result.platform == "pagerduty"
            assert len(result.evidence_items) > 0
            assert result.started_at is not None
            assert result.completed_at is not None

    def test_collect_specific_evidence_types(self, collector, mock_incident):
        """Test collecting specific evidence types."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "incidents": [mock_incident],
            "more": False,
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["incidents"])

            assert result.platform == "pagerduty"
            assert len(result.evidence_items) == 1
            assert result.evidence_items[0].evidence_type == "incidents"

    def test_collect_evidence_invalid_type(self, collector):
        """Test collecting invalid evidence type."""
        with pytest.raises(CollectionError, match="Unsupported evidence types"):
            collector.collect_evidence(evidence_types=["invalid_type"])

    def test_collect_incidents_evidence(self, collector, mock_incident, mock_triggered_incident):
        """Test collecting incidents evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "incidents": [mock_incident, mock_triggered_incident],
            "more": False,
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["incidents"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "incidents"
            assert evidence.platform == "pagerduty"
            assert evidence.raw_data["total_count"] == 2
            assert evidence.raw_data["resolved_count"] == 1
            assert evidence.raw_data["high_urgency_count"] == 2
            assert "compliance_controls" in evidence.metadata

    def test_collect_services_evidence(self, collector, mock_service):
        """Test collecting services evidence."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "/integrations" in url:
                response.json.return_value = {"integrations": []}
            else:
                response.json.return_value = {
                    "services": [mock_service],
                    "more": False,
                }
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["services"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "services"
            assert evidence.raw_data["total_count"] == 1
            assert evidence.raw_data["active_count"] == 1

    def test_collect_schedules_evidence(self, collector, mock_schedule):
        """Test collecting schedules evidence."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "schedules/" in url and url != "https://api.pagerduty.com/schedules":
                response.json.return_value = {"schedule": mock_schedule}
            else:
                response.json.return_value = {
                    "schedules": [mock_schedule],
                    "more": False,
                }
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["schedules"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "schedules"
            assert evidence.raw_data["total_count"] == 1

    def test_collect_escalation_policies_evidence(self, collector, mock_escalation_policy):
        """Test collecting escalation policies evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "escalation_policies": [mock_escalation_policy],
            "more": False,
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["escalation_policies"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "escalation_policies"
            assert evidence.raw_data["total_count"] == 1

    def test_collect_users_evidence(self, collector, mock_user, mock_admin_user):
        """Test collecting users evidence."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "/contact_methods" in url:
                response.json.return_value = {"contact_methods": []}
            else:
                response.json.return_value = {
                    "users": [mock_user, mock_admin_user],
                    "more": False,
                }
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["users"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "users"
            assert evidence.raw_data["total_count"] == 2
            assert "user" in evidence.raw_data["role_counts"]
            assert "admin" in evidence.raw_data["role_counts"]

    def test_collect_teams_evidence(self, collector, mock_team):
        """Test collecting teams evidence."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "/members" in url:
                response.json.return_value = {"members": []}
            else:
                response.json.return_value = {
                    "teams": [mock_team],
                    "more": False,
                }
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["teams"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "teams"
            assert evidence.raw_data["total_count"] == 1

    def test_collect_analytics_evidence(self, collector, mock_incident):
        """Test collecting analytics evidence."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "incidents": [mock_incident],
            "more": False,
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["analytics"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "analytics"
            assert "period" in evidence.raw_data
            assert "summary" in evidence.raw_data


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestCollectResources:
    """Tests for resource collection."""

    def test_collect_all_resource_types(self, collector, mock_incident, mock_service, mock_schedule, mock_user):
        """Test collecting all resource types."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "/incidents" in url:
                response.json.return_value = {
                    "incidents": [mock_incident],
                    "more": False,
                }
            elif "/services" in url:
                response.json.return_value = {
                    "services": [mock_service],
                    "more": False,
                }
            elif "/schedules" in url:
                response.json.return_value = {
                    "schedules": [mock_schedule],
                    "more": False,
                }
            elif "/users" in url:
                response.json.return_value = {
                    "users": [mock_user],
                    "more": False,
                }
            else:
                response.json.return_value = {"more": False}

            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            resources = collector.collect_resources()

            assert len(resources) > 0
            types = {r.type for r in resources}
            assert "pagerduty_incident" in types
            assert "pagerduty_service" in types
            assert "pagerduty_schedule" in types
            assert "pagerduty_user" in types

    def test_collect_specific_resource_types(self, collector, mock_incident):
        """Test collecting specific resource types."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "incidents": [mock_incident],
            "more": False,
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["pagerduty_incident"])

            assert len(resources) == 1
            assert resources[0].type == "pagerduty_incident"

    def test_collect_resources_invalid_type(self, collector):
        """Test collecting invalid resource type."""
        with pytest.raises(CollectionError, match="Unsupported resource types"):
            collector.collect_resources(resource_types=["invalid_type"])

    def test_collect_incident_resources(self, collector, mock_incident):
        """Test collecting incident resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "incidents": [mock_incident],
            "more": False,
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["pagerduty_incident"])

            assert len(resources) == 1
            resource = resources[0]
            assert resource.type == "pagerduty_incident"
            assert resource.provider == "pagerduty"
            assert resource.id == "PINCIDENT1"
            assert resource.tags["status"] == "resolved"
            assert resource.tags["urgency"] == "high"

    def test_collect_service_resources(self, collector, mock_service):
        """Test collecting service resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "services": [mock_service],
            "more": False,
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["pagerduty_service"])

            assert len(resources) == 1
            resource = resources[0]
            assert resource.type == "pagerduty_service"
            assert resource.id == "PSERVICE1"
            assert resource.name == "Production API"
            assert resource.tags["status"] == "active"

    def test_collect_schedule_resources(self, collector, mock_schedule):
        """Test collecting schedule resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "schedules": [mock_schedule],
            "more": False,
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["pagerduty_schedule"])

            assert len(resources) == 1
            resource = resources[0]
            assert resource.type == "pagerduty_schedule"
            assert resource.id == "PSCHEDULE1"
            assert resource.name == "Production On-Call"
            assert resource.tags["user_count"] == "2"

    def test_collect_user_resources(self, collector, mock_user):
        """Test collecting user resources."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "users": [mock_user],
            "more": False,
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            resources = collector.collect_resources(resource_types=["pagerduty_user"])

            assert len(resources) == 1
            resource = resources[0]
            assert resource.type == "pagerduty_user"
            assert resource.id == "PUSER1"
            assert resource.name == "John Doe"
            assert resource.tags["role"] == "user"


# =============================================================================
# Pagination Tests
# =============================================================================


class TestPagination:
    """Tests for API pagination."""

    def test_pagination_multiple_pages(self, collector, mock_incident):
        """Test pagination across multiple pages."""
        page1_incident = mock_incident.copy()
        page1_incident["id"] = "PINCIDENT1"

        page2_incident = mock_incident.copy()
        page2_incident["id"] = "PINCIDENT2"

        call_count = [0]

        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            call_count[0] += 1

            params = kwargs.get("params", {})
            offset = params.get("offset", 0)

            if offset == 0:
                response.json.return_value = {
                    "incidents": [page1_incident],
                    "more": True,
                }
            else:
                response.json.return_value = {
                    "incidents": [page2_incident],
                    "more": False,
                }
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["incidents"])

            evidence = result.evidence_items[0]
            assert evidence.raw_data["total_count"] == 2

    def test_pagination_stops_on_error(self, collector, mock_incident):
        """Test pagination stops on API error."""
        call_count = [0]

        def mock_get(url, **kwargs):
            call_count[0] += 1

            if call_count[0] == 1:
                response = MagicMock()
                response.raise_for_status = MagicMock()
                response.json.return_value = {
                    "incidents": [mock_incident],
                    "more": True,
                }
                return response
            else:
                raise requests.RequestException("API error")

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["incidents"])

            # Should still have results from first page
            evidence = result.evidence_items[0]
            assert evidence.raw_data["total_count"] == 1


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    def test_api_error_logged_but_continues(self, collector, mock_incident):
        """Test that API errors are logged but collection continues."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "/incidents" in url:
                response.json.return_value = {
                    "incidents": [mock_incident],
                    "more": False,
                }
            else:
                raise requests.RequestException("API error")
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["incidents", "services"])

            # Should still have incidents evidence
            evidence_types = [e.evidence_type for e in result.evidence_items]
            assert "incidents" in evidence_types

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

    def test_incidents_evidence_has_controls(self, collector, mock_incident):
        """Test incidents evidence has compliance controls."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "incidents": [mock_incident],
            "more": False,
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["incidents"])

            evidence = result.evidence_items[0]
            controls = evidence.metadata["compliance_controls"]
            assert "soc2" in controls
            assert "nist_800_53" in controls
            assert "iso_27001" in controls
            assert "hitrust" in controls
            # Check specific incident response controls
            assert "IR-4" in controls["nist_800_53"]

    def test_services_evidence_has_controls(self, collector, mock_service):
        """Test services evidence has compliance controls."""
        def mock_get(url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "/integrations" in url:
                response.json.return_value = {"integrations": []}
            else:
                response.json.return_value = {
                    "services": [mock_service],
                    "more": False,
                }
            return response

        with patch.object(collector.session, "get", side_effect=mock_get):
            result = collector.collect_evidence(evidence_types=["services"])

            evidence = result.evidence_items[0]
            controls = evidence.metadata["compliance_controls"]
            assert "CC7.1" in controls["soc2"]
            assert "CM-2" in controls["nist_800_53"]

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
# Analytics Tests
# =============================================================================


class TestAnalytics:
    """Tests for analytics evidence collection."""

    def test_analytics_calculates_mtta(self, collector, mock_incident):
        """Test MTTA calculation."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "incidents": [mock_incident],
            "more": False,
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["analytics"])

            evidence = result.evidence_items[0]
            summary = evidence.raw_data["summary"]
            assert summary["total_incidents"] == 1
            assert summary["mean_time_to_acknowledge_seconds"] is not None

    def test_analytics_calculates_mttr(self, collector, mock_incident):
        """Test MTTR calculation."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "incidents": [mock_incident],
            "more": False,
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["analytics"])

            evidence = result.evidence_items[0]
            summary = evidence.raw_data["summary"]
            assert summary["resolved_incidents"] == 1
            assert summary["mean_time_to_resolve_seconds"] is not None

    def test_analytics_handles_empty_incidents(self, collector):
        """Test analytics with no incidents."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "incidents": [],
            "more": False,
        }

        with patch.object(collector.session, "get", return_value=mock_response):
            result = collector.collect_evidence(evidence_types=["analytics"])

            evidence = result.evidence_items[0]
            summary = evidence.raw_data["summary"]
            assert summary["total_incidents"] == 0
            assert summary["mean_time_to_acknowledge_seconds"] is None
            assert summary["mean_time_to_resolve_seconds"] is None
