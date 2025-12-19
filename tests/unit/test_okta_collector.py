"""
Unit tests for Okta collector.

Tests cover:
- Configuration and initialization
- Credential validation
- Resource collection (users, groups, applications)
- Evidence collection (users, mfa_factors, groups, applications, policies, system_log)
- Pagination handling
- Error handling and rate limiting
- Mocked API responses
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import Mock, patch, MagicMock

import pytest
from requests.exceptions import HTTPError

from attestful.collectors.platforms.okta import OktaCollector, OktaCollectorConfig
from attestful.core.models import CollectionResult, Evidence, Resource
from attestful.core.exceptions import ConfigurationError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def okta_config() -> OktaCollectorConfig:
    """Sample Okta configuration."""
    return OktaCollectorConfig(
        domain="test.okta.com",
        api_token="00abc123def456",
        timeout=30,
        page_size=200,
    )


@pytest.fixture
def collector(okta_config: OktaCollectorConfig) -> OktaCollector:
    """Okta collector instance."""
    return OktaCollector(config=okta_config)


@pytest.fixture
def mock_response():
    """Create a mock response factory."""
    def _create_response(json_data, status_code=200, headers=None):
        response = Mock()
        response.json.return_value = json_data
        response.status_code = status_code
        response.headers = headers or {}
        response.raise_for_status = Mock()
        if status_code >= 400:
            response.raise_for_status.side_effect = HTTPError(f"HTTP {status_code}")
        return response
    return _create_response


@pytest.fixture
def sample_users() -> list[dict]:
    """Sample Okta users data."""
    return [
        {
            "id": "00u1",
            "status": "ACTIVE",
            "created": "2024-01-01T00:00:00.000Z",
            "profile": {
                "firstName": "John",
                "lastName": "Doe",
                "email": "john.doe@example.com",
                "login": "john.doe@example.com",
            },
            "type": {"id": "default"},
        },
        {
            "id": "00u2",
            "status": "PROVISIONED",
            "created": "2024-01-02T00:00:00.000Z",
            "profile": {
                "firstName": "Jane",
                "lastName": "Smith",
                "email": "jane.smith@example.com",
                "login": "jane.smith@example.com",
            },
            "type": {"id": "default"},
        },
        {
            "id": "00u3",
            "status": "SUSPENDED",
            "created": "2024-01-03T00:00:00.000Z",
            "profile": {
                "firstName": "Bob",
                "lastName": "Wilson",
                "email": "bob.wilson@example.com",
                "login": "bob.wilson@example.com",
            },
            "type": {"id": "default"},
        },
    ]


@pytest.fixture
def sample_groups() -> list[dict]:
    """Sample Okta groups data."""
    return [
        {
            "id": "00g1",
            "type": "OKTA_GROUP",
            "profile": {
                "name": "Everyone",
                "description": "All users",
            },
        },
        {
            "id": "00g2",
            "type": "OKTA_GROUP",
            "profile": {
                "name": "Administrators",
                "description": "Admin users",
            },
        },
    ]


@pytest.fixture
def sample_applications() -> list[dict]:
    """Sample Okta applications data."""
    return [
        {
            "id": "0oa1",
            "name": "oidc_client",
            "label": "Internal App",
            "status": "ACTIVE",
            "signOnMode": "OPENID_CONNECT",
            "created": "2024-01-01T00:00:00.000Z",
            "lastUpdated": "2024-01-15T00:00:00.000Z",
            "visibility": {"autoSubmitToolbar": False},
            "features": [],
        },
        {
            "id": "0oa2",
            "name": "saml_client",
            "label": "External App",
            "status": "ACTIVE",
            "signOnMode": "SAML_2_0",
            "created": "2024-01-01T00:00:00.000Z",
            "lastUpdated": "2024-01-10T00:00:00.000Z",
            "visibility": {},
            "features": ["PUSH_NEW_USERS"],
        },
    ]


@pytest.fixture
def sample_mfa_factors() -> list[dict]:
    """Sample MFA factors data."""
    return [
        {
            "id": "fac1",
            "factorType": "push",
            "provider": "OKTA",
            "status": "ACTIVE",
        },
        {
            "id": "fac2",
            "factorType": "token:software:totp",
            "provider": "GOOGLE",
            "status": "ACTIVE",
        },
    ]


@pytest.fixture
def sample_policies() -> list[dict]:
    """Sample Okta policies data."""
    return [
        {
            "id": "pol1",
            "name": "Default Password Policy",
            "type": "PASSWORD",
            "status": "ACTIVE",
            "priority": 1,
            "conditions": {},
            "settings": {
                "password": {
                    "complexity": {"minLength": 8},
                    "age": {"maxAgeDays": 90},
                },
            },
        },
    ]


@pytest.fixture
def sample_system_log_events() -> list[dict]:
    """Sample system log events."""
    return [
        {
            "uuid": "event1",
            "published": "2024-01-15T10:00:00.000Z",
            "eventType": "user.session.start",
            "displayMessage": "User login to Okta",
            "severity": "INFO",
            "outcome": {"result": "SUCCESS"},
            "actor": {"id": "00u1", "type": "User", "displayName": "John Doe"},
            "target": [],
            "client": {"ipAddress": "192.168.1.1"},
        },
        {
            "uuid": "event2",
            "published": "2024-01-15T10:05:00.000Z",
            "eventType": "user.authentication.auth_via_mfa",
            "displayMessage": "User authenticated via MFA",
            "severity": "INFO",
            "outcome": {"result": "SUCCESS"},
            "actor": {"id": "00u1", "type": "User"},
            "target": [],
            "client": {},
        },
        {
            "uuid": "event3",
            "published": "2024-01-15T10:10:00.000Z",
            "eventType": "security.threat.detected",
            "displayMessage": "Suspicious activity detected",
            "severity": "WARN",
            "outcome": {"result": "CHALLENGE"},
            "actor": {"id": "00u2", "type": "User"},
            "target": [],
            "client": {},
        },
    ]


# =============================================================================
# Configuration Tests
# =============================================================================


class TestOktaCollectorConfig:
    """Tests for OktaCollectorConfig."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = OktaCollectorConfig()

        assert config.domain == ""
        assert config.api_token == ""
        assert config.timeout == 30
        assert config.max_retries == 3
        assert config.page_size == 200

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = OktaCollectorConfig(
            domain="company.okta.com",
            api_token="test-token",
            timeout=60,
            max_retries=5,
            page_size=100,
        )

        assert config.domain == "company.okta.com"
        assert config.api_token == "test-token"
        assert config.timeout == 60
        assert config.max_retries == 5
        assert config.page_size == 100


# =============================================================================
# Collector Initialization Tests
# =============================================================================


class TestOktaCollectorInit:
    """Tests for collector initialization."""

    def test_init_with_config(self, okta_config: OktaCollectorConfig) -> None:
        """Test initialization with config."""
        collector = OktaCollector(config=okta_config)

        assert collector.config == okta_config
        assert collector.PLATFORM == "okta"

    def test_init_without_config(self) -> None:
        """Test initialization without config uses defaults."""
        collector = OktaCollector()

        assert collector.config is not None
        assert collector.config.domain == ""

    def test_base_url(self, collector: OktaCollector) -> None:
        """Test base URL construction."""
        assert collector.base_url == "https://test.okta.com/api/v1"

    def test_base_url_with_https_prefix(self) -> None:
        """Test base URL when domain already has https."""
        config = OktaCollectorConfig(
            domain="https://test.okta.com",
            api_token="token",
        )
        collector = OktaCollector(config=config)

        # Should not duplicate https:// prefix
        assert collector.base_url == "https://test.okta.com/api/v1"

    def test_base_url_without_domain(self) -> None:
        """Test base URL raises error when domain not set."""
        config = OktaCollectorConfig(api_token="token")
        collector = OktaCollector(config=config)

        with pytest.raises(ConfigurationError):
            _ = collector.base_url

    def test_supported_types(self, collector: OktaCollector) -> None:
        """Test supported resource and evidence types."""
        assert "okta_user" in collector.SUPPORTED_RESOURCE_TYPES
        assert "okta_group" in collector.SUPPORTED_RESOURCE_TYPES
        assert "okta_application" in collector.SUPPORTED_RESOURCE_TYPES

        assert "users" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "mfa_factors" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "groups" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "applications" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "policies" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "system_log" in collector.SUPPORTED_EVIDENCE_TYPES


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestCredentialValidation:
    """Tests for credential validation."""

    def test_validate_credentials_success(
        self, collector: OktaCollector, mock_response
    ) -> None:
        """Test successful credential validation."""
        with patch.object(collector, "_request") as mock_request:
            mock_request.return_value = mock_response({
                "id": "00u1",
                "profile": {"email": "admin@example.com"},
            })

            result = collector.validate_credentials()

            assert result is True
            mock_request.assert_called_once_with("GET", "/users/me")

    def test_validate_credentials_failure(self, collector: OktaCollector) -> None:
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

    def test_collect_okta_users(
        self, collector: OktaCollector, sample_users: list[dict]
    ) -> None:
        """Test collecting Okta users as resources."""
        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter(sample_users)

            resources = collector.collect_resources(resource_types=["okta_user"])

            assert len(resources) == 3
            assert all(isinstance(r, Resource) for r in resources)
            assert resources[0].type == "okta_user"
            assert resources[0].name == "john.doe@example.com"
            assert resources[0].provider == "okta"
            assert resources[0].tags["status"] == "ACTIVE"

    def test_collect_okta_groups(
        self, collector: OktaCollector, sample_groups: list[dict]
    ) -> None:
        """Test collecting Okta groups as resources."""
        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter(sample_groups)

            resources = collector.collect_resources(resource_types=["okta_group"])

            assert len(resources) == 2
            assert resources[0].type == "okta_group"
            assert resources[0].name == "Everyone"
            assert resources[0].tags["type"] == "OKTA_GROUP"

    def test_collect_okta_applications(
        self, collector: OktaCollector, sample_applications: list[dict]
    ) -> None:
        """Test collecting Okta applications as resources."""
        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter(sample_applications)

            resources = collector.collect_resources(resource_types=["okta_application"])

            assert len(resources) == 2
            assert resources[0].type == "okta_application"
            assert resources[0].name == "Internal App"
            assert resources[0].tags["sign_on_mode"] == "OPENID_CONNECT"

    def test_collect_all_resource_types(
        self, collector: OktaCollector, sample_users: list[dict]
    ) -> None:
        """Test collecting all resource types."""
        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter(sample_users)

            resources = collector.collect_resources()

            # Should attempt to collect all supported types
            assert mock_paginate.call_count >= 1

    def test_collect_unknown_resource_type(self, collector: OktaCollector) -> None:
        """Test handling unknown resource type."""
        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter([])

            resources = collector.collect_resources(resource_types=["unknown_type"])

            assert resources == []

    def test_resource_collection_error_handling(
        self, collector: OktaCollector
    ) -> None:
        """Test that resource collection handles errors gracefully."""
        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.side_effect = Exception("API Error")

            # Should not raise, just return empty list
            resources = collector.collect_resources(resource_types=["okta_user"])

            assert resources == []


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestUsersEvidence:
    """Tests for users evidence collection."""

    def test_collect_users_evidence(
        self, collector: OktaCollector, sample_users: list[dict]
    ) -> None:
        """Test collecting users evidence."""
        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter(sample_users)

            result = collector.collect_evidence(evidence_types=["users"])

            assert isinstance(result, CollectionResult)
            assert len(result.evidence) == 1

            evidence = result.evidence[0]
            assert evidence.evidence_type == "users"
            assert evidence.raw_data["total_count"] == 3
            assert "ACTIVE" in evidence.raw_data["status_breakdown"]
            assert evidence.raw_data["status_breakdown"]["ACTIVE"] == 1
            assert evidence.raw_data["status_breakdown"]["PROVISIONED"] == 1
            assert evidence.raw_data["status_breakdown"]["SUSPENDED"] == 1


class TestMFAFactorsEvidence:
    """Tests for MFA factors evidence collection."""

    def test_collect_mfa_factors_evidence(
        self,
        collector: OktaCollector,
        sample_users: list[dict],
        sample_mfa_factors: list[dict],
        mock_response,
    ) -> None:
        """Test collecting MFA factors evidence."""
        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter(sample_users)
            with patch.object(collector, "_request") as mock_request:
                # First user has MFA, others don't
                mock_request.side_effect = [
                    mock_response(sample_mfa_factors),  # User 1 - has MFA
                    mock_response([]),  # User 2 - no MFA
                    mock_response([]),  # User 3 - no MFA
                ]

                result = collector.collect_evidence(evidence_types=["mfa_factors"])

                assert len(result.evidence) == 1
                evidence = result.evidence[0]
                assert evidence.evidence_type == "mfa_factors"
                assert evidence.raw_data["summary"]["total_users"] == 3
                assert evidence.raw_data["summary"]["users_with_mfa"] == 1
                assert evidence.raw_data["summary"]["users_without_mfa"] == 2
                assert evidence.raw_data["summary"]["mfa_enrollment_rate"] == pytest.approx(33.33, rel=0.1)

    def test_mfa_factors_with_api_error(
        self,
        collector: OktaCollector,
        sample_users: list[dict],
        mock_response,
    ) -> None:
        """Test MFA collection handles API errors for individual users."""
        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter([sample_users[0]])  # Just one user
            with patch.object(collector, "_request") as mock_request:
                mock_request.side_effect = Exception("API Error")

                result = collector.collect_evidence(evidence_types=["mfa_factors"])

                assert len(result.evidence) == 1
                evidence = result.evidence[0]
                # User should still be recorded but with error
                assert evidence.raw_data["users"][0]["has_mfa"] is False
                assert "error" in evidence.raw_data["users"][0]


class TestGroupsEvidence:
    """Tests for groups evidence collection."""

    def test_collect_groups_evidence(
        self,
        collector: OktaCollector,
        sample_groups: list[dict],
        sample_users: list[dict],
    ) -> None:
        """Test collecting groups evidence with members."""
        with patch.object(collector, "_paginate") as mock_paginate:
            # First call returns groups, subsequent calls return group members
            mock_paginate.side_effect = [
                iter(sample_groups),
                iter(sample_users[:2]),  # Group 1 members
                iter(sample_users[2:]),  # Group 2 members
            ]

            result = collector.collect_evidence(evidence_types=["groups"])

            assert len(result.evidence) == 1
            evidence = result.evidence[0]
            assert evidence.evidence_type == "groups"
            assert evidence.raw_data["total_groups"] == 2
            assert evidence.raw_data["groups"][0]["name"] == "Everyone"
            assert evidence.raw_data["groups"][0]["member_count"] == 2


class TestApplicationsEvidence:
    """Tests for applications evidence collection."""

    def test_collect_applications_evidence(
        self,
        collector: OktaCollector,
        sample_applications: list[dict],
        sample_users: list[dict],
    ) -> None:
        """Test collecting applications evidence."""
        with patch.object(collector, "_paginate") as mock_paginate:
            # First call returns apps, subsequent calls return app users
            mock_paginate.side_effect = [
                iter(sample_applications),
                iter(sample_users[:1]),  # App 1 users
                iter(sample_users[1:]),  # App 2 users
            ]

            result = collector.collect_evidence(evidence_types=["applications"])

            assert len(result.evidence) == 1
            evidence = result.evidence[0]
            assert evidence.evidence_type == "applications"
            assert evidence.raw_data["total_applications"] == 2
            assert evidence.raw_data["active_applications"] == 2


class TestPoliciesEvidence:
    """Tests for policies evidence collection."""

    def test_collect_policies_evidence(
        self,
        collector: OktaCollector,
        sample_policies: list[dict],
        mock_response,
    ) -> None:
        """Test collecting policies evidence."""
        with patch.object(collector, "_request") as mock_request:
            mock_request.side_effect = [
                mock_response(sample_policies),  # Password policies
                mock_response([]),  # Password policy rules
                mock_response([]),  # Sign-on policies
            ]

            result = collector.collect_evidence(evidence_types=["policies"])

            assert len(result.evidence) == 1
            evidence = result.evidence[0]
            assert evidence.evidence_type == "policies"
            assert len(evidence.raw_data["password_policies"]) == 1
            assert evidence.raw_data["password_policies"][0]["name"] == "Default Password Policy"

    def test_policies_with_rules(
        self,
        collector: OktaCollector,
        sample_policies: list[dict],
        mock_response,
    ) -> None:
        """Test policy collection includes rules."""
        policy_rules = [
            {"id": "rule1", "name": "Default Rule", "status": "ACTIVE"},
        ]

        with patch.object(collector, "_request") as mock_request:
            mock_request.side_effect = [
                mock_response(sample_policies),
                mock_response(policy_rules),  # Rules for policy
                mock_response([]),  # Sign-on policies
            ]

            result = collector.collect_evidence(evidence_types=["policies"])

            evidence = result.evidence[0]
            assert len(evidence.raw_data["password_policies"][0]["rules"]) == 1


class TestSystemLogEvidence:
    """Tests for system log evidence collection."""

    def test_collect_system_log_evidence(
        self,
        collector: OktaCollector,
        sample_system_log_events: list[dict],
    ) -> None:
        """Test collecting system log evidence."""
        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter(sample_system_log_events)

            result = collector.collect_evidence(evidence_types=["system_log"])

            assert len(result.evidence) == 1
            evidence = result.evidence[0]
            assert evidence.evidence_type == "system_log"
            assert evidence.raw_data["total_events"] == 3
            # Should identify security-relevant events
            assert evidence.raw_data["security_events_count"] >= 1

    def test_system_log_event_type_breakdown(
        self,
        collector: OktaCollector,
        sample_system_log_events: list[dict],
    ) -> None:
        """Test system log includes event type breakdown."""
        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter(sample_system_log_events)

            result = collector.collect_evidence(evidence_types=["system_log"])

            evidence = result.evidence[0]
            breakdown = evidence.raw_data["event_type_breakdown"]
            assert "user.session.start" in breakdown
            assert "user.authentication.auth_via_mfa" in breakdown


# =============================================================================
# Pagination Tests
# =============================================================================


class TestPagination:
    """Tests for API pagination."""

    def test_paginate_single_page(
        self, collector: OktaCollector, sample_users: list[dict], mock_response
    ) -> None:
        """Test pagination with single page."""
        with patch.object(collector, "_get_session") as mock_session:
            session = Mock()
            mock_session.return_value = session
            session.request.return_value = mock_response(
                sample_users,
                headers={"Link": ""},  # No next page
            )

            results = list(collector._paginate("/users"))

            assert len(results) == 3

    def test_paginate_multiple_pages(
        self, collector: OktaCollector, mock_response
    ) -> None:
        """Test pagination with multiple pages."""
        page1 = [{"id": "1"}, {"id": "2"}]
        page2 = [{"id": "3"}, {"id": "4"}]

        with patch.object(collector, "_get_session") as mock_session:
            session = Mock()
            mock_session.return_value = session

            # First page has next link
            resp1 = mock_response(
                page1,
                headers={"Link": '<https://test.okta.com/api/v1/users?after=2>; rel="next"'},
            )
            # Second page has no next link
            resp2 = mock_response(page2, headers={"Link": ""})

            session.request.side_effect = [resp1, resp2]

            results = list(collector._paginate("/users"))

            assert len(results) == 4
            assert [r["id"] for r in results] == ["1", "2", "3", "4"]


# =============================================================================
# Rate Limiting Tests
# =============================================================================


class TestRateLimiting:
    """Tests for rate limiting handling."""

    def test_rate_limit_retry(
        self, collector: OktaCollector, sample_users: list[dict], mock_response
    ) -> None:
        """Test rate limit handling with retry."""
        with patch.object(collector, "_get_session") as mock_session:
            session = Mock()
            mock_session.return_value = session

            # First request is rate limited, second succeeds
            rate_limited = mock_response(
                {"error": "rate limited"},
                status_code=429,
                headers={"X-Rate-Limit-Reset": "1"},
            )
            rate_limited.raise_for_status = Mock()  # Don't raise for 429
            success = mock_response(sample_users)

            session.request.side_effect = [rate_limited, success]

            with patch("time.sleep"):  # Don't actually sleep
                response = collector._request("GET", "/users")

            assert response.json() == sample_users


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    def test_evidence_collection_error(self, collector: OktaCollector) -> None:
        """Test that evidence collection handles errors gracefully."""
        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.side_effect = Exception("API Error")

            result = collector.collect_evidence(evidence_types=["users"])

            assert isinstance(result, CollectionResult)
            assert len(result.errors) > 0
            assert "users" in result.errors[0]

    def test_unknown_evidence_type(self, collector: OktaCollector) -> None:
        """Test handling unknown evidence type."""
        result = collector.collect_evidence(evidence_types=["unknown_type"])

        assert result.evidence == []

    def test_all_evidence_collection(
        self, collector: OktaCollector, sample_users: list[dict]
    ) -> None:
        """Test collecting all evidence types."""
        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter(sample_users)
            with patch.object(collector, "_request") as mock_request:
                mock_request.return_value = Mock(json=lambda: [])

                result = collector.collect_evidence()

                assert isinstance(result, CollectionResult)
                assert result.platform == "okta"


# =============================================================================
# Session Management Tests
# =============================================================================


class TestSessionManagement:
    """Tests for session management."""

    def test_session_created_once(self, collector: OktaCollector) -> None:
        """Test that session is reused."""
        with patch("requests.Session") as mock_session_class:
            mock_session = Mock()
            mock_session_class.return_value = mock_session

            # Get session twice
            session1 = collector._get_session()
            session2 = collector._get_session()

            # Should be the same session
            assert session1 is session2
            # Session should only be created once
            mock_session_class.assert_called_once()

    def test_session_headers(self, collector: OktaCollector) -> None:
        """Test that session has correct headers."""
        with patch("requests.Session") as mock_session_class:
            mock_session = Mock()
            mock_session_class.return_value = mock_session

            collector._get_session()

            # Check headers were set
            mock_session.headers.update.assert_called_once()
            headers = mock_session.headers.update.call_args[0][0]
            assert "Authorization" in headers
            assert headers["Authorization"] == "SSWS 00abc123def456"
            assert headers["Accept"] == "application/json"


# =============================================================================
# Integration with Mock Collectors
# =============================================================================


class TestWithMockCollector:
    """Tests using the mock collector framework."""

    def test_mock_collector_recorded_responses(self) -> None:
        """Test that MockOktaCollector can use fixture data."""
        from tests.mocks.collectors import MockOktaCollector

        mock = MockOktaCollector(
            fixtures={
                "users": [
                    {"id": "u1", "status": "ACTIVE", "profile": {"email": "test@example.com"}},
                ],
            }
        )

        # collect_evidence returns evidence for users
        result = mock.collect_evidence()

        assert result.success
        assert len(result.evidence) > 0

    def test_mock_collector_evidence(self) -> None:
        """Test mock collector evidence collection."""
        from tests.mocks.collectors import MockOktaCollector

        mock = MockOktaCollector(
            fixtures={
                "users": [
                    {"id": "u1", "status": "ACTIVE", "profile": {"email": "test@example.com"}},
                    {"id": "u2", "status": "SUSPENDED", "profile": {"email": "test2@example.com"}},
                ],
            }
        )

        result = mock.collect_evidence()

        assert result.success
        # Should have at least users evidence
        user_evidence = [e for e in result.evidence if e.evidence_type == "users"]
        assert len(user_evidence) == 1


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_response(self, collector: OktaCollector) -> None:
        """Test handling empty API responses."""
        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter([])

            resources = collector.collect_resources(resource_types=["okta_user"])

            assert resources == []

    def test_user_without_email(self, collector: OktaCollector) -> None:
        """Test handling user without email in profile."""
        users = [{"id": "00u1", "status": "ACTIVE", "profile": {}, "type": {"id": "default"}}]

        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter(users)

            resources = collector.collect_resources(resource_types=["okta_user"])

            assert len(resources) == 1
            assert resources[0].name == "00u1"  # Falls back to ID

    def test_collection_result_metadata(self, collector: OktaCollector) -> None:
        """Test that collection result has correct metadata."""
        with patch.object(collector, "_paginate") as mock_paginate:
            mock_paginate.return_value = iter([])

            result = collector.collect_evidence(evidence_types=["users"])

            assert result.platform == "okta"
            assert result.completed_at is not None
