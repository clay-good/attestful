"""Tests for SpotDraft collector."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
import requests

from attestful.collectors.platforms.spotdraft import (
    SpotDraftCollector,
    SpotDraftCollectorConfig,
)
from attestful.core.exceptions import CollectionError, ConfigurationError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def config():
    """Create a test configuration."""
    return SpotDraftCollectorConfig(
        api_key="test_api_key_xxx",
        base_url="https://api.spotdraft.com",
    )


@pytest.fixture
def collector(config):
    """Create a collector instance."""
    return SpotDraftCollector(config=config)


@pytest.fixture
def mock_contract():
    """Create a mock contract response."""
    now = datetime.now(timezone.utc)
    future = now + timedelta(days=60)
    return {
        "id": "contract-123",
        "name": "Service Agreement",
        "status": "active",
        "type": "service_agreement",
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "updated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expiry_date": future.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "effective_date": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "value": 50000,
        "currency": "USD",
        "counterparty": {"id": "cp-1", "name": "Acme Corp"},
        "owner": {"id": "user-1", "email": "owner@example.com"},
        "tags": ["important", "renewal"],
    }


@pytest.fixture
def mock_expiring_contract():
    """Create a mock contract expiring soon."""
    now = datetime.now(timezone.utc)
    expiring = now + timedelta(days=15)  # Within 30 days
    return {
        "id": "contract-456",
        "name": "NDA Agreement",
        "status": "active",
        "type": "nda",
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "updated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expiry_date": expiring.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "effective_date": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "value": 0,
        "currency": "USD",
        "counterparty": {"id": "cp-2", "name": "Beta Inc"},
        "owner": {"id": "user-1", "email": "owner@example.com"},
        "tags": [],
    }


@pytest.fixture
def mock_template():
    """Create a mock template response."""
    return {
        "id": "template-123",
        "name": "Master Service Agreement",
        "status": "active",
        "category": "service",
        "version": 3,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-06-01T00:00:00Z",
        "created_by": {"id": "user-1", "email": "legal@example.com"},
        "usage_count": 25,
    }


@pytest.fixture
def mock_approval():
    """Create a mock approval response."""
    now = datetime.now(timezone.utc)
    return {
        "id": "approval-123",
        "contract_id": "contract-123",
        "contract_name": "Service Agreement",
        "status": "pending",
        "stage": "legal_review",
        "approver": {"id": "user-2", "email": "legal@example.com"},
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "completed_at": None,
        "comment": None,
    }


@pytest.fixture
def mock_completed_approval():
    """Create a mock completed approval response."""
    now = datetime.now(timezone.utc)
    completed = now - timedelta(hours=12)
    created = completed - timedelta(hours=24)
    return {
        "id": "approval-456",
        "contract_id": "contract-456",
        "contract_name": "NDA Agreement",
        "status": "approved",
        "stage": "final_approval",
        "approver": {"id": "user-3", "email": "ceo@example.com"},
        "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "completed_at": completed.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "comment": "Approved as submitted",
    }


@pytest.fixture
def mock_user():
    """Create a mock user response."""
    return {
        "id": "user-123",
        "email": "user@example.com",
        "name": "Test User",
        "role": "admin",
        "status": "active",
        "created_at": "2024-01-01T00:00:00Z",
        "last_login_at": "2024-12-01T00:00:00Z",
        "mfa_enabled": True,
        "teams": [{"id": "team-1", "name": "Legal"}],
    }


@pytest.fixture
def mock_audit_log():
    """Create a mock audit log entry."""
    now = datetime.now(timezone.utc)
    return {
        "id": "log-123",
        "action": "contract.signed",
        "resource_type": "contract",
        "resource_id": "contract-123",
        "resource_name": "Service Agreement",
        "actor": {"id": "user-1", "email": "user@example.com"},
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ip_address": "192.168.1.1",
        "details": {"signature_method": "electronic"},
    }


@pytest.fixture
def mock_folder():
    """Create a mock folder response."""
    return {
        "id": "folder-123",
        "name": "Active Contracts",
        "parent_id": None,
        "created_at": "2024-01-01T00:00:00Z",
        "contract_count": 15,
        "permissions": ["admin", "legal"],
    }


# =============================================================================
# Initialization Tests
# =============================================================================


class TestSpotDraftCollectorInit:
    """Test collector initialization."""

    def test_init_with_config(self, config):
        """Test initialization with config."""
        collector = SpotDraftCollector(config=config)
        assert collector.config.api_key == "test_api_key_xxx"
        assert collector.config.base_url == "https://api.spotdraft.com"

    def test_init_default_config(self):
        """Test initialization with default config."""
        collector = SpotDraftCollector()
        assert collector.config.api_key == ""
        assert collector.config.base_url == "https://api.spotdraft.com"
        assert collector.config.timeout == 30
        assert collector.config.page_size == 50
        assert collector.config.days_of_history == 90

    def test_metadata(self, collector):
        """Test metadata property."""
        metadata = collector.metadata
        assert metadata.name == "SpotDraft Collector"
        assert metadata.platform == "spotdraft"
        assert "contract" in metadata.description.lower()
        assert metadata.version == "1.0.0"
        assert len(metadata.resource_types) == 4
        assert len(metadata.evidence_types) == 6

    def test_platform(self, collector):
        """Test platform constant."""
        assert collector.PLATFORM == "spotdraft"

    def test_api_url(self, collector):
        """Test API URL property."""
        assert collector.api_url == "https://api.spotdraft.com"

    def test_api_url_strips_trailing_slash(self, config):
        """Test API URL removes trailing slash."""
        config.base_url = "https://api.spotdraft.com/"
        collector = SpotDraftCollector(config=config)
        assert collector.api_url == "https://api.spotdraft.com"


# =============================================================================
# Session Tests
# =============================================================================


class TestSpotDraftSession:
    """Test HTTP session handling."""

    def test_session_creation(self, collector):
        """Test session is created on first access."""
        session = collector.session
        assert session is not None
        assert "Authorization" in session.headers

    def test_session_cached(self, collector):
        """Test session is cached."""
        session1 = collector.session
        session2 = collector.session
        assert session1 is session2

    def test_session_has_auth_header(self, collector):
        """Test session has correct auth header."""
        session = collector.session
        assert session.headers["Authorization"] == "Bearer test_api_key_xxx"
        assert session.headers["Content-Type"] == "application/json"


# =============================================================================
# Credential Validation Tests
# =============================================================================


class TestValidateCredentials:
    """Test credential validation."""

    def test_validate_credentials_success(self, collector):
        """Test successful credential validation."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"name": "Test User", "email": "test@example.com"}

        with patch.object(collector.session, "request", return_value=mock_response):
            assert collector.validate_credentials() is True

    def test_validate_credentials_no_key(self):
        """Test validation fails without API key."""
        collector = SpotDraftCollector(config=SpotDraftCollectorConfig())
        with pytest.raises(ConfigurationError, match="api_key is required"):
            collector.validate_credentials()

    def test_validate_credentials_invalid_key(self, collector):
        """Test validation fails with invalid key."""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.HTTPError("401 Unauthorized")

        with patch.object(collector.session, "request", side_effect=requests.HTTPError("401 Unauthorized")):
            with pytest.raises(ConfigurationError, match="Invalid SpotDraft API key"):
                collector.validate_credentials()

    def test_validate_credentials_api_error(self, collector):
        """Test validation handles API errors."""
        with patch.object(collector.session, "request", side_effect=requests.RequestException("Connection error")):
            with pytest.raises(ConfigurationError, match="Failed to validate"):
                collector.validate_credentials()


# =============================================================================
# Evidence Collection Tests
# =============================================================================


class TestCollectEvidence:
    """Test evidence collection."""

    def test_collect_all_evidence_types(self, collector, mock_contract, mock_template, mock_approval, mock_user, mock_audit_log, mock_folder):
        """Test collecting all evidence types."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "/contracts" in url:
                response.json.return_value = {"data": [mock_contract], "total": 1}
            elif "/templates" in url:
                response.json.return_value = {"data": [mock_template], "total": 1}
            elif "/approvals" in url:
                response.json.return_value = {"data": [mock_approval], "total": 1}
            elif "/users" in url:
                response.json.return_value = {"data": [mock_user], "total": 1}
            elif "/audit-logs" in url:
                response.json.return_value = {"logs": [mock_audit_log], "total": 1}
            elif "/folders" in url:
                response.json.return_value = {"data": [mock_folder], "total": 1}
            else:
                response.json.return_value = {"data": [], "total": 0}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            result = collector.collect_evidence()

            assert result.success
            assert len(result.evidence_items) == 6
            evidence_types = [e.evidence_type for e in result.evidence_items]
            assert "contracts" in evidence_types
            assert "templates" in evidence_types
            assert "approvals" in evidence_types
            assert "users" in evidence_types
            assert "audit_logs" in evidence_types
            assert "folders" in evidence_types

    def test_collect_specific_evidence_types(self, collector, mock_contract):
        """Test collecting specific evidence types."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = {"data": [mock_contract], "total": 1}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            result = collector.collect_evidence(evidence_types=["contracts"])

            assert len(result.evidence_items) == 1
            assert result.evidence_items[0].evidence_type == "contracts"

    def test_collect_evidence_invalid_type(self, collector):
        """Test collecting invalid evidence type."""
        with pytest.raises(CollectionError, match="Unsupported evidence types"):
            collector.collect_evidence(evidence_types=["invalid_type"])

    def test_collect_contracts_evidence(self, collector, mock_contract, mock_expiring_contract):
        """Test contracts evidence collection."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = {"data": [mock_contract, mock_expiring_contract], "total": 2}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            result = collector.collect_evidence(evidence_types=["contracts"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "contracts"
            assert evidence.raw_data["total_count"] == 2
            assert evidence.raw_data["status_counts"]["active"] == 2
            assert evidence.raw_data["total_value"] == 50000.0
            # Should have one contract expiring soon
            assert evidence.raw_data["expiring_soon_count"] == 1

    def test_collect_templates_evidence(self, collector, mock_template):
        """Test templates evidence collection."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = {"data": [mock_template], "total": 1}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            result = collector.collect_evidence(evidence_types=["templates"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "templates"
            assert evidence.raw_data["total_count"] == 1
            assert evidence.raw_data["status_counts"]["active"] == 1
            assert evidence.raw_data["category_counts"]["service"] == 1

    def test_collect_approvals_evidence(self, collector, mock_approval, mock_completed_approval):
        """Test approvals evidence collection."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = {"data": [mock_approval, mock_completed_approval], "total": 2}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            result = collector.collect_evidence(evidence_types=["approvals"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "approvals"
            assert evidence.raw_data["total_count"] == 2
            assert evidence.raw_data["pending_count"] == 1
            assert evidence.raw_data["avg_approval_time_hours"] > 0

    def test_collect_users_evidence(self, collector, mock_user):
        """Test users evidence collection."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = {"data": [mock_user], "total": 1}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            result = collector.collect_evidence(evidence_types=["users"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "users"
            assert evidence.raw_data["total_count"] == 1
            assert evidence.raw_data["role_counts"]["admin"] == 1
            assert evidence.raw_data["active_count"] == 1

    def test_collect_audit_logs_evidence(self, collector, mock_audit_log):
        """Test audit logs evidence collection."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = {"logs": [mock_audit_log], "total": 1}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            result = collector.collect_evidence(evidence_types=["audit_logs"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "audit_logs"
            assert evidence.raw_data["total_count"] == 1
            assert evidence.raw_data["action_counts"]["contract.signed"] == 1
            assert evidence.raw_data["resource_counts"]["contract"] == 1

    def test_collect_folders_evidence(self, collector, mock_folder):
        """Test folders evidence collection."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = {"data": [mock_folder], "total": 1}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            result = collector.collect_evidence(evidence_types=["folders"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.evidence_type == "folders"
            assert evidence.raw_data["total_count"] == 1
            assert evidence.raw_data["root_folder_count"] == 1


# =============================================================================
# Resource Collection Tests
# =============================================================================


class TestCollectResources:
    """Test resource collection."""

    def test_collect_all_resource_types(self, collector, mock_contract, mock_template, mock_user, mock_folder):
        """Test collecting all resource types."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            if "/contracts" in url:
                response.json.return_value = {"data": [mock_contract], "total": 1}
            elif "/templates" in url:
                response.json.return_value = {"data": [mock_template], "total": 1}
            elif "/users" in url:
                response.json.return_value = {"data": [mock_user], "total": 1}
            elif "/folders" in url:
                response.json.return_value = {"data": [mock_folder], "total": 1}
            else:
                response.json.return_value = {"data": [], "total": 0}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            resources = collector.collect_resources()

            assert len(resources) == 4
            resource_types = [r.type for r in resources]
            assert "spotdraft_contract" in resource_types
            assert "spotdraft_template" in resource_types
            assert "spotdraft_user" in resource_types
            assert "spotdraft_folder" in resource_types

    def test_collect_specific_resource_types(self, collector, mock_contract):
        """Test collecting specific resource types."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = {"data": [mock_contract], "total": 1}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            resources = collector.collect_resources(resource_types=["spotdraft_contract"])

            assert len(resources) == 1
            assert resources[0].type == "spotdraft_contract"

    def test_collect_resources_invalid_type(self, collector):
        """Test collecting invalid resource type."""
        with pytest.raises(CollectionError, match="Unsupported resource types"):
            collector.collect_resources(resource_types=["invalid_type"])

    def test_collect_contract_resources(self, collector, mock_contract):
        """Test contract resource collection."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = {"data": [mock_contract], "total": 1}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            resources = collector.collect_resources(resource_types=["spotdraft_contract"])

            assert len(resources) == 1
            resource = resources[0]
            assert resource.type == "spotdraft_contract"
            assert resource.id == "contract-123"
            assert resource.name == "Service Agreement"
            assert resource.provider == "spotdraft"
            assert resource.metadata["status"] == "active"
            assert resource.metadata["counterparty"] == "Acme Corp"

    def test_collect_template_resources(self, collector, mock_template):
        """Test template resource collection."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = {"data": [mock_template], "total": 1}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            resources = collector.collect_resources(resource_types=["spotdraft_template"])

            assert len(resources) == 1
            resource = resources[0]
            assert resource.type == "spotdraft_template"
            assert resource.id == "template-123"
            assert resource.metadata["version"] == 3
            assert resource.metadata["usage_count"] == 25

    def test_collect_user_resources(self, collector, mock_user):
        """Test user resource collection."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = {"data": [mock_user], "total": 1}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            resources = collector.collect_resources(resource_types=["spotdraft_user"])

            assert len(resources) == 1
            resource = resources[0]
            assert resource.type == "spotdraft_user"
            assert resource.id == "user-123"
            assert resource.metadata["role"] == "admin"
            assert resource.metadata["mfa_enabled"] is True

    def test_collect_folder_resources(self, collector, mock_folder):
        """Test folder resource collection."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = {"data": [mock_folder], "total": 1}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            resources = collector.collect_resources(resource_types=["spotdraft_folder"])

            assert len(resources) == 1
            resource = resources[0]
            assert resource.type == "spotdraft_folder"
            assert resource.id == "folder-123"
            assert resource.metadata["contract_count"] == 15


# =============================================================================
# Pagination Tests
# =============================================================================


class TestPagination:
    """Test pagination handling."""

    def test_pagination_multiple_pages(self, collector, mock_contract):
        """Test pagination across multiple pages."""
        page1_contract = {**mock_contract, "id": "contract-1"}
        page2_contract = {**mock_contract, "id": "contract-2"}

        call_count = [0]

        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()

            call_count[0] += 1
            if call_count[0] == 1:
                response.json.return_value = {"data": [page1_contract], "total": 2}
            else:
                response.json.return_value = {"data": [page2_contract], "total": 2}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            # Force small page size
            collector.config.page_size = 1
            result = collector.collect_evidence(evidence_types=["contracts"])

            assert len(result.evidence_items) == 1
            evidence = result.evidence_items[0]
            assert evidence.raw_data["total_count"] == 2

    def test_pagination_stops_on_error(self, collector, mock_contract):
        """Test pagination stops gracefully on error after getting data."""
        call_count = [0]

        def mock_request(method, url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                response = MagicMock()
                response.raise_for_status = MagicMock()
                response.json.return_value = {"data": [mock_contract], "total": 10}
                return response
            else:
                raise requests.RequestException("Network error")

        with patch.object(collector.session, "request", side_effect=mock_request):
            collector.config.page_size = 1
            result = collector.collect_evidence(evidence_types=["contracts"])

            # Should return partial data
            assert len(result.evidence_items) == 1
            assert result.evidence_items[0].raw_data["total_count"] == 1


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Test error handling."""

    def test_api_error_logged_but_continues(self, collector, mock_template):
        """Test that API errors for one type don't stop other collections."""
        call_count = [0]

        def mock_request(method, url, **kwargs):
            call_count[0] += 1
            if "/contracts" in url:
                raise requests.RequestException("API error")
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = {"data": [mock_template], "total": 1}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            result = collector.collect_evidence(evidence_types=["contracts", "templates"])

            # Should still have templates evidence
            evidence_types = [e.evidence_type for e in result.evidence_items]
            assert "templates" in evidence_types
            # Should have error for contracts
            assert len(result.errors) > 0

    def test_collection_continues_on_error(self, collector):
        """Test that collection continues despite errors."""
        def mock_request(method, url, **kwargs):
            raise requests.RequestException("Network error")

        with patch.object(collector.session, "request", side_effect=mock_request):
            result = collector.collect_evidence()

            # Should complete with errors
            assert result.completed_at is not None
            assert len(result.errors) == 6  # All 6 evidence types failed


# =============================================================================
# Compliance Control Mapping Tests
# =============================================================================


class TestComplianceControls:
    """Test compliance control mappings."""

    def test_contracts_evidence_has_controls(self, collector, mock_contract):
        """Test contracts evidence has compliance controls."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = {"data": [mock_contract], "total": 1}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            result = collector.collect_evidence(evidence_types=["contracts"])

            evidence = result.evidence_items[0]
            controls = evidence.metadata["compliance_controls"]
            assert "soc2" in controls
            assert "nist_800_53" in controls
            assert "iso_27001" in controls
            assert "hitrust" in controls
            assert "SA-4" in controls["nist_800_53"]
            assert "A.13.2.4" in controls["iso_27001"]

    def test_audit_logs_evidence_has_controls(self, collector, mock_audit_log):
        """Test audit logs evidence has compliance controls."""
        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = {"logs": [mock_audit_log], "total": 1}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            result = collector.collect_evidence(evidence_types=["audit_logs"])

            evidence = result.evidence_items[0]
            controls = evidence.metadata["compliance_controls"]
            assert "AU-2" in controls["nist_800_53"]
            assert "A.12.4.1" in controls["iso_27001"]

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


class TestSpotDraftCLI:
    """Test CLI commands."""

    def test_collect_spotdraft_missing_api_key(self):
        """Test collect spotdraft fails without API key."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "spotdraft"])

        assert result.exit_code == 0
        assert "API key is required" in result.output

    def test_collect_spotdraft_help(self):
        """Test collect spotdraft help."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "spotdraft", "--help"])

        assert result.exit_code == 0
        assert "SpotDraft" in result.output
        assert "--api-key" in result.output
        assert "--types" in result.output

    def test_collect_list_shows_spotdraft(self):
        """Test collect list shows spotdraft."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["collect", "list"])

        assert result.exit_code == 0
        assert "spotdraft" in result.output


# =============================================================================
# Contract Value Calculation Tests
# =============================================================================


class TestContractValueCalculation:
    """Test contract value calculations."""

    def test_total_value_calculation(self, collector):
        """Test total contract value is calculated correctly."""
        contracts = [
            {"id": "1", "name": "Contract 1", "status": "active", "type": "service", "value": 10000, "counterparty": {}, "owner": {}, "tags": []},
            {"id": "2", "name": "Contract 2", "status": "active", "type": "service", "value": 25000, "counterparty": {}, "owner": {}, "tags": []},
            {"id": "3", "name": "Contract 3", "status": "active", "type": "nda", "value": None, "counterparty": {}, "owner": {}, "tags": []},
        ]

        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = {"data": contracts, "total": 3}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            result = collector.collect_evidence(evidence_types=["contracts"])

            evidence = result.evidence_items[0]
            assert evidence.raw_data["total_value"] == 35000.0
            assert evidence.raw_data["type_counts"]["service"] == 2
            assert evidence.raw_data["type_counts"]["nda"] == 1


# =============================================================================
# Approval Time Calculation Tests
# =============================================================================


class TestApprovalTimeCalculation:
    """Test approval time calculations."""

    def test_avg_approval_time_calculation(self, collector):
        """Test average approval time is calculated correctly."""
        now = datetime.now(timezone.utc)

        approvals = [
            {
                "id": "1",
                "contract_id": "c1",
                "contract_name": "Contract 1",
                "status": "approved",
                "stage": "final",
                "approver": {},
                "created_at": (now - timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "completed_at": (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            {
                "id": "2",
                "contract_id": "c2",
                "contract_name": "Contract 2",
                "status": "approved",
                "stage": "final",
                "approver": {},
                "created_at": (now - timedelta(hours=36)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "completed_at": (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        ]

        def mock_request(method, url, **kwargs):
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json.return_value = {"data": approvals, "total": 2}
            return response

        with patch.object(collector.session, "request", side_effect=mock_request):
            result = collector.collect_evidence(evidence_types=["approvals"])

            evidence = result.evidence_items[0]
            # First approval: 24 hours, Second approval: 12 hours, Average: 18 hours
            assert evidence.raw_data["avg_approval_time_hours"] == 18.0
