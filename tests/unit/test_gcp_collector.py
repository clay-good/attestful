"""
Unit tests for GCP collector.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from attestful.core.models import CollectionResult, Evidence, Resource


# Mock the GCP SDK before importing the collector
@pytest.fixture(autouse=True)
def mock_gcp_sdk():
    """Mock GCP SDK modules."""
    mock_modules = {
        "google.cloud.compute_v1": MagicMock(),
        "google.cloud.storage": MagicMock(),
        "google.cloud.kms_v1": MagicMock(),
        "google.cloud.resourcemanager_v3": MagicMock(),
        "google.cloud.logging_v2": MagicMock(),
        "google.cloud.iam_admin_v1": MagicMock(),
        "google.api_core.exceptions": MagicMock(),
        "google.auth": MagicMock(),
        "google.auth.default": MagicMock(),
        "google.auth.credentials": MagicMock(),
    }

    with patch.dict("sys.modules", mock_modules):
        # Set GCP_SDK_AVAILABLE to True
        import attestful.collectors.cloud.gcp as gcp_module

        gcp_module.GCP_SDK_AVAILABLE = True
        gcp_module.gcp_exceptions = MagicMock()

        yield


class TestGCPCollectorConfig:
    """Tests for GCPCollectorConfig."""

    def test_default_config(self, mock_gcp_sdk):
        """Test default configuration values."""
        from attestful.collectors.cloud.gcp import GCPCollectorConfig

        config = GCPCollectorConfig()

        assert config.project_id is None
        assert config.credentials_file is None
        assert config.project_ids == []
        assert config.zones == []
        assert config.regions == []
        assert config.max_retries == 3
        assert config.timeout == 30

    def test_custom_config(self, mock_gcp_sdk):
        """Test custom configuration values."""
        from attestful.collectors.cloud.gcp import GCPCollectorConfig

        config = GCPCollectorConfig(
            project_id="test-project",
            credentials_file="/path/to/creds.json",
            project_ids=["proj-1", "proj-2"],
            zones=["us-central1-a", "us-central1-b"],
            regions=["us-central1", "us-east1"],
            max_retries=5,
            timeout=60,
        )

        assert config.project_id == "test-project"
        assert config.credentials_file == "/path/to/creds.json"
        assert config.project_ids == ["proj-1", "proj-2"]
        assert config.zones == ["us-central1-a", "us-central1-b"]
        assert config.regions == ["us-central1", "us-east1"]
        assert config.max_retries == 5
        assert config.timeout == 60

    def test_single_project_config(self, mock_gcp_sdk):
        """Test configuration with single project."""
        from attestful.collectors.cloud.gcp import GCPCollectorConfig

        config = GCPCollectorConfig(
            project_id="my-project",
        )

        assert config.project_id == "my-project"
        assert config.project_ids == []


class TestGCPCollector:
    """Tests for GCPCollector."""

    def test_init_with_config(self, mock_gcp_sdk):
        """Test initialization with configuration."""
        from attestful.collectors.cloud.gcp import (
            GCPCollector,
            GCPCollectorConfig,
        )

        config = GCPCollectorConfig(
            project_ids=["proj-1"],
            credentials_file="/path/to/creds.json",
        )

        collector = GCPCollector(config=config)

        assert collector.config == config
        assert collector.PLATFORM == "gcp"

    def test_init_without_config(self, mock_gcp_sdk):
        """Test initialization without configuration."""
        from attestful.collectors.cloud.gcp import (
            GCPCollector,
            GCPCollectorConfig,
        )

        collector = GCPCollector()

        assert isinstance(collector.config, GCPCollectorConfig)

    def test_supported_resource_types(self, mock_gcp_sdk):
        """Test supported resource types."""
        from attestful.collectors.cloud.gcp import GCPCollector

        collector = GCPCollector()

        assert "compute_instance" in collector.SUPPORTED_RESOURCE_TYPES
        assert "compute_disk" in collector.SUPPORTED_RESOURCE_TYPES
        assert "compute_firewall" in collector.SUPPORTED_RESOURCE_TYPES
        assert "compute_network" in collector.SUPPORTED_RESOURCE_TYPES
        assert "compute_subnetwork" in collector.SUPPORTED_RESOURCE_TYPES
        assert "storage_bucket" in collector.SUPPORTED_RESOURCE_TYPES
        assert "kms_key" in collector.SUPPORTED_RESOURCE_TYPES
        assert "kms_key_ring" in collector.SUPPORTED_RESOURCE_TYPES
        assert "iam_service_account" in collector.SUPPORTED_RESOURCE_TYPES
        assert "sql_instance" in collector.SUPPORTED_RESOURCE_TYPES
        assert len(collector.SUPPORTED_RESOURCE_TYPES) == 10

    def test_supported_evidence_types(self, mock_gcp_sdk):
        """Test supported evidence types."""
        from attestful.collectors.cloud.gcp import GCPCollector

        collector = GCPCollector()

        assert "project_info" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "iam_policy" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "organization_policy" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "audit_log_config" in collector.SUPPORTED_EVIDENCE_TYPES
        assert "security_health" in collector.SUPPORTED_EVIDENCE_TYPES
        assert len(collector.SUPPORTED_EVIDENCE_TYPES) == 5


class TestGCPCredentials:
    """Tests for GCP credential handling."""

    def test_credentials_file_config(self, mock_gcp_sdk):
        """Test that credentials file is stored in config."""
        from attestful.collectors.cloud.gcp import (
            GCPCollector,
            GCPCollectorConfig,
        )

        config = GCPCollectorConfig(
            credentials_file="/path/to/service-account.json",
            project_ids=["proj-1"],
        )

        collector = GCPCollector(config=config)
        assert collector.config.credentials_file == "/path/to/service-account.json"

    def test_no_credentials_file_config(self, mock_gcp_sdk):
        """Test default credentials when no file specified."""
        from attestful.collectors.cloud.gcp import (
            GCPCollector,
            GCPCollectorConfig,
        )

        config = GCPCollectorConfig(project_ids=["proj-1"])

        collector = GCPCollector(config=config)
        assert collector.config.credentials_file is None


class TestProjectDiscovery:
    """Tests for project discovery."""

    def test_explicit_project_ids(self, mock_gcp_sdk):
        """Test using explicit project IDs."""
        from attestful.collectors.cloud.gcp import (
            GCPCollector,
            GCPCollectorConfig,
        )

        config = GCPCollectorConfig(project_ids=["proj-1", "proj-2"])

        collector = GCPCollector(config=config)
        project_ids = collector._get_project_ids()

        assert project_ids == ["proj-1", "proj-2"]

    def test_single_project_id(self, mock_gcp_sdk):
        """Test using single project ID."""
        from attestful.collectors.cloud.gcp import (
            GCPCollector,
            GCPCollectorConfig,
        )

        config = GCPCollectorConfig(project_id="my-project")

        collector = GCPCollector(config=config)
        project_ids = collector._get_project_ids()

        assert project_ids == ["my-project"]


class TestResourceCollection:
    """Tests for resource collection."""

    def test_collect_unknown_resource_type(self, mock_gcp_sdk):
        """Test handling unknown resource types."""
        from attestful.collectors.cloud.gcp import (
            GCPCollector,
            GCPCollectorConfig,
        )

        config = GCPCollectorConfig(project_ids=["proj-1"])
        collector = GCPCollector(config=config)

        resources = collector.collect_resources(resource_types=["unknown_type"])

        assert len(resources) == 0

    def test_collect_resources_handles_error(self, mock_gcp_sdk):
        """Test that collect_resources handles errors gracefully."""
        from attestful.collectors.cloud.gcp import (
            GCPCollector,
            GCPCollectorConfig,
        )

        config = GCPCollectorConfig(project_ids=["proj-1"])
        collector = GCPCollector(config=config)

        # Mock _collect_compute_instance to raise an error
        with patch.object(collector, "_collect_compute_instance", side_effect=Exception("API Error")):
            resources = collector.collect_resources(resource_types=["compute_instance"])
            # Should return empty list, not raise
            assert len(resources) == 0

    def test_collect_resources_calls_correct_methods(self, mock_gcp_sdk):
        """Test that collect_resources calls the correct collector methods."""
        from attestful.collectors.cloud.gcp import (
            GCPCollector,
            GCPCollectorConfig,
        )

        config = GCPCollectorConfig(project_ids=["proj-1"])
        collector = GCPCollector(config=config)

        # Mock the collector method to return empty
        with patch.object(collector, "_collect_storage_bucket", return_value=iter([])) as mock_method:
            resources = collector.collect_resources(resource_types=["storage_bucket"])
            mock_method.assert_called_once()
            assert len(resources) == 0


class TestEvidenceCollection:
    """Tests for evidence collection."""

    def test_collect_unknown_evidence_type(self, mock_gcp_sdk):
        """Test handling unknown evidence types."""
        from attestful.collectors.cloud.gcp import (
            GCPCollector,
            GCPCollectorConfig,
        )

        config = GCPCollectorConfig(project_ids=["proj-1"])
        collector = GCPCollector(config=config)

        result = collector.collect_evidence(evidence_types=["unknown_type"])

        assert isinstance(result, CollectionResult)
        assert len(result.evidence) == 0

    def test_collect_evidence_returns_collection_result(self, mock_gcp_sdk):
        """Test that collect_evidence returns a CollectionResult."""
        from attestful.collectors.cloud.gcp import (
            GCPCollector,
            GCPCollectorConfig,
        )

        config = GCPCollectorConfig(project_ids=["proj-1"])
        collector = GCPCollector(config=config)

        # Mock the evidence collection method
        with patch.object(collector, "_collect_evidence_project_info", return_value=[]):
            result = collector.collect_evidence(evidence_types=["project_info"])

            assert isinstance(result, CollectionResult)
            assert result.platform == "gcp"

    def test_collect_evidence_handles_error(self, mock_gcp_sdk):
        """Test that collect_evidence handles errors gracefully."""
        from attestful.collectors.cloud.gcp import (
            GCPCollector,
            GCPCollectorConfig,
        )

        config = GCPCollectorConfig(project_ids=["proj-1"])
        collector = GCPCollector(config=config)

        # Mock the evidence collection method to raise an error
        with patch.object(collector, "_collect_evidence_project_info", side_effect=Exception("API Error")):
            result = collector.collect_evidence(evidence_types=["project_info"])
            # Should return result with empty evidence, not raise
            assert isinstance(result, CollectionResult)
            assert len(result.evidence) == 0


class TestGCPCollectorIntegration:
    """Integration tests for GCP collector."""

    def test_collector_workflow(self, mock_gcp_sdk):
        """Test basic collector workflow."""
        from attestful.collectors.cloud.gcp import (
            GCPCollector,
            GCPCollectorConfig,
        )

        config = GCPCollectorConfig(
            project_ids=["proj-1"],
        )
        collector = GCPCollector(config=config)

        # Mock the methods
        with (
            patch.object(collector, "_collect_compute_instance", return_value=iter([])),
            patch.object(collector, "_collect_evidence_project_info", return_value=[]),
        ):
            # Collect resources
            resources = collector.collect_resources(resource_types=["compute_instance"])
            assert isinstance(resources, list)

            # Collect evidence
            evidence = collector.collect_evidence(evidence_types=["project_info"])
            assert isinstance(evidence, CollectionResult)


class TestGCPCollectorSdkNotAvailable:
    """Tests for when GCP SDK is not available."""

    def test_raises_error_without_sdk(self):
        """Test that collector raises error when SDK is not available."""
        import attestful.collectors.cloud.gcp as gcp_module

        # Temporarily set SDK as unavailable
        original_value = gcp_module.GCP_SDK_AVAILABLE
        gcp_module.GCP_SDK_AVAILABLE = False

        try:
            from attestful.collectors.cloud.gcp import GCPCollector
            from attestful.core.exceptions import ConfigurationError

            with pytest.raises(ConfigurationError) as exc_info:
                GCPCollector()

            assert "GCP SDK not installed" in str(exc_info.value)
        finally:
            gcp_module.GCP_SDK_AVAILABLE = original_value


class TestGCPValidateCredentials:
    """Tests for GCP credential validation."""

    def test_validate_credentials_method_exists(self, mock_gcp_sdk):
        """Test that validate_credentials method exists."""
        from attestful.collectors.cloud.gcp import (
            GCPCollector,
            GCPCollectorConfig,
        )

        config = GCPCollectorConfig(project_ids=["proj-1"])
        collector = GCPCollector(config=config)

        assert hasattr(collector, "validate_credentials")
        assert callable(collector.validate_credentials)


class TestGCPZoneFiltering:
    """Tests for GCP zone filtering."""

    def test_zone_filter(self, mock_gcp_sdk):
        """Test filtering by zone."""
        from attestful.collectors.cloud.gcp import (
            GCPCollector,
            GCPCollectorConfig,
        )

        config = GCPCollectorConfig(
            project_ids=["proj-1"],
            zones=["us-central1-a"],
        )
        collector = GCPCollector(config=config)

        assert collector.config.zones == ["us-central1-a"]

    def test_region_filter(self, mock_gcp_sdk):
        """Test filtering by region."""
        from attestful.collectors.cloud.gcp import (
            GCPCollector,
            GCPCollectorConfig,
        )

        config = GCPCollectorConfig(
            project_ids=["proj-1"],
            regions=["us-central1"],
        )
        collector = GCPCollector(config=config)

        assert collector.config.regions == ["us-central1"]

    def test_explicit_zones_used(self, mock_gcp_sdk):
        """Test that explicit zones are used when provided."""
        from attestful.collectors.cloud.gcp import (
            GCPCollector,
            GCPCollectorConfig,
        )

        config = GCPCollectorConfig(
            project_ids=["proj-1"],
            zones=["us-central1-a", "us-central1-b"],
        )
        collector = GCPCollector(config=config)

        zones = collector._get_zones("proj-1")
        assert zones == ["us-central1-a", "us-central1-b"]


class TestGCPCollectorPlatform:
    """Tests for GCP collector platform attribute."""

    def test_platform_is_gcp(self, mock_gcp_sdk):
        """Test that platform is correctly set to 'gcp'."""
        from attestful.collectors.cloud.gcp import GCPCollector

        collector = GCPCollector()
        assert collector.PLATFORM == "gcp"

    def test_collector_inherits_base(self, mock_gcp_sdk):
        """Test that GCPCollector inherits from BaseCollector."""
        from attestful.collectors.cloud.gcp import GCPCollector
        from attestful.collectors.base import BaseCollector

        collector = GCPCollector()
        assert isinstance(collector, BaseCollector)


class TestGCPCollectorResourceTypeMethods:
    """Tests for resource type specific methods."""

    def test_has_compute_instance_collector(self, mock_gcp_sdk):
        """Test that compute_instance collector method exists."""
        from attestful.collectors.cloud.gcp import GCPCollector

        collector = GCPCollector()
        assert hasattr(collector, "_collect_compute_instance")

    def test_has_storage_bucket_collector(self, mock_gcp_sdk):
        """Test that storage_bucket collector method exists."""
        from attestful.collectors.cloud.gcp import GCPCollector

        collector = GCPCollector()
        assert hasattr(collector, "_collect_storage_bucket")

    def test_has_compute_firewall_collector(self, mock_gcp_sdk):
        """Test that compute_firewall collector method exists."""
        from attestful.collectors.cloud.gcp import GCPCollector

        collector = GCPCollector()
        assert hasattr(collector, "_collect_compute_firewall")

    def test_has_compute_network_collector(self, mock_gcp_sdk):
        """Test that compute_network collector method exists."""
        from attestful.collectors.cloud.gcp import GCPCollector

        collector = GCPCollector()
        assert hasattr(collector, "_collect_compute_network")

    def test_has_iam_service_account_collector(self, mock_gcp_sdk):
        """Test that iam_service_account collector method exists."""
        from attestful.collectors.cloud.gcp import GCPCollector

        collector = GCPCollector()
        assert hasattr(collector, "_collect_iam_service_account")


class TestGCPCollectorEvidenceTypeMethods:
    """Tests for evidence type specific methods."""

    def test_has_project_info_evidence_collector(self, mock_gcp_sdk):
        """Test that project_info evidence collector method exists."""
        from attestful.collectors.cloud.gcp import GCPCollector

        collector = GCPCollector()
        assert hasattr(collector, "_collect_evidence_project_info")

    def test_has_iam_policy_evidence_collector(self, mock_gcp_sdk):
        """Test that iam_policy evidence collector method exists."""
        from attestful.collectors.cloud.gcp import GCPCollector

        collector = GCPCollector()
        assert hasattr(collector, "_collect_evidence_iam_policy")
