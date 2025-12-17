"""
Unit tests for OSCAL SSP generation.
"""

import json
import pytest
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from attestful.oscal.ssp import (
    SSPGenerator,
    SSPLoader,
    SystemConfig,
    ComponentConfig,
    UserConfig,
    ImplementationDetail,
    create_ssp_from_scan_results,
)
from attestful.oscal.models import (
    SystemSecurityPlan,
    SystemCharacteristics,
    SystemImplementation,
    SSPControlImplementation,
)
from attestful.core.models import CheckResult, CheckStatus, ComplianceCheck


# =============================================================================
# SystemConfig Tests
# =============================================================================


class TestSystemConfig:
    """Tests for SystemConfig dataclass."""

    def test_required_fields(self):
        """Test creating config with required fields."""
        config = SystemConfig(
            system_name="Test System",
            system_id="test-123",
            description="A test system",
        )

        assert config.system_name == "Test System"
        assert config.system_id == "test-123"
        assert config.description == "A test system"

    def test_default_values(self):
        """Test default values."""
        config = SystemConfig(
            system_name="Test",
            system_id="test",
            description="Test",
        )

        assert config.system_status == "operational"
        assert config.authorization_boundary_description == "System authorization boundary"
        assert config.organization_name == "Organization"
        assert config.version == "1.0.0"

    def test_optional_fields(self):
        """Test setting optional fields."""
        config = SystemConfig(
            system_name="Prod System",
            system_id="prod-001",
            description="Production system",
            system_name_short="PROD",
            system_status="under-development",
            security_sensitivity_level="moderate",
            organization_name="Acme Corp",
            version="2.0.0",
        )

        assert config.system_name_short == "PROD"
        assert config.system_status == "under-development"
        assert config.security_sensitivity_level == "moderate"
        assert config.organization_name == "Acme Corp"
        assert config.version == "2.0.0"


# =============================================================================
# ComponentConfig Tests
# =============================================================================


class TestComponentConfig:
    """Tests for ComponentConfig dataclass."""

    def test_required_fields(self):
        """Test creating config with required fields."""
        config = ComponentConfig(
            title="Web Server",
            description="Frontend web server",
        )

        assert config.title == "Web Server"
        assert config.description == "Frontend web server"

    def test_default_values(self):
        """Test default values."""
        config = ComponentConfig(
            title="Test",
            description="Test",
        )

        assert config.type == "software"
        assert config.status == "operational"
        assert config.uuid is not None

    def test_optional_fields(self):
        """Test setting optional fields."""
        config = ComponentConfig(
            title="Database",
            description="PostgreSQL database",
            type="software",
            status="operational",
            purpose="Store application data",
        )

        assert config.type == "software"
        assert config.status == "operational"
        assert config.purpose == "Store application data"


# =============================================================================
# UserConfig Tests
# =============================================================================


class TestUserConfig:
    """Tests for UserConfig dataclass."""

    def test_required_fields(self):
        """Test creating config with required fields."""
        config = UserConfig(title="Administrator")

        assert config.title == "Administrator"

    def test_default_values(self):
        """Test default values."""
        config = UserConfig(title="User")

        assert config.description is None
        assert config.role_ids == []
        assert config.uuid is not None

    def test_optional_fields(self):
        """Test setting optional fields."""
        config = UserConfig(
            title="System Admin",
            description="Full access administrator",
            role_ids=["system-owner", "admin"],
        )

        assert config.description == "Full access administrator"
        assert "system-owner" in config.role_ids


# =============================================================================
# SSPGenerator Tests
# =============================================================================


class TestSSPGeneratorBasic:
    """Basic tests for SSPGenerator."""

    def test_generator_creation(self):
        """Test creating a generator."""
        config = SystemConfig(
            system_name="Test System",
            system_id="test-123",
            description="A test system",
        )

        generator = SSPGenerator(config, profile_href="#test-profile")

        assert generator.system_config == config
        assert generator.profile_href == "#test-profile"
        assert generator.components == []
        assert generator.users == []
        assert generator.check_results == []

    def test_add_component(self):
        """Test adding a component."""
        config = SystemConfig(
            system_name="Test",
            system_id="test",
            description="Test",
        )
        generator = SSPGenerator(config)

        component = ComponentConfig(
            title="Web App",
            description="Main web application",
        )
        generator.add_component(component)

        assert len(generator.components) == 1
        assert generator.components[0].title == "Web App"

    def test_add_user(self):
        """Test adding a user."""
        config = SystemConfig(
            system_name="Test",
            system_id="test",
            description="Test",
        )
        generator = SSPGenerator(config)

        user = UserConfig(
            title="Admin",
            description="System administrator",
        )
        generator.add_user(user)

        assert len(generator.users) == 1
        assert generator.users[0].title == "Admin"

    def test_add_check_results(self):
        """Test adding check results."""
        config = SystemConfig(
            system_name="Test",
            system_id="test",
            description="Test",
        )
        generator = SSPGenerator(config)

        results = [
            CheckResult(
                check=ComplianceCheck(id="check-1", title="Check 1"),
                resource_id="resource-1",
                passed=True,
            ),
            CheckResult(
                check=ComplianceCheck(id="check-2", title="Check 2"),
                resource_id="resource-2",
                passed=False,
            ),
        ]
        generator.add_check_results(results)

        assert len(generator.check_results) == 2


class TestSSPGeneratorGeneration:
    """Tests for SSP generation."""

    def test_generate_basic_ssp(self):
        """Test generating a basic SSP."""
        config = SystemConfig(
            system_name="Production System",
            system_id="prod-001",
            description="Production web application",
        )

        generator = SSPGenerator(config, profile_href="#nist-800-53-moderate")
        ssp = generator.generate()

        assert isinstance(ssp, SystemSecurityPlan)
        assert ssp.metadata.title == "System Security Plan for Production System"
        assert ssp.import_profile.href == "#nist-800-53-moderate"

    def test_generate_ssp_with_components(self):
        """Test SSP generation with components."""
        config = SystemConfig(
            system_name="Test System",
            system_id="test-001",
            description="Test system",
        )

        generator = SSPGenerator(config)
        generator.add_component(ComponentConfig(
            title="Web Server",
            description="Nginx web server",
            type="software",
        ))
        generator.add_component(ComponentConfig(
            title="Database",
            description="PostgreSQL database",
            type="software",
        ))

        ssp = generator.generate()

        assert len(ssp.system_implementation.components) == 2
        titles = [c.title for c in ssp.system_implementation.components]
        assert "Web Server" in titles
        assert "Database" in titles

    def test_generate_ssp_with_users(self):
        """Test SSP generation with users."""
        config = SystemConfig(
            system_name="Test System",
            system_id="test-001",
            description="Test system",
        )

        generator = SSPGenerator(config)
        generator.add_user(UserConfig(
            title="Administrator",
            description="Full access user",
            role_ids=["system-owner"],
        ))
        generator.add_user(UserConfig(
            title="Operator",
            description="Limited access user",
        ))

        ssp = generator.generate()

        assert len(ssp.system_implementation.users) == 2

    def test_generate_ssp_with_control_implementations(self):
        """Test SSP generation with explicit control implementations."""
        config = SystemConfig(
            system_name="Test System",
            system_id="test-001",
            description="Test system",
        )

        component_uuid = uuid4()
        generator = SSPGenerator(config)
        generator.add_component(ComponentConfig(
            title="Security Module",
            description="Security controls",
            uuid=component_uuid,
        ))

        generator.add_control_implementation(
            control_id="AC-2",
            component_uuid=component_uuid,
            description="User accounts managed through IAM",
            status="implemented",
        )
        generator.add_control_implementation(
            control_id="AC-3",
            component_uuid=component_uuid,
            description="RBAC enforced at API level",
            status="partial",
        )

        ssp = generator.generate()

        control_ids = [
            req.control_id
            for req in ssp.control_implementation.implemented_requirements
        ]
        assert "AC-2" in control_ids
        assert "AC-3" in control_ids

    def test_generate_ssp_default_component(self):
        """Test SSP generation creates default component when none provided."""
        config = SystemConfig(
            system_name="Test",
            system_id="test",
            description="Test",
        )

        generator = SSPGenerator(config)
        ssp = generator.generate()

        # Should have a default component
        assert len(ssp.system_implementation.components) >= 1

    def test_generate_ssp_default_user(self):
        """Test SSP generation creates default user when none provided."""
        config = SystemConfig(
            system_name="Test",
            system_id="test",
            description="Test",
        )

        generator = SSPGenerator(config)
        ssp = generator.generate()

        # Should have a default user
        assert len(ssp.system_implementation.users) >= 1


class TestSSPGeneratorWithCheckResults:
    """Tests for SSP generation from check results."""

    def test_control_implementations_from_checks(self):
        """Test that check results create control implementations."""
        config = SystemConfig(
            system_name="Test System",
            system_id="test-001",
            description="Test system",
        )

        generator = SSPGenerator(config)
        generator.add_component(ComponentConfig(
            title="App",
            description="Application",
        ))

        results = [
            CheckResult(
                check=ComplianceCheck(
                    id="check-1",
                    title="S3 Encryption",
                    framework_mappings={"nist-800-53": ["SC-13"]},
                ),
                resource_id="bucket-1",
                passed=True,
                status=CheckStatus.PASS,
            ),
            CheckResult(
                check=ComplianceCheck(
                    id="check-2",
                    title="EC2 IMDSv2",
                    framework_mappings={"nist-800-53": ["CM-6"]},
                ),
                resource_id="instance-1",
                passed=False,
                status=CheckStatus.FAIL,
            ),
        ]
        generator.add_check_results(results)

        ssp = generator.generate()

        control_ids = [
            req.control_id
            for req in ssp.control_implementation.implemented_requirements
        ]
        assert "SC-13" in control_ids
        assert "CM-6" in control_ids

    def test_implementation_status_from_passing_checks(self):
        """Test that passing checks result in 'implemented' status."""
        config = SystemConfig(
            system_name="Test",
            system_id="test",
            description="Test",
        )

        generator = SSPGenerator(config)
        generator.add_component(ComponentConfig(title="App", description="App"))

        results = [
            CheckResult(
                check=ComplianceCheck(
                    id="check-1",
                    title="Test Check",
                    framework_mappings={"soc2": ["CC6.1"]},
                ),
                resource_id="resource-1",
                passed=True,
                status=CheckStatus.PASS,
            ),
        ]
        generator.add_check_results(results)

        ssp = generator.generate()

        req = next(
            r for r in ssp.control_implementation.implemented_requirements
            if r.control_id == "CC6.1"
        )
        assert req.by_components[0].implementation_status["state"] == "implemented"

    def test_implementation_status_from_failing_checks(self):
        """Test that failing checks result in appropriate status."""
        config = SystemConfig(
            system_name="Test",
            system_id="test",
            description="Test",
        )

        generator = SSPGenerator(config)
        generator.add_component(ComponentConfig(title="App", description="App"))

        results = [
            CheckResult(
                check=ComplianceCheck(
                    id="check-1",
                    title="Test Check",
                    framework_mappings={"soc2": ["CC6.2"]},
                ),
                resource_id="resource-1",
                passed=False,
                status=CheckStatus.FAIL,
            ),
        ]
        generator.add_check_results(results)

        ssp = generator.generate()

        req = next(
            r for r in ssp.control_implementation.implemented_requirements
            if r.control_id == "CC6.2"
        )
        assert req.by_components[0].implementation_status["state"] == "not-implemented"


class TestSSPGeneratorSave:
    """Tests for saving SSP to files."""

    def test_save_json(self, temp_dir):
        """Test saving SSP as JSON."""
        config = SystemConfig(
            system_name="Test System",
            system_id="test-001",
            description="Test system",
        )

        generator = SSPGenerator(config)
        output_path = temp_dir / "ssp.json"

        result = generator.save(output_path, format="json")

        assert result.exists()
        assert result.suffix == ".json"

        # Verify it's valid JSON
        content = json.loads(result.read_text())
        assert "system-security-plan" in content

    def test_save_yaml(self, temp_dir):
        """Test saving SSP as YAML."""
        config = SystemConfig(
            system_name="Test System",
            system_id="test-001",
            description="Test system",
        )

        generator = SSPGenerator(config)
        output_path = temp_dir / "ssp.yaml"

        result = generator.save(output_path, format="yaml")

        assert result.exists()
        assert result.suffix == ".yaml"

    def test_save_creates_directories(self, temp_dir):
        """Test that save creates parent directories."""
        config = SystemConfig(
            system_name="Test",
            system_id="test",
            description="Test",
        )

        generator = SSPGenerator(config)
        output_path = temp_dir / "subdir" / "nested" / "ssp.json"

        result = generator.save(output_path, format="json")

        assert result.exists()
        assert result.parent.exists()


# =============================================================================
# SSPLoader Tests
# =============================================================================


class TestSSPLoader:
    """Tests for SSPLoader."""

    def test_load_json_ssp(self, temp_dir):
        """Test loading SSP from JSON."""
        # Create an SSP file
        config = SystemConfig(
            system_name="Loaded System",
            system_id="loaded-001",
            description="Test loading",
        )
        generator = SSPGenerator(config)
        ssp_path = generator.save(temp_dir / "test_ssp.json", format="json")

        # Load it back
        loader = SSPLoader()
        loaded_ssp = loader.load(ssp_path)

        assert isinstance(loaded_ssp, SystemSecurityPlan)
        assert loaded_ssp.system_characteristics.system_name == "Loaded System"

    def test_load_yaml_ssp(self, temp_dir):
        """Test loading SSP from YAML."""
        config = SystemConfig(
            system_name="YAML System",
            system_id="yaml-001",
            description="Test YAML loading",
        )
        generator = SSPGenerator(config)
        ssp_path = generator.save(temp_dir / "test_ssp.yaml", format="yaml")

        loader = SSPLoader()
        loaded_ssp = loader.load(ssp_path)

        assert loaded_ssp.system_characteristics.system_name == "YAML System"

    def test_load_caching(self, temp_dir):
        """Test that loaded SSPs are cached."""
        config = SystemConfig(
            system_name="Cached",
            system_id="cached-001",
            description="Test caching",
        )
        generator = SSPGenerator(config)
        ssp_path = generator.save(temp_dir / "cached.json", format="json")

        loader = SSPLoader()

        # Load twice
        ssp1 = loader.load(ssp_path)
        ssp2 = loader.load(ssp_path)

        # Should be same object due to caching
        assert ssp1 is ssp2

    def test_load_without_cache(self, temp_dir):
        """Test loading without cache."""
        config = SystemConfig(
            system_name="NoCache",
            system_id="nocache-001",
            description="Test no caching",
        )
        generator = SSPGenerator(config)
        ssp_path = generator.save(temp_dir / "nocache.json", format="json")

        loader = SSPLoader()

        ssp1 = loader.load(ssp_path, use_cache=False)
        ssp2 = loader.load(ssp_path, use_cache=False)

        # Should be different objects
        assert ssp1 is not ssp2

    def test_load_nonexistent_file(self):
        """Test loading non-existent file raises error."""
        loader = SSPLoader()

        with pytest.raises(Exception):  # OSCALError
            loader.load("/nonexistent/path/ssp.json")


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestCreateSSPFromScanResults:
    """Tests for create_ssp_from_scan_results convenience function."""

    def test_basic_usage(self):
        """Test basic usage of convenience function."""
        results = [
            CheckResult(
                check=ComplianceCheck(
                    id="check-1",
                    title="Test Check",
                    framework_mappings={"nist-800-53": ["AC-1"]},
                ),
                resource_id="resource-1",
                passed=True,
                status=CheckStatus.PASS,
            ),
        ]

        ssp = create_ssp_from_scan_results(
            system_name="Quick System",
            system_id="quick-001",
            description="Quickly created system",
            check_results=results,
        )

        assert isinstance(ssp, SystemSecurityPlan)
        assert ssp.system_characteristics.system_name == "Quick System"

    def test_with_additional_kwargs(self):
        """Test passing additional kwargs."""
        ssp = create_ssp_from_scan_results(
            system_name="Advanced System",
            system_id="adv-001",
            description="System with extra options",
            check_results=[],
            profile_href="#custom-profile",
            organization_name="Custom Org",
        )

        assert ssp.import_profile.href == "#custom-profile"


# =============================================================================
# SSP Serialization Tests
# =============================================================================


class TestSSPSerialization:
    """Tests for SSP serialization."""

    def test_to_json(self):
        """Test SSP JSON serialization."""
        config = SystemConfig(
            system_name="JSON Test",
            system_id="json-001",
            description="Test JSON output",
        )

        generator = SSPGenerator(config)
        ssp = generator.generate()

        json_str = ssp.to_json()

        # Should be valid JSON
        data = json.loads(json_str)
        assert "metadata" in data
        assert "import-profile" in data
        assert "system-characteristics" in data

    def test_to_yaml(self):
        """Test SSP YAML serialization."""
        import yaml

        config = SystemConfig(
            system_name="YAML Test",
            system_id="yaml-001",
            description="Test YAML output",
        )

        generator = SSPGenerator(config)
        ssp = generator.generate()

        yaml_str = ssp.to_yaml()

        # Should be valid YAML
        data = yaml.safe_load(yaml_str)
        assert "metadata" in data
