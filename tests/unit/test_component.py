"""
Unit tests for OSCAL Component Definition loading and generation.
"""

import json
import pytest
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from attestful.oscal.component import (
    ComponentDefinitionGenerator,
    ComponentDefinitionIndex,
    ComponentDefinitionLoader,
    ComponentConfig,
    ComponentError,
    ControlImplementationConfig,
    create_aws_component_definition,
    create_azure_component_definition,
    create_component_from_check_results,
    get_component_definition_summary,
    merge_component_definitions,
)
from attestful.oscal.models import (
    Component,
    ComponentDefinition,
    ControlImplementation,
    ImplementedRequirement,
    Metadata,
    Property,
)
from attestful.core.models import CheckResult, CheckStatus, ComplianceCheck


# =============================================================================
# Sample Data Fixtures
# =============================================================================


@pytest.fixture
def sample_component_data():
    """Create sample OSCAL component definition data."""
    return {
        "uuid": str(uuid4()),
        "metadata": {
            "title": "Test Component Definition",
            "last-modified": datetime.now(timezone.utc).isoformat(),
            "version": "1.0.0",
            "oscal-version": "1.1.2",
        },
        "components": [
            {
                "uuid": str(uuid4()),
                "type": "software",
                "title": "Security Scanner",
                "description": "Automated security scanning component",
                "control-implementations": [
                    {
                        "uuid": str(uuid4()),
                        "source": "#test-catalog",
                        "description": "Security controls implementation",
                        "implemented-requirements": [
                            {
                                "uuid": str(uuid4()),
                                "control-id": "AC-1",
                                "description": "Access control policy implementation",
                            },
                            {
                                "uuid": str(uuid4()),
                                "control-id": "AC-2",
                                "description": "Account management implementation",
                            },
                        ],
                    },
                ],
            },
            {
                "uuid": str(uuid4()),
                "type": "service",
                "title": "Logging Service",
                "description": "Centralized logging service",
                "control-implementations": [
                    {
                        "uuid": str(uuid4()),
                        "source": "#test-catalog",
                        "description": "Audit controls implementation",
                        "implemented-requirements": [
                            {
                                "uuid": str(uuid4()),
                                "control-id": "AU-2",
                                "description": "Audit events implementation",
                            },
                        ],
                    },
                ],
            },
        ],
    }


@pytest.fixture
def sample_component_definition(sample_component_data):
    """Create a sample ComponentDefinition object."""
    return ComponentDefinition.model_validate(sample_component_data)


@pytest.fixture
def sample_component_file(temp_dir, sample_component_data):
    """Create a sample component definition file."""
    comp_path = temp_dir / "component.json"
    comp_path.write_text(json.dumps({"component-definition": sample_component_data}))
    return comp_path


@pytest.fixture
def sample_checks():
    """Create sample compliance checks."""
    return [
        ComplianceCheck(
            id="s3-encryption",
            title="S3 Bucket Encryption",
            description="Ensure S3 buckets are encrypted",
            severity="high",
            resource_types=["s3_bucket"],
            framework_mappings={"soc2": ["CC6.1"], "nist_800_53": ["SC-13"]},
        ),
        ComplianceCheck(
            id="s3-versioning",
            title="S3 Bucket Versioning",
            description="Ensure S3 buckets have versioning enabled",
            severity="medium",
            resource_types=["s3_bucket"],
            framework_mappings={"soc2": ["CC6.1", "CC7.2"]},
        ),
        ComplianceCheck(
            id="iam-mfa",
            title="IAM MFA Enabled",
            description="Ensure IAM users have MFA enabled",
            severity="critical",
            resource_types=["iam_user"],
            framework_mappings={"soc2": ["CC6.1", "CC6.2"], "nist_800_53": ["IA-2"]},
        ),
        ComplianceCheck(
            id="ec2-imdsv2",
            title="EC2 IMDSv2",
            description="Ensure EC2 instances use IMDSv2",
            severity="high",
            resource_types=["ec2_instance"],
            framework_mappings={"soc2": ["CC6.1"]},
        ),
    ]


@pytest.fixture
def sample_check_results(sample_checks):
    """Create sample check results."""
    return [
        CheckResult(
            check=sample_checks[0],
            resource_id="bucket-1",
            passed=True,
            status=CheckStatus.PASS,
        ),
        CheckResult(
            check=sample_checks[1],
            resource_id="bucket-1",
            passed=True,
            status=CheckStatus.PASS,
        ),
        CheckResult(
            check=sample_checks[2],
            resource_id="user-1",
            passed=False,
            status=CheckStatus.FAIL,
        ),
        CheckResult(
            check=sample_checks[3],
            resource_id="instance-1",
            passed=True,
            status=CheckStatus.PASS,
        ),
    ]


# =============================================================================
# ComponentDefinitionLoader Tests
# =============================================================================


class TestComponentDefinitionLoader:
    """Tests for ComponentDefinitionLoader class."""

    def test_load_json_component(self, sample_component_file):
        """Test loading a component definition from JSON file."""
        loader = ComponentDefinitionLoader()
        comp_def = loader.load(sample_component_file)

        assert isinstance(comp_def, ComponentDefinition)
        assert comp_def.metadata.title == "Test Component Definition"
        assert len(comp_def.components) == 2

    def test_load_yaml_component(self, temp_dir):
        """Test loading a component definition from YAML file."""
        import yaml

        comp_data = {
            "component-definition": {
                "uuid": str(uuid4()),
                "metadata": {
                    "title": "YAML Component",
                    "last-modified": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
                "components": [
                    {
                        "uuid": str(uuid4()),
                        "type": "software",
                        "title": "Test Component",
                        "description": "A test component",
                    },
                ],
            }
        }

        comp_path = temp_dir / "component.yaml"
        comp_path.write_text(yaml.dump(comp_data))

        loader = ComponentDefinitionLoader()
        comp_def = loader.load(comp_path)

        assert comp_def.metadata.title == "YAML Component"

    def test_load_nonexistent_file(self):
        """Test loading non-existent file raises error."""
        loader = ComponentDefinitionLoader()

        with pytest.raises(ComponentError) as exc_info:
            loader.load("/nonexistent/path/component.json")

        assert "not found" in str(exc_info.value).lower()

    def test_load_with_cache(self, sample_component_file):
        """Test that component definitions are cached."""
        loader = ComponentDefinitionLoader()

        comp1 = loader.load(sample_component_file)
        comp2 = loader.load(sample_component_file)

        assert comp1 is comp2

    def test_load_without_cache(self, sample_component_file):
        """Test loading without cache."""
        loader = ComponentDefinitionLoader()

        comp1 = loader.load(sample_component_file, use_cache=False)
        comp2 = loader.load(sample_component_file, use_cache=False)

        assert comp1 is not comp2

    def test_clear_cache(self, sample_component_file):
        """Test clearing the cache."""
        loader = ComponentDefinitionLoader()

        comp1 = loader.load(sample_component_file)
        loader.clear_cache()
        comp2 = loader.load(sample_component_file)

        assert comp1 is not comp2

    def test_load_from_string_json(self, sample_component_data):
        """Test loading component from JSON string."""
        loader = ComponentDefinitionLoader()
        json_str = json.dumps({"component-definition": sample_component_data})

        comp_def = loader.load_from_string(json_str, format="json")

        assert isinstance(comp_def, ComponentDefinition)

    def test_load_from_string_yaml(self):
        """Test loading component from YAML string."""
        import yaml

        loader = ComponentDefinitionLoader()
        yaml_data = {
            "component-definition": {
                "uuid": str(uuid4()),
                "metadata": {
                    "title": "String Component",
                    "last-modified": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
            }
        }

        comp_def = loader.load_from_string(yaml.dump(yaml_data), format="yaml")

        assert comp_def.metadata.title == "String Component"


# =============================================================================
# ComponentDefinitionIndex Tests
# =============================================================================


class TestComponentDefinitionIndex:
    """Tests for ComponentDefinitionIndex class."""

    def test_index_creation(self, sample_component_definition):
        """Test creating an index."""
        index = ComponentDefinitionIndex(sample_component_definition)

        assert index.component_count == 2

    def test_get_component_by_uuid(self, sample_component_definition):
        """Test getting a component by UUID."""
        index = ComponentDefinitionIndex(sample_component_definition)
        component = sample_component_definition.components[0]

        result = index.get_component(component.uuid)

        assert result is not None
        assert result.uuid == component.uuid

    def test_get_component_by_title(self, sample_component_definition):
        """Test getting a component by title."""
        index = ComponentDefinitionIndex(sample_component_definition)

        result = index.get_component_by_title("Security Scanner")

        assert result is not None
        assert result.title == "Security Scanner"

    def test_get_component_by_title_case_insensitive(self, sample_component_definition):
        """Test title lookup is case-insensitive."""
        index = ComponentDefinitionIndex(sample_component_definition)

        result = index.get_component_by_title("SECURITY SCANNER")

        assert result is not None

    def test_get_implementations_for_control(self, sample_component_definition):
        """Test getting implementations for a control."""
        index = ComponentDefinitionIndex(sample_component_definition)

        implementations = index.get_implementations_for_control("AC-1")

        assert len(implementations) == 1
        component, req = implementations[0]
        assert req.control_id == "AC-1"

    def test_list_components(self, sample_component_definition):
        """Test listing all components."""
        index = ComponentDefinitionIndex(sample_component_definition)

        components = index.list_components()

        assert len(components) == 2

    def test_list_control_ids(self, sample_component_definition):
        """Test listing all control IDs."""
        index = ComponentDefinitionIndex(sample_component_definition)

        control_ids = index.list_control_ids()

        assert "AC-1" in control_ids
        assert "AC-2" in control_ids
        assert "AU-2" in control_ids

    def test_control_implementation_count(self, sample_component_definition):
        """Test control implementation count."""
        index = ComponentDefinitionIndex(sample_component_definition)

        count = index.control_implementation_count

        assert count == 3  # AC-1, AC-2, AU-2


# =============================================================================
# ComponentDefinitionGenerator Tests
# =============================================================================


class TestComponentDefinitionGenerator:
    """Tests for ComponentDefinitionGenerator class."""

    def test_generator_creation(self):
        """Test creating a generator."""
        generator = ComponentDefinitionGenerator(
            title="Test Definition",
            version="1.0.0",
            organization="Test Org",
        )

        assert generator.title == "Test Definition"
        assert generator.version == "1.0.0"

    def test_add_component(self):
        """Test adding a component."""
        generator = ComponentDefinitionGenerator(title="Test")

        config = ComponentConfig(
            title="My Component",
            description="A test component",
            type="software",
        )
        uuid = generator.add_component(config)

        assert uuid is not None
        assert len(generator._components) == 1

    def test_add_control_implementation(self):
        """Test adding a control implementation to a component."""
        generator = ComponentDefinitionGenerator(title="Test")

        comp_uuid = generator.add_component(
            ComponentConfig(
                title="Security Component",
                description="Security controls",
            )
        )

        generator.add_control_implementation(
            comp_uuid,
            ControlImplementationConfig(
                control_id="AC-1",
                description="Access control policy",
                implementation_status="implemented",
            ),
        )

        # Verify the implementation was added
        comp_def = generator.generate()
        assert len(comp_def.components) == 1
        assert len(comp_def.components[0].control_implementations[0].implemented_requirements) == 1

    def test_add_control_implementation_invalid_component(self):
        """Test adding implementation to non-existent component raises error."""
        generator = ComponentDefinitionGenerator(title="Test")

        with pytest.raises(ComponentError):
            generator.add_control_implementation(
                uuid4(),  # Non-existent component
                ControlImplementationConfig(
                    control_id="AC-1",
                    description="Test",
                ),
            )

    def test_add_component_from_checks(self, sample_checks):
        """Test creating a component from compliance checks."""
        generator = ComponentDefinitionGenerator(title="Test")

        uuid = generator.add_component_from_checks(
            ComponentConfig(
                title="AWS Component",
                description="AWS security controls",
            ),
            checks=sample_checks,
            framework="soc2",
        )

        comp_def = generator.generate()
        assert len(comp_def.components) == 1

        # Check that control implementations were created
        ctrl_impls = comp_def.components[0].control_implementations[0].implemented_requirements
        control_ids = [req.control_id for req in ctrl_impls]
        assert "CC6.1" in control_ids
        assert "CC6.2" in control_ids
        assert "CC7.2" in control_ids

    def test_add_component_from_checks_all_frameworks(self, sample_checks):
        """Test creating component with all framework mappings."""
        generator = ComponentDefinitionGenerator(title="Test")

        generator.add_component_from_checks(
            ComponentConfig(
                title="Multi-Framework Component",
                description="Controls for multiple frameworks",
            ),
            checks=sample_checks,
            framework=None,  # All frameworks
        )

        comp_def = generator.generate()
        ctrl_impls = comp_def.components[0].control_implementations[0].implemented_requirements
        control_ids = [req.control_id for req in ctrl_impls]

        # Should have both SOC 2 and NIST controls
        assert "CC6.1" in control_ids
        assert "SC-13" in control_ids
        assert "IA-2" in control_ids

    def test_add_capability(self):
        """Test adding a capability."""
        generator = ComponentDefinitionGenerator(title="Test")

        comp_uuid = generator.add_component(
            ComponentConfig(title="Component 1", description="Test")
        )

        cap_uuid = generator.add_capability(
            name="Security Capability",
            description="Provides security functions",
            component_uuids=[comp_uuid],
        )

        assert cap_uuid is not None
        comp_def = generator.generate()
        assert len(comp_def.capabilities) == 1

    def test_generate(self):
        """Test generating a component definition."""
        generator = ComponentDefinitionGenerator(
            title="Generated Definition",
            version="2.0.0",
        )

        generator.add_component(
            ComponentConfig(
                title="Test Component",
                description="A test component",
            )
        )

        comp_def = generator.generate()

        assert isinstance(comp_def, ComponentDefinition)
        assert comp_def.metadata.title == "Generated Definition"
        assert comp_def.metadata.version == "2.0.0"
        assert len(comp_def.components) == 1

    def test_save_json(self, temp_dir):
        """Test saving as JSON."""
        generator = ComponentDefinitionGenerator(title="Save Test")
        generator.add_component(
            ComponentConfig(title="Test", description="Test")
        )

        path = generator.save(temp_dir / "output.json", format="json")

        assert path.exists()
        content = json.loads(path.read_text())
        assert "component-definition" in content

    def test_save_yaml(self, temp_dir):
        """Test saving as YAML."""
        import yaml

        generator = ComponentDefinitionGenerator(title="Save Test")
        generator.add_component(
            ComponentConfig(title="Test", description="Test")
        )

        path = generator.save(temp_dir / "output.yaml", format="yaml")

        assert path.exists()
        content = yaml.safe_load(path.read_text())
        assert "component-definition" in content

    def test_save_creates_directories(self, temp_dir):
        """Test that save creates parent directories."""
        generator = ComponentDefinitionGenerator(title="Test")
        generator.add_component(ComponentConfig(title="Test", description="Test"))

        path = generator.save(temp_dir / "sub" / "dir" / "comp.json")

        assert path.exists()


# =============================================================================
# Utility Function Tests
# =============================================================================


class TestCreateComponentFromCheckResults:
    """Tests for create_component_from_check_results function."""

    def test_basic_creation(self, sample_check_results):
        """Test basic component creation from results."""
        comp_def = create_component_from_check_results(
            results=sample_check_results,
            component_title="Test Component",
            component_description="Created from check results",
        )

        assert isinstance(comp_def, ComponentDefinition)
        assert len(comp_def.components) == 1
        assert comp_def.components[0].title == "Test Component"

    def test_implementation_status_from_results(self, sample_check_results):
        """Test that implementation status is derived from results."""
        comp_def = create_component_from_check_results(
            results=sample_check_results,
            component_title="Status Test",
            component_description="Testing status derivation",
        )

        ctrl_impls = comp_def.components[0].control_implementations[0].implemented_requirements

        # Find CC6.1 - should be partial (some passed, some failed)
        cc61 = next((r for r in ctrl_impls if r.control_id == "CC6.1"), None)
        assert cc61 is not None

        # Check for implementation-status property
        status_prop = next(
            (p for p in cc61.props if p.name == "implementation-status"),
            None
        )
        # With 3 passing checks and 1 failing, should be partial
        assert status_prop is not None


class TestMergeComponentDefinitions:
    """Tests for merge_component_definitions function."""

    def test_merge_multiple_definitions(self, sample_component_definition):
        """Test merging multiple component definitions."""
        # Create second definition
        second_data = {
            "uuid": str(uuid4()),
            "metadata": {
                "title": "Second Definition",
                "last-modified": datetime.now(timezone.utc).isoformat(),
                "version": "1.0.0",
                "oscal-version": "1.1.2",
            },
            "components": [
                {
                    "uuid": str(uuid4()),
                    "type": "software",
                    "title": "Additional Component",
                    "description": "Another component",
                },
            ],
        }
        second_def = ComponentDefinition.model_validate(second_data)

        merged = merge_component_definitions(
            definitions=[sample_component_definition, second_def],
            title="Merged Definition",
            version="1.0.0",
        )

        assert merged.metadata.title == "Merged Definition"
        assert len(merged.components) == 3  # 2 from first + 1 from second

    def test_merge_preserves_components(self, sample_component_definition):
        """Test that merged definition preserves all component data."""
        merged = merge_component_definitions(
            definitions=[sample_component_definition],
            title="Single Merge",
        )

        # Should have same components as original
        assert len(merged.components) == len(sample_component_definition.components)


class TestGetComponentDefinitionSummary:
    """Tests for get_component_definition_summary function."""

    def test_basic_summary(self, sample_component_definition):
        """Test getting basic summary."""
        summary = get_component_definition_summary(sample_component_definition)

        assert "uuid" in summary
        assert "title" in summary
        assert "version" in summary
        assert "components" in summary
        assert summary["title"] == "Test Component Definition"

    def test_summary_includes_component_details(self, sample_component_definition):
        """Test that summary includes component details."""
        summary = get_component_definition_summary(sample_component_definition)

        assert len(summary["components"]) == 2
        assert summary["components"][0]["title"] == "Security Scanner"
        assert summary["components"][0]["control_implementations"] == 2

    def test_summary_total_implementations(self, sample_component_definition):
        """Test that summary includes total implementation count."""
        summary = get_component_definition_summary(sample_component_definition)

        assert summary["total_control_implementations"] == 3


# =============================================================================
# Pre-built Component Factory Tests
# =============================================================================


class TestCreateAWSComponentDefinition:
    """Tests for create_aws_component_definition function."""

    def test_creates_service_components(self, sample_checks):
        """Test that AWS components are grouped by service."""
        comp_def = create_aws_component_definition(sample_checks)

        assert comp_def is not None
        titles = [c.title for c in comp_def.components]

        # Should have components for different services
        assert any("S3" in t for t in titles)
        assert any("IAM" in t for t in titles)
        assert any("EC2" in t for t in titles)

    def test_aws_component_has_implementations(self, sample_checks):
        """Test that AWS components have control implementations."""
        comp_def = create_aws_component_definition(sample_checks)

        for component in comp_def.components:
            assert component.control_implementations is not None
            assert len(component.control_implementations) > 0


class TestCreateAzureComponentDefinition:
    """Tests for create_azure_component_definition function."""

    def test_creates_azure_components(self):
        """Test creating Azure component definition."""
        checks = [
            ComplianceCheck(
                id="storage-encryption",
                title="Storage Encryption",
                resource_types=["storage_account"],
                framework_mappings={"soc2": ["CC6.1"]},
            ),
            ComplianceCheck(
                id="keyvault-purge",
                title="Key Vault Purge Protection",
                resource_types=["key_vault"],
                framework_mappings={"soc2": ["CC6.1"]},
            ),
        ]

        comp_def = create_azure_component_definition(checks)

        assert comp_def is not None
        titles = [c.title for c in comp_def.components]
        assert any("Storage" in t for t in titles)
        assert any("Key Vault" in t for t in titles)


# =============================================================================
# Integration Tests
# =============================================================================


class TestComponentDefinitionRoundTrip:
    """Tests for saving and loading component definitions."""

    def test_save_and_load(self, temp_dir, sample_checks):
        """Test saving and loading a generated component definition."""
        # Generate
        generator = ComponentDefinitionGenerator(title="Round Trip Test")
        generator.add_component_from_checks(
            ComponentConfig(
                title="Test Component",
                description="Round trip test",
            ),
            checks=sample_checks,
        )

        # Save
        path = generator.save(temp_dir / "roundtrip.json")

        # Load
        loader = ComponentDefinitionLoader()
        loaded = loader.load(path)

        assert loaded.metadata.title == "Round Trip Test"
        assert len(loaded.components) == 1

    def test_index_loaded_definition(self, sample_component_file):
        """Test indexing a loaded component definition."""
        loader = ComponentDefinitionLoader()
        comp_def = loader.load(sample_component_file)

        index = ComponentDefinitionIndex(comp_def)

        assert index.component_count == 2
        assert "AC-1" in index.list_control_ids()
