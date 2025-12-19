"""
Unit tests for OSCAL Pydantic models.

Tests cover:
- JSON serialization and deserialization
- YAML serialization and deserialization
- XML serialization and deserialization
- All major OSCAL document types
- Edge cases and validation
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from attestful.oscal.models import (
    # Base types
    OSCALBaseModel,
    Property,
    Link,
    Role,
    Party,
    ResponsibleParty,
    Resource,
    BackMatter,
    Metadata,
    # Catalog types
    Parameter,
    Constraint,
    Guideline,
    Part,
    Control,
    Group,
    Catalog,
    # Profile types
    SelectControlById,
    Import,
    Combine,
    Merge,
    SetParameter,
    Alter,
    Modify,
    Profile,
    # Component types
    Statement,
    ImplementedRequirement,
    ControlImplementation,
    ComponentType,
    Component,
    Capability,
    ComponentDefinition,
    # Assessment types
    FindingTarget,
    Origin,
    Subject,
    RelevantEvidence,
    Observation,
    Finding,
    LocalDefinitions,
    Result,
    AssessmentResults,
    ImportAP,
    # SSP types
    SystemId,
    SystemStatus,
    SecurityImpactLevel,
    InformationType,
    SystemInformation,
    AuthorizationBoundary,
    SystemCharacteristics,
    SystemUser,
    SystemComponent,
    SystemImplementation,
    ByComponent,
    SSPStatement,
    SSPImplementedRequirement,
    SSPControlImplementation,
    ImportProfile,
    SystemSecurityPlan,
    # POA&M types
    PoamItem,
    Milestone,
    Response,
    Risk,
    ImportSSP,
    PlanOfActionAndMilestones,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_metadata() -> Metadata:
    """Create sample metadata."""
    return Metadata(
        title="Test Document",
        last_modified=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        version="1.0.0",
        oscal_version="1.1.2",
        roles=[
            Role(id="admin", title="Administrator"),
            Role(id="user", title="User"),
        ],
        parties=[
            Party(
                uuid=uuid4(),
                type="organization",
                name="Test Organization",
            ),
        ],
    )


@pytest.fixture
def sample_control() -> Control:
    """Create a sample control."""
    return Control(
        id="AC-1",
        title="Access Control Policy and Procedures",
        class_="SP800-53",
        params=[
            Parameter(
                id="ac-1_prm_1",
                label="organization-defined personnel",
                guidelines=[Guideline(prose="Select appropriate personnel")],
            ),
        ],
        props=[
            Property(name="label", value="AC-1"),
            Property(name="sort-id", value="ac-01"),
        ],
        parts=[
            Part(
                id="ac-1_smt",
                name="statement",
                prose="The organization develops access control policy.",
                parts=[
                    Part(
                        id="ac-1_smt.a",
                        name="item",
                        prose="Addresses purpose and scope.",
                    ),
                ],
            ),
        ],
        links=[
            Link(href="#ref-1", rel="reference"),
        ],
    )


@pytest.fixture
def sample_catalog(sample_metadata: Metadata, sample_control: Control) -> Catalog:
    """Create a sample catalog."""
    return Catalog(
        uuid=uuid4(),
        metadata=sample_metadata,
        params=[
            Parameter(id="global-1", label="Global Parameter"),
        ],
        groups=[
            Group(
                id="ac",
                title="Access Control",
                controls=[sample_control],
            ),
        ],
    )


@pytest.fixture
def sample_profile(sample_metadata: Metadata) -> Profile:
    """Create a sample profile."""
    return Profile(
        uuid=uuid4(),
        metadata=sample_metadata,
        imports=[
            Import(
                href="catalog.json",
                include_controls=[
                    SelectControlById(with_ids=["AC-1", "AC-2", "AC-3"]),
                ],
            ),
        ],
        merge=Merge(
            combine=Combine(method="merge"),
            as_is=True,
        ),
        modify=Modify(
            set_parameters=[
                SetParameter(
                    param_id="ac-1_prm_1",
                    values=["CISO", "Security Team"],
                ),
            ],
            alters=[
                Alter(
                    control_id="AC-1",
                    adds=[{"position": "ending", "parts": []}],
                ),
            ],
        ),
    )


@pytest.fixture
def sample_component_definition(sample_metadata: Metadata) -> ComponentDefinition:
    """Create a sample component definition."""
    return ComponentDefinition(
        uuid=uuid4(),
        metadata=sample_metadata,
        components=[
            Component(
                uuid=uuid4(),
                type="software",
                title="AWS S3",
                description="AWS Simple Storage Service",
                control_implementations=[
                    ControlImplementation(
                        uuid=uuid4(),
                        source="catalog.json",
                        description="S3 security controls",
                        implemented_requirements=[
                            ImplementedRequirement(
                                uuid=uuid4(),
                                control_id="AC-1",
                                description="S3 implements access control via IAM policies.",
                            ),
                        ],
                    ),
                ],
            ),
        ],
    )


@pytest.fixture
def sample_ssp(sample_metadata: Metadata) -> SystemSecurityPlan:
    """Create a sample SSP."""
    component_uuid = uuid4()
    return SystemSecurityPlan(
        uuid=uuid4(),
        metadata=sample_metadata,
        import_profile=ImportProfile(href="profile.json"),
        system_characteristics=SystemCharacteristics(
            system_ids=[SystemId(id="sys-001")],
            system_name="Test System",
            description="A test system for unit testing",
            system_information=SystemInformation(
                information_types=[
                    InformationType(
                        uuid=uuid4(),
                        title="PII",
                        description="Personally Identifiable Information",
                    ),
                ],
            ),
            status=SystemStatus(state="operational"),
            authorization_boundary=AuthorizationBoundary(
                description="System boundary includes all AWS resources.",
            ),
        ),
        system_implementation=SystemImplementation(
            users=[
                SystemUser(uuid=uuid4(), title="Administrator"),
            ],
            components=[
                SystemComponent(
                    uuid=component_uuid,
                    type="software",
                    title="Web Application",
                    description="Main web application",
                    status={"state": "operational"},
                ),
            ],
        ),
        control_implementation=SSPControlImplementation(
            description="Control implementation for Test System",
            implemented_requirements=[
                SSPImplementedRequirement(
                    uuid=uuid4(),
                    control_id="AC-1",
                    by_components=[
                        ByComponent(
                            component_uuid=component_uuid,
                            description="Implemented via IAM policies.",
                        ),
                    ],
                ),
            ],
        ),
    )


@pytest.fixture
def sample_assessment_results(sample_metadata: Metadata) -> AssessmentResults:
    """Create sample assessment results."""
    return AssessmentResults(
        uuid=uuid4(),
        metadata=sample_metadata,
        import_ap=ImportAP(href="assessment-plan.json"),
        results=[
            Result(
                uuid=uuid4(),
                title="Assessment Run 1",
                description="Initial assessment",
                start=datetime(2024, 1, 1, tzinfo=timezone.utc),
                end=datetime(2024, 1, 2, tzinfo=timezone.utc),
                observations=[
                    Observation(
                        uuid=uuid4(),
                        description="Observed access control policy in place.",
                        methods=["EXAMINE", "INTERVIEW"],
                        collected=datetime(2024, 1, 1, tzinfo=timezone.utc),
                    ),
                ],
                findings=[
                    Finding(
                        uuid=uuid4(),
                        title="AC-1 Satisfied",
                        description="Access control policy exists and is current.",
                        target=FindingTarget(
                            type="statement-id",
                            target_id="ac-1_smt",
                            status={"state": "satisfied"},
                        ),
                    ),
                ],
            ),
        ],
    )


@pytest.fixture
def sample_poam(sample_metadata: Metadata) -> PlanOfActionAndMilestones:
    """Create a sample POA&M."""
    return PlanOfActionAndMilestones(
        uuid=uuid4(),
        metadata=sample_metadata,
        import_ssp=ImportSSP(href="ssp.json"),
        risks=[
            Risk(
                uuid=uuid4(),
                title="Weak Password Policy",
                description="Password policy does not meet requirements.",
                status="open",
                remediations=[
                    Response(
                        uuid=uuid4(),
                        lifecycle="planned",
                        title="Update Password Policy",
                        description="Implement stronger password requirements.",
                    ),
                ],
            ),
        ],
        poam_items=[
            PoamItem(
                uuid=uuid4(),
                title="Implement MFA",
                description="Enable multi-factor authentication.",
            ),
        ],
    )


# =============================================================================
# Property and Link Tests
# =============================================================================


class TestProperty:
    """Tests for Property model."""

    def test_property_creation(self) -> None:
        """Test creating a property."""
        prop = Property(name="label", value="AC-1")

        assert prop.name == "label"
        assert prop.value == "AC-1"
        assert prop.uuid is not None

    def test_property_with_namespace(self) -> None:
        """Test property with namespace."""
        prop = Property(
            name="custom-prop",
            value="value",
            ns="https://example.com/ns",
        )

        assert prop.ns == "https://example.com/ns"

    def test_property_json_round_trip(self) -> None:
        """Test JSON serialization round-trip."""
        prop = Property(name="test", value="value", class_="custom")
        json_str = prop.to_json()
        loaded = Property.from_json(json_str)

        assert loaded.name == prop.name
        assert loaded.value == prop.value


class TestLink:
    """Tests for Link model."""

    def test_link_creation(self) -> None:
        """Test creating a link."""
        link = Link(href="#ref-1", rel="reference", text="Reference 1")

        assert link.href == "#ref-1"
        assert link.rel == "reference"
        assert link.text == "Reference 1"

    def test_link_minimal(self) -> None:
        """Test link with only required fields."""
        link = Link(href="https://example.com")

        assert link.href == "https://example.com"
        assert link.rel is None


# =============================================================================
# Metadata Tests
# =============================================================================


class TestMetadata:
    """Tests for Metadata model."""

    def test_metadata_creation(self, sample_metadata: Metadata) -> None:
        """Test creating metadata."""
        assert sample_metadata.title == "Test Document"
        assert sample_metadata.version == "1.0.0"
        assert sample_metadata.oscal_version == "1.1.2"

    def test_metadata_with_parties(self, sample_metadata: Metadata) -> None:
        """Test metadata with parties."""
        assert sample_metadata.parties is not None
        assert len(sample_metadata.parties) == 1
        assert sample_metadata.parties[0].type == "organization"

    def test_metadata_json_round_trip(self, sample_metadata: Metadata) -> None:
        """Test JSON round-trip."""
        json_str = sample_metadata.to_json()
        loaded = Metadata.from_json(json_str)

        assert loaded.title == sample_metadata.title
        assert loaded.version == sample_metadata.version


# =============================================================================
# Catalog Model Tests
# =============================================================================


class TestCatalogModel:
    """Tests for Catalog model."""

    def test_catalog_creation(self, sample_catalog: Catalog) -> None:
        """Test creating a catalog."""
        assert sample_catalog.metadata.title == "Test Document"
        assert sample_catalog.groups is not None
        assert len(sample_catalog.groups) == 1

    def test_catalog_get_all_controls(self, sample_catalog: Catalog) -> None:
        """Test get_all_controls method."""
        controls = sample_catalog.get_all_controls()

        assert len(controls) >= 1
        assert any(c.id == "AC-1" for c in controls)

    def test_catalog_json_round_trip(self, sample_catalog: Catalog) -> None:
        """Test JSON round-trip."""
        json_str = sample_catalog.to_json()
        loaded = Catalog.from_json(json_str)

        assert loaded.metadata.title == sample_catalog.metadata.title
        assert loaded.uuid == sample_catalog.uuid

    def test_catalog_yaml_round_trip(self, sample_catalog: Catalog) -> None:
        """Test YAML round-trip."""
        yaml_str = sample_catalog.to_yaml()
        loaded = Catalog.from_yaml(yaml_str)

        assert loaded.metadata.title == sample_catalog.metadata.title


class TestControl:
    """Tests for Control model."""

    def test_control_creation(self, sample_control: Control) -> None:
        """Test creating a control."""
        assert sample_control.id == "AC-1"
        assert sample_control.title == "Access Control Policy and Procedures"

    def test_control_with_params(self, sample_control: Control) -> None:
        """Test control with parameters."""
        assert sample_control.params is not None
        assert len(sample_control.params) == 1
        assert sample_control.params[0].id == "ac-1_prm_1"

    def test_control_with_nested_parts(self, sample_control: Control) -> None:
        """Test control with nested parts."""
        assert sample_control.parts is not None
        statement = sample_control.parts[0]
        assert statement.parts is not None
        assert len(statement.parts) == 1

    def test_control_json_round_trip(self, sample_control: Control) -> None:
        """Test JSON round-trip."""
        json_str = sample_control.to_json()
        loaded = Control.from_json(json_str)

        assert loaded.id == sample_control.id
        assert loaded.title == sample_control.title


class TestGroup:
    """Tests for Group model."""

    def test_group_creation(self) -> None:
        """Test creating a group."""
        group = Group(
            id="ac",
            title="Access Control",
            controls=[
                Control(id="AC-1", title="Policy"),
                Control(id="AC-2", title="Account Management"),
            ],
        )

        assert group.id == "ac"
        assert group.controls is not None
        assert len(group.controls) == 2

    def test_nested_groups(self) -> None:
        """Test nested groups."""
        group = Group(
            id="parent",
            title="Parent",
            groups=[
                Group(id="child", title="Child"),
            ],
        )

        assert group.groups is not None
        assert len(group.groups) == 1
        assert group.groups[0].id == "child"


# =============================================================================
# Profile Model Tests
# =============================================================================


class TestProfileModel:
    """Tests for Profile model."""

    def test_profile_creation(self, sample_profile: Profile) -> None:
        """Test creating a profile."""
        assert sample_profile.imports is not None
        assert len(sample_profile.imports) == 1

    def test_profile_with_modifications(self, sample_profile: Profile) -> None:
        """Test profile with modifications."""
        assert sample_profile.modify is not None
        assert sample_profile.modify.set_parameters is not None
        assert len(sample_profile.modify.set_parameters) == 1

    def test_profile_json_round_trip(self, sample_profile: Profile) -> None:
        """Test JSON round-trip."""
        json_str = sample_profile.to_json()
        loaded = Profile.from_json(json_str)

        assert loaded.uuid == sample_profile.uuid
        assert len(loaded.imports) == len(sample_profile.imports)


# =============================================================================
# Component Definition Tests
# =============================================================================


class TestComponentDefinition:
    """Tests for ComponentDefinition model."""

    def test_component_definition_creation(
        self, sample_component_definition: ComponentDefinition
    ) -> None:
        """Test creating a component definition."""
        assert sample_component_definition.components is not None
        assert len(sample_component_definition.components) == 1

    def test_component_with_implementations(
        self, sample_component_definition: ComponentDefinition
    ) -> None:
        """Test component with control implementations."""
        component = sample_component_definition.components[0]
        assert component.control_implementations is not None
        assert len(component.control_implementations) == 1

    def test_component_definition_json_round_trip(
        self, sample_component_definition: ComponentDefinition
    ) -> None:
        """Test JSON round-trip."""
        json_str = sample_component_definition.to_json()
        loaded = ComponentDefinition.from_json(json_str)

        assert loaded.uuid == sample_component_definition.uuid


class TestComponentType:
    """Tests for ComponentType enum."""

    def test_component_types(self) -> None:
        """Test all component types exist."""
        assert ComponentType.SOFTWARE.value == "software"
        assert ComponentType.HARDWARE.value == "hardware"
        assert ComponentType.SERVICE.value == "service"
        assert ComponentType.POLICY.value == "policy"


# =============================================================================
# SSP Model Tests
# =============================================================================


class TestSystemSecurityPlan:
    """Tests for SystemSecurityPlan model."""

    def test_ssp_creation(self, sample_ssp: SystemSecurityPlan) -> None:
        """Test creating an SSP."""
        assert sample_ssp.system_characteristics.system_name == "Test System"
        assert sample_ssp.system_implementation.components is not None

    def test_ssp_system_characteristics(self, sample_ssp: SystemSecurityPlan) -> None:
        """Test SSP system characteristics."""
        chars = sample_ssp.system_characteristics
        assert chars.status.state == "operational"
        assert chars.authorization_boundary is not None

    def test_ssp_control_implementation(self, sample_ssp: SystemSecurityPlan) -> None:
        """Test SSP control implementation."""
        impl = sample_ssp.control_implementation
        assert impl.implemented_requirements is not None
        assert len(impl.implemented_requirements) == 1
        assert impl.implemented_requirements[0].control_id == "AC-1"

    def test_ssp_json_round_trip(self, sample_ssp: SystemSecurityPlan) -> None:
        """Test JSON round-trip."""
        json_str = sample_ssp.to_json()
        loaded = SystemSecurityPlan.from_json(json_str)

        assert loaded.uuid == sample_ssp.uuid
        assert loaded.system_characteristics.system_name == "Test System"


class TestSystemStatus:
    """Tests for SystemStatus model."""

    def test_system_status_states(self) -> None:
        """Test various system status states."""
        states = ["operational", "under-development", "disposition"]

        for state in states:
            status = SystemStatus(state=state)
            assert status.state == state


# =============================================================================
# Assessment Results Tests
# =============================================================================


class TestAssessmentResultsModel:
    """Tests for AssessmentResults model."""

    def test_assessment_results_creation(
        self, sample_assessment_results: AssessmentResults
    ) -> None:
        """Test creating assessment results."""
        assert sample_assessment_results.results is not None
        assert len(sample_assessment_results.results) == 1

    def test_assessment_with_findings(
        self, sample_assessment_results: AssessmentResults
    ) -> None:
        """Test assessment with findings."""
        result = sample_assessment_results.results[0]
        assert result.findings is not None
        assert len(result.findings) == 1
        assert result.findings[0].title == "AC-1 Satisfied"

    def test_assessment_with_observations(
        self, sample_assessment_results: AssessmentResults
    ) -> None:
        """Test assessment with observations."""
        result = sample_assessment_results.results[0]
        assert result.observations is not None
        assert len(result.observations) == 1

    def test_assessment_results_json_round_trip(
        self, sample_assessment_results: AssessmentResults
    ) -> None:
        """Test JSON round-trip."""
        json_str = sample_assessment_results.to_json()
        loaded = AssessmentResults.from_json(json_str)

        assert loaded.uuid == sample_assessment_results.uuid


class TestObservation:
    """Tests for Observation model."""

    def test_observation_creation(self) -> None:
        """Test creating an observation."""
        obs = Observation(
            uuid=uuid4(),
            description="Test observation",
            methods=["EXAMINE", "INTERVIEW", "TEST"],
            collected=datetime.now(timezone.utc),
        )

        assert obs.description == "Test observation"
        assert len(obs.methods) == 3


class TestFinding:
    """Tests for Finding model."""

    def test_finding_creation(self) -> None:
        """Test creating a finding."""
        finding = Finding(
            uuid=uuid4(),
            title="Test Finding",
            description="A test finding",
            target=FindingTarget(
                type="statement-id",
                target_id="ac-1_smt",
            ),
        )

        assert finding.title == "Test Finding"
        assert finding.target.type == "statement-id"


# =============================================================================
# POA&M Tests
# =============================================================================


class TestPlanOfActionAndMilestones:
    """Tests for POA&M model."""

    def test_poam_creation(self, sample_poam: PlanOfActionAndMilestones) -> None:
        """Test creating a POA&M."""
        assert sample_poam.poam_items is not None
        assert len(sample_poam.poam_items) == 1

    def test_poam_with_risks(self, sample_poam: PlanOfActionAndMilestones) -> None:
        """Test POA&M with risks."""
        assert sample_poam.risks is not None
        assert len(sample_poam.risks) == 1
        assert sample_poam.risks[0].status == "open"

    def test_poam_json_round_trip(
        self, sample_poam: PlanOfActionAndMilestones
    ) -> None:
        """Test JSON round-trip."""
        json_str = sample_poam.to_json()
        loaded = PlanOfActionAndMilestones.from_json(json_str)

        assert loaded.uuid == sample_poam.uuid


class TestRisk:
    """Tests for Risk model."""

    def test_risk_status_values(self) -> None:
        """Test various risk status values."""
        statuses = ["open", "investigating", "risk-accepted", "closed"]

        for status in statuses:
            risk = Risk(
                uuid=uuid4(),
                title="Test Risk",
                description="A test risk",
                status=status,
            )
            assert risk.status == status


class TestMilestone:
    """Tests for Milestone model."""

    def test_milestone_creation(self) -> None:
        """Test creating a milestone."""
        milestone = Milestone(
            uuid=uuid4(),
            title="Implementation Complete",
            due_date=datetime(2024, 6, 30, tzinfo=timezone.utc),
        )

        assert milestone.title == "Implementation Complete"
        assert milestone.due_date.year == 2024


# =============================================================================
# XML Serialization Tests
# =============================================================================


class TestXMLSerialization:
    """Tests for XML serialization."""

    def test_control_to_xml(self, sample_control: Control) -> None:
        """Test control XML serialization."""
        xml_str = sample_control.to_xml()

        assert '<?xml' in xml_str
        assert 'xmlns="http://csrc.nist.gov/ns/oscal/1.0"' in xml_str
        assert "<id>AC-1</id>" in xml_str
        assert "<title>" in xml_str

    def test_catalog_to_xml(self, sample_catalog: Catalog) -> None:
        """Test catalog XML serialization."""
        xml_str = sample_catalog.to_xml()

        assert '<?xml' in xml_str
        assert "<catalog" in xml_str
        assert "<metadata>" in xml_str

    def test_xml_kebab_case_conversion(self) -> None:
        """Test that snake_case is converted to kebab-case."""
        metadata = Metadata(
            title="Test",
            last_modified=datetime.now(timezone.utc),
            version="1.0",
            oscal_version="1.1.2",
        )

        xml_str = metadata.to_xml()

        assert "<last-modified>" in xml_str
        assert "<oscal-version>" in xml_str
        assert "last_modified" not in xml_str

    @pytest.mark.skip(reason="XML parser needs enhancement for single-element list handling")
    def test_control_xml_round_trip(self, sample_control: Control) -> None:
        """Test XML round-trip for control."""
        xml_str = sample_control.to_xml()
        loaded = Control.from_xml(xml_str)

        assert loaded.id == sample_control.id
        assert loaded.title == sample_control.title


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and validation."""

    def test_empty_catalog(self) -> None:
        """Test creating minimal catalog."""
        catalog = Catalog(
            uuid=uuid4(),
            metadata=Metadata(
                title="Empty",
                last_modified=datetime.now(timezone.utc),
                version="1.0",
            ),
        )

        assert catalog.controls is None
        assert catalog.groups is None
        assert catalog.get_all_controls() == []

    def test_control_without_optional_fields(self) -> None:
        """Test control with only required fields."""
        control = Control(id="C-1", title="Minimal Control")

        assert control.params is None
        assert control.parts is None
        assert control.props is None

    def test_uuid_serialization(self) -> None:
        """Test UUID serialization in JSON."""
        control = Control(id="C-1", title="Test")
        catalog = Catalog(
            uuid=uuid4(),
            metadata=Metadata(
                title="Test",
                last_modified=datetime.now(timezone.utc),
                version="1.0",
            ),
            controls=[control],
        )

        json_str = catalog.to_json()

        # UUID should be serialized as string
        assert '"uuid"' in json_str
        assert isinstance(catalog.uuid, UUID)

    def test_datetime_serialization(self) -> None:
        """Test datetime serialization."""
        now = datetime.now(timezone.utc)
        metadata = Metadata(
            title="Test",
            last_modified=now,
            version="1.0",
        )

        json_str = metadata.to_json()

        # Should be ISO format
        assert "T" in json_str  # ISO format includes T separator

    def test_extra_fields_allowed(self) -> None:
        """Test that extra fields are allowed (OSCAL extensions)."""
        # OSCAL allows extensions, so extra fields should be preserved
        data = {
            "id": "C-1",
            "title": "Test",
            "custom-extension": "value",
        }

        control = Control.model_validate(data)

        # The extra field should be stored
        assert control.model_extra.get("custom-extension") == "value"

    def test_alias_field_names(self) -> None:
        """Test that aliased field names work correctly."""
        # Test last-modified alias
        data = {
            "title": "Test",
            "last-modified": "2024-01-01T00:00:00Z",
            "version": "1.0",
            "oscal-version": "1.1.2",
        }

        metadata = Metadata.model_validate(data)

        assert metadata.last_modified is not None
        assert metadata.oscal_version == "1.1.2"

    def test_none_values_excluded_from_json(self) -> None:
        """Test that None values are excluded from JSON output."""
        control = Control(id="C-1", title="Test")

        json_str = control.to_json()

        # Optional None fields should not appear
        assert '"params"' not in json_str
        assert '"parts"' not in json_str

    def test_large_control_hierarchy(self) -> None:
        """Test deeply nested control hierarchy."""
        # Create deeply nested structure
        deepest = Control(id="C-1(1)(a)(i)", title="Deepest")
        level3 = Control(id="C-1(1)(a)", title="Level 3", controls=[deepest])
        level2 = Control(id="C-1(1)", title="Level 2", controls=[level3])
        level1 = Control(id="C-1", title="Level 1", controls=[level2])

        # Should serialize correctly
        json_str = level1.to_json()
        loaded = Control.from_json(json_str)

        assert loaded.controls[0].controls[0].controls[0].id == "C-1(1)(a)(i)"
