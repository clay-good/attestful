"""
OSCAL Pydantic models.

These models represent the OSCAL document types and can serialize to/from
JSON, YAML, and XML formats.

Reference: https://pages.nist.gov/OSCAL/reference/latest/
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

import orjson
import yaml
from pydantic import BaseModel, ConfigDict, Field


# =============================================================================
# Configuration
# =============================================================================


def orjson_dumps(v: Any, *, default: Any = None) -> str:
    """Serialize using orjson for performance."""
    return orjson.dumps(v, default=default).decode()


class OSCALBaseModel(BaseModel):
    """Base model for all OSCAL types with common configuration."""

    model_config = ConfigDict(
        populate_by_name=True,
        use_enum_values=True,
        extra="allow",  # OSCAL allows extensions
        json_encoders={
            datetime: lambda v: v.isoformat(),
            UUID: str,
        },
    )

    def to_json(self, indent: bool = True) -> str:
        """Serialize to JSON string."""
        data = self.model_dump(by_alias=True, exclude_none=True, mode="json")
        if indent:
            return orjson.dumps(data, option=orjson.OPT_INDENT_2).decode()
        return orjson.dumps(data).decode()

    def to_yaml(self) -> str:
        """Serialize to YAML string."""
        # Use mode="json" to convert UUIDs and datetimes to strings
        data = self.model_dump(by_alias=True, exclude_none=True, mode="json")
        return yaml.dump(data, default_flow_style=False, sort_keys=False)

    @classmethod
    def from_json(cls, json_str: str) -> OSCALBaseModel:
        """Parse from JSON string."""
        data = orjson.loads(json_str)
        return cls.model_validate(data)

    @classmethod
    def from_yaml(cls, yaml_str: str) -> OSCALBaseModel:
        """Parse from YAML string."""
        data = yaml.safe_load(yaml_str)
        return cls.model_validate(data)


# =============================================================================
# Common Types
# =============================================================================


class Property(OSCALBaseModel):
    """A property with a name and value."""

    name: str
    value: str
    uuid: UUID = Field(default_factory=uuid4)
    ns: str | None = Field(default=None, alias="ns")
    class_: str | None = Field(default=None, alias="class")
    remarks: str | None = None


class Link(OSCALBaseModel):
    """A link to an external or internal resource."""

    href: str
    rel: str | None = None
    media_type: str | None = Field(default=None, alias="media-type")
    text: str | None = None


class Role(OSCALBaseModel):
    """A role within the organization."""

    id: str
    title: str
    short_name: str | None = Field(default=None, alias="short-name")
    description: str | None = None
    props: list[Property] | None = None
    links: list[Link] | None = None
    remarks: str | None = None


class Party(OSCALBaseModel):
    """An organization or individual."""

    uuid: UUID = Field(default_factory=uuid4)
    type: Literal["person", "organization"]
    name: str | None = None
    short_name: str | None = Field(default=None, alias="short-name")
    external_ids: list[dict[str, str]] | None = Field(default=None, alias="external-ids")
    props: list[Property] | None = None
    links: list[Link] | None = None
    email_addresses: list[str] | None = Field(default=None, alias="email-addresses")
    telephone_numbers: list[dict[str, str]] | None = Field(
        default=None, alias="telephone-numbers"
    )
    addresses: list[dict[str, Any]] | None = None
    remarks: str | None = None


class ResponsibleParty(OSCALBaseModel):
    """Assignment of a party to a role."""

    role_id: str = Field(alias="role-id")
    party_uuids: list[UUID] = Field(alias="party-uuids")
    props: list[Property] | None = None
    links: list[Link] | None = None
    remarks: str | None = None


class Resource(OSCALBaseModel):
    """A resource in back-matter."""

    uuid: UUID = Field(default_factory=uuid4)
    title: str | None = None
    description: str | None = None
    props: list[Property] | None = None
    document_ids: list[dict[str, str]] | None = Field(default=None, alias="document-ids")
    citation: dict[str, Any] | None = None
    rlinks: list[dict[str, str]] | None = None
    base64: dict[str, str] | None = None
    remarks: str | None = None


class BackMatter(OSCALBaseModel):
    """Back matter containing resources."""

    resources: list[Resource] | None = None


class Metadata(OSCALBaseModel):
    """Document metadata required for all OSCAL documents."""

    title: str
    last_modified: datetime = Field(alias="last-modified")
    version: str
    oscal_version: str = Field(alias="oscal-version", default="1.1.2")
    published: datetime | None = None
    revisions: list[dict[str, Any]] | None = None
    document_ids: list[dict[str, str]] | None = Field(default=None, alias="document-ids")
    props: list[Property] | None = None
    links: list[Link] | None = None
    roles: list[Role] | None = None
    locations: list[dict[str, Any]] | None = None
    parties: list[Party] | None = None
    responsible_parties: list[ResponsibleParty] | None = Field(
        default=None, alias="responsible-parties"
    )
    remarks: str | None = None


class OSCALDocument(OSCALBaseModel):
    """Base class for OSCAL documents."""

    uuid: UUID = Field(default_factory=uuid4)
    metadata: Metadata


# =============================================================================
# Catalog Layer
# =============================================================================


class Constraint(OSCALBaseModel):
    """A constraint on a parameter value."""

    description: str | None = None
    tests: list[dict[str, str]] | None = None


class Guideline(OSCALBaseModel):
    """Guidance for parameter value selection."""

    prose: str


class Parameter(OSCALBaseModel):
    """A parameter that can be set in a profile."""

    id: str
    class_: str | None = Field(default=None, alias="class")
    depends_on: str | None = Field(default=None, alias="depends-on")
    props: list[Property] | None = None
    links: list[Link] | None = None
    label: str | None = None
    usage: str | None = None
    constraints: list[Constraint] | None = None
    guidelines: list[Guideline] | None = None
    values: list[str] | None = None
    select: dict[str, Any] | None = None
    remarks: str | None = None


class Part(OSCALBaseModel):
    """A part of a control (statement, guidance, etc.)."""

    id: str | None = None
    name: str
    ns: str | None = None
    class_: str | None = Field(default=None, alias="class")
    title: str | None = None
    props: list[Property] | None = None
    prose: str | None = None
    parts: list[Part] | None = None
    links: list[Link] | None = None


class Control(OSCALBaseModel):
    """A security or privacy control."""

    id: str
    class_: str | None = Field(default=None, alias="class")
    title: str
    params: list[Parameter] | None = None
    props: list[Property] | None = None
    links: list[Link] | None = None
    parts: list[Part] | None = None
    controls: list[Control] | None = None  # Control enhancements


class Group(OSCALBaseModel):
    """A group of controls."""

    id: str | None = None
    class_: str | None = Field(default=None, alias="class")
    title: str
    params: list[Parameter] | None = None
    props: list[Property] | None = None
    links: list[Link] | None = None
    parts: list[Part] | None = None
    groups: list[Group] | None = None  # Nested groups
    controls: list[Control] | None = None


class Catalog(OSCALDocument):
    """An OSCAL catalog containing control definitions."""

    params: list[Parameter] | None = None
    controls: list[Control] | None = None
    groups: list[Group] | None = None
    back_matter: BackMatter | None = Field(default=None, alias="back-matter")

    def get_all_controls(self) -> list[Control]:
        """Get all controls including those in groups."""
        controls: list[Control] = []

        def collect_from_group(group: Group) -> None:
            if group.controls:
                for control in group.controls:
                    controls.append(control)
                    # Also get control enhancements
                    if control.controls:
                        controls.extend(control.controls)
            if group.groups:
                for subgroup in group.groups:
                    collect_from_group(subgroup)

        # Top-level controls
        if self.controls:
            for control in self.controls:
                controls.append(control)
                if control.controls:
                    controls.extend(control.controls)

        # Controls in groups
        if self.groups:
            for group in self.groups:
                collect_from_group(group)

        return controls


# =============================================================================
# Profile Layer
# =============================================================================


class SelectControlById(OSCALBaseModel):
    """Select controls by ID."""

    with_ids: list[str] | None = Field(default=None, alias="with-ids")
    with_child_controls: str | None = Field(default=None, alias="with-child-controls")
    matching: list[dict[str, str]] | None = None


class Import(OSCALBaseModel):
    """Import controls from a catalog or profile."""

    href: str
    include_all: dict[str, Any] | None = Field(default=None, alias="include-all")
    include_controls: list[SelectControlById] | None = Field(
        default=None, alias="include-controls"
    )
    exclude_controls: list[SelectControlById] | None = Field(
        default=None, alias="exclude-controls"
    )


class Combine(OSCALBaseModel):
    """How to combine multiple imports."""

    method: str | None = None  # "use-first", "merge", "keep"


class CustomGroup(OSCALBaseModel):
    """Custom group structure for profile."""

    id: str | None = None
    class_: str | None = Field(default=None, alias="class")
    title: str
    params: list[Parameter] | None = None
    props: list[Property] | None = None
    links: list[Link] | None = None
    parts: list[Part] | None = None
    groups: list[CustomGroup] | None = None
    insert_controls: list[dict[str, Any]] | None = Field(
        default=None, alias="insert-controls"
    )


class Merge(OSCALBaseModel):
    """How to merge imported controls."""

    combine: Combine | None = None
    flat: dict[str, Any] | None = None  # Flatten structure
    as_is: bool | None = Field(default=None, alias="as-is")
    custom: CustomGroup | None = None


class SetParameter(OSCALBaseModel):
    """Set a parameter value."""

    param_id: str = Field(alias="param-id")
    class_: str | None = Field(default=None, alias="class")
    depends_on: str | None = Field(default=None, alias="depends-on")
    props: list[Property] | None = None
    links: list[Link] | None = None
    label: str | None = None
    usage: str | None = None
    constraints: list[Constraint] | None = None
    guidelines: list[Guideline] | None = None
    values: list[str] | None = None
    select: dict[str, Any] | None = None


class Alter(OSCALBaseModel):
    """Alterations to a control."""

    control_id: str = Field(alias="control-id")
    adds: list[dict[str, Any]] | None = None
    removes: list[dict[str, str]] | None = None


class Modify(OSCALBaseModel):
    """Modifications to imported controls."""

    set_parameters: list[SetParameter] | None = Field(default=None, alias="set-parameters")
    alters: list[Alter] | None = None


class Profile(OSCALDocument):
    """An OSCAL profile for control selection and customization."""

    imports: list[Import]
    merge: Merge | None = None
    modify: Modify | None = None
    back_matter: BackMatter | None = Field(default=None, alias="back-matter")


# =============================================================================
# Component Definition Layer
# =============================================================================


class Statement(OSCALBaseModel):
    """A statement within an implemented requirement."""

    statement_id: str = Field(alias="statement-id")
    uuid: UUID = Field(default_factory=uuid4)
    description: str
    props: list[Property] | None = None
    links: list[Link] | None = None
    responsible_roles: list[dict[str, Any]] | None = Field(
        default=None, alias="responsible-roles"
    )
    remarks: str | None = None


class ImplementedRequirement(OSCALBaseModel):
    """Documentation of how a control is implemented."""

    uuid: UUID = Field(default_factory=uuid4)
    control_id: str = Field(alias="control-id")
    description: str
    props: list[Property] | None = None
    links: list[Link] | None = None
    set_parameters: list[SetParameter] | None = Field(default=None, alias="set-parameters")
    responsible_roles: list[dict[str, Any]] | None = Field(
        default=None, alias="responsible-roles"
    )
    statements: list[Statement] | None = None
    remarks: str | None = None


class ControlImplementation(OSCALBaseModel):
    """A set of control implementations for a source catalog/profile."""

    uuid: UUID = Field(default_factory=uuid4)
    source: str  # URI to catalog or profile
    description: str
    props: list[Property] | None = None
    links: list[Link] | None = None
    set_parameters: list[SetParameter] | None = Field(default=None, alias="set-parameters")
    implemented_requirements: list[ImplementedRequirement] = Field(
        alias="implemented-requirements"
    )


class ComponentType(str, Enum):
    """Types of components."""

    SOFTWARE = "software"
    HARDWARE = "hardware"
    SERVICE = "service"
    INTERCONNECTION = "interconnection"
    POLICY = "policy"
    PROCESS = "process"
    PROCEDURE = "procedure"
    PLAN = "plan"
    GUIDANCE = "guidance"
    STANDARD = "standard"
    VALIDATION = "validation"


class Component(OSCALBaseModel):
    """A component that implements controls."""

    uuid: UUID = Field(default_factory=uuid4)
    type: str  # ComponentType value
    title: str
    description: str
    purpose: str | None = None
    props: list[Property] | None = None
    links: list[Link] | None = None
    responsible_roles: list[dict[str, Any]] | None = Field(
        default=None, alias="responsible-roles"
    )
    protocols: list[dict[str, Any]] | None = None
    control_implementations: list[ControlImplementation] | None = Field(
        default=None, alias="control-implementations"
    )
    remarks: str | None = None


class Capability(OSCALBaseModel):
    """A capability provided by components."""

    uuid: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    props: list[Property] | None = None
    links: list[Link] | None = None
    incorporates_components: list[dict[str, UUID]] | None = Field(
        default=None, alias="incorporates-components"
    )
    control_implementations: list[ControlImplementation] | None = Field(
        default=None, alias="control-implementations"
    )
    remarks: str | None = None


class ComponentDefinition(OSCALDocument):
    """A collection of component definitions."""

    import_component_definitions: list[dict[str, str]] | None = Field(
        default=None, alias="import-component-definitions"
    )
    components: list[Component] | None = None
    capabilities: list[Capability] | None = None
    back_matter: BackMatter | None = Field(default=None, alias="back-matter")


# =============================================================================
# Assessment Results Layer
# =============================================================================


class FindingTarget(OSCALBaseModel):
    """Target of a finding."""

    type: str  # "statement-id", "objective-id"
    target_id: str = Field(alias="target-id")
    title: str | None = None
    description: str | None = None
    props: list[Property] | None = None
    links: list[Link] | None = None
    status: dict[str, str] | None = None
    implementation_status: dict[str, str] | None = Field(
        default=None, alias="implementation-status"
    )
    remarks: str | None = None


class Origin(OSCALBaseModel):
    """Origin of an observation or finding."""

    actors: list[dict[str, Any]]
    related_tasks: list[dict[str, UUID]] | None = Field(default=None, alias="related-tasks")


class Subject(OSCALBaseModel):
    """Subject of an observation."""

    subject_uuid: UUID = Field(alias="subject-uuid")
    type: str
    title: str | None = None
    props: list[Property] | None = None
    links: list[Link] | None = None
    remarks: str | None = None


class RelevantEvidence(OSCALBaseModel):
    """Evidence relevant to an observation."""

    href: str | None = None
    description: str
    props: list[Property] | None = None
    links: list[Link] | None = None
    remarks: str | None = None


class Observation(OSCALBaseModel):
    """An observation made during assessment."""

    uuid: UUID = Field(default_factory=uuid4)
    title: str | None = None
    description: str
    props: list[Property] | None = None
    links: list[Link] | None = None
    methods: list[str]
    types: list[str] | None = None
    origins: list[Origin] | None = None
    subjects: list[Subject] | None = None
    relevant_evidence: list[RelevantEvidence] | None = Field(
        default=None, alias="relevant-evidence"
    )
    collected: datetime
    expires: datetime | None = None
    remarks: str | None = None


class AssociatedRisk(OSCALBaseModel):
    """Risk associated with a finding."""

    risk_uuid: UUID = Field(alias="risk-uuid")


class Finding(OSCALBaseModel):
    """A finding from an assessment."""

    uuid: UUID = Field(default_factory=uuid4)
    title: str
    description: str
    props: list[Property] | None = None
    links: list[Link] | None = None
    origins: list[Origin] | None = None
    target: FindingTarget
    implementation_statement_uuid: UUID | None = Field(
        default=None, alias="implementation-statement-uuid"
    )
    related_observations: list[dict[str, UUID]] | None = Field(
        default=None, alias="related-observations"
    )
    related_risks: list[AssociatedRisk] | None = Field(default=None, alias="related-risks")
    remarks: str | None = None


class LocalDefinitions(OSCALBaseModel):
    """Local definitions within a result."""

    components: list[Component] | None = None
    users: list[dict[str, Any]] | None = None
    assessment_assets: dict[str, Any] | None = Field(default=None, alias="assessment-assets")
    tasks: list[dict[str, Any]] | None = None


class Attestation(OSCALBaseModel):
    """An attestation statement."""

    responsible_parties: list[ResponsibleParty] = Field(alias="responsible-parties")
    parts: list[Part]


class Result(OSCALBaseModel):
    """A set of assessment results."""

    uuid: UUID = Field(default_factory=uuid4)
    title: str
    description: str
    start: datetime
    end: datetime | None = None
    props: list[Property] | None = None
    links: list[Link] | None = None
    local_definitions: LocalDefinitions | None = Field(
        default=None, alias="local-definitions"
    )
    reviewed_controls: dict[str, Any] | None = Field(default=None, alias="reviewed-controls")
    attestations: list[Attestation] | None = None
    assessment_log: dict[str, Any] | None = Field(default=None, alias="assessment-log")
    observations: list[Observation] | None = None
    risks: list[dict[str, Any]] | None = None
    findings: list[Finding] | None = None
    remarks: str | None = None


# =============================================================================
# System Security Plan (SSP) Layer
# =============================================================================


class SystemId(OSCALBaseModel):
    """Unique identifier for a system."""

    id: str
    identifier_type: str | None = Field(default=None, alias="identifier-type")


class SystemStatus(OSCALBaseModel):
    """Status of the system."""

    state: str  # "operational", "under-development", "under-major-modification", "disposition", "other"
    remarks: str | None = None


class SecurityImpactLevel(OSCALBaseModel):
    """Security impact level for confidentiality, integrity, or availability."""

    base: str  # "fips-199-low", "fips-199-moderate", "fips-199-high"
    selected: str | None = None
    adjustment_justification: str | None = Field(
        default=None, alias="adjustment-justification"
    )


class SecuritySensitivityLevel(OSCALBaseModel):
    """Security sensitivity level."""

    security_sensitivity_level: str = Field(alias="security-sensitivity-level")


class InformationType(OSCALBaseModel):
    """Information type processed by the system."""

    uuid: UUID = Field(default_factory=uuid4)
    title: str
    description: str
    categorizations: list[dict[str, Any]] | None = None
    props: list[Property] | None = None
    links: list[Link] | None = None
    confidentiality_impact: SecurityImpactLevel | None = Field(
        default=None, alias="confidentiality-impact"
    )
    integrity_impact: SecurityImpactLevel | None = Field(
        default=None, alias="integrity-impact"
    )
    availability_impact: SecurityImpactLevel | None = Field(
        default=None, alias="availability-impact"
    )


class SystemInformation(OSCALBaseModel):
    """Information about the system and its information types."""

    props: list[Property] | None = None
    links: list[Link] | None = None
    information_types: list[InformationType] = Field(alias="information-types")


class AuthorizationBoundary(OSCALBaseModel):
    """System authorization boundary."""

    description: str
    props: list[Property] | None = None
    links: list[Link] | None = None
    diagrams: list[dict[str, Any]] | None = None
    remarks: str | None = None


class NetworkArchitecture(OSCALBaseModel):
    """Network architecture description."""

    description: str
    props: list[Property] | None = None
    links: list[Link] | None = None
    diagrams: list[dict[str, Any]] | None = None
    remarks: str | None = None


class DataFlow(OSCALBaseModel):
    """Data flow description."""

    description: str
    props: list[Property] | None = None
    links: list[Link] | None = None
    diagrams: list[dict[str, Any]] | None = None
    remarks: str | None = None


class LeveragedAuthorization(OSCALBaseModel):
    """Reference to a leveraged external authorization."""

    uuid: UUID = Field(default_factory=uuid4)
    title: str
    props: list[Property] | None = None
    links: list[Link] | None = None
    party_uuid: UUID = Field(alias="party-uuid")
    date_authorized: datetime | None = Field(default=None, alias="date-authorized")
    remarks: str | None = None


class SystemUser(OSCALBaseModel):
    """A user of the system."""

    uuid: UUID = Field(default_factory=uuid4)
    title: str | None = None
    short_name: str | None = Field(default=None, alias="short-name")
    description: str | None = None
    props: list[Property] | None = None
    links: list[Link] | None = None
    role_ids: list[str] | None = Field(default=None, alias="role-ids")
    authorized_privileges: list[dict[str, Any]] | None = Field(
        default=None, alias="authorized-privileges"
    )
    remarks: str | None = None


class InventoryItem(OSCALBaseModel):
    """An inventory item in the system."""

    uuid: UUID = Field(default_factory=uuid4)
    description: str
    props: list[Property] | None = None
    links: list[Link] | None = None
    responsible_parties: list[ResponsibleParty] | None = Field(
        default=None, alias="responsible-parties"
    )
    implemented_components: list[dict[str, Any]] | None = Field(
        default=None, alias="implemented-components"
    )
    remarks: str | None = None


class SystemComponent(OSCALBaseModel):
    """A component within the system implementation."""

    uuid: UUID = Field(default_factory=uuid4)
    type: str
    title: str
    description: str
    purpose: str | None = None
    props: list[Property] | None = None
    links: list[Link] | None = None
    status: dict[str, str]
    responsible_roles: list[dict[str, Any]] | None = Field(
        default=None, alias="responsible-roles"
    )
    protocols: list[dict[str, Any]] | None = None
    remarks: str | None = None


class SystemImplementation(OSCALBaseModel):
    """System implementation details."""

    props: list[Property] | None = None
    links: list[Link] | None = None
    leveraged_authorizations: list[LeveragedAuthorization] | None = Field(
        default=None, alias="leveraged-authorizations"
    )
    users: list[SystemUser]
    components: list[SystemComponent]
    inventory_items: list[InventoryItem] | None = Field(
        default=None, alias="inventory-items"
    )
    remarks: str | None = None


class ByComponent(OSCALBaseModel):
    """Control implementation by component."""

    component_uuid: UUID = Field(alias="component-uuid")
    uuid: UUID = Field(default_factory=uuid4)
    description: str
    props: list[Property] | None = None
    links: list[Link] | None = None
    set_parameters: list[SetParameter] | None = Field(
        default=None, alias="set-parameters"
    )
    implementation_status: dict[str, str] | None = Field(
        default=None, alias="implementation-status"
    )
    export: dict[str, Any] | None = None
    inherited: list[dict[str, Any]] | None = None
    satisfied: list[dict[str, Any]] | None = None
    responsible_roles: list[dict[str, Any]] | None = Field(
        default=None, alias="responsible-roles"
    )
    remarks: str | None = None


class SSPStatement(OSCALBaseModel):
    """Statement within an SSP implemented requirement."""

    statement_id: str = Field(alias="statement-id")
    uuid: UUID = Field(default_factory=uuid4)
    props: list[Property] | None = None
    links: list[Link] | None = None
    responsible_roles: list[dict[str, Any]] | None = Field(
        default=None, alias="responsible-roles"
    )
    by_components: list[ByComponent] | None = Field(default=None, alias="by-components")
    remarks: str | None = None


class SSPImplementedRequirement(OSCALBaseModel):
    """An implemented requirement within an SSP."""

    uuid: UUID = Field(default_factory=uuid4)
    control_id: str = Field(alias="control-id")
    props: list[Property] | None = None
    links: list[Link] | None = None
    set_parameters: list[SetParameter] | None = Field(
        default=None, alias="set-parameters"
    )
    responsible_roles: list[dict[str, Any]] | None = Field(
        default=None, alias="responsible-roles"
    )
    statements: list[SSPStatement] | None = None
    by_components: list[ByComponent] | None = Field(default=None, alias="by-components")
    remarks: str | None = None


class SSPControlImplementation(OSCALBaseModel):
    """Control implementation section of an SSP."""

    description: str
    set_parameters: list[SetParameter] | None = Field(
        default=None, alias="set-parameters"
    )
    implemented_requirements: list[SSPImplementedRequirement] = Field(
        alias="implemented-requirements"
    )


class ImportProfile(OSCALBaseModel):
    """Import a profile for the SSP."""

    href: str
    remarks: str | None = None


class SystemCharacteristics(OSCALBaseModel):
    """Characteristics of the system being documented."""

    system_ids: list[SystemId] = Field(alias="system-ids")
    system_name: str = Field(alias="system-name")
    system_name_short: str | None = Field(default=None, alias="system-name-short")
    description: str
    props: list[Property] | None = None
    links: list[Link] | None = None
    date_authorized: datetime | None = Field(default=None, alias="date-authorized")
    security_sensitivity_level: str | None = Field(
        default=None, alias="security-sensitivity-level"
    )
    system_information: SystemInformation = Field(alias="system-information")
    security_impact_level: dict[str, Any] | None = Field(
        default=None, alias="security-impact-level"
    )
    status: SystemStatus
    authorization_boundary: AuthorizationBoundary = Field(alias="authorization-boundary")
    network_architecture: NetworkArchitecture | None = Field(
        default=None, alias="network-architecture"
    )
    data_flow: DataFlow | None = Field(default=None, alias="data-flow")
    responsible_parties: list[ResponsibleParty] | None = Field(
        default=None, alias="responsible-parties"
    )
    remarks: str | None = None


class SystemSecurityPlan(OSCALDocument):
    """OSCAL System Security Plan (SSP) document."""

    import_profile: ImportProfile = Field(alias="import-profile")
    system_characteristics: SystemCharacteristics = Field(alias="system-characteristics")
    system_implementation: SystemImplementation = Field(alias="system-implementation")
    control_implementation: SSPControlImplementation = Field(alias="control-implementation")
    back_matter: BackMatter | None = Field(default=None, alias="back-matter")


class ImportAP(OSCALBaseModel):
    """Import an assessment plan."""

    href: str
    remarks: str | None = None


class AssessmentResults(OSCALDocument):
    """OSCAL Assessment Results document."""

    import_ap: ImportAP = Field(alias="import-ap")
    local_definitions: LocalDefinitions | None = Field(
        default=None, alias="local-definitions"
    )
    results: list[Result]
    back_matter: BackMatter | None = Field(default=None, alias="back-matter")
