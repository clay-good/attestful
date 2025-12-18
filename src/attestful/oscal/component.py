"""
OSCAL Component Definition loader, generator, and utilities.

Provides functionality for loading, creating, and managing OSCAL Component
Definitions that document how controls are implemented by software, services,
policies, and other components.

Component definitions enable reusable control implementation documentation
that can be assembled into System Security Plans (SSPs).
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import orjson
import yaml

from attestful.core.exceptions import OSCALError
from attestful.core.logging import get_logger
from attestful.core.models import CheckResult, ComplianceCheck
from attestful.oscal.models import (
    BackMatter,
    Capability,
    Component,
    ComponentDefinition,
    ComponentType,
    ControlImplementation,
    ImplementedRequirement,
    Link,
    Metadata,
    Property,
    SetParameter,
    Statement,
)

logger = get_logger("oscal.component")


class ComponentError(OSCALError):
    """Error loading or processing a component definition."""

    def __init__(
        self,
        message: str,
        *,
        component_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.component_id = component_id


# =============================================================================
# Component Definition Loader
# =============================================================================


class ComponentDefinitionLoader:
    """
    Load OSCAL Component Definitions from various sources.

    Supports JSON and YAML formats.
    """

    def __init__(self) -> None:
        self._cache: dict[str, ComponentDefinition] = {}

    def load(
        self,
        path: str | Path,
        *,
        use_cache: bool = True,
    ) -> ComponentDefinition:
        """
        Load a component definition from a file path.

        Args:
            path: Path to the component definition file
            use_cache: Whether to use cached definition if available

        Returns:
            Parsed ComponentDefinition object

        Raises:
            ComponentError: If the file cannot be loaded or parsed
        """
        path = Path(path)
        cache_key = str(path.resolve())

        if use_cache and cache_key in self._cache:
            logger.debug(f"Using cached component definition: {path}")
            return self._cache[cache_key]

        if not path.exists():
            raise ComponentError(
                f"Component definition file not found: {path}",
                component_id=str(path),
            )

        try:
            content = path.read_text(encoding="utf-8")
            comp_def = self._parse_content(content, path.suffix.lower())

            if use_cache:
                self._cache[cache_key] = comp_def

            logger.info(
                f"Loaded component definition: {comp_def.metadata.title} ({path})"
            )
            return comp_def

        except Exception as e:
            if isinstance(e, ComponentError):
                raise
            raise ComponentError(
                f"Failed to load component definition: {e}",
                component_id=str(path),
                cause=e,
            ) from e

    def load_from_string(
        self,
        content: str,
        format: str = "json",
    ) -> ComponentDefinition:
        """
        Load a component definition from a string.

        Args:
            content: The component definition content
            format: Format of the content ("json", "yaml")

        Returns:
            Parsed ComponentDefinition object
        """
        return self._parse_content(content, f".{format}")

    def _parse_content(self, content: str, suffix: str) -> ComponentDefinition:
        """Parse component definition content based on format."""
        if suffix in (".json",):
            data = orjson.loads(content)
        elif suffix in (".yaml", ".yml"):
            data = yaml.safe_load(content)
        else:
            # Try JSON first, then YAML
            try:
                data = orjson.loads(content)
            except orjson.JSONDecodeError:
                data = yaml.safe_load(content)

        # Handle wrapped format (component-definition key at root)
        if "component-definition" in data:
            data = data["component-definition"]

        return ComponentDefinition.model_validate(data)

    def clear_cache(self) -> None:
        """Clear the component definition cache."""
        self._cache.clear()


# =============================================================================
# Component Definition Index
# =============================================================================


class ComponentDefinitionIndex:
    """
    Index for fast lookup of components and control implementations.

    Provides O(1) lookup by component UUID or control ID.
    """

    def __init__(self, comp_def: ComponentDefinition) -> None:
        self.component_definition = comp_def
        self._components: dict[UUID, Component] = {}
        self._components_by_title: dict[str, Component] = {}
        self._control_implementations: dict[str, list[tuple[Component, ImplementedRequirement]]] = {}
        self._capabilities: dict[UUID, Capability] = {}
        self._build_index()

    def _build_index(self) -> None:
        """Build the component index."""
        if self.component_definition.components:
            for component in self.component_definition.components:
                self._components[component.uuid] = component
                self._components_by_title[component.title.lower()] = component

                # Index control implementations
                if component.control_implementations:
                    for ctrl_impl in component.control_implementations:
                        for req in ctrl_impl.implemented_requirements:
                            control_id = req.control_id
                            if control_id not in self._control_implementations:
                                self._control_implementations[control_id] = []
                            self._control_implementations[control_id].append(
                                (component, req)
                            )

        if self.component_definition.capabilities:
            for capability in self.component_definition.capabilities:
                self._capabilities[capability.uuid] = capability

        logger.debug(
            f"Indexed {len(self._components)} components, "
            f"{len(self._control_implementations)} control implementations"
        )

    def get_component(self, uuid: UUID) -> Component | None:
        """Get a component by UUID."""
        return self._components.get(uuid)

    def get_component_by_title(self, title: str) -> Component | None:
        """Get a component by title (case-insensitive)."""
        return self._components_by_title.get(title.lower())

    def get_implementations_for_control(
        self,
        control_id: str,
    ) -> list[tuple[Component, ImplementedRequirement]]:
        """
        Get all implementations for a control.

        Returns list of (component, implemented_requirement) tuples.
        """
        return self._control_implementations.get(control_id, [])

    def list_components(self) -> list[Component]:
        """Get all components."""
        return list(self._components.values())

    def list_control_ids(self) -> list[str]:
        """Get all control IDs with implementations."""
        return list(self._control_implementations.keys())

    def get_capability(self, uuid: UUID) -> Capability | None:
        """Get a capability by UUID."""
        return self._capabilities.get(uuid)

    @property
    def component_count(self) -> int:
        """Number of components in the definition."""
        return len(self._components)

    @property
    def control_implementation_count(self) -> int:
        """Number of unique control implementations."""
        return sum(len(impls) for impls in self._control_implementations.values())


# =============================================================================
# Component Definition Generator
# =============================================================================


@dataclass
class ComponentConfig:
    """Configuration for generating a component."""

    title: str
    description: str
    type: str = "software"
    purpose: str | None = None
    uuid: UUID = field(default_factory=uuid4)


@dataclass
class ControlImplementationConfig:
    """Configuration for a control implementation."""

    control_id: str
    description: str
    implementation_status: str = "implemented"
    props: dict[str, str] = field(default_factory=dict)
    responsible_roles: list[str] = field(default_factory=list)


class ComponentDefinitionGenerator:
    """
    Generate OSCAL Component Definitions.

    Creates component definitions from various sources including
    Attestful compliance checks and manual configurations.
    """

    def __init__(
        self,
        title: str,
        version: str = "1.0.0",
        organization: str = "Organization",
    ) -> None:
        """
        Initialize the generator.

        Args:
            title: Title for the component definition
            version: Version string
            organization: Organization name for metadata
        """
        self.title = title
        self.version = version
        self.organization = organization
        self._components: list[Component] = []
        self._capabilities: list[Capability] = []

    def add_component(
        self,
        config: ComponentConfig,
        source_uri: str = "#attestful-checks",
    ) -> UUID:
        """
        Add a component to the definition.

        Args:
            config: Component configuration
            source_uri: URI to the source catalog/profile for control implementations

        Returns:
            UUID of the created component
        """
        component = Component(
            uuid=config.uuid,
            type=config.type,
            title=config.title,
            description=config.description,
            purpose=config.purpose,
            control_implementations=[
                ControlImplementation(
                    source=source_uri,
                    description=f"Control implementations for {config.title}",
                    implemented_requirements=[],
                )
            ],
        )
        self._components.append(component)
        logger.debug(f"Added component: {config.title}")
        return config.uuid

    def add_control_implementation(
        self,
        component_uuid: UUID,
        config: ControlImplementationConfig,
    ) -> None:
        """
        Add a control implementation to a component.

        Args:
            component_uuid: UUID of the component
            config: Control implementation configuration
        """
        # Find the component
        component = None
        for comp in self._components:
            if comp.uuid == component_uuid:
                component = comp
                break

        if not component:
            raise ComponentError(
                f"Component not found: {component_uuid}",
                component_id=str(component_uuid),
            )

        # Create the implemented requirement
        props = [
            Property(name=name, value=value)
            for name, value in config.props.items()
        ]

        # Add implementation status property
        props.append(
            Property(
                name="implementation-status",
                value=config.implementation_status,
            )
        )

        implemented_req = ImplementedRequirement(
            control_id=config.control_id,
            description=config.description,
            props=props if props else None,
            responsible_roles=[
                {"role-id": role} for role in config.responsible_roles
            ] if config.responsible_roles else None,
        )

        # Add to the component's control implementations
        if component.control_implementations:
            component.control_implementations[0].implemented_requirements.append(
                implemented_req
            )

    def add_component_from_checks(
        self,
        component_config: ComponentConfig,
        checks: list[ComplianceCheck],
        source_uri: str = "#attestful-checks",
        framework: str | None = None,
    ) -> UUID:
        """
        Create a component from Attestful compliance checks.

        Maps checks to OSCAL control implementations based on their
        framework_controls or framework_mappings.

        Args:
            component_config: Configuration for the component
            checks: List of compliance checks
            source_uri: URI to the source catalog/profile
            framework: Specific framework to map (e.g., "soc2", "nist_800_53")
                      If None, uses all framework mappings

        Returns:
            UUID of the created component
        """
        component_uuid = self.add_component(component_config, source_uri)

        # Group checks by control
        control_checks: dict[str, list[ComplianceCheck]] = {}

        for check in checks:
            # Get framework mappings
            mappings = check.framework_mappings or check.framework_controls

            for fw, controls in mappings.items():
                if framework and fw != framework:
                    continue

                for control_id in controls:
                    if control_id not in control_checks:
                        control_checks[control_id] = []
                    control_checks[control_id].append(check)

        # Create control implementations
        for control_id, mapped_checks in control_checks.items():
            check_descriptions = [
                f"- {c.title or c.id}: {c.description or 'Automated check'}"
                for c in mapped_checks
            ]

            config = ControlImplementationConfig(
                control_id=control_id,
                description=(
                    f"Automated verification through {len(mapped_checks)} check(s):\n"
                    + "\n".join(check_descriptions)
                ),
                implementation_status="implemented",
                props={
                    "check-count": str(len(mapped_checks)),
                    "automated": "true",
                },
            )

            self.add_control_implementation(component_uuid, config)

        logger.info(
            f"Created component '{component_config.title}' with "
            f"{len(control_checks)} control implementations from {len(checks)} checks"
        )

        return component_uuid

    def add_capability(
        self,
        name: str,
        description: str,
        component_uuids: list[UUID] | None = None,
    ) -> UUID:
        """
        Add a capability that groups multiple components.

        Args:
            name: Capability name
            description: Capability description
            component_uuids: UUIDs of components in this capability

        Returns:
            UUID of the created capability
        """
        capability = Capability(
            name=name,
            description=description,
            incorporates_components=[
                {"component-uuid": str(uuid)}
                for uuid in (component_uuids or [])
            ] if component_uuids else None,
        )
        self._capabilities.append(capability)
        return capability.uuid

    def generate(self) -> ComponentDefinition:
        """
        Generate the OSCAL Component Definition.

        Returns:
            ComponentDefinition object
        """
        metadata = Metadata(
            title=self.title,
            last_modified=datetime.now(timezone.utc),
            version=self.version,
            oscal_version="1.1.2",
            props=[
                Property(name="generator", value="attestful"),
            ],
        )

        comp_def = ComponentDefinition(
            uuid=uuid4(),
            metadata=metadata,
            components=self._components if self._components else None,
            capabilities=self._capabilities if self._capabilities else None,
        )

        logger.info(
            f"Generated component definition '{self.title}' with "
            f"{len(self._components)} components"
        )

        return comp_def

    def save(
        self,
        path: str | Path,
        format: str = "json",
    ) -> Path:
        """
        Generate and save the component definition.

        Args:
            path: Output file path
            format: Output format ("json" or "yaml")

        Returns:
            Path to the saved file
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        comp_def = self.generate()

        # Wrap in component-definition key per OSCAL spec
        data = {"component-definition": comp_def.model_dump(
            by_alias=True,
            exclude_none=True,
            mode="json",
        )}

        if format == "json":
            content = orjson.dumps(data, option=orjson.OPT_INDENT_2).decode()
        else:
            content = yaml.dump(data, default_flow_style=False, sort_keys=False)

        path.write_text(content, encoding="utf-8")
        logger.info(f"Saved component definition to {path}")

        return path


# =============================================================================
# Component Mapping Utilities
# =============================================================================


def create_component_from_check_results(
    results: list[CheckResult],
    component_title: str,
    component_description: str,
    source_uri: str = "#attestful-checks",
) -> ComponentDefinition:
    """
    Create a component definition from check results.

    Groups check results by control and creates implementations
    with pass/fail status.

    Args:
        results: List of check results
        component_title: Title for the component
        component_description: Description for the component
        source_uri: URI to the source catalog/profile

    Returns:
        ComponentDefinition with the component and implementations
    """
    generator = ComponentDefinitionGenerator(
        title=f"Component Definition: {component_title}",
    )

    component_uuid = generator.add_component(
        ComponentConfig(
            title=component_title,
            description=component_description,
            type="validation",
        ),
        source_uri=source_uri,
    )

    # Group results by control
    control_results: dict[str, list[CheckResult]] = {}

    for result in results:
        check = result.check
        if not check:
            continue

        mappings = check.framework_mappings or check.framework_controls
        for fw, controls in mappings.items():
            for control_id in controls:
                if control_id not in control_results:
                    control_results[control_id] = []
                control_results[control_id].append(result)

    # Create control implementations
    for control_id, ctrl_results in control_results.items():
        passed = sum(1 for r in ctrl_results if r.passed)
        failed = sum(1 for r in ctrl_results if r.passed is False)
        total = len(ctrl_results)

        # Determine implementation status
        if failed == 0 and passed > 0:
            status = "implemented"
        elif passed == 0 and failed > 0:
            status = "not-implemented"
        else:
            status = "partial"

        config = ControlImplementationConfig(
            control_id=control_id,
            description=(
                f"Automated verification: {passed}/{total} checks passed"
            ),
            implementation_status=status,
            props={
                "checks-passed": str(passed),
                "checks-failed": str(failed),
                "checks-total": str(total),
            },
        )

        generator.add_control_implementation(component_uuid, config)

    return generator.generate()


def merge_component_definitions(
    definitions: list[ComponentDefinition],
    title: str,
    version: str = "1.0.0",
) -> ComponentDefinition:
    """
    Merge multiple component definitions into one.

    Args:
        definitions: List of component definitions to merge
        title: Title for the merged definition
        version: Version for the merged definition

    Returns:
        Merged ComponentDefinition
    """
    all_components: list[Component] = []
    all_capabilities: list[Capability] = []

    for comp_def in definitions:
        if comp_def.components:
            for component in comp_def.components:
                # Deep copy to avoid modifying originals
                all_components.append(deepcopy(component))

        if comp_def.capabilities:
            for capability in comp_def.capabilities:
                all_capabilities.append(deepcopy(capability))

    metadata = Metadata(
        title=title,
        last_modified=datetime.now(timezone.utc),
        version=version,
        oscal_version="1.1.2",
        props=[
            Property(name="merged-from", value=str(len(definitions))),
            Property(name="generator", value="attestful"),
        ],
    )

    return ComponentDefinition(
        uuid=uuid4(),
        metadata=metadata,
        components=all_components if all_components else None,
        capabilities=all_capabilities if all_capabilities else None,
    )


def get_component_definition_summary(comp_def: ComponentDefinition) -> dict[str, Any]:
    """
    Get a summary of a component definition.

    Returns:
        Dictionary with summary information
    """
    summary: dict[str, Any] = {
        "uuid": str(comp_def.uuid),
        "title": comp_def.metadata.title,
        "version": comp_def.metadata.version,
        "components": [],
        "capabilities_count": 0,
        "total_control_implementations": 0,
    }

    if comp_def.components:
        for component in comp_def.components:
            comp_summary: dict[str, Any] = {
                "uuid": str(component.uuid),
                "title": component.title,
                "type": component.type,
                "control_implementations": 0,
            }

            if component.control_implementations:
                for ctrl_impl in component.control_implementations:
                    count = len(ctrl_impl.implemented_requirements)
                    comp_summary["control_implementations"] += count
                    summary["total_control_implementations"] += count

            summary["components"].append(comp_summary)

    if comp_def.capabilities:
        summary["capabilities_count"] = len(comp_def.capabilities)

    return summary


# =============================================================================
# Pre-built Component Factories
# =============================================================================


def create_aws_component_definition(
    checks: list[ComplianceCheck],
    source_uri: str = "#attestful-aws-checks",
) -> ComponentDefinition:
    """
    Create a component definition for AWS infrastructure.

    Args:
        checks: AWS compliance checks
        source_uri: URI to the source catalog/profile

    Returns:
        ComponentDefinition for AWS
    """
    generator = ComponentDefinitionGenerator(
        title="AWS Infrastructure Component",
        organization="AWS",
    )

    # Group checks by service
    service_checks: dict[str, list[ComplianceCheck]] = {}

    for check in checks:
        # Determine AWS service from resource types
        service = "General"
        for rt in check.resource_types:
            if rt.startswith("s3"):
                service = "S3"
            elif rt.startswith("ec2"):
                service = "EC2"
            elif rt.startswith("iam"):
                service = "IAM"
            elif rt.startswith("rds"):
                service = "RDS"
            elif rt.startswith("kms"):
                service = "KMS"
            elif rt.startswith("cloudtrail"):
                service = "CloudTrail"
            elif rt.startswith("security_group"):
                service = "VPC"
            break

        if service not in service_checks:
            service_checks[service] = []
        service_checks[service].append(check)

    # Create components for each service
    for service, svc_checks in service_checks.items():
        generator.add_component_from_checks(
            ComponentConfig(
                title=f"AWS {service}",
                description=f"AWS {service} security controls and configurations",
                type="service",
                purpose=f"Provides {service} infrastructure services",
            ),
            checks=svc_checks,
            source_uri=source_uri,
        )

    return generator.generate()


def create_azure_component_definition(
    checks: list[ComplianceCheck],
    source_uri: str = "#attestful-azure-checks",
) -> ComponentDefinition:
    """
    Create a component definition for Azure infrastructure.

    Args:
        checks: Azure compliance checks
        source_uri: URI to the source catalog/profile

    Returns:
        ComponentDefinition for Azure
    """
    generator = ComponentDefinitionGenerator(
        title="Azure Infrastructure Component",
        organization="Microsoft Azure",
    )

    # Group checks by service
    service_checks: dict[str, list[ComplianceCheck]] = {}

    for check in checks:
        service = "General"
        for rt in check.resource_types:
            if "storage" in rt.lower():
                service = "Storage"
            elif "keyvault" in rt.lower() or "key_vault" in rt.lower():
                service = "Key Vault"
            elif "sql" in rt.lower():
                service = "SQL"
            elif "nsg" in rt.lower() or "network_security" in rt.lower():
                service = "Network"
            elif "vm" in rt.lower() or "virtual_machine" in rt.lower():
                service = "Compute"
            break

        if service not in service_checks:
            service_checks[service] = []
        service_checks[service].append(check)

    for service, svc_checks in service_checks.items():
        generator.add_component_from_checks(
            ComponentConfig(
                title=f"Azure {service}",
                description=f"Azure {service} security controls and configurations",
                type="service",
                purpose=f"Provides {service} infrastructure services",
            ),
            checks=svc_checks,
            source_uri=source_uri,
        )

    return generator.generate()


# =============================================================================
# Component Registry
# =============================================================================


class ComponentRegistry:
    """
    Registry for tracking available components and their control implementations.

    Provides rapid lookup of components by various criteria:
    - Control ID: Find components that implement a specific control
    - Component type: Find all components of a given type (service, software, etc.)
    - Platform: Find components for a specific platform (AWS, Azure, GCP)

    Example:
        registry = ComponentRegistry()

        # Register a component definition
        registry.register(aws_component_def)
        registry.register(azure_component_def)

        # Find components implementing a specific control
        components = registry.find_by_control("AC-2")

        # Find all service components
        services = registry.find_by_type("service")

        # Get all implemented controls
        controls = registry.get_all_implemented_controls()
    """

    def __init__(self) -> None:
        """Initialize the component registry."""
        self._components: dict[str, ComponentDefinition] = {}
        self._control_index: dict[str, list[str]] = {}  # control_id -> component_ids
        self._type_index: dict[str, list[str]] = {}  # component_type -> component_ids
        self._platform_index: dict[str, list[str]] = {}  # platform -> component_ids

    def register(self, component_def: ComponentDefinition) -> None:
        """
        Register a component definition in the registry.

        Args:
            component_def: The component definition to register

        Raises:
            ComponentError: If component with same UUID already registered
        """
        comp_id = str(component_def.uuid)

        if comp_id in self._components:
            logger.warning(f"Component {comp_id} already registered, updating")

        self._components[comp_id] = component_def
        self._index_component(component_def)

        logger.info(
            f"Registered component definition: {component_def.metadata.title} "
            f"({len(component_def.components or [])} components)"
        )

    def _index_component(self, component_def: ComponentDefinition) -> None:
        """Build indexes for rapid lookup."""
        comp_id = str(component_def.uuid)

        if not component_def.components:
            return

        for component in component_def.components:
            # Index by type
            comp_type = component.type.value if hasattr(component.type, "value") else str(component.type)
            if comp_type not in self._type_index:
                self._type_index[comp_type] = []
            if comp_id not in self._type_index[comp_type]:
                self._type_index[comp_type].append(comp_id)

            # Index by platform (from props)
            if component.props:
                for prop in component.props:
                    if prop.name == "platform":
                        platform = prop.value.lower()
                        if platform not in self._platform_index:
                            self._platform_index[platform] = []
                        if comp_id not in self._platform_index[platform]:
                            self._platform_index[platform].append(comp_id)

            # Index by control implementation
            if component.control_implementations:
                for impl in component.control_implementations:
                    if impl.implemented_requirements:
                        for req in impl.implemented_requirements:
                            control_id = req.control_id
                            if control_id not in self._control_index:
                                self._control_index[control_id] = []
                            if comp_id not in self._control_index[control_id]:
                                self._control_index[control_id].append(comp_id)

    def unregister(self, component_uuid: str | UUID) -> bool:
        """
        Remove a component definition from the registry.

        Args:
            component_uuid: UUID of the component to remove

        Returns:
            True if component was removed, False if not found
        """
        comp_id = str(component_uuid)

        if comp_id not in self._components:
            return False

        # Remove from indexes
        for control_comps in self._control_index.values():
            if comp_id in control_comps:
                control_comps.remove(comp_id)

        for type_comps in self._type_index.values():
            if comp_id in type_comps:
                type_comps.remove(comp_id)

        for platform_comps in self._platform_index.values():
            if comp_id in platform_comps:
                platform_comps.remove(comp_id)

        del self._components[comp_id]
        return True

    def find_by_control(self, control_id: str) -> list[ComponentDefinition]:
        """
        Find all component definitions that implement a specific control.

        Args:
            control_id: The control ID to search for (e.g., "AC-2")

        Returns:
            List of component definitions implementing the control
        """
        comp_ids = self._control_index.get(control_id, [])
        return [self._components[cid] for cid in comp_ids if cid in self._components]

    def find_by_type(self, component_type: str) -> list[ComponentDefinition]:
        """
        Find all component definitions containing components of a given type.

        Args:
            component_type: The component type (e.g., "service", "software")

        Returns:
            List of matching component definitions
        """
        comp_ids = self._type_index.get(component_type.lower(), [])
        return [self._components[cid] for cid in comp_ids if cid in self._components]

    def find_by_platform(self, platform: str) -> list[ComponentDefinition]:
        """
        Find all component definitions for a specific platform.

        Args:
            platform: The platform (e.g., "aws", "azure", "gcp")

        Returns:
            List of matching component definitions
        """
        comp_ids = self._platform_index.get(platform.lower(), [])
        return [self._components[cid] for cid in comp_ids if cid in self._components]

    def get(self, component_uuid: str | UUID) -> ComponentDefinition | None:
        """
        Get a component definition by its UUID.

        Args:
            component_uuid: The UUID of the component definition

        Returns:
            The component definition or None if not found
        """
        return self._components.get(str(component_uuid))

    def get_all(self) -> list[ComponentDefinition]:
        """
        Get all registered component definitions.

        Returns:
            List of all component definitions
        """
        return list(self._components.values())

    def get_all_implemented_controls(self) -> set[str]:
        """
        Get all control IDs that have implementations in the registry.

        Returns:
            Set of control IDs
        """
        return set(self._control_index.keys())

    def get_implementation_coverage(self, control_ids: list[str]) -> dict[str, Any]:
        """
        Get coverage statistics for a list of controls.

        Args:
            control_ids: List of control IDs to check

        Returns:
            Dictionary with coverage statistics
        """
        implemented = set()
        not_implemented = set()

        for control_id in control_ids:
            if control_id in self._control_index and self._control_index[control_id]:
                implemented.add(control_id)
            else:
                not_implemented.add(control_id)

        total = len(control_ids)
        coverage_percent = (len(implemented) / total * 100) if total > 0 else 0

        return {
            "total_controls": total,
            "implemented_count": len(implemented),
            "not_implemented_count": len(not_implemented),
            "coverage_percent": round(coverage_percent, 1),
            "implemented": sorted(implemented),
            "not_implemented": sorted(not_implemented),
        }

    def clear(self) -> None:
        """Clear all registered components and indexes."""
        self._components.clear()
        self._control_index.clear()
        self._type_index.clear()
        self._platform_index.clear()

    def __len__(self) -> int:
        """Return number of registered component definitions."""
        return len(self._components)

    def __contains__(self, component_uuid: str | UUID) -> bool:
        """Check if a component is registered."""
        return str(component_uuid) in self._components
