"""
OSCAL System Security Plan (SSP) generator.

Provides functionality for generating OSCAL SSP documents from system
configuration, check results, and evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from attestful.core.exceptions import OSCALError
from attestful.core.logging import get_logger
from attestful.core.models import CheckResult, CheckStatus
from attestful.oscal.catalog import CatalogLoader
from attestful.oscal.models import (
    AuthorizationBoundary,
    BackMatter,
    ByComponent,
    ImportProfile,
    InformationType,
    Metadata,
    Party,
    Property,
    ResponsibleParty,
    Role,
    SSPControlImplementation,
    SSPImplementedRequirement,
    SystemCharacteristics,
    SystemComponent,
    SystemId,
    SystemImplementation,
    SystemInformation,
    SystemSecurityPlan,
    SystemStatus,
    SystemUser,
)

logger = get_logger("oscal.ssp")


@dataclass
class SystemConfig:
    """Configuration for the system being documented."""

    # Required fields
    system_name: str
    system_id: str
    description: str

    # Optional fields
    system_name_short: str | None = None
    system_status: str = "operational"  # operational, under-development, etc.
    security_sensitivity_level: str | None = None  # low, moderate, high
    authorization_boundary_description: str = "System authorization boundary"

    # Organization info
    organization_name: str = "Organization"
    organization_uuid: UUID = field(default_factory=uuid4)

    # Information types
    information_types: list[dict[str, Any]] = field(default_factory=list)

    # Version
    version: str = "1.0.0"


@dataclass
class ComponentConfig:
    """Configuration for a system component."""

    title: str
    description: str
    type: str = "software"  # software, hardware, service, etc.
    uuid: UUID = field(default_factory=uuid4)
    status: str = "operational"
    purpose: str | None = None


@dataclass
class UserConfig:
    """Configuration for a system user type."""

    title: str
    description: str | None = None
    role_ids: list[str] = field(default_factory=list)
    uuid: UUID = field(default_factory=uuid4)


class SSPGenerator:
    """
    Generate OSCAL System Security Plan documents.

    Combines system configuration, compliance check results, and control
    implementations into a valid OSCAL SSP.
    """

    def __init__(
        self,
        system_config: SystemConfig,
        profile_href: str = "#profile",
    ) -> None:
        """
        Initialize the SSP generator.

        Args:
            system_config: Configuration for the system
            profile_href: Reference to the profile (catalog baseline)
        """
        self.system_config = system_config
        self.profile_href = profile_href
        self.components: list[ComponentConfig] = []
        self.users: list[UserConfig] = []
        self.check_results: list[CheckResult] = []
        self.control_implementations: dict[str, list[ImplementationDetail]] = {}
        self._catalog_loader = CatalogLoader()

    def add_component(self, component: ComponentConfig) -> None:
        """Add a component to the system."""
        self.components.append(component)
        logger.debug(f"Added component: {component.title}")

    def add_user(self, user: UserConfig) -> None:
        """Add a user type to the system."""
        self.users.append(user)
        logger.debug(f"Added user: {user.title}")

    def add_check_results(self, results: list[CheckResult]) -> None:
        """Add compliance check results to inform control implementation status."""
        self.check_results.extend(results)
        logger.debug(f"Added {len(results)} check results")

    def add_control_implementation(
        self,
        control_id: str,
        component_uuid: UUID,
        description: str,
        status: str = "implemented",
    ) -> None:
        """
        Add a control implementation description.

        Args:
            control_id: The control ID (e.g., "AC-2")
            component_uuid: UUID of the component implementing this control
            description: Description of how the control is implemented
            status: Implementation status (implemented, partial, planned, etc.)
        """
        if control_id not in self.control_implementations:
            self.control_implementations[control_id] = []

        self.control_implementations[control_id].append(
            ImplementationDetail(
                component_uuid=component_uuid,
                description=description,
                status=status,
            )
        )

    def generate(self) -> SystemSecurityPlan:
        """
        Generate the OSCAL System Security Plan.

        Returns:
            Complete SystemSecurityPlan document
        """
        logger.info(f"Generating SSP for system: {self.system_config.system_name}")

        # Build metadata
        metadata = self._build_metadata()

        # Build import-profile
        import_profile = ImportProfile(href=self.profile_href)

        # Build system characteristics
        system_characteristics = self._build_system_characteristics()

        # Build system implementation
        system_implementation = self._build_system_implementation()

        # Build control implementation
        control_implementation = self._build_control_implementation()

        # Create the SSP
        ssp = SystemSecurityPlan(
            metadata=metadata,
            import_profile=import_profile,
            system_characteristics=system_characteristics,
            system_implementation=system_implementation,
            control_implementation=control_implementation,
        )

        logger.info(
            f"Generated SSP with {len(self.components)} components, "
            f"{len(self.control_implementations)} control implementations"
        )

        return ssp

    def _build_metadata(self) -> Metadata:
        """Build the SSP metadata section."""
        now = datetime.now(timezone.utc)

        # Build roles
        roles = [
            Role(
                id="system-owner",
                title="System Owner",
                description="Individual responsible for the system",
            ),
            Role(
                id="authorizing-official",
                title="Authorizing Official",
                description="Official with authority to authorize the system",
            ),
            Role(
                id="information-system-security-officer",
                title="Information System Security Officer",
                description="Individual responsible for system security",
            ),
        ]

        # Build parties
        parties = [
            Party(
                uuid=self.system_config.organization_uuid,
                type="organization",
                name=self.system_config.organization_name,
            ),
        ]

        return Metadata(
            title=f"System Security Plan for {self.system_config.system_name}",
            last_modified=now,
            version=self.system_config.version,
            oscal_version="1.1.2",
            roles=roles,
            parties=parties,
            props=[
                Property(name="marking", value="Confidential"),
            ],
        )

    def _build_system_characteristics(self) -> SystemCharacteristics:
        """Build the system characteristics section."""
        # Build system IDs
        system_ids = [
            SystemId(
                id=self.system_config.system_id,
                identifier_type="https://attestful.dev/system-id",
            ),
        ]

        # Build information types
        info_types: list[InformationType] = []
        for info in self.system_config.information_types:
            info_types.append(
                InformationType(
                    title=info.get("title", "General Information"),
                    description=info.get("description", "System information"),
                )
            )

        # Default information type if none specified
        if not info_types:
            info_types.append(
                InformationType(
                    title="System Data",
                    description="Data processed by the system",
                )
            )

        system_information = SystemInformation(information_types=info_types)

        # Build authorization boundary
        auth_boundary = AuthorizationBoundary(
            description=self.system_config.authorization_boundary_description,
        )

        # Build system status
        status = SystemStatus(state=self.system_config.system_status)

        return SystemCharacteristics(
            system_ids=system_ids,
            system_name=self.system_config.system_name,
            system_name_short=self.system_config.system_name_short,
            description=self.system_config.description,
            security_sensitivity_level=self.system_config.security_sensitivity_level,
            system_information=system_information,
            status=status,
            authorization_boundary=auth_boundary,
        )

    def _build_system_implementation(self) -> SystemImplementation:
        """Build the system implementation section."""
        # Build users
        users = []
        for user_config in self.users:
            users.append(
                SystemUser(
                    uuid=user_config.uuid,
                    title=user_config.title,
                    description=user_config.description,
                    role_ids=user_config.role_ids if user_config.role_ids else None,
                )
            )

        # Default user if none specified
        if not users:
            users.append(
                SystemUser(
                    title="System Administrator",
                    description="Administrative user with full access",
                    role_ids=["system-owner"],
                )
            )

        # Build components
        components = []
        for comp_config in self.components:
            components.append(
                SystemComponent(
                    uuid=comp_config.uuid,
                    type=comp_config.type,
                    title=comp_config.title,
                    description=comp_config.description,
                    purpose=comp_config.purpose,
                    status={"state": comp_config.status},
                )
            )

        # Default component if none specified
        if not components:
            components.append(
                SystemComponent(
                    type="software",
                    title="Application",
                    description="Primary application component",
                    status={"state": "operational"},
                )
            )

        return SystemImplementation(
            users=users,
            components=components,
        )

    def _build_control_implementation(self) -> SSPControlImplementation:
        """Build the control implementation section."""
        implemented_requirements: list[SSPImplementedRequirement] = []

        # Get control IDs from check results if we have them
        control_ids_from_checks = set()
        check_results_by_control: dict[str, list[CheckResult]] = {}

        for result in self.check_results:
            # Extract control IDs from check if available
            if result.check and result.check.framework_mappings:
                for framework, controls in result.check.framework_mappings.items():
                    for control_id in controls:
                        control_ids_from_checks.add(control_id)
                        if control_id not in check_results_by_control:
                            check_results_by_control[control_id] = []
                        check_results_by_control[control_id].append(result)

        # Build implemented requirements from explicit implementations
        for control_id, implementations in self.control_implementations.items():
            by_components = []
            for impl in implementations:
                by_components.append(
                    ByComponent(
                        component_uuid=impl.component_uuid,
                        description=impl.description,
                        implementation_status={"state": impl.status},
                    )
                )

            implemented_requirements.append(
                SSPImplementedRequirement(
                    control_id=control_id,
                    by_components=by_components,
                )
            )

        # Add controls from check results that don't have explicit implementations
        for control_id in control_ids_from_checks:
            if control_id not in self.control_implementations:
                # Determine implementation status from check results
                results = check_results_by_control.get(control_id, [])
                status = self._determine_status_from_checks(results)

                # Use the first component or create a generic one
                component_uuid = (
                    self.components[0].uuid if self.components else uuid4()
                )

                by_components = [
                    ByComponent(
                        component_uuid=component_uuid,
                        description=f"Control implementation verified by automated checks. "
                        f"Status determined from {len(results)} check(s).",
                        implementation_status={"state": status},
                    )
                ]

                implemented_requirements.append(
                    SSPImplementedRequirement(
                        control_id=control_id,
                        by_components=by_components,
                    )
                )

        # Sort by control ID for consistent output
        implemented_requirements.sort(key=lambda x: x.control_id)

        return SSPControlImplementation(
            description="Control implementation for the system",
            implemented_requirements=implemented_requirements,
        )

    def _determine_status_from_checks(self, results: list[CheckResult]) -> str:
        """Determine implementation status from check results."""
        if not results:
            return "not-applicable"

        passed = sum(1 for r in results if r.status == CheckStatus.PASS)
        failed = sum(1 for r in results if r.status == CheckStatus.FAIL)
        total = len(results)

        if passed == total:
            return "implemented"
        elif failed == total:
            return "not-implemented"
        elif passed > 0:
            return "partial"
        else:
            return "planned"

    def save(self, path: str | Path, format: str = "json") -> Path:
        """
        Generate and save the SSP to a file.

        Args:
            path: Output file path
            format: Output format ("json" or "yaml")

        Returns:
            Path to the saved file
        """
        path = Path(path)
        ssp = self.generate()

        # Wrap in standard OSCAL format
        if format == "json":
            content = '{"system-security-plan": ' + ssp.to_json() + "}"
            if not path.suffix:
                path = path.with_suffix(".json")
        elif format == "yaml":
            import yaml

            # Use mode="json" to convert UUIDs and datetimes to strings
            data = {"system-security-plan": ssp.model_dump(by_alias=True, exclude_none=True, mode="json")}
            content = yaml.dump(data, default_flow_style=False, sort_keys=False)
            if not path.suffix:
                path = path.with_suffix(".yaml")
        else:
            raise OSCALError(f"Unsupported format: {format}")

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

        logger.info(f"Saved SSP to {path}")
        return path


@dataclass
class ImplementationDetail:
    """Details of a control implementation by a component."""

    component_uuid: UUID
    description: str
    status: str = "implemented"


class SSPLoader:
    """Load and parse existing OSCAL SSP documents."""

    def __init__(self) -> None:
        self._cache: dict[str, SystemSecurityPlan] = {}

    def load(self, path: str | Path, *, use_cache: bool = True) -> SystemSecurityPlan:
        """
        Load an SSP from a file.

        Args:
            path: Path to the SSP file
            use_cache: Whether to use cached SSP if available

        Returns:
            Parsed SystemSecurityPlan

        Raises:
            OscalError: If the file cannot be loaded
        """
        import orjson
        import yaml as pyyaml

        path = Path(path)
        cache_key = str(path.resolve())

        if use_cache and cache_key in self._cache:
            return self._cache[cache_key]

        if not path.exists():
            raise OSCALError(f"SSP file not found: {path}")

        try:
            content = path.read_text(encoding="utf-8")
            suffix = path.suffix.lower()

            if suffix == ".json":
                data = orjson.loads(content)
            elif suffix in (".yaml", ".yml"):
                data = pyyaml.safe_load(content)
            else:
                # Try JSON first
                try:
                    data = orjson.loads(content)
                except orjson.JSONDecodeError:
                    data = pyyaml.safe_load(content)

            # Handle wrapped format
            if "system-security-plan" in data:
                data = data["system-security-plan"]

            ssp = SystemSecurityPlan.model_validate(data)

            if use_cache:
                self._cache[cache_key] = ssp

            logger.info(f"Loaded SSP: {ssp.metadata.title}")
            return ssp

        except Exception as e:
            raise OSCALError(f"Failed to load SSP: {e}") from e

    def clear_cache(self) -> None:
        """Clear the SSP cache."""
        self._cache.clear()


def create_ssp_from_scan_results(
    system_name: str,
    system_id: str,
    description: str,
    check_results: list[CheckResult],
    profile_href: str = "#profile",
    **kwargs: Any,
) -> SystemSecurityPlan:
    """
    Convenience function to create an SSP from scan results.

    Args:
        system_name: Name of the system
        system_id: Unique identifier for the system
        description: System description
        check_results: Results from compliance scans
        profile_href: Reference to the baseline profile
        **kwargs: Additional SystemConfig parameters

    Returns:
        Generated SystemSecurityPlan
    """
    config = SystemConfig(
        system_name=system_name,
        system_id=system_id,
        description=description,
        **kwargs,
    )

    generator = SSPGenerator(config, profile_href=profile_href)
    generator.add_check_results(check_results)

    return generator.generate()


# =============================================================================
# SSP Diff
# =============================================================================


@dataclass
class SSPDifference:
    """
    Represents a difference between two SSPs.

    Attributes:
        category: Category of the difference (control, component, parameter, etc.)
        change_type: Type of change (added, removed, modified)
        path: Path to the changed element
        old_value: Previous value (None if added)
        new_value: New value (None if removed)
        description: Human-readable description of the change
    """

    category: str
    change_type: str  # added, removed, modified
    path: str
    old_value: Any
    new_value: Any
    description: str


@dataclass
class SSPDiffResult:
    """
    Result of comparing two SSPs.

    Attributes:
        ssp1_uuid: UUID of the first SSP
        ssp2_uuid: UUID of the second SSP
        differences: List of differences found
        summary: Summary statistics
    """

    ssp1_uuid: str
    ssp2_uuid: str
    differences: list[SSPDifference]
    summary: dict[str, int]

    def has_differences(self) -> bool:
        """Check if there are any differences."""
        return len(self.differences) > 0

    def get_by_category(self, category: str) -> list[SSPDifference]:
        """Get differences by category."""
        return [d for d in self.differences if d.category == category]

    def get_by_change_type(self, change_type: str) -> list[SSPDifference]:
        """Get differences by change type."""
        return [d for d in self.differences if d.change_type == change_type]


class SSPDiff:
    """
    Compare two OSCAL System Security Plans and identify differences.

    Identifies differences in:
    - Control implementations
    - Component configurations
    - Responsibility assignments
    - Parameter values
    - System characteristics

    Example:
        diff = SSPDiff()
        result = diff.compare(ssp1, ssp2)

        if result.has_differences():
            for difference in result.differences:
                print(f"{difference.change_type}: {difference.description}")

            # Get only control changes
            control_changes = result.get_by_category("control")
    """

    def compare(
        self,
        ssp1: SystemSecurityPlan,
        ssp2: SystemSecurityPlan,
    ) -> SSPDiffResult:
        """
        Compare two SSPs and identify all differences.

        Args:
            ssp1: First SSP (baseline/original)
            ssp2: Second SSP (comparison/updated)

        Returns:
            SSPDiffResult containing all differences
        """
        differences: list[SSPDifference] = []

        # Compare system characteristics
        differences.extend(self._compare_system_characteristics(ssp1, ssp2))

        # Compare components
        differences.extend(self._compare_components(ssp1, ssp2))

        # Compare control implementations
        differences.extend(self._compare_control_implementations(ssp1, ssp2))

        # Compare users
        differences.extend(self._compare_users(ssp1, ssp2))

        # Compare metadata
        differences.extend(self._compare_metadata(ssp1, ssp2))

        # Build summary
        summary = {
            "total": len(differences),
            "added": len([d for d in differences if d.change_type == "added"]),
            "removed": len([d for d in differences if d.change_type == "removed"]),
            "modified": len([d for d in differences if d.change_type == "modified"]),
            "controls": len([d for d in differences if d.category == "control"]),
            "components": len([d for d in differences if d.category == "component"]),
            "parameters": len([d for d in differences if d.category == "parameter"]),
            "responsibilities": len([d for d in differences if d.category == "responsibility"]),
        }

        return SSPDiffResult(
            ssp1_uuid=str(ssp1.uuid),
            ssp2_uuid=str(ssp2.uuid),
            differences=differences,
            summary=summary,
        )

    def _compare_system_characteristics(
        self,
        ssp1: SystemSecurityPlan,
        ssp2: SystemSecurityPlan,
    ) -> list[SSPDifference]:
        """Compare system characteristics between two SSPs."""
        differences: list[SSPDifference] = []

        char1 = ssp1.system_characteristics
        char2 = ssp2.system_characteristics

        if not char1 or not char2:
            return differences

        # Compare system name
        name1 = char1.system_name or ""
        name2 = char2.system_name or ""
        if name1 != name2:
            differences.append(SSPDifference(
                category="system",
                change_type="modified",
                path="system-characteristics.system-name",
                old_value=name1,
                new_value=name2,
                description=f"System name changed from '{name1}' to '{name2}'",
            ))

        # Compare description
        desc1 = char1.description or ""
        desc2 = char2.description or ""
        if desc1 != desc2:
            differences.append(SSPDifference(
                category="system",
                change_type="modified",
                path="system-characteristics.description",
                old_value=desc1[:100] + "..." if len(desc1) > 100 else desc1,
                new_value=desc2[:100] + "..." if len(desc2) > 100 else desc2,
                description="System description changed",
            ))

        # Compare status
        status1 = char1.status.state if char1.status else None
        status2 = char2.status.state if char2.status else None
        if status1 != status2:
            differences.append(SSPDifference(
                category="system",
                change_type="modified",
                path="system-characteristics.status",
                old_value=status1,
                new_value=status2,
                description=f"System status changed from '{status1}' to '{status2}'",
            ))

        return differences

    def _compare_components(
        self,
        ssp1: SystemSecurityPlan,
        ssp2: SystemSecurityPlan,
    ) -> list[SSPDifference]:
        """Compare system components between two SSPs."""
        differences: list[SSPDifference] = []

        impl1 = ssp1.system_implementation
        impl2 = ssp2.system_implementation

        comps1 = {str(c.uuid): c for c in (impl1.components or [])} if impl1 else {}
        comps2 = {str(c.uuid): c for c in (impl2.components or [])} if impl2 else {}

        # Find added components
        for uuid, comp in comps2.items():
            if uuid not in comps1:
                differences.append(SSPDifference(
                    category="component",
                    change_type="added",
                    path=f"system-implementation.components.{uuid}",
                    old_value=None,
                    new_value=comp.title,
                    description=f"Component '{comp.title}' added",
                ))

        # Find removed components
        for uuid, comp in comps1.items():
            if uuid not in comps2:
                differences.append(SSPDifference(
                    category="component",
                    change_type="removed",
                    path=f"system-implementation.components.{uuid}",
                    old_value=comp.title,
                    new_value=None,
                    description=f"Component '{comp.title}' removed",
                ))

        # Find modified components
        for uuid in comps1:
            if uuid in comps2:
                comp1 = comps1[uuid]
                comp2 = comps2[uuid]

                if comp1.title != comp2.title:
                    differences.append(SSPDifference(
                        category="component",
                        change_type="modified",
                        path=f"system-implementation.components.{uuid}.title",
                        old_value=comp1.title,
                        new_value=comp2.title,
                        description=f"Component title changed from '{comp1.title}' to '{comp2.title}'",
                    ))

                status1 = comp1.status.state if comp1.status else None
                status2 = comp2.status.state if comp2.status else None
                if status1 != status2:
                    differences.append(SSPDifference(
                        category="component",
                        change_type="modified",
                        path=f"system-implementation.components.{uuid}.status",
                        old_value=status1,
                        new_value=status2,
                        description=f"Component '{comp1.title}' status changed from '{status1}' to '{status2}'",
                    ))

        return differences

    def _compare_control_implementations(
        self,
        ssp1: SystemSecurityPlan,
        ssp2: SystemSecurityPlan,
    ) -> list[SSPDifference]:
        """Compare control implementations between two SSPs."""
        differences: list[SSPDifference] = []

        impl1 = ssp1.control_implementation
        impl2 = ssp2.control_implementation

        if not impl1 and not impl2:
            return differences

        reqs1 = {r.control_id: r for r in (impl1.implemented_requirements or [])} if impl1 else {}
        reqs2 = {r.control_id: r for r in (impl2.implemented_requirements or [])} if impl2 else {}

        # Find added controls
        for control_id in reqs2:
            if control_id not in reqs1:
                differences.append(SSPDifference(
                    category="control",
                    change_type="added",
                    path=f"control-implementation.implemented-requirements.{control_id}",
                    old_value=None,
                    new_value=control_id,
                    description=f"Control implementation '{control_id}' added",
                ))

        # Find removed controls
        for control_id in reqs1:
            if control_id not in reqs2:
                differences.append(SSPDifference(
                    category="control",
                    change_type="removed",
                    path=f"control-implementation.implemented-requirements.{control_id}",
                    old_value=control_id,
                    new_value=None,
                    description=f"Control implementation '{control_id}' removed",
                ))

        # Find modified controls
        for control_id in reqs1:
            if control_id in reqs2:
                req1 = reqs1[control_id]
                req2 = reqs2[control_id]

                # Compare parameters
                params1 = {p.param_id: p.values for p in (req1.set_parameters or [])}
                params2 = {p.param_id: p.values for p in (req2.set_parameters or [])}

                for param_id in set(params1.keys()) | set(params2.keys()):
                    val1 = params1.get(param_id)
                    val2 = params2.get(param_id)
                    if val1 != val2:
                        differences.append(SSPDifference(
                            category="parameter",
                            change_type="added" if val1 is None else ("removed" if val2 is None else "modified"),
                            path=f"control-implementation.implemented-requirements.{control_id}.set-parameters.{param_id}",
                            old_value=val1,
                            new_value=val2,
                            description=f"Parameter '{param_id}' for control '{control_id}' changed",
                        ))

                # Compare responsible roles
                roles1 = set(req1.responsible_roles or []) if hasattr(req1, 'responsible_roles') and req1.responsible_roles else set()
                roles2 = set(req2.responsible_roles or []) if hasattr(req2, 'responsible_roles') and req2.responsible_roles else set()

                for role in roles2 - roles1:
                    differences.append(SSPDifference(
                        category="responsibility",
                        change_type="added",
                        path=f"control-implementation.implemented-requirements.{control_id}.responsible-roles",
                        old_value=None,
                        new_value=role,
                        description=f"Role '{role}' added to control '{control_id}'",
                    ))

                for role in roles1 - roles2:
                    differences.append(SSPDifference(
                        category="responsibility",
                        change_type="removed",
                        path=f"control-implementation.implemented-requirements.{control_id}.responsible-roles",
                        old_value=role,
                        new_value=None,
                        description=f"Role '{role}' removed from control '{control_id}'",
                    ))

        return differences

    def _compare_users(
        self,
        ssp1: SystemSecurityPlan,
        ssp2: SystemSecurityPlan,
    ) -> list[SSPDifference]:
        """Compare system users between two SSPs."""
        differences: list[SSPDifference] = []

        impl1 = ssp1.system_implementation
        impl2 = ssp2.system_implementation

        users1 = {str(u.uuid): u for u in (impl1.users or [])} if impl1 else {}
        users2 = {str(u.uuid): u for u in (impl2.users or [])} if impl2 else {}

        # Find added users
        for uuid, user in users2.items():
            if uuid not in users1:
                differences.append(SSPDifference(
                    category="user",
                    change_type="added",
                    path=f"system-implementation.users.{uuid}",
                    old_value=None,
                    new_value=user.title,
                    description=f"User type '{user.title}' added",
                ))

        # Find removed users
        for uuid, user in users1.items():
            if uuid not in users2:
                differences.append(SSPDifference(
                    category="user",
                    change_type="removed",
                    path=f"system-implementation.users.{uuid}",
                    old_value=user.title,
                    new_value=None,
                    description=f"User type '{user.title}' removed",
                ))

        return differences

    def _compare_metadata(
        self,
        ssp1: SystemSecurityPlan,
        ssp2: SystemSecurityPlan,
    ) -> list[SSPDifference]:
        """Compare metadata between two SSPs."""
        differences: list[SSPDifference] = []

        meta1 = ssp1.metadata
        meta2 = ssp2.metadata

        # Compare version
        ver1 = meta1.version or ""
        ver2 = meta2.version or ""
        if ver1 != ver2:
            differences.append(SSPDifference(
                category="metadata",
                change_type="modified",
                path="metadata.version",
                old_value=ver1,
                new_value=ver2,
                description=f"SSP version changed from '{ver1}' to '{ver2}'",
            ))

        # Compare title
        title1 = meta1.title or ""
        title2 = meta2.title or ""
        if title1 != title2:
            differences.append(SSPDifference(
                category="metadata",
                change_type="modified",
                path="metadata.title",
                old_value=title1,
                new_value=title2,
                description=f"SSP title changed from '{title1}' to '{title2}'",
            ))

        return differences


# =============================================================================
# SSP Validation
# =============================================================================


@dataclass
class SSPValidationIssue:
    """
    Represents a validation issue found in an SSP.

    Attributes:
        severity: Severity level (error, warning, info)
        category: Category of the issue
        path: Path to the problematic element
        message: Human-readable description
        control_id: Related control ID (if applicable)
    """

    severity: str  # error, warning, info
    category: str
    path: str
    message: str
    control_id: str | None = None


@dataclass
class SSPValidationResult:
    """
    Result of validating an SSP.

    Attributes:
        is_valid: Whether the SSP passed validation (no errors)
        issues: List of validation issues found
        summary: Summary statistics
    """

    is_valid: bool
    issues: list[SSPValidationIssue]
    summary: dict[str, int]

    def get_errors(self) -> list[SSPValidationIssue]:
        """Get only error-level issues."""
        return [i for i in self.issues if i.severity == "error"]

    def get_warnings(self) -> list[SSPValidationIssue]:
        """Get only warning-level issues."""
        return [i for i in self.issues if i.severity == "warning"]

    def get_by_category(self, category: str) -> list[SSPValidationIssue]:
        """Get issues by category."""
        return [i for i in self.issues if i.category == category]


class SSPValidator:
    """
    Validate an OSCAL SSP against a profile.

    Validates:
    - All required controls are implemented
    - No implementations for excluded controls
    - Parameter values satisfy constraints
    - Responsibility assignments are complete

    Example:
        validator = SSPValidator()
        result = validator.validate(ssp, profile_controls=["AC-1", "AC-2", "AC-3"])

        if not result.is_valid:
            for error in result.get_errors():
                print(f"ERROR: {error.message}")
    """

    def validate(
        self,
        ssp: SystemSecurityPlan,
        *,
        profile_controls: list[str] | None = None,
        excluded_controls: list[str] | None = None,
        required_roles: list[str] | None = None,
    ) -> SSPValidationResult:
        """
        Validate an SSP against requirements.

        Args:
            ssp: The SSP to validate
            profile_controls: List of control IDs required by the profile
            excluded_controls: List of control IDs that should not be implemented
            required_roles: List of roles that must be assigned

        Returns:
            SSPValidationResult with all issues found
        """
        issues: list[SSPValidationIssue] = []

        # Validate structure
        issues.extend(self._validate_structure(ssp))

        # Validate control implementations
        if profile_controls:
            issues.extend(self._validate_required_controls(ssp, profile_controls))

        if excluded_controls:
            issues.extend(self._validate_excluded_controls(ssp, excluded_controls))

        # Validate responsibilities
        if required_roles:
            issues.extend(self._validate_responsibilities(ssp, required_roles))

        # Validate parameters
        issues.extend(self._validate_parameters(ssp))

        # Build summary
        summary = {
            "total_issues": len(issues),
            "errors": len([i for i in issues if i.severity == "error"]),
            "warnings": len([i for i in issues if i.severity == "warning"]),
            "info": len([i for i in issues if i.severity == "info"]),
        }

        return SSPValidationResult(
            is_valid=summary["errors"] == 0,
            issues=issues,
            summary=summary,
        )

    def _validate_structure(self, ssp: SystemSecurityPlan) -> list[SSPValidationIssue]:
        """Validate SSP structural requirements."""
        issues: list[SSPValidationIssue] = []

        # Check metadata
        if not ssp.metadata:
            issues.append(SSPValidationIssue(
                severity="error",
                category="structure",
                path="metadata",
                message="SSP must have metadata",
            ))
        elif not ssp.metadata.title:
            issues.append(SSPValidationIssue(
                severity="error",
                category="structure",
                path="metadata.title",
                message="SSP metadata must have a title",
            ))

        # Check system characteristics
        if not ssp.system_characteristics:
            issues.append(SSPValidationIssue(
                severity="error",
                category="structure",
                path="system-characteristics",
                message="SSP must have system characteristics",
            ))
        else:
            if not ssp.system_characteristics.system_name:
                issues.append(SSPValidationIssue(
                    severity="error",
                    category="structure",
                    path="system-characteristics.system-name",
                    message="System characteristics must have a system name",
                ))
            if not ssp.system_characteristics.system_ids:
                issues.append(SSPValidationIssue(
                    severity="warning",
                    category="structure",
                    path="system-characteristics.system-ids",
                    message="System characteristics should have at least one system ID",
                ))

        # Check system implementation
        if not ssp.system_implementation:
            issues.append(SSPValidationIssue(
                severity="error",
                category="structure",
                path="system-implementation",
                message="SSP must have system implementation",
            ))

        # Check control implementation
        if not ssp.control_implementation:
            issues.append(SSPValidationIssue(
                severity="error",
                category="structure",
                path="control-implementation",
                message="SSP must have control implementation",
            ))

        # Check import-profile
        if not ssp.import_profile:
            issues.append(SSPValidationIssue(
                severity="error",
                category="structure",
                path="import-profile",
                message="SSP must import a profile",
            ))

        return issues

    def _validate_required_controls(
        self,
        ssp: SystemSecurityPlan,
        required_controls: list[str],
    ) -> list[SSPValidationIssue]:
        """Validate that all required controls are implemented."""
        issues: list[SSPValidationIssue] = []

        if not ssp.control_implementation:
            return issues

        implemented = {
            r.control_id
            for r in (ssp.control_implementation.implemented_requirements or [])
        }

        for control_id in required_controls:
            if control_id not in implemented:
                issues.append(SSPValidationIssue(
                    severity="error",
                    category="control",
                    path="control-implementation.implemented-requirements",
                    message=f"Required control '{control_id}' is not implemented",
                    control_id=control_id,
                ))

        return issues

    def _validate_excluded_controls(
        self,
        ssp: SystemSecurityPlan,
        excluded_controls: list[str],
    ) -> list[SSPValidationIssue]:
        """Validate that excluded controls are not implemented."""
        issues: list[SSPValidationIssue] = []

        if not ssp.control_implementation:
            return issues

        implemented = {
            r.control_id
            for r in (ssp.control_implementation.implemented_requirements or [])
        }

        for control_id in excluded_controls:
            if control_id in implemented:
                issues.append(SSPValidationIssue(
                    severity="error",
                    category="control",
                    path=f"control-implementation.implemented-requirements.{control_id}",
                    message=f"Control '{control_id}' is excluded but has implementation",
                    control_id=control_id,
                ))

        return issues

    def _validate_responsibilities(
        self,
        ssp: SystemSecurityPlan,
        required_roles: list[str],
    ) -> list[SSPValidationIssue]:
        """Validate responsibility assignments."""
        issues: list[SSPValidationIssue] = []

        if not ssp.control_implementation:
            return issues

        for req in (ssp.control_implementation.implemented_requirements or []):
            # Check if control has any responsibility assignment
            has_responsibility = False

            if hasattr(req, 'responsible_roles') and req.responsible_roles:
                has_responsibility = True

            if req.by_components:
                for by_comp in req.by_components:
                    if hasattr(by_comp, 'responsible_roles') and by_comp.responsible_roles:
                        has_responsibility = True
                        break

            if not has_responsibility:
                issues.append(SSPValidationIssue(
                    severity="warning",
                    category="responsibility",
                    path=f"control-implementation.implemented-requirements.{req.control_id}",
                    message=f"Control '{req.control_id}' has no responsibility assignment",
                    control_id=req.control_id,
                ))

        return issues

    def _validate_parameters(self, ssp: SystemSecurityPlan) -> list[SSPValidationIssue]:
        """Validate parameter values."""
        issues: list[SSPValidationIssue] = []

        if not ssp.control_implementation:
            return issues

        for req in (ssp.control_implementation.implemented_requirements or []):
            if req.set_parameters:
                for param in req.set_parameters:
                    # Check for empty parameter values
                    if not param.values:
                        issues.append(SSPValidationIssue(
                            severity="warning",
                            category="parameter",
                            path=f"control-implementation.implemented-requirements.{req.control_id}.set-parameters.{param.param_id}",
                            message=f"Parameter '{param.param_id}' for control '{req.control_id}' has no values",
                            control_id=req.control_id,
                        ))

        return issues
