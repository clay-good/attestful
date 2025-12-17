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
