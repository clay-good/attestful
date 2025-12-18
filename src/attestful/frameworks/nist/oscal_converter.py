"""
NIST CSF 2.0 to OSCAL Catalog Converter.

Converts the NIST CSF 2.0 control hierarchy from the internal representation
to OSCAL catalog format. This enables interoperability with other OSCAL-based
tools and standardized exchange of compliance data.

The conversion maps:
    - Functions (GV, ID, PR, DE, RS, RC) → OSCAL Groups (top-level)
    - Categories (GV.OC, ID.AM, etc.) → OSCAL Groups (nested)
    - Subcategories (GV.OC-01, PR.AA-03, etc.) → OSCAL Controls
    - Maturity criteria → OSCAL Parts (implementation guidance)
    - Evidence types → OSCAL Properties on controls
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import orjson
import yaml

from attestful.frameworks.nist.csf2_controls import (
    NistCategory,
    NistFunction,
    NistSubcategory,
    get_all_functions,
)
from attestful.oscal.models import (
    Catalog,
    Control,
    Group,
    Link,
    Metadata,
    Part,
    Property,
)


# NIST CSF 2.0 source reference
NIST_CSF2_REFERENCE = "https://www.nist.gov/cyberframework"
NIST_CSF2_VERSION = "2.0"
NIST_CSF2_DATE = "2024-02-26"


class NistCSF2OSCALConverter:
    """
    Converts NIST CSF 2.0 controls to OSCAL catalog format.

    The converter creates a complete OSCAL catalog from the internal
    NIST CSF 2.0 control definitions, preserving all metadata including
    evidence types, maturity criteria, and API collectibility flags.

    Example:
        converter = NistCSF2OSCALConverter()
        catalog = converter.convert()
        converter.save_catalog(catalog, "nist-csf2-catalog.json")
    """

    def __init__(
        self,
        *,
        include_maturity_criteria: bool = True,
        include_evidence_types: bool = True,
        organization_name: str = "Attestful",
    ) -> None:
        """
        Initialize the converter.

        Args:
            include_maturity_criteria: Include maturity level guidance as parts
            include_evidence_types: Include evidence types as properties
            organization_name: Name of the publishing organization
        """
        self.include_maturity_criteria = include_maturity_criteria
        self.include_evidence_types = include_evidence_types
        self.organization_name = organization_name

    def convert(self) -> Catalog:
        """
        Convert the complete NIST CSF 2.0 hierarchy to an OSCAL catalog.

        Returns:
            OSCAL Catalog containing all functions, categories, and subcategories
        """
        functions = get_all_functions()

        # Create metadata
        metadata = Metadata(
            title="NIST Cybersecurity Framework 2.0",
            version=NIST_CSF2_VERSION,
            oscal_version="1.1.2",
            last_modified=datetime.fromisoformat(NIST_CSF2_DATE),
            published=datetime.fromisoformat(NIST_CSF2_DATE),
            props=[
                Property(name="source", value="NIST"),
                Property(name="framework", value="CSF"),
                Property(name="framework-version", value="2.0"),
            ],
            links=[
                Link(href=NIST_CSF2_REFERENCE, rel="reference"),
            ],
        )

        # Convert functions to groups
        groups = [self._convert_function(func) for func in functions]

        return Catalog(
            uuid=uuid4(),
            metadata=metadata,
            groups=groups,
        )

    def _convert_function(self, function: NistFunction) -> Group:
        """Convert a NIST CSF function to an OSCAL group."""
        # Convert categories to nested groups
        category_groups = [
            self._convert_category(cat)
            for cat in function.categories
        ]

        return Group(
            id=function.id,
            class_="function",
            title=function.name,
            props=[
                Property(name="function-id", value=function.id),
                Property(name="function-name", value=function.name),
            ],
            parts=[
                Part(
                    name="overview",
                    prose=function.description,
                ),
            ],
            groups=category_groups if category_groups else None,
        )

    def _convert_category(self, category: NistCategory) -> Group:
        """Convert a NIST CSF category to an OSCAL group with controls."""
        # Convert subcategories to controls
        controls = [
            self._convert_subcategory(subcat)
            for subcat in category.subcategories
        ]

        return Group(
            id=category.id,
            class_="category",
            title=category.name,
            props=[
                Property(name="category-id", value=category.id),
                Property(name="category-name", value=category.name),
                Property(name="function-id", value=category.function_id),
            ],
            parts=[
                Part(
                    name="overview",
                    prose=category.description,
                ),
            ],
            controls=controls if controls else None,
        )

    def _convert_subcategory(self, subcategory: NistSubcategory) -> Control:
        """Convert a NIST CSF subcategory to an OSCAL control."""
        props: list[Property] = [
            Property(name="subcategory-id", value=subcategory.id),
            Property(name="subcategory-name", value=subcategory.name),
            Property(name="category-id", value=subcategory.category_id),
            Property(
                name="api-collectible",
                value="true" if subcategory.api_collectible else "false",
            ),
        ]

        # Add evidence types as properties
        if self.include_evidence_types and subcategory.evidence_types:
            for ev_type in subcategory.evidence_types:
                props.append(
                    Property(
                        name="evidence-type",
                        value=ev_type,
                        class_="attestful",
                    )
                )

        # Build parts
        parts: list[Part] = [
            Part(
                id=f"{subcategory.id}_stmt",
                name="statement",
                prose=subcategory.description,
            ),
        ]

        # Add maturity criteria as implementation guidance
        if self.include_maturity_criteria:
            maturity_parts = self._create_maturity_parts(subcategory)
            if maturity_parts:
                parts.append(
                    Part(
                        id=f"{subcategory.id}_guidance",
                        name="guidance",
                        title="Maturity Level Criteria",
                        parts=maturity_parts,
                    )
                )

        return Control(
            id=subcategory.id,
            class_="subcategory",
            title=subcategory.name,
            props=props,
            parts=parts,
        )

    def _create_maturity_parts(self, subcategory: NistSubcategory) -> list[Part]:
        """Create OSCAL parts for maturity level criteria."""
        criteria = subcategory.maturity_criteria

        return [
            Part(
                id=f"{subcategory.id}_maturity_0",
                name="maturity-level",
                title="Level 0: Not Implemented",
                props=[Property(name="maturity-level", value="0")],
                prose=criteria.level_0,
            ),
            Part(
                id=f"{subcategory.id}_maturity_1",
                name="maturity-level",
                title="Level 1: Partial",
                props=[Property(name="maturity-level", value="1")],
                prose=criteria.level_1,
            ),
            Part(
                id=f"{subcategory.id}_maturity_2",
                name="maturity-level",
                title="Level 2: Risk Informed",
                props=[Property(name="maturity-level", value="2")],
                prose=criteria.level_2,
            ),
            Part(
                id=f"{subcategory.id}_maturity_3",
                name="maturity-level",
                title="Level 3: Repeatable",
                props=[Property(name="maturity-level", value="3")],
                prose=criteria.level_3,
            ),
            Part(
                id=f"{subcategory.id}_maturity_4",
                name="maturity-level",
                title="Level 4: Adaptive",
                props=[Property(name="maturity-level", value="4")],
                prose=criteria.level_4,
            ),
        ]

    def save_catalog(
        self,
        catalog: Catalog,
        path: str | Path,
        *,
        format: str = "json",
        pretty: bool = True,
    ) -> None:
        """
        Save the OSCAL catalog to a file.

        Args:
            catalog: The catalog to save
            path: Output file path
            format: Output format ("json" or "yaml")
            pretty: Whether to format the output for readability
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Serialize to dict with OSCAL standard wrapper
        data = {
            "catalog": catalog.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
        }

        if format == "yaml":
            content = yaml.dump(
                data,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
            )
            path.write_text(content, encoding="utf-8")
        else:
            options = orjson.OPT_NON_STR_KEYS
            if pretty:
                options |= orjson.OPT_INDENT_2
            content = orjson.dumps(data, option=options)
            path.write_bytes(content)

    def get_catalog_statistics(self, catalog: Catalog) -> dict[str, Any]:
        """
        Get statistics about the generated catalog.

        Args:
            catalog: The catalog to analyze

        Returns:
            Dictionary with counts and metadata
        """
        function_count = 0
        category_count = 0
        control_count = 0
        api_collectible = 0

        if catalog.groups:
            function_count = len(catalog.groups)
            for func_group in catalog.groups:
                if func_group.groups:
                    category_count += len(func_group.groups)
                    for cat_group in func_group.groups:
                        if cat_group.controls:
                            for control in cat_group.controls:
                                control_count += 1
                                # Check api-collectible property
                                if control.props:
                                    for prop in control.props:
                                        if prop.name == "api-collectible" and prop.value == "true":
                                            api_collectible += 1
                                            break

        return {
            "title": catalog.metadata.title if catalog.metadata else "Unknown",
            "version": catalog.metadata.version if catalog.metadata else "Unknown",
            "functions": function_count,
            "categories": category_count,
            "controls": control_count,
            "api_collectible_controls": api_collectible,
            "manual_evidence_controls": control_count - api_collectible,
        }


def create_nist_csf2_catalog(
    *,
    include_maturity: bool = True,
    include_evidence: bool = True,
) -> Catalog:
    """
    Create an OSCAL catalog for NIST CSF 2.0.

    Convenience function for creating a complete OSCAL catalog
    from the NIST CSF 2.0 control definitions.

    Args:
        include_maturity: Include maturity criteria as guidance
        include_evidence: Include evidence types as properties

    Returns:
        Complete OSCAL Catalog

    Example:
        catalog = create_nist_csf2_catalog()
        print(f"Catalog has {len(catalog.get_all_controls())} controls")
    """
    converter = NistCSF2OSCALConverter(
        include_maturity_criteria=include_maturity,
        include_evidence_types=include_evidence,
    )
    return converter.convert()


def save_nist_csf2_catalog(
    path: str | Path,
    *,
    format: str = "json",
    include_maturity: bool = True,
    include_evidence: bool = True,
) -> Catalog:
    """
    Create and save an OSCAL catalog for NIST CSF 2.0.

    Convenience function for creating and saving a catalog in one step.

    Args:
        path: Output file path
        format: Output format ("json" or "yaml")
        include_maturity: Include maturity criteria as guidance
        include_evidence: Include evidence types as properties

    Returns:
        The created OSCAL Catalog

    Example:
        catalog = save_nist_csf2_catalog("data/oscal/nist-csf2.json")
    """
    converter = NistCSF2OSCALConverter(
        include_maturity_criteria=include_maturity,
        include_evidence_types=include_evidence,
    )
    catalog = converter.convert()
    converter.save_catalog(catalog, path, format=format)
    return catalog


def get_csf2_catalog_path() -> Path:
    """
    Get the default path for the NIST CSF 2.0 OSCAL catalog.

    Returns:
        Path to the catalog file in the data directory
    """
    # Navigate up from this file to find data directory
    base = Path(__file__).parent.parent.parent.parent.parent
    return base / "data" / "oscal" / "catalogs" / "nist-csf-2.0.json"


def ensure_csf2_catalog_exists() -> Path:
    """
    Ensure the NIST CSF 2.0 OSCAL catalog file exists.

    Creates the catalog if it doesn't exist.

    Returns:
        Path to the catalog file
    """
    path = get_csf2_catalog_path()
    if not path.exists():
        save_nist_csf2_catalog(path)
    return path


# =============================================================================
# OSCAL Profile Generation
# =============================================================================

class NistCSF2ProfileGenerator:
    """
    Generate OSCAL profiles for NIST CSF 2.0.

    Profiles allow selecting specific controls from the catalog
    and customizing parameters for organization-specific needs.

    Example:
        generator = NistCSF2ProfileGenerator()

        # Full CSF 2.0 profile (all controls)
        full_profile = generator.create_full_profile()

        # Custom profile with selected functions
        custom_profile = generator.create_custom_profile(
            title="Critical Infrastructure Profile",
            functions=["GV", "PR", "DE"],  # Govern, Protect, Detect only
        )
    """

    def __init__(
        self,
        *,
        catalog_href: str | None = None,
        organization_name: str = "Attestful",
    ) -> None:
        """
        Initialize the profile generator.

        Args:
            catalog_href: Href to the NIST CSF 2.0 catalog (defaults to bundled)
            organization_name: Name of the publishing organization
        """
        self.catalog_href = catalog_href or "./nist-csf-2.0.json"
        self.organization_name = organization_name

    def create_full_profile(
        self,
        *,
        title: str = "NIST CSF 2.0 Full Profile",
        version: str = "1.0.0",
    ) -> "Profile":
        """
        Create a profile that includes all NIST CSF 2.0 controls.

        Args:
            title: Profile title
            version: Profile version

        Returns:
            OSCAL Profile including all controls
        """
        from attestful.oscal.models import (
            Import,
            Metadata,
            Profile,
            Property,
        )

        metadata = Metadata(
            title=title,
            version=version,
            oscal_version="1.1.2",
            last_modified=datetime.fromisoformat(NIST_CSF2_DATE),
            props=[
                Property(name="framework", value="NIST-CSF"),
                Property(name="framework-version", value="2.0"),
                Property(name="profile-type", value="full"),
            ],
        )

        # include-all is an empty object in OSCAL
        imports = [
            Import(
                href=self.catalog_href,
                include_all={},
            )
        ]

        return Profile(
            uuid=uuid4(),
            metadata=metadata,
            imports=imports,
        )

    def create_custom_profile(
        self,
        *,
        title: str,
        version: str = "1.0.0",
        functions: list[str] | None = None,
        categories: list[str] | None = None,
        subcategories: list[str] | None = None,
        exclude_subcategories: list[str] | None = None,
        target_maturity_level: int | None = None,
    ) -> "Profile":
        """
        Create a custom profile with selected controls.

        Args:
            title: Profile title
            version: Profile version
            functions: List of function IDs to include (e.g., ["GV", "ID", "PR"])
            categories: List of category IDs to include (e.g., ["GV.OC", "PR.AA"])
            subcategories: List of subcategory IDs to include
            exclude_subcategories: Subcategory IDs to exclude
            target_maturity_level: Target maturity level (adds as profile property)

        Returns:
            OSCAL Profile with selected controls
        """
        from attestful.oscal.models import (
            Import,
            Metadata,
            Profile,
            Property,
            SelectControlById,
        )

        # Build control selection
        control_ids = self._get_control_ids(
            functions=functions,
            categories=categories,
            subcategories=subcategories,
        )

        # Apply exclusions
        if exclude_subcategories:
            control_ids = [cid for cid in control_ids if cid not in exclude_subcategories]

        # Build properties
        props = [
            Property(name="framework", value="NIST-CSF"),
            Property(name="framework-version", value="2.0"),
            Property(name="profile-type", value="custom"),
        ]

        if target_maturity_level is not None:
            props.append(
                Property(
                    name="target-maturity-level",
                    value=str(target_maturity_level),
                )
            )

        metadata = Metadata(
            title=title,
            version=version,
            oscal_version="1.1.2",
            last_modified=datetime.now(),
            props=props,
        )

        # Build import with control selection
        include_controls = [
            SelectControlById(with_ids=control_ids)
        ]

        imports = [
            Import(
                href=self.catalog_href,
                include_controls=include_controls,
            )
        ]

        return Profile(
            uuid=uuid4(),
            metadata=metadata,
            imports=imports,
        )

    def create_api_collectible_profile(
        self,
        *,
        title: str = "NIST CSF 2.0 Automated Evidence Profile",
        version: str = "1.0.0",
    ) -> "Profile":
        """
        Create a profile containing only controls with API-collectible evidence.

        This is useful for organizations focusing on automated compliance.

        Args:
            title: Profile title
            version: Profile version

        Returns:
            OSCAL Profile with only API-collectible controls
        """
        from attestful.frameworks.nist.csf2_controls import get_api_collectible_subcategories
        from attestful.oscal.models import (
            Import,
            Metadata,
            Profile,
            Property,
            SelectControlById,
        )

        # Get all API-collectible subcategory IDs
        api_controls = get_api_collectible_subcategories()
        control_ids = [sc.id for sc in api_controls]

        metadata = Metadata(
            title=title,
            version=version,
            oscal_version="1.1.2",
            last_modified=datetime.now(),
            props=[
                Property(name="framework", value="NIST-CSF"),
                Property(name="framework-version", value="2.0"),
                Property(name="profile-type", value="automated"),
                Property(name="api-collectible-only", value="true"),
            ],
        )

        imports = [
            Import(
                href=self.catalog_href,
                include_controls=[SelectControlById(with_ids=control_ids)],
            )
        ]

        return Profile(
            uuid=uuid4(),
            metadata=metadata,
            imports=imports,
        )

    def create_quick_start_profile(
        self,
        *,
        title: str = "NIST CSF 2.0 Quick Start Profile",
        version: str = "1.0.0",
    ) -> "Profile":
        """
        Create a minimal profile for organizations starting their CSF journey.

        Includes key controls from each function to establish a baseline.

        Args:
            title: Profile title
            version: Profile version

        Returns:
            OSCAL Profile with essential controls
        """
        from attestful.oscal.models import (
            Import,
            Metadata,
            Profile,
            Property,
            SelectControlById,
        )

        # Essential subcategories for a quick start
        essential_controls = [
            # Govern - Establish oversight
            "GV.OC-01",  # Mission Understanding
            "GV.RM-01",  # Risk Management Objectives
            "GV.RR-01",  # Leadership Accountability
            "GV.PO-01",  # Policy Established
            # Identify - Know your assets and risks
            "ID.AM-01",  # Hardware Inventory
            "ID.AM-02",  # Software Inventory
            "ID.RA-01",  # Vulnerability Identification
            "ID.RA-05",  # Risk Determination
            # Protect - Safeguard critical systems
            "PR.AA-01",  # Identity Management
            "PR.AA-03",  # Authentication
            "PR.AA-05",  # Access Permissions
            "PR.DS-01",  # Data-at-Rest Protection
            "PR.DS-02",  # Data-in-Transit Protection
            "PR.PS-02",  # Software Maintenance
            # Detect - Monitor for threats
            "DE.CM-01",  # Network Monitoring
            "DE.CM-09",  # Computing Hardware Monitoring
            "DE.AE-02",  # Event Analysis
            # Respond - Handle incidents
            "RS.MA-01",  # Incident Response Plan
            "RS.MA-02",  # Incident Reporting
            "RS.MI-01",  # Containment
            # Recover - Restore operations
            "RC.RP-01",  # Recovery Plan Execution
            "RC.RP-03",  # Backup Integrity
        ]

        metadata = Metadata(
            title=title,
            version=version,
            oscal_version="1.1.2",
            last_modified=datetime.now(),
            props=[
                Property(name="framework", value="NIST-CSF"),
                Property(name="framework-version", value="2.0"),
                Property(name="profile-type", value="quick-start"),
                Property(name="control-count", value=str(len(essential_controls))),
            ],
        )

        imports = [
            Import(
                href=self.catalog_href,
                include_controls=[SelectControlById(with_ids=essential_controls)],
            )
        ]

        return Profile(
            uuid=uuid4(),
            metadata=metadata,
            imports=imports,
        )

    def _get_control_ids(
        self,
        *,
        functions: list[str] | None = None,
        categories: list[str] | None = None,
        subcategories: list[str] | None = None,
    ) -> list[str]:
        """Get control IDs based on selection criteria."""
        control_ids: list[str] = []

        # If specific subcategories are provided, use them
        if subcategories:
            control_ids.extend(subcategories)

        # If categories are provided, get all subcategories in those categories
        if categories:
            from attestful.frameworks.nist.csf2_controls import get_category
            for cat_id in categories:
                category = get_category(cat_id)
                if category:
                    for subcat in category.subcategories:
                        if subcat.id not in control_ids:
                            control_ids.append(subcat.id)

        # If functions are provided, get all subcategories in those functions
        if functions:
            from attestful.frameworks.nist.csf2_controls import get_function
            for func_id in functions:
                function = get_function(func_id)
                if function:
                    for category in function.categories:
                        for subcat in category.subcategories:
                            if subcat.id not in control_ids:
                                control_ids.append(subcat.id)

        # If nothing specified, get all
        if not control_ids:
            from attestful.frameworks.nist.csf2_controls import get_all_subcategories
            control_ids = [sc.id for sc in get_all_subcategories()]

        return control_ids

    def save_profile(
        self,
        profile: "Profile",
        path: str | Path,
        *,
        format: str = "json",
        pretty: bool = True,
    ) -> None:
        """
        Save an OSCAL profile to a file.

        Args:
            profile: The profile to save
            path: Output file path
            format: Output format ("json" or "yaml")
            pretty: Whether to format the output for readability
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Serialize to dict with OSCAL standard wrapper
        data = {
            "profile": profile.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
        }

        if format == "yaml":
            content = yaml.dump(
                data,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
            )
            path.write_text(content, encoding="utf-8")
        else:
            options = orjson.OPT_NON_STR_KEYS
            if pretty:
                options |= orjson.OPT_INDENT_2
            content = orjson.dumps(data, option=options)
            path.write_bytes(content)


def create_nist_csf2_profile(
    *,
    profile_type: str = "full",
    title: str | None = None,
    functions: list[str] | None = None,
    categories: list[str] | None = None,
    subcategories: list[str] | None = None,
    catalog_href: str | None = None,
) -> "Profile":
    """
    Create an OSCAL profile for NIST CSF 2.0.

    Convenience function for creating various types of profiles.

    Args:
        profile_type: Type of profile ("full", "quick-start", "automated", "custom")
        title: Optional custom title
        functions: For custom profile, functions to include
        categories: For custom profile, categories to include
        subcategories: For custom profile, subcategories to include
        catalog_href: Href to the catalog (defaults to bundled)

    Returns:
        OSCAL Profile

    Example:
        # Full profile with all controls
        profile = create_nist_csf2_profile(profile_type="full")

        # Quick start profile
        profile = create_nist_csf2_profile(profile_type="quick-start")

        # Custom profile with specific functions
        profile = create_nist_csf2_profile(
            profile_type="custom",
            title="Protection Focus",
            functions=["PR", "DE"],
        )
    """
    generator = NistCSF2ProfileGenerator(catalog_href=catalog_href)

    if profile_type == "full":
        return generator.create_full_profile(title=title or "NIST CSF 2.0 Full Profile")
    elif profile_type == "quick-start":
        return generator.create_quick_start_profile(
            title=title or "NIST CSF 2.0 Quick Start Profile"
        )
    elif profile_type == "automated":
        return generator.create_api_collectible_profile(
            title=title or "NIST CSF 2.0 Automated Evidence Profile"
        )
    elif profile_type == "custom":
        return generator.create_custom_profile(
            title=title or "NIST CSF 2.0 Custom Profile",
            functions=functions,
            categories=categories,
            subcategories=subcategories,
        )
    else:
        raise ValueError(f"Unknown profile type: {profile_type}")


def save_nist_csf2_profile(
    path: str | Path,
    *,
    profile_type: str = "full",
    format: str = "json",
    **kwargs: Any,
) -> "Profile":
    """
    Create and save an OSCAL profile for NIST CSF 2.0.

    Args:
        path: Output file path
        profile_type: Type of profile ("full", "quick-start", "automated", "custom")
        format: Output format ("json" or "yaml")
        **kwargs: Additional arguments for create_nist_csf2_profile

    Returns:
        The created OSCAL Profile
    """
    profile = create_nist_csf2_profile(profile_type=profile_type, **kwargs)
    generator = NistCSF2ProfileGenerator()
    generator.save_profile(profile, path, format=format)
    return profile


def get_csf2_profile_path(profile_type: str = "full") -> Path:
    """
    Get the default path for a NIST CSF 2.0 OSCAL profile.

    Args:
        profile_type: Type of profile ("full", "quick-start", "automated")

    Returns:
        Path to the profile file in the data directory
    """
    base = Path(__file__).parent.parent.parent.parent.parent
    filename = f"nist-csf-2.0-{profile_type}.json"
    return base / "data" / "oscal" / "profiles" / filename


def ensure_csf2_profiles_exist() -> dict[str, Path]:
    """
    Ensure all standard NIST CSF 2.0 OSCAL profiles exist.

    Creates the profiles if they don't exist.

    Returns:
        Dictionary mapping profile type to path
    """
    profiles: dict[str, Path] = {}

    for profile_type in ["full", "quick-start", "automated"]:
        path = get_csf2_profile_path(profile_type)
        if not path.exists():
            save_nist_csf2_profile(path, profile_type=profile_type)
        profiles[profile_type] = path

    return profiles


# =============================================================================
# OSCAL Component Definition Generation (Evidence Platform Mappings)
# =============================================================================


# Evidence platform definitions with metadata
EVIDENCE_PLATFORMS: dict[str, dict[str, str]] = {
    "okta": {
        "title": "Okta Identity Management",
        "type": "service",
        "description": "Identity and access management platform providing SSO, MFA, and user lifecycle management.",
        "purpose": "Provides evidence for identity management, authentication, and access control.",
    },
    "jamf": {
        "title": "Jamf Pro Endpoint Management",
        "type": "software",
        "description": "Apple device management platform for macOS, iOS, and tvOS devices.",
        "purpose": "Provides evidence for endpoint security, device inventory, and configuration management.",
    },
    "google_workspace": {
        "title": "Google Workspace",
        "type": "service",
        "description": "Cloud productivity and collaboration suite including Gmail, Drive, and admin controls.",
        "purpose": "Provides evidence for user management, security policies, and collaboration controls.",
    },
    "snowflake": {
        "title": "Snowflake Data Cloud",
        "type": "service",
        "description": "Cloud data platform for data warehousing, data lakes, and analytics.",
        "purpose": "Provides evidence for data access controls, query auditing, and data governance.",
    },
    "datadog": {
        "title": "Datadog Monitoring",
        "type": "service",
        "description": "Cloud monitoring and security platform for infrastructure and applications.",
        "purpose": "Provides evidence for continuous monitoring, alerting, and security signals.",
    },
    "gitlab": {
        "title": "GitLab DevSecOps",
        "type": "service",
        "description": "DevSecOps platform for source control, CI/CD, and security scanning.",
        "purpose": "Provides evidence for secure development, code review, and vulnerability scanning.",
    },
    "jira": {
        "title": "Jira Project Management",
        "type": "service",
        "description": "Project and issue tracking platform for agile development.",
        "purpose": "Provides evidence for change management, issue tracking, and workflow documentation.",
    },
    "zendesk": {
        "title": "Zendesk Support",
        "type": "service",
        "description": "Customer service and support platform.",
        "purpose": "Provides evidence for support processes and customer communication.",
    },
    "zoom": {
        "title": "Zoom Communications",
        "type": "service",
        "description": "Video conferencing and communications platform.",
        "purpose": "Provides evidence for communication security and meeting controls.",
    },
    "notion": {
        "title": "Notion Workspace",
        "type": "service",
        "description": "Collaborative workspace for documentation and knowledge management.",
        "purpose": "Provides evidence for documentation practices and information sharing.",
    },
    "slab": {
        "title": "Slab Knowledge Base",
        "type": "service",
        "description": "Knowledge management platform for documentation.",
        "purpose": "Provides evidence for policy documentation and knowledge sharing.",
    },
    "spotdraft": {
        "title": "SpotDraft Contract Management",
        "type": "service",
        "description": "Contract lifecycle management platform.",
        "purpose": "Provides evidence for vendor agreements and contractual obligations.",
    },
    "aws": {
        "title": "Amazon Web Services",
        "type": "service",
        "description": "Cloud infrastructure and services platform.",
        "purpose": "Provides evidence for cloud infrastructure security, access controls, and configuration.",
    },
    "azure": {
        "title": "Microsoft Azure",
        "type": "service",
        "description": "Cloud computing platform and services.",
        "purpose": "Provides evidence for cloud infrastructure security, identity, and compliance.",
    },
    "gcp": {
        "title": "Google Cloud Platform",
        "type": "service",
        "description": "Cloud computing platform and services.",
        "purpose": "Provides evidence for cloud infrastructure security and data protection.",
    },
}


class NistCSF2ComponentGenerator:
    """
    Generate OSCAL Component Definitions from NIST CSF 2.0 evidence mappings.

    Creates components for each evidence source platform, with implemented
    requirements linking to the NIST CSF 2.0 controls they satisfy.

    Example:
        generator = NistCSF2ComponentGenerator()
        comp_def = generator.generate_for_platform("okta")
        generator.save_component_definition(comp_def, "okta-component.json")
    """

    def __init__(
        self,
        *,
        catalog_href: str = "./nist-csf-2.0.json",
        organization_name: str = "Attestful",
    ) -> None:
        """
        Initialize the generator.

        Args:
            catalog_href: Href to the NIST CSF 2.0 catalog
            organization_name: Name of the publishing organization
        """
        self.catalog_href = catalog_href
        self.organization_name = organization_name

    def generate_for_platform(
        self,
        platform: str,
        *,
        version: str = "1.0.0",
    ) -> "ComponentDefinition":
        """
        Generate a component definition for a specific platform.

        Args:
            platform: Platform identifier (e.g., "okta", "jamf")
            version: Component definition version

        Returns:
            OSCAL ComponentDefinition for the platform
        """
        from attestful.oscal.models import (
            Component,
            ComponentDefinition,
            ControlImplementation,
            ImplementedRequirement,
            Metadata,
            Property,
        )

        if platform not in EVIDENCE_PLATFORMS:
            raise ValueError(f"Unknown platform: {platform}")

        platform_info = EVIDENCE_PLATFORMS[platform]

        # Get subcategories that this platform can satisfy
        from attestful.frameworks.nist.csf2_controls import get_all_subcategories
        controls_for_platform = []
        for subcat in get_all_subcategories():
            if self._platform_provides_evidence(platform, subcat.evidence_types):
                controls_for_platform.append(subcat)

        # Create implemented requirements
        implemented_reqs = []
        for subcat in controls_for_platform:
            matching_evidence = [
                et for et in subcat.evidence_types
                if self._evidence_type_matches_platform(et, platform)
            ]

            impl_req = ImplementedRequirement(
                control_id=subcat.id,
                description=f"Evidence collected from {platform_info['title']} supports this control.",
                props=[
                    Property(
                        name="implementation-status",
                        value="implemented" if subcat.api_collectible else "partial",
                    ),
                    Property(name="platform", value=platform),
                    Property(
                        name="api-collectible",
                        value="true" if subcat.api_collectible else "false",
                    ),
                ] + [
                    Property(name="evidence-type", value=et, class_="attestful")
                    for et in matching_evidence
                ],
            )
            implemented_reqs.append(impl_req)

        # Create the component
        component = Component(
            uuid=uuid4(),
            type=platform_info["type"],
            title=platform_info["title"],
            description=platform_info["description"],
            purpose=platform_info["purpose"],
            props=[
                Property(name="platform-id", value=platform),
                Property(name="control-count", value=str(len(controls_for_platform))),
            ],
            control_implementations=[
                ControlImplementation(
                    source=self.catalog_href,
                    description=f"NIST CSF 2.0 controls implemented through {platform_info['title']}",
                    implemented_requirements=implemented_reqs,
                )
            ] if implemented_reqs else None,
        )

        # Create the component definition
        metadata = Metadata(
            title=f"{platform_info['title']} - NIST CSF 2.0 Evidence Mappings",
            version=version,
            oscal_version="1.1.2",
            last_modified=datetime.now(),
            props=[
                Property(name="framework", value="NIST-CSF"),
                Property(name="framework-version", value="2.0"),
                Property(name="platform", value=platform),
            ],
        )

        return ComponentDefinition(
            uuid=uuid4(),
            metadata=metadata,
            components=[component],
        )

    def generate_all_platforms(
        self,
        *,
        version: str = "1.0.0",
    ) -> "ComponentDefinition":
        """
        Generate a combined component definition for all platforms.

        Args:
            version: Component definition version

        Returns:
            OSCAL ComponentDefinition with all platform components
        """
        from attestful.oscal.models import (
            Component,
            ComponentDefinition,
            ControlImplementation,
            ImplementedRequirement,
            Metadata,
            Property,
        )
        from attestful.frameworks.nist.csf2_controls import get_all_subcategories

        all_subcategories = get_all_subcategories()
        components = []

        for platform, platform_info in EVIDENCE_PLATFORMS.items():
            # Get subcategories for this platform
            controls_for_platform = []
            for subcat in all_subcategories:
                if self._platform_provides_evidence(platform, subcat.evidence_types):
                    controls_for_platform.append(subcat)

            if not controls_for_platform:
                continue

            # Create implemented requirements
            implemented_reqs = []
            for subcat in controls_for_platform:
                matching_evidence = [
                    et for et in subcat.evidence_types
                    if self._evidence_type_matches_platform(et, platform)
                ]

                impl_req = ImplementedRequirement(
                    control_id=subcat.id,
                    description=f"Evidence from {platform_info['title']}.",
                    props=[
                        Property(name="implementation-status", value="implemented"),
                        Property(name="platform", value=platform),
                    ] + [
                        Property(name="evidence-type", value=et, class_="attestful")
                        for et in matching_evidence
                    ],
                )
                implemented_reqs.append(impl_req)

            # Create the component
            component = Component(
                uuid=uuid4(),
                type=platform_info["type"],
                title=platform_info["title"],
                description=platform_info["description"],
                purpose=platform_info["purpose"],
                props=[
                    Property(name="platform-id", value=platform),
                    Property(name="control-count", value=str(len(controls_for_platform))),
                ],
                control_implementations=[
                    ControlImplementation(
                        source=self.catalog_href,
                        description=f"NIST CSF 2.0 controls for {platform_info['title']}",
                        implemented_requirements=implemented_reqs,
                    )
                ],
            )
            components.append(component)

        # Create the combined component definition
        metadata = Metadata(
            title="Attestful Evidence Platforms - NIST CSF 2.0",
            version=version,
            oscal_version="1.1.2",
            last_modified=datetime.now(),
            props=[
                Property(name="framework", value="NIST-CSF"),
                Property(name="framework-version", value="2.0"),
                Property(name="component-count", value=str(len(components))),
            ],
        )

        return ComponentDefinition(
            uuid=uuid4(),
            metadata=metadata,
            components=components,
        )

    def _platform_provides_evidence(
        self,
        platform: str,
        evidence_types: list[str],
    ) -> bool:
        """Check if a platform provides any of the evidence types."""
        for et in evidence_types:
            if self._evidence_type_matches_platform(et, platform):
                return True
        return False

    def _evidence_type_matches_platform(
        self,
        evidence_type: str,
        platform: str,
    ) -> bool:
        """Check if an evidence type is provided by a platform."""
        # Evidence type to platform mapping
        evidence_platform_map = {
            # Identity and Access
            "user_inventory": ["okta", "google_workspace", "aws", "azure", "gcp"],
            "identity_provider_config": ["okta", "azure"],
            "mfa_status": ["okta", "google_workspace", "aws", "azure"],
            "sso_config": ["okta", "google_workspace", "azure"],
            "authentication_logs": ["okta", "google_workspace", "datadog"],
            "access_policies": ["okta", "aws", "azure", "gcp"],
            "rbac_config": ["okta", "aws", "azure", "gcp", "snowflake"],
            "access_reviews": ["okta"],
            # Device and Endpoint
            "device_inventory": ["jamf", "google_workspace"],
            "jamf_inventory": ["jamf"],
            "software_inventory": ["jamf"],
            "application_catalog": ["jamf", "google_workspace"],
            "patch_status": ["jamf", "aws", "azure"],
            # Data and Security
            "encryption_status": ["aws", "azure", "gcp", "snowflake"],
            "data_protection_config": ["aws", "azure", "gcp", "snowflake"],
            "tls_config": ["aws", "azure", "gcp"],
            "backup_config": ["aws", "azure", "gcp"],
            "dlp_config": ["google_workspace", "datadog"],
            # Monitoring and Detection
            "logging_config": ["aws", "azure", "gcp", "datadog"],
            "audit_logs": ["aws", "azure", "gcp", "snowflake", "google_workspace"],
            "network_monitoring": ["datadog", "aws", "azure"],
            "ids_alerts": ["datadog"],
            "siem_config": ["datadog"],
            "security_findings": ["datadog", "aws", "azure", "gitlab"],
            "endpoint_monitoring": ["datadog", "jamf"],
            "edr_alerts": ["datadog"],
            # Development and Code
            "code_review_records": ["gitlab"],
            "sdlc_policy": ["gitlab", "jira"],
            "vulnerability_scan": ["gitlab", "aws", "azure"],
            "pipeline_status": ["gitlab"],
            # Incident and Response
            "incident_log": ["jira", "datadog"],
            "incident_response_plan": ["jira", "notion", "slab"],
            "containment_procedures": ["jira", "datadog"],
            "escalation_procedures": ["jira"],
            # Documentation
            "policy_document": ["notion", "slab", "google_workspace"],
            "security_policy": ["notion", "slab"],
            "training_records": ["google_workspace", "notion"],
            # Vendor and Contract
            "vendor_inventory": ["spotdraft", "notion"],
            "vendor_agreements": ["spotdraft"],
            "contract_templates": ["spotdraft"],
            "due_diligence_reports": ["spotdraft"],
            # Communication
            "meeting_records": ["zoom"],
            "communication_logs": ["zoom", "zendesk"],
            # Support
            "support_tickets": ["zendesk", "jira"],
            "satisfaction_surveys": ["zendesk"],
            # Cloud Infrastructure
            "firewall_config": ["aws", "azure", "gcp"],
            "network_segmentation": ["aws", "azure", "gcp"],
            "ha_config": ["aws", "azure", "gcp"],
            "capacity_monitoring": ["aws", "azure", "gcp", "datadog"],
            "config_standards": ["aws", "azure", "gcp"],
            "baseline_config": ["aws", "azure", "gcp"],
        }

        if evidence_type in evidence_platform_map:
            return platform in evidence_platform_map[evidence_type]

        # Check for platform-specific evidence types
        if platform in evidence_type.lower():
            return True

        return False

    def save_component_definition(
        self,
        comp_def: "ComponentDefinition",
        path: str | Path,
        *,
        format: str = "json",
        pretty: bool = True,
    ) -> None:
        """
        Save an OSCAL component definition to a file.

        Args:
            comp_def: The component definition to save
            path: Output file path
            format: Output format ("json" or "yaml")
            pretty: Whether to format the output for readability
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "component-definition": comp_def.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
        }

        if format == "yaml":
            content = yaml.dump(
                data,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
            )
            path.write_text(content, encoding="utf-8")
        else:
            options = orjson.OPT_NON_STR_KEYS
            if pretty:
                options |= orjson.OPT_INDENT_2
            content = orjson.dumps(data, option=options)
            path.write_bytes(content)


def create_nist_csf2_component_definition(
    *,
    platform: str | None = None,
    catalog_href: str = "./nist-csf-2.0.json",
) -> "ComponentDefinition":
    """
    Create an OSCAL component definition for NIST CSF 2.0.

    Args:
        platform: Specific platform (None for all platforms combined)
        catalog_href: Href to the NIST CSF 2.0 catalog

    Returns:
        OSCAL ComponentDefinition

    Example:
        # Single platform
        comp_def = create_nist_csf2_component_definition(platform="okta")

        # All platforms
        comp_def = create_nist_csf2_component_definition()
    """
    generator = NistCSF2ComponentGenerator(catalog_href=catalog_href)

    if platform:
        return generator.generate_for_platform(platform)
    else:
        return generator.generate_all_platforms()


def get_csf2_component_path(platform: str | None = None) -> Path:
    """
    Get the default path for a NIST CSF 2.0 component definition.

    Args:
        platform: Specific platform (None for combined)

    Returns:
        Path to the component definition file
    """
    base = Path(__file__).parent.parent.parent.parent.parent
    if platform:
        filename = f"nist-csf-2.0-{platform}-component.json"
    else:
        filename = "nist-csf-2.0-all-components.json"
    return base / "data" / "oscal" / "components" / filename


def ensure_csf2_components_exist() -> dict[str, Path]:
    """
    Ensure NIST CSF 2.0 component definitions exist.

    Creates the combined component definition if it doesn't exist.

    Returns:
        Dictionary with 'all' key mapping to path
    """
    generator = NistCSF2ComponentGenerator()
    path = get_csf2_component_path()

    if not path.exists():
        comp_def = generator.generate_all_platforms()
        generator.save_component_definition(comp_def, path)

    return {"all": path}
