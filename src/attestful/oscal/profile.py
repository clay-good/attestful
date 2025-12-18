"""
OSCAL Profile loader, resolver, and utilities.

Provides functionality for loading OSCAL profiles, resolving them against
source catalogs, and applying modifications to produce resolved catalogs.

Profile resolution follows the OSCAL Profile Resolution Specification:
https://pages.nist.gov/OSCAL/concepts/processing/profile-resolution/
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import orjson
import yaml

from attestful.core.exceptions import ProfileError
from attestful.core.logging import get_logger
from attestful.oscal.catalog import CatalogIndex, CatalogLoader
from attestful.oscal.models import (
    Alter,
    BackMatter,
    Catalog,
    Combine,
    Control,
    CustomGroup,
    Group,
    Import,
    Merge,
    Metadata,
    Modify,
    Parameter,
    Part,
    Profile,
    Property,
    SelectControlById,
    SetParameter,
)

logger = get_logger("oscal.profile")


class ResolvedCatalog:
    """
    A catalog produced by resolving a profile.

    Contains the selected controls with all modifications applied.
    """

    def __init__(
        self,
        catalog: Catalog,
        source_profile: Profile,
        resolved_parameters: dict[str, str],
    ) -> None:
        self.catalog = catalog
        self.source_profile = source_profile
        self.resolved_parameters = resolved_parameters
        self._index: CatalogIndex | None = None

    @property
    def index(self) -> CatalogIndex:
        """Get or create the catalog index."""
        if self._index is None:
            self._index = CatalogIndex(self.catalog)
        return self._index

    def get_control(self, control_id: str) -> Control | None:
        """Get a control by ID."""
        return self.index.get_control(control_id)

    def list_control_ids(self) -> list[str]:
        """List all control IDs in the resolved catalog."""
        return self.index.list_control_ids()

    @property
    def control_count(self) -> int:
        """Number of controls in the resolved catalog."""
        return self.index.control_count


class ProfileLoader:
    """
    Load OSCAL profiles from various sources.

    Supports JSON, YAML formats.
    """

    def __init__(self) -> None:
        self._cache: dict[str, Profile] = {}

    def load(self, path: str | Path, *, use_cache: bool = True) -> Profile:
        """
        Load a profile from a file path.

        Args:
            path: Path to the profile file
            use_cache: Whether to use cached profile if available

        Returns:
            Parsed Profile object

        Raises:
            ProfileError: If the file cannot be loaded or parsed
        """
        path = Path(path)
        cache_key = str(path.resolve())

        if use_cache and cache_key in self._cache:
            logger.debug(f"Using cached profile: {path}")
            return self._cache[cache_key]

        if not path.exists():
            raise ProfileError(f"Profile file not found: {path}", profile_id=str(path))

        try:
            content = path.read_text(encoding="utf-8")
            profile = self._parse_content(content, path.suffix.lower())

            if use_cache:
                self._cache[cache_key] = profile

            logger.info(f"Loaded profile: {profile.metadata.title} ({path})")
            return profile

        except Exception as e:
            if isinstance(e, ProfileError):
                raise
            raise ProfileError(
                f"Failed to load profile: {e}",
                profile_id=str(path),
                cause=e,
            ) from e

    def load_from_string(
        self,
        content: str,
        format: str = "json",
    ) -> Profile:
        """
        Load a profile from a string.

        Args:
            content: The profile content
            format: Format of the content ("json", "yaml")

        Returns:
            Parsed Profile object
        """
        return self._parse_content(content, f".{format}")

    def _parse_content(self, content: str, suffix: str) -> Profile:
        """Parse profile content based on format."""
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

        # Handle wrapped format (profile key at root)
        if "profile" in data:
            data = data["profile"]

        return Profile.model_validate(data)

    def clear_cache(self) -> None:
        """Clear the profile cache."""
        self._cache.clear()


class ProfileResolver:
    """
    Resolve OSCAL profiles into catalogs.

    Takes a profile and its source catalogs/profiles, and produces a
    resolved catalog with selected controls and applied modifications.

    Resolution steps:
    1. Import: Select controls from source catalogs/profiles
    2. Merge: Combine controls from multiple imports
    3. Modify: Apply parameter settings and control alterations
    """

    def __init__(
        self,
        catalog_loader: CatalogLoader | None = None,
        profile_loader: ProfileLoader | None = None,
        base_path: Path | None = None,
    ) -> None:
        """
        Initialize the resolver.

        Args:
            catalog_loader: Loader for source catalogs
            profile_loader: Loader for source profiles (for profile chaining)
            base_path: Base path for resolving relative hrefs
        """
        self.catalog_loader = catalog_loader or CatalogLoader()
        self.profile_loader = profile_loader or ProfileLoader()
        self.base_path = base_path or Path.cwd()
        self._resolved_cache: dict[str, ResolvedCatalog] = {}

    def resolve(
        self,
        profile: Profile,
        *,
        use_cache: bool = True,
    ) -> ResolvedCatalog:
        """
        Resolve a profile into a catalog.

        Args:
            profile: The profile to resolve
            use_cache: Whether to cache and reuse resolved catalogs

        Returns:
            ResolvedCatalog containing selected controls with modifications
        """
        cache_key = str(profile.uuid)

        if use_cache and cache_key in self._resolved_cache:
            logger.debug(f"Using cached resolved catalog for profile {profile.uuid}")
            return self._resolved_cache[cache_key]

        logger.info(f"Resolving profile: {profile.metadata.title}")

        # Step 1: Import - collect controls from sources
        imported_controls = self._process_imports(profile.imports)

        # Step 2: Merge - combine imported controls
        merged_controls, merged_groups = self._process_merge(
            imported_controls,
            profile.merge,
        )

        # Step 3: Modify - apply parameter settings and alterations
        modified_controls, resolved_params = self._process_modify(
            merged_controls,
            profile.modify,
        )

        # Build the resolved catalog
        resolved_catalog = self._build_catalog(
            profile,
            modified_controls,
            merged_groups,
        )

        result = ResolvedCatalog(
            catalog=resolved_catalog,
            source_profile=profile,
            resolved_parameters=resolved_params,
        )

        if use_cache:
            self._resolved_cache[cache_key] = result

        logger.info(
            f"Resolved profile '{profile.metadata.title}' with "
            f"{result.control_count} controls"
        )

        return result

    def resolve_from_file(
        self,
        path: str | Path,
        *,
        use_cache: bool = True,
    ) -> ResolvedCatalog:
        """
        Load and resolve a profile from a file.

        Args:
            path: Path to the profile file
            use_cache: Whether to cache results

        Returns:
            ResolvedCatalog
        """
        profile = self.profile_loader.load(path, use_cache=use_cache)

        # Update base path for relative href resolution
        path = Path(path)
        old_base = self.base_path
        self.base_path = path.parent

        try:
            return self.resolve(profile, use_cache=use_cache)
        finally:
            self.base_path = old_base

    def _process_imports(
        self,
        imports: list[Import],
    ) -> list[tuple[Import, list[Control], dict[str, Parameter]]]:
        """
        Process import statements to collect controls from sources.

        Returns list of (import, controls, parameters) tuples.
        """
        results: list[tuple[Import, list[Control], dict[str, Parameter]]] = []

        for imp in imports:
            controls, params = self._import_controls(imp)
            results.append((imp, controls, params))
            logger.debug(f"Imported {len(controls)} controls from {imp.href}")

        return results

    def _import_controls(
        self,
        imp: Import,
    ) -> tuple[list[Control], dict[str, Parameter]]:
        """
        Import controls from a catalog or profile.

        Returns (controls, parameters) from the source.
        """
        # Resolve the href
        source_path = self._resolve_href(imp.href)

        # Load source (could be catalog or profile)
        source_catalog = self._load_source(source_path)
        index = CatalogIndex(source_catalog)

        # Collect parameters from the source
        source_params: dict[str, Parameter] = {}
        for control_id in index.list_control_ids():
            control = index.get_control(control_id)
            if control and control.params:
                for param in control.params:
                    source_params[param.id] = param

        # Collect catalog-level parameters
        if source_catalog.params:
            for param in source_catalog.params:
                source_params[param.id] = param

        # Select controls based on import criteria
        if imp.include_all is not None:
            # Include all controls
            selected = index.list_all_controls()
        elif imp.include_controls:
            # Include specific controls
            selected = self._select_controls(index, imp.include_controls)
        else:
            # No selection criteria - include nothing
            selected = []

        # Apply exclusions
        if imp.exclude_controls:
            excluded_ids = self._get_control_ids(index, imp.exclude_controls)
            selected = [c for c in selected if c.id not in excluded_ids]

        return selected, source_params

    def _resolve_href(self, href: str) -> Path:
        """Resolve an href to a file path."""
        parsed = urlparse(href)

        if parsed.scheme in ("", "file"):
            # Local file reference
            path = Path(parsed.path)
            if not path.is_absolute():
                path = self.base_path / path
            return path
        else:
            raise ProfileError(
                f"Unsupported href scheme: {parsed.scheme}",
                profile_id=href,
            )

    def _load_source(self, path: Path) -> Catalog:
        """
        Load a source catalog or profile.

        If the source is a profile, resolve it first.
        """
        suffix = path.suffix.lower()
        content = path.read_text(encoding="utf-8")

        # Try to detect if it's a profile or catalog
        if suffix in (".json",):
            data = orjson.loads(content)
        else:
            data = yaml.safe_load(content)

        if "profile" in data:
            # Source is a profile - resolve it first (profile chaining)
            logger.debug(f"Resolving chained profile: {path}")
            old_base = self.base_path
            self.base_path = path.parent
            try:
                profile = Profile.model_validate(data["profile"])
                resolved = self.resolve(profile)
                return resolved.catalog
            finally:
                self.base_path = old_base
        else:
            # Source is a catalog
            return self.catalog_loader.load(path)

    def _select_controls(
        self,
        index: CatalogIndex,
        selectors: list[SelectControlById],
    ) -> list[Control]:
        """Select controls based on selection criteria."""
        selected: list[Control] = []
        seen_ids: set[str] = set()

        for selector in selectors:
            # Select by explicit IDs
            if selector.with_ids:
                for control_id in selector.with_ids:
                    control = index.get_control(control_id)
                    if control and control.id not in seen_ids:
                        selected.append(deepcopy(control))
                        seen_ids.add(control.id)

                        # Include child controls if requested
                        if selector.with_child_controls == "yes":
                            enhancements = index.get_enhancements(control_id)
                            for enh in enhancements:
                                if enh.id not in seen_ids:
                                    selected.append(deepcopy(enh))
                                    seen_ids.add(enh.id)

            # Select by pattern matching
            if selector.matching:
                for pattern in selector.matching:
                    pattern_value = pattern.get("pattern", "")
                    for control in index.list_all_controls():
                        if self._matches_pattern(control.id, pattern_value):
                            if control.id not in seen_ids:
                                selected.append(deepcopy(control))
                                seen_ids.add(control.id)

        return selected

    def _get_control_ids(
        self,
        index: CatalogIndex,
        selectors: list[SelectControlById],
    ) -> set[str]:
        """Get set of control IDs matching selection criteria."""
        ids: set[str] = set()

        for selector in selectors:
            if selector.with_ids:
                ids.update(selector.with_ids)

                if selector.with_child_controls == "yes":
                    for control_id in selector.with_ids:
                        for enh in index.get_enhancements(control_id):
                            ids.add(enh.id)

            if selector.matching:
                for pattern in selector.matching:
                    pattern_value = pattern.get("pattern", "")
                    for control in index.list_all_controls():
                        if self._matches_pattern(control.id, pattern_value):
                            ids.add(control.id)

        return ids

    def _matches_pattern(self, control_id: str, pattern: str) -> bool:
        """Check if a control ID matches a pattern (simple glob-style)."""
        import fnmatch
        return fnmatch.fnmatch(control_id, pattern)

    def _process_merge(
        self,
        imported: list[tuple[Import, list[Control], dict[str, Parameter]]],
        merge: Merge | None,
    ) -> tuple[list[Control], list[Group] | None]:
        """
        Merge controls from multiple imports.

        Returns (merged_controls, groups).
        """
        if not imported:
            return [], None

        # Determine merge strategy
        method = "merge"  # Default
        if merge and merge.combine:
            method = merge.combine.method or "merge"

        # Collect all controls
        all_controls: dict[str, Control] = {}

        for imp, controls, params in imported:
            for control in controls:
                if control.id in all_controls:
                    if method == "use-first":
                        # Keep first occurrence
                        continue
                    elif method == "keep":
                        # Keep both (append suffix)
                        # For now, just keep first
                        continue
                    elif method == "merge":
                        # Merge properties
                        existing = all_controls[control.id]
                        all_controls[control.id] = self._merge_controls(
                            existing, control
                        )
                else:
                    all_controls[control.id] = control

        merged_controls = list(all_controls.values())

        # Handle structure
        groups: list[Group] | None = None

        if merge:
            if merge.flat is not None:
                # Flatten structure - just return controls without groups
                pass
            elif merge.as_is:
                # Preserve original structure
                # For now, we return flat controls
                pass
            elif merge.custom:
                # Use custom structure
                groups = self._build_custom_structure(
                    merge.custom,
                    all_controls,
                )

        return merged_controls, groups

    def _merge_controls(self, control1: Control, control2: Control) -> Control:
        """Merge two controls with the same ID."""
        # Merge parameters (second overwrites first)
        merged_params: dict[str, Parameter] | None = None
        if control1.params or control2.params:
            merged_params = {}
            if control1.params:
                for p in control1.params:
                    merged_params[p.id] = p
            if control2.params:
                for p in control2.params:
                    merged_params[p.id] = p

        # Merge properties
        merged_props: list[Property] | None = None
        if control1.props or control2.props:
            merged_props = list(control1.props or []) + list(control2.props or [])

        # Merge parts
        merged_parts: list[Part] | None = None
        if control1.parts or control2.parts:
            merged_parts = list(control1.parts or []) + list(control2.parts or [])

        # Create merged control
        return Control(
            id=control1.id,
            title=control2.title or control1.title,  # Prefer second
            class_=control2.class_ or control1.class_,
            params=list(merged_params.values()) if merged_params else None,
            props=merged_props,
            links=list(control1.links or []) + list(control2.links or []),
            parts=merged_parts,
            controls=control1.controls or control2.controls,
        )

    def _build_custom_structure(
        self,
        custom: CustomGroup,
        controls: dict[str, Control],
    ) -> list[Group]:
        """Build custom group structure from custom definition."""
        # This is a simplified implementation
        # Full implementation would handle insert-controls directives
        return [
            Group(
                id=custom.id,
                title=custom.title,
                params=custom.params,
                props=custom.props,
                links=custom.links,
                parts=custom.parts,
                groups=[
                    self._custom_to_group(g, controls)
                    for g in (custom.groups or [])
                ],
            )
        ]

    def _custom_to_group(
        self,
        custom: CustomGroup,
        controls: dict[str, Control],
    ) -> Group:
        """Convert a CustomGroup to a Group."""
        group_controls: list[Control] = []

        if custom.insert_controls:
            for insert in custom.insert_controls:
                # Handle include-controls within insert-controls
                include = insert.get("include-controls", [])
                for selection in include:
                    with_ids = selection.get("with-ids", [])
                    for control_id in with_ids:
                        if control_id in controls:
                            group_controls.append(controls[control_id])

        return Group(
            id=custom.id,
            title=custom.title,
            params=custom.params,
            props=custom.props,
            links=custom.links,
            parts=custom.parts,
            controls=group_controls if group_controls else None,
            groups=[
                self._custom_to_group(g, controls)
                for g in (custom.groups or [])
            ] if custom.groups else None,
        )

    def _process_modify(
        self,
        controls: list[Control],
        modify: Modify | None,
    ) -> tuple[list[Control], dict[str, str]]:
        """
        Apply modifications to controls.

        Returns (modified_controls, resolved_parameters).
        """
        if not modify:
            return controls, {}

        # Build control lookup
        control_map: dict[str, Control] = {c.id: c for c in controls}
        resolved_params: dict[str, str] = {}

        # Apply parameter settings
        if modify.set_parameters:
            for set_param in modify.set_parameters:
                # Store resolved value
                if set_param.values:
                    resolved_params[set_param.param_id] = set_param.values[0]

                # Apply to controls that have this parameter
                for control in controls:
                    self._apply_param_to_control(control, set_param)

        # Apply alterations
        if modify.alters:
            for alter in modify.alters:
                if alter.control_id in control_map:
                    control_map[alter.control_id] = self._apply_alter(
                        control_map[alter.control_id],
                        alter,
                    )

        return list(control_map.values()), resolved_params

    def _apply_param_to_control(
        self,
        control: Control,
        set_param: SetParameter,
    ) -> None:
        """Apply a parameter setting to a control."""
        if not control.params:
            return

        for i, param in enumerate(control.params):
            if param.id == set_param.param_id:
                # Update parameter with new values
                control.params[i] = Parameter(
                    id=param.id,
                    class_=set_param.class_ or param.class_,
                    depends_on=set_param.depends_on or param.depends_on,
                    props=set_param.props or param.props,
                    links=set_param.links or param.links,
                    label=set_param.label or param.label,
                    usage=set_param.usage or param.usage,
                    constraints=set_param.constraints or param.constraints,
                    guidelines=set_param.guidelines or param.guidelines,
                    values=set_param.values or param.values,
                    select=set_param.select or param.select,
                    remarks=param.remarks,
                )
                break

        # Also apply to control enhancements
        if control.controls:
            for enhancement in control.controls:
                self._apply_param_to_control(enhancement, set_param)

    def _apply_alter(self, control: Control, alter: Alter) -> Control:
        """Apply an alteration to a control."""
        control = deepcopy(control)

        # Process removals first
        if alter.removes:
            for remove in alter.removes:
                self._apply_removal(control, remove)

        # Process additions
        if alter.adds:
            for add in alter.adds:
                self._apply_addition(control, add)

        return control

    def _apply_removal(self, control: Control, remove: dict[str, str]) -> None:
        """Apply a removal to a control."""
        by_name = remove.get("by-name")
        by_class = remove.get("by-class")
        by_id = remove.get("by-id")
        by_item_name = remove.get("by-item-name")

        # Remove properties
        if control.props and (by_name or by_class):
            control.props = [
                p for p in control.props
                if not (
                    (by_name and p.name == by_name) or
                    (by_class and p.class_ == by_class)
                )
            ]

        # Remove parts
        if control.parts and (by_name or by_id or by_item_name):
            control.parts = [
                p for p in control.parts
                if not (
                    (by_name and p.name == by_name) or
                    (by_id and p.id == by_id) or
                    (by_item_name and p.name == by_item_name)
                )
            ]

        # Remove links
        if control.links and by_name:
            control.links = [
                l for l in control.links
                if l.rel != by_name
            ]

    def _apply_addition(self, control: Control, add: dict[str, Any]) -> None:
        """Apply an addition to a control."""
        position = add.get("position", "ending")  # starting, ending, before, after
        by_id = add.get("by-id")

        # Add properties
        if "props" in add:
            new_props = [Property.model_validate(p) for p in add["props"]]
            if not control.props:
                control.props = []
            if position == "starting":
                control.props = new_props + control.props
            else:
                control.props.extend(new_props)

        # Add parts
        if "parts" in add:
            new_parts = [Part.model_validate(p) for p in add["parts"]]
            if not control.parts:
                control.parts = []

            if by_id and position in ("before", "after"):
                # Insert relative to existing part
                for i, part in enumerate(control.parts):
                    if part.id == by_id:
                        if position == "before":
                            control.parts = (
                                control.parts[:i] + new_parts + control.parts[i:]
                            )
                        else:  # after
                            control.parts = (
                                control.parts[:i+1] + new_parts + control.parts[i+1:]
                            )
                        break
            elif position == "starting":
                control.parts = new_parts + control.parts
            else:
                control.parts.extend(new_parts)

        # Add links
        if "links" in add:
            from attestful.oscal.models import Link
            new_links = [Link.model_validate(l) for l in add["links"]]
            if not control.links:
                control.links = []
            if position == "starting":
                control.links = new_links + control.links
            else:
                control.links.extend(new_links)

    def _build_catalog(
        self,
        profile: Profile,
        controls: list[Control],
        groups: list[Group] | None,
    ) -> Catalog:
        """Build a resolved catalog from the profile and controls."""
        from datetime import datetime, timezone
        from uuid import uuid4

        # Create metadata for the resolved catalog
        metadata = Metadata(
            title=f"Resolved: {profile.metadata.title}",
            last_modified=datetime.now(timezone.utc),
            version=profile.metadata.version,
            oscal_version=profile.metadata.oscal_version,
            props=[
                Property(
                    name="resolution-tool",
                    value="attestful-oscal-resolver",
                ),
                Property(
                    name="source-profile-uuid",
                    value=str(profile.uuid),
                ),
            ],
            roles=profile.metadata.roles,
            parties=profile.metadata.parties,
            responsible_parties=profile.metadata.responsible_parties,
        )

        # Build catalog
        if groups:
            return Catalog(
                uuid=uuid4(),
                metadata=metadata,
                groups=groups,
                back_matter=profile.back_matter,
            )
        else:
            return Catalog(
                uuid=uuid4(),
                metadata=metadata,
                controls=controls,
                back_matter=profile.back_matter,
            )

    def clear_cache(self) -> None:
        """Clear resolution caches."""
        self._resolved_cache.clear()
        self.catalog_loader.clear_cache()
        self.profile_loader.clear_cache()


def create_profile(
    *,
    title: str,
    imports: list[dict[str, Any]],
    version: str = "1.0.0",
    modify: dict[str, Any] | None = None,
    merge: dict[str, Any] | None = None,
) -> Profile:
    """
    Create a new OSCAL profile.

    Args:
        title: Profile title
        imports: List of import definitions
        version: Profile version
        modify: Optional modifications
        merge: Optional merge settings

    Returns:
        Profile object

    Example:
        profile = create_profile(
            title="My Custom Profile",
            imports=[
                {
                    "href": "nist-800-53-rev5.json",
                    "include-controls": [
                        {"with-ids": ["AC-1", "AC-2", "AC-3"]}
                    ]
                }
            ],
            modify={
                "set-parameters": [
                    {"param-id": "ac-1_prm_1", "values": ["30 days"]}
                ]
            }
        )
    """
    from datetime import datetime, timezone
    from uuid import uuid4

    metadata = Metadata(
        title=title,
        last_modified=datetime.now(timezone.utc),
        version=version,
        oscal_version="1.1.2",
    )

    # Parse imports
    parsed_imports = [Import.model_validate(imp) for imp in imports]

    # Parse modify if provided
    parsed_modify = Modify.model_validate(modify) if modify else None

    # Parse merge if provided
    parsed_merge = Merge.model_validate(merge) if merge else None

    return Profile(
        uuid=uuid4(),
        metadata=metadata,
        imports=parsed_imports,
        modify=parsed_modify,
        merge=parsed_merge,
    )


def get_profile_summary(profile: Profile) -> dict[str, Any]:
    """
    Get a summary of a profile's configuration.

    Returns:
        Dictionary with profile summary information
    """
    summary: dict[str, Any] = {
        "uuid": str(profile.uuid),
        "title": profile.metadata.title,
        "version": profile.metadata.version,
        "imports": [],
        "modifications": {
            "parameter_settings": 0,
            "alterations": 0,
        },
    }

    # Summarize imports
    for imp in profile.imports:
        imp_summary: dict[str, Any] = {
            "href": imp.href,
            "include_all": imp.include_all is not None,
            "control_selections": 0,
            "control_exclusions": 0,
        }

        if imp.include_controls:
            for sel in imp.include_controls:
                if sel.with_ids:
                    imp_summary["control_selections"] += len(sel.with_ids)

        if imp.exclude_controls:
            for sel in imp.exclude_controls:
                if sel.with_ids:
                    imp_summary["control_exclusions"] += len(sel.with_ids)

        summary["imports"].append(imp_summary)

    # Summarize modifications
    if profile.modify:
        if profile.modify.set_parameters:
            summary["modifications"]["parameter_settings"] = len(
                profile.modify.set_parameters
            )
        if profile.modify.alters:
            summary["modifications"]["alterations"] = len(profile.modify.alters)

    return summary
