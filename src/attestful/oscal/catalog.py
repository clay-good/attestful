"""
OSCAL Catalog loader and indexer.

Provides functionality for loading OSCAL catalogs from files or URLs,
and indexing controls for fast lookup.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import orjson
import yaml

from attestful.core.exceptions import CatalogError
from attestful.core.logging import get_logger
from attestful.oscal.models import Catalog, Control, Group, Parameter

logger = get_logger("oscal.catalog")


class CatalogIndex:
    """
    Index for fast control lookup in a catalog.

    Provides O(1) lookup by control ID and various traversal methods.
    """

    def __init__(self, catalog: Catalog) -> None:
        self.catalog = catalog
        self._controls: dict[str, Control] = {}
        self._control_groups: dict[str, Group] = {}
        self._control_parents: dict[str, str] = {}  # child_id -> parent_id
        self._groups: dict[str, Group] = {}
        self._parameters: dict[str, Parameter] = {}
        self._build_index()

    def _build_index(self) -> None:
        """Build the control index from the catalog."""
        # Index top-level controls
        if self.catalog.controls:
            for control in self.catalog.controls:
                self._index_control(control, None, None)

        # Index groups
        if self.catalog.groups:
            for group in self.catalog.groups:
                self._index_group(group, None)

        # Index top-level parameters
        if self.catalog.params:
            for param in self.catalog.params:
                self._parameters[param.id] = param

        logger.debug(
            f"Indexed {len(self._controls)} controls, "
            f"{len(self._groups)} groups, "
            f"{len(self._parameters)} parameters"
        )

    def _index_group(self, group: Group, parent_group: Group | None) -> None:
        """Recursively index a group and its contents."""
        if group.id:
            self._groups[group.id] = group

        # Index parameters in group
        if group.params:
            for param in group.params:
                self._parameters[param.id] = param

        # Index controls in group
        if group.controls:
            for control in group.controls:
                self._index_control(control, group, None)

        # Index nested groups
        if group.groups:
            for subgroup in group.groups:
                self._index_group(subgroup, group)

    def _index_control(
        self,
        control: Control,
        group: Group | None,
        parent_control: Control | None,
    ) -> None:
        """Index a control and its enhancements."""
        self._controls[control.id] = control

        if group:
            self._control_groups[control.id] = group

        if parent_control:
            self._control_parents[control.id] = parent_control.id

        # Index parameters in control
        if control.params:
            for param in control.params:
                self._parameters[param.id] = param

        # Index control enhancements (nested controls)
        if control.controls:
            for enhancement in control.controls:
                self._index_control(enhancement, group, control)

    def get_control(self, control_id: str) -> Control | None:
        """
        Get a control by ID.

        Args:
            control_id: The control ID (e.g., "AC-2", "AC-2(1)")

        Returns:
            The Control if found, None otherwise
        """
        return self._controls.get(control_id)

    def get_control_with_path(self, control_id: str) -> tuple[Control | None, list[str]]:
        """
        Get a control and its path (parent controls/groups).

        Returns:
            Tuple of (control, path) where path is list of parent IDs
        """
        control = self._controls.get(control_id)
        if not control:
            return None, []

        path: list[str] = []

        # Build path from parent controls
        current_id = control_id
        while current_id in self._control_parents:
            parent_id = self._control_parents[current_id]
            path.insert(0, parent_id)
            current_id = parent_id

        # Add group if present
        if control_id in self._control_groups:
            group = self._control_groups[control_id]
            if group.id:
                path.insert(0, group.id)

        return control, path

    def get_enhancements(self, control_id: str) -> list[Control]:
        """
        Get all enhancements (child controls) for a control.

        Args:
            control_id: The parent control ID (e.g., "AC-2")

        Returns:
            List of enhancement controls
        """
        control = self._controls.get(control_id)
        if not control or not control.controls:
            return []
        return list(control.controls)

    def get_parent_control(self, control_id: str) -> Control | None:
        """Get the parent control of an enhancement."""
        parent_id = self._control_parents.get(control_id)
        if parent_id:
            return self._controls.get(parent_id)
        return None

    def get_group(self, control_id: str) -> Group | None:
        """Get the group containing a control."""
        return self._control_groups.get(control_id)

    def get_parameter(self, param_id: str) -> Parameter | None:
        """Get a parameter by ID."""
        return self._parameters.get(param_id)

    def list_all_controls(self) -> list[Control]:
        """Get all controls in the catalog."""
        return list(self._controls.values())

    def list_control_ids(self) -> list[str]:
        """Get all control IDs."""
        return list(self._controls.keys())

    def list_groups(self) -> list[Group]:
        """Get all groups in the catalog."""
        return list(self._groups.values())

    def search_controls(
        self,
        *,
        title_contains: str | None = None,
        has_property: str | None = None,
        in_group: str | None = None,
    ) -> list[Control]:
        """
        Search for controls matching criteria.

        Args:
            title_contains: Filter by title substring (case-insensitive)
            has_property: Filter by property name
            in_group: Filter by group ID

        Returns:
            List of matching controls
        """
        results: list[Control] = []

        for control_id, control in self._controls.items():
            # Filter by title
            if title_contains:
                if title_contains.lower() not in control.title.lower():
                    continue

            # Filter by property
            if has_property:
                if not control.props:
                    continue
                if not any(p.name == has_property for p in control.props):
                    continue

            # Filter by group
            if in_group:
                group = self._control_groups.get(control_id)
                if not group or group.id != in_group:
                    continue

            results.append(control)

        return results

    @property
    def control_count(self) -> int:
        """Total number of controls in the index."""
        return len(self._controls)

    @property
    def group_count(self) -> int:
        """Total number of groups in the index."""
        return len(self._groups)


class CatalogLoader:
    """
    Load OSCAL catalogs from various sources.

    Supports JSON, YAML, and XML formats.
    """

    def __init__(self) -> None:
        self._cache: dict[str, Catalog] = {}

    def load(self, path: str | Path, *, use_cache: bool = True) -> Catalog:
        """
        Load a catalog from a file path.

        Args:
            path: Path to the catalog file
            use_cache: Whether to use cached catalog if available

        Returns:
            Parsed Catalog object

        Raises:
            CatalogError: If the file cannot be loaded or parsed
        """
        path = Path(path)
        cache_key = str(path.resolve())

        if use_cache and cache_key in self._cache:
            logger.debug(f"Using cached catalog: {path}")
            return self._cache[cache_key]

        if not path.exists():
            raise CatalogError(f"Catalog file not found: {path}", catalog_id=str(path))

        try:
            content = path.read_text(encoding="utf-8")
            catalog = self._parse_content(content, path.suffix.lower())

            if use_cache:
                self._cache[cache_key] = catalog

            logger.info(f"Loaded catalog: {catalog.metadata.title} ({path})")
            return catalog

        except Exception as e:
            if isinstance(e, CatalogError):
                raise
            raise CatalogError(
                f"Failed to load catalog: {e}",
                catalog_id=str(path),
                cause=e,
            ) from e

    def load_from_string(
        self,
        content: str,
        format: str = "json",
    ) -> Catalog:
        """
        Load a catalog from a string.

        Args:
            content: The catalog content
            format: Format of the content ("json", "yaml", "xml")

        Returns:
            Parsed Catalog object
        """
        return self._parse_content(content, f".{format}")

    def _parse_content(self, content: str, suffix: str) -> Catalog:
        """Parse catalog content based on format."""
        if suffix in (".json",):
            data = orjson.loads(content)
        elif suffix in (".yaml", ".yml"):
            data = yaml.safe_load(content)
        elif suffix in (".xml",):
            raise CatalogError("XML parsing not yet implemented")
        else:
            # Try JSON first, then YAML
            try:
                data = orjson.loads(content)
            except orjson.JSONDecodeError:
                data = yaml.safe_load(content)

        # Handle wrapped format (catalog key at root)
        if "catalog" in data:
            data = data["catalog"]

        return Catalog.model_validate(data)

    def clear_cache(self) -> None:
        """Clear the catalog cache."""
        self._cache.clear()

    def create_index(self, catalog: Catalog) -> CatalogIndex:
        """Create an index for a catalog."""
        return CatalogIndex(catalog)


def resolve_parameters(text: str, parameters: dict[str, str]) -> str:
    """
    Resolve parameter placeholders in control prose.

    OSCAL uses {{ insert: param, param-id }} syntax for parameters.

    Args:
        text: The text containing parameter placeholders
        parameters: Dictionary mapping parameter IDs to values

    Returns:
        Text with parameters resolved
    """
    import re

    # Pattern for OSCAL parameter insertion points
    # {{ insert: param, param-id }}
    pattern = r"\{\{\s*insert:\s*param,\s*([^}\s]+)\s*\}\}"

    def replace_param(match: re.Match[str]) -> str:
        param_id = match.group(1)
        return parameters.get(param_id, f"[{param_id}]")

    return re.sub(pattern, replace_param, text)
