"""
HITRUST CSF OSCAL Catalog Loader.

Provides access to the HITRUST CSF OSCAL catalog, with functions for
loading, parsing, and querying controls.

The catalog follows the HITRUST CSF structure:
- 14 Control Categories (00-13)
- Control requirements with maturity levels
- Mappings to underlying frameworks (NIST, ISO, HIPAA, PCI)

Control Categories:
- 00: Information Security Management Program
- 01: Access Control
- 02: Human Resources Security
- 03: Risk Management
- 04: Security Policy
- 05: Organization of Information Security
- 06: Compliance
- 07: Asset Management
- 08: Physical and Environmental Security
- 09: Communications and Operations Management
- 10: Information Systems Acquisition, Development, and Maintenance
- 11: Information Security Incident Management
- 12: Business Continuity Management
- 13: Privacy Practices
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from attestful.core.exceptions import CatalogError
from attestful.core.logging import get_logger

logger = get_logger("frameworks.hitrust.oscal_catalog")


# =============================================================================
# Constants
# =============================================================================

# Path to the HITRUST OSCAL catalog file
HITRUST_OSCAL_CATALOG_PATH = (
    Path(__file__).parent.parent.parent.parent.parent
    / "data"
    / "oscal"
    / "catalogs"
    / "hitrust-csf-11.json"
)

# SHA-256 hash for integrity verification (computed on first load)
HITRUST_CATALOG_SHA256: str | None = None

# Control Categories
CONTROL_CATEGORIES = {
    "00": {
        "name": "Information Security Management Program",
        "description": "Establishing and maintaining an information security program",
    },
    "01": {
        "name": "Access Control",
        "description": "Controlling access to information and systems",
    },
    "02": {
        "name": "Human Resources Security",
        "description": "Security throughout the employment lifecycle",
    },
    "03": {
        "name": "Risk Management",
        "description": "Identifying and managing information security risks",
    },
    "04": {
        "name": "Security Policy",
        "description": "Information security policy management",
    },
    "05": {
        "name": "Organization of Information Security",
        "description": "Internal organization and external party management",
    },
    "06": {
        "name": "Compliance",
        "description": "Compliance with legal and regulatory requirements",
    },
    "07": {
        "name": "Asset Management",
        "description": "Asset inventory, ownership, and acceptable use",
    },
    "08": {
        "name": "Physical and Environmental Security",
        "description": "Physical protection of facilities and equipment",
    },
    "09": {
        "name": "Communications and Operations Management",
        "description": "Operational procedures and security controls",
    },
    "10": {
        "name": "Information Systems Acquisition, Development, and Maintenance",
        "description": "Secure development and maintenance practices",
    },
    "11": {
        "name": "Information Security Incident Management",
        "description": "Incident reporting, response, and management",
    },
    "12": {
        "name": "Business Continuity Management",
        "description": "Business continuity planning and testing",
    },
    "13": {
        "name": "Privacy Practices",
        "description": "Privacy governance and data protection",
    },
}

# Maturity Levels
MATURITY_LEVELS = {
    1: {"name": "Policy", "description": "Policy exists and is documented"},
    2: {"name": "Procedure", "description": "Procedure exists and is implemented"},
    3: {"name": "Implemented", "description": "Control is implemented"},
    4: {"name": "Measured", "description": "Control is measured and monitored"},
    5: {"name": "Managed", "description": "Control is managed and optimized"},
}

# Control types
CONTROL_TYPES = {
    "administrative": "Administrative/procedural control",
    "technical": "Technical/automated control",
    "physical": "Physical security control",
}


# =============================================================================
# Catalog Loading Functions
# =============================================================================


def get_catalog_path() -> Path:
    """
    Get the path to the HITRUST OSCAL catalog file.

    Returns:
        Path to the catalog JSON file.

    Raises:
        CatalogError: If the catalog file does not exist.
    """
    if not HITRUST_OSCAL_CATALOG_PATH.exists():
        raise CatalogError(
            f"HITRUST OSCAL catalog not found at: {HITRUST_OSCAL_CATALOG_PATH}. "
            "Please ensure the data/oscal/catalogs/ directory contains the catalog file.",
            catalog_id="hitrust-csf-11",
        )
    return HITRUST_OSCAL_CATALOG_PATH


def verify_catalog_integrity() -> tuple[bool, str, str]:
    """
    Verify the integrity of the HITRUST OSCAL catalog.

    Computes SHA-256 hash of the catalog file.

    Returns:
        Tuple of (is_valid, message, hash).
    """
    try:
        path = get_catalog_path()
        content = path.read_bytes()
        actual_hash = hashlib.sha256(content).hexdigest()

        return True, f"Catalog hash computed (SHA-256: {actual_hash[:16]}...)", actual_hash

    except Exception as e:
        return False, f"Failed to verify catalog integrity: {e}", ""


@lru_cache(maxsize=1)
def load_hitrust_catalog() -> dict[str, Any]:
    """
    Load the HITRUST CSF OSCAL catalog.

    Returns:
        The catalog as a dictionary.

    Raises:
        CatalogError: If the catalog cannot be loaded.
    """
    path = get_catalog_path()

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        logger.info(f"Loaded HITRUST OSCAL catalog from {path}")
        return data

    except json.JSONDecodeError as e:
        raise CatalogError(
            f"Failed to parse HITRUST catalog JSON: {e}",
            catalog_id="hitrust-csf-11",
        ) from e
    except Exception as e:
        raise CatalogError(
            f"Failed to load HITRUST catalog: {e}",
            catalog_id="hitrust-csf-11",
        ) from e


@lru_cache(maxsize=1)
def get_hitrust_catalog_index() -> dict[str, dict]:
    """
    Build an index of all controls by ID for fast lookup.

    Returns:
        Dictionary mapping control IDs to their definitions.
    """
    catalog = load_hitrust_catalog()
    index: dict[str, dict] = {}

    def _index_controls(controls: list[dict], category: str | None = None) -> None:
        """Index controls from a list."""
        for control in controls:
            control_id = control.get("id", "")
            index[control_id] = {
                "id": control_id,
                "title": control.get("title", ""),
                "class": control.get("class", ""),
                "category": category,
                "props": control.get("props", []),
                "parts": control.get("parts", []),
            }

    def _process_group(group: dict) -> None:
        """Process a group and its controls."""
        group_id = group.get("id", "")

        # Extract category code from group ID (e.g., "category-01" -> "01")
        category = None
        if group_id.startswith("category-"):
            category = group_id.replace("category-", "")

        # Index controls in this group
        controls = group.get("controls", [])
        _index_controls(controls, category)

    # Process all groups
    for group in catalog.get("catalog", {}).get("groups", []):
        _process_group(group)

    logger.debug(f"Built HITRUST catalog index with {len(index)} controls")
    return index


# =============================================================================
# Control Access Functions
# =============================================================================


def get_oscal_control(control_id: str) -> dict | None:
    """
    Get a specific control by its ID.

    Args:
        control_id: The control identifier (e.g., "01.a", "09.t").

    Returns:
        The control definition or None if not found.
    """
    index = get_hitrust_catalog_index()
    return index.get(control_id)


def get_control_statement(control_id: str) -> str | None:
    """
    Get the statement prose for a control.

    Args:
        control_id: The control identifier.

    Returns:
        The statement text or None if not found.
    """
    control = get_oscal_control(control_id)
    if not control:
        return None

    for part in control.get("parts", []):
        if part.get("name") == "statement":
            return part.get("prose")

    return None


def get_control_guidance(control_id: str) -> str | None:
    """
    Get the implementation guidance for a control.

    Args:
        control_id: The control identifier.

    Returns:
        The guidance text or None if not found.
    """
    control = get_oscal_control(control_id)
    if not control:
        return None

    for part in control.get("parts", []):
        if part.get("name") == "guidance":
            return part.get("prose")

    return None


def get_control_automation_status(control_id: str) -> str:
    """
    Get the automation status for a control.

    Args:
        control_id: The control identifier.

    Returns:
        Automation status: "automated", "partial", or "manual".
    """
    control = get_oscal_control(control_id)
    if not control:
        return "manual"

    for prop in control.get("props", []):
        if prop.get("name") == "automation-status":
            return prop.get("value", "manual")

    return "manual"


def get_control_maturity_level(control_id: str) -> int:
    """
    Get the required maturity level for a control.

    Args:
        control_id: The control identifier.

    Returns:
        Maturity level (1-5), defaults to 3 (Implemented).
    """
    control = get_oscal_control(control_id)
    if not control:
        return 3

    for prop in control.get("props", []):
        if prop.get("name") == "maturity-level":
            try:
                return int(prop.get("value", "3"))
            except ValueError:
                return 3

    return 3


def get_control_type(control_id: str) -> str:
    """
    Get the control type (administrative, technical, physical).

    Args:
        control_id: The control identifier.

    Returns:
        Control type or "administrative" if not specified.
    """
    control = get_oscal_control(control_id)
    if not control:
        return "administrative"

    for prop in control.get("props", []):
        if prop.get("name") == "control-type":
            return prop.get("value", "administrative")

    return "administrative"


# =============================================================================
# Category Functions
# =============================================================================


def get_category_controls(category_code: str) -> list[dict]:
    """
    Get all controls in a control category.

    Args:
        category_code: Category code (e.g., "01", "09", "13").

    Returns:
        List of controls in the category.
    """
    index = get_hitrust_catalog_index()
    return [
        control
        for control in index.values()
        if control.get("category") == category_code
    ]


def get_all_control_ids() -> list[str]:
    """
    Get all control IDs in the catalog.

    Returns:
        Sorted list of all control IDs.
    """
    index = get_hitrust_catalog_index()
    return sorted(index.keys())


def get_controls_by_maturity(level: int) -> list[dict]:
    """
    Get all controls at or below a maturity level.

    Args:
        level: Maturity level (1-5).

    Returns:
        List of controls at or below the specified maturity level.
    """
    index = get_hitrust_catalog_index()
    return [
        control
        for control in index.values()
        if get_control_maturity_level(control.get("id", "")) <= level
    ]


# =============================================================================
# Statistics Functions
# =============================================================================


def get_catalog_statistics() -> dict:
    """
    Get statistics about the HITRUST catalog.

    Returns:
        Dictionary with catalog statistics.
    """
    index = get_hitrust_catalog_index()

    # Count by category
    category_counts: dict[str, int] = {}
    for control in index.values():
        category = control.get("category")
        if category:
            category_counts[category] = category_counts.get(category, 0) + 1

    # Count by automation status
    automation_counts: dict[str, int] = {"automated": 0, "partial": 0, "manual": 0}
    for control_id in index.keys():
        status = get_control_automation_status(control_id)
        automation_counts[status] = automation_counts.get(status, 0) + 1

    # Count by control type
    type_counts: dict[str, int] = {"administrative": 0, "technical": 0, "physical": 0}
    for control_id in index.keys():
        ctrl_type = get_control_type(control_id)
        type_counts[ctrl_type] = type_counts.get(ctrl_type, 0) + 1

    # Count by maturity level
    maturity_counts: dict[int, int] = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
    for control_id in index.keys():
        level = get_control_maturity_level(control_id)
        maturity_counts[level] = maturity_counts.get(level, 0) + 1

    # Verify integrity
    _, _, file_hash = verify_catalog_integrity()

    total_controls = len(index)

    return {
        "total_controls": total_controls,
        "categories": len(CONTROL_CATEGORIES),
        "category_counts": category_counts,
        "automation_status": automation_counts,
        "control_types": type_counts,
        "maturity_levels": maturity_counts,
        "automated_percentage": round(
            (automation_counts["automated"] / total_controls * 100) if total_controls > 0 else 0, 1
        ),
        "sha256": file_hash[:32] + "..." if file_hash else None,
    }


def get_catalog_metadata() -> dict:
    """
    Get metadata from the HITRUST catalog.

    Returns:
        Dictionary with catalog metadata.
    """
    catalog = load_hitrust_catalog()
    metadata = catalog.get("catalog", {}).get("metadata", {})

    return {
        "uuid": catalog.get("catalog", {}).get("uuid"),
        "title": metadata.get("title"),
        "version": metadata.get("version"),
        "oscal_version": metadata.get("oscal-version"),
        "published": metadata.get("published"),
        "last_modified": metadata.get("last-modified"),
        "framework": next(
            (p.get("value") for p in metadata.get("props", []) if p.get("name") == "framework"),
            None,
        ),
    }


# =============================================================================
# Search Functions
# =============================================================================


def search_controls(query: str, fields: list[str] | None = None) -> list[dict]:
    """
    Search controls by text query.

    Args:
        query: Text to search for (case-insensitive).
        fields: Fields to search in (default: ["id", "title"]).

    Returns:
        List of matching controls.
    """
    if fields is None:
        fields = ["id", "title"]

    query_lower = query.lower()
    index = get_hitrust_catalog_index()
    results = []

    for control in index.values():
        for field in fields:
            value = control.get(field, "")
            if isinstance(value, str) and query_lower in value.lower():
                results.append(control)
                break

        # Also search in statement
        if "statement" in fields or len(fields) == 0:
            control_id = control.get("id", "")
            statement = get_control_statement(control_id)
            if statement and query_lower in statement.lower():
                if control not in results:
                    results.append(control)

    return results


def get_controls_by_automation_status(status: str) -> list[dict]:
    """
    Get controls by automation status.

    Args:
        status: "automated", "partial", or "manual".

    Returns:
        List of controls with the specified automation status.
    """
    index = get_hitrust_catalog_index()
    return [
        control
        for control in index.values()
        if get_control_automation_status(control.get("id", "")) == status
    ]


def get_controls_by_type(control_type: str) -> list[dict]:
    """
    Get controls by control type.

    Args:
        control_type: "administrative", "technical", or "physical".

    Returns:
        List of controls with the specified type.
    """
    index = get_hitrust_catalog_index()
    return [
        control
        for control in index.values()
        if get_control_type(control.get("id", "")) == control_type
    ]


__all__ = [
    # Constants
    "HITRUST_OSCAL_CATALOG_PATH",
    "HITRUST_CATALOG_SHA256",
    "CONTROL_CATEGORIES",
    "MATURITY_LEVELS",
    "CONTROL_TYPES",
    # Path functions
    "get_catalog_path",
    "verify_catalog_integrity",
    # Loading
    "load_hitrust_catalog",
    "get_hitrust_catalog_index",
    # Control access
    "get_oscal_control",
    "get_control_statement",
    "get_control_guidance",
    "get_control_automation_status",
    "get_control_maturity_level",
    "get_control_type",
    # Category access
    "get_category_controls",
    "get_all_control_ids",
    "get_controls_by_maturity",
    # Statistics
    "get_catalog_statistics",
    "get_catalog_metadata",
    # Search
    "search_controls",
    "get_controls_by_automation_status",
    "get_controls_by_type",
]
