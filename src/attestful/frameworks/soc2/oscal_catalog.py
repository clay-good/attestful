"""
SOC 2 Trust Services Criteria OSCAL Catalog Loader.

Provides access to the SOC 2 Trust Services Criteria OSCAL catalog,
with functions for loading, parsing, and querying criteria.

The catalog follows the AICPA Trust Services Criteria (2017) structure:
- Security (Common Criteria CC1-CC9) - Mandatory
- Availability (A1) - Optional
- Processing Integrity (PI1) - Optional
- Confidentiality (C1) - Optional
- Privacy (P1-P8) - Optional
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from attestful.core.exceptions import CatalogError
from attestful.core.logging import get_logger

logger = get_logger("frameworks.soc2.oscal_catalog")


# =============================================================================
# Constants
# =============================================================================

# Path to the SOC 2 OSCAL catalog file
SOC2_OSCAL_CATALOG_PATH = (
    Path(__file__).parent.parent.parent.parent.parent
    / "data"
    / "oscal"
    / "catalogs"
    / "soc2-trust-services-criteria.json"
)

# SHA-256 hash for integrity verification (computed on first load)
SOC2_CATALOG_SHA256: str | None = None

# Trust Services Categories
TSC_CATEGORIES = {
    "CC": {
        "name": "Security (Common Criteria)",
        "mandatory": True,
        "description": "Controls over the security of the system",
    },
    "A": {
        "name": "Availability",
        "mandatory": False,
        "description": "Controls over system availability",
    },
    "PI": {
        "name": "Processing Integrity",
        "mandatory": False,
        "description": "Controls over processing completeness, validity, accuracy, and timeliness",
    },
    "C": {
        "name": "Confidentiality",
        "mandatory": False,
        "description": "Controls over confidential information protection",
    },
    "P": {
        "name": "Privacy",
        "mandatory": False,
        "description": "Controls over personal information handling",
    },
}

# Common Criteria Groups (within Security category)
CC_GROUPS = {
    "CC1": "Control Environment",
    "CC2": "Communication and Information",
    "CC3": "Risk Assessment",
    "CC4": "Monitoring Activities",
    "CC5": "Control Activities",
    "CC6": "Logical and Physical Access Controls",
    "CC7": "System Operations",
    "CC8": "Change Management",
    "CC9": "Risk Mitigation",
}


# =============================================================================
# Catalog Loading Functions
# =============================================================================


def get_catalog_path() -> Path:
    """
    Get the path to the SOC 2 OSCAL catalog file.

    Returns:
        Path to the catalog JSON file.

    Raises:
        CatalogError: If the catalog file does not exist.
    """
    if not SOC2_OSCAL_CATALOG_PATH.exists():
        raise CatalogError(
            f"SOC 2 OSCAL catalog not found at: {SOC2_OSCAL_CATALOG_PATH}. "
            "Please ensure the data/oscal/catalogs/ directory contains the catalog file.",
            catalog_id="soc2-trust-services-criteria",
        )
    return SOC2_OSCAL_CATALOG_PATH


def verify_catalog_integrity() -> tuple[bool, str, str]:
    """
    Verify the integrity of the SOC 2 OSCAL catalog.

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
def load_soc2_catalog() -> dict[str, Any]:
    """
    Load the SOC 2 Trust Services Criteria OSCAL catalog.

    Returns:
        The catalog as a dictionary.

    Raises:
        CatalogError: If the catalog cannot be loaded.
    """
    path = get_catalog_path()

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        logger.info(f"Loaded SOC 2 OSCAL catalog from {path}")
        return data

    except json.JSONDecodeError as e:
        raise CatalogError(
            f"Failed to parse SOC 2 catalog JSON: {e}",
            catalog_id="soc2-trust-services-criteria",
        ) from e
    except Exception as e:
        raise CatalogError(
            f"Failed to load SOC 2 catalog: {e}",
            catalog_id="soc2-trust-services-criteria",
        ) from e


@lru_cache(maxsize=1)
def get_soc2_catalog_index() -> dict[str, dict]:
    """
    Build an index of all criteria by ID for fast lookup.

    Returns:
        Dictionary mapping criterion IDs to their definitions.
    """
    catalog = load_soc2_catalog()
    index: dict[str, dict] = {}

    def _index_controls(controls: list[dict], category: str, group: str | None = None) -> None:
        """Recursively index controls."""
        for control in controls:
            control_id = control.get("id", "")
            index[control_id] = {
                "id": control_id,
                "title": control.get("title", ""),
                "class": control.get("class", ""),
                "category": category,
                "group": group,
                "props": control.get("props", []),
                "parts": control.get("parts", []),
            }

    def _process_group(group: dict, category: str) -> None:
        """Process a group and its nested groups/controls."""
        group_id = group.get("id", "")

        # Index controls in this group
        controls = group.get("controls", [])
        _index_controls(controls, category, group_id)

        # Process nested groups
        for nested_group in group.get("groups", []):
            _process_group(nested_group, category)

    # Process each category
    for category_group in catalog.get("catalog", {}).get("groups", []):
        category_id = category_group.get("id", "")

        # Index controls directly under category
        controls = category_group.get("controls", [])
        _index_controls(controls, category_id)

        # Process sub-groups (like CC1, CC2, etc. under CC)
        for group in category_group.get("groups", []):
            _process_group(group, category_id)

    logger.debug(f"Built SOC 2 catalog index with {len(index)} criteria")
    return index


# =============================================================================
# Criterion Access Functions
# =============================================================================


def get_oscal_criterion(criterion_id: str) -> dict | None:
    """
    Get a specific criterion by its ID.

    Args:
        criterion_id: The criterion identifier (e.g., "CC6.1", "A1.2").

    Returns:
        The criterion definition or None if not found.
    """
    index = get_soc2_catalog_index()
    return index.get(criterion_id)


def get_criterion_statement(criterion_id: str) -> str | None:
    """
    Get the statement prose for a criterion.

    Args:
        criterion_id: The criterion identifier.

    Returns:
        The statement text or None if not found.
    """
    criterion = get_oscal_criterion(criterion_id)
    if not criterion:
        return None

    for part in criterion.get("parts", []):
        if part.get("name") == "statement":
            return part.get("prose")

    return None


def get_criterion_points_of_focus(criterion_id: str) -> list[str]:
    """
    Get the points of focus for a criterion.

    Args:
        criterion_id: The criterion identifier.

    Returns:
        List of points of focus text.
    """
    criterion = get_oscal_criterion(criterion_id)
    if not criterion:
        return []

    points = []
    for part in criterion.get("parts", []):
        if part.get("name") == "points-of-focus":
            for pof_part in part.get("parts", []):
                if pof_part.get("name") == "point-of-focus":
                    prose = pof_part.get("prose", "")
                    if prose:
                        points.append(prose)

    return points


def get_criterion_automation_status(criterion_id: str) -> str:
    """
    Get the automation status for a criterion.

    Args:
        criterion_id: The criterion identifier.

    Returns:
        Automation status: "automated", "partial", or "manual".
    """
    criterion = get_oscal_criterion(criterion_id)
    if not criterion:
        return "manual"

    for prop in criterion.get("props", []):
        if prop.get("name") == "automation-status":
            return prop.get("value", "manual")

    return "manual"


# =============================================================================
# Category and Group Functions
# =============================================================================


def get_category_criteria(category_id: str) -> list[dict]:
    """
    Get all criteria in a category.

    Args:
        category_id: Category ID ("CC", "A", "PI", "C", or "P").

    Returns:
        List of criteria in the category.
    """
    index = get_soc2_catalog_index()
    return [
        criterion
        for criterion in index.values()
        if criterion.get("category") == category_id
    ]


def get_group_criteria(group_id: str) -> list[dict]:
    """
    Get all criteria in a Common Criteria group.

    Args:
        group_id: Group ID (e.g., "CC6", "CC7").

    Returns:
        List of criteria in the group.
    """
    index = get_soc2_catalog_index()
    return [
        criterion
        for criterion in index.values()
        if criterion.get("group") == group_id
    ]


def get_all_criteria_ids() -> list[str]:
    """
    Get all criterion IDs in the catalog.

    Returns:
        Sorted list of all criterion IDs.
    """
    index = get_soc2_catalog_index()
    return sorted(index.keys())


def get_mandatory_criteria() -> list[dict]:
    """
    Get all mandatory (Common Criteria) criteria.

    Returns:
        List of mandatory criteria (CC category).
    """
    return get_category_criteria("CC")


def get_optional_categories() -> dict[str, list[dict]]:
    """
    Get criteria organized by optional category.

    Returns:
        Dictionary mapping category IDs to their criteria.
    """
    return {
        "A": get_category_criteria("A"),
        "PI": get_category_criteria("PI"),
        "C": get_category_criteria("C"),
        "P": get_category_criteria("P"),
    }


# =============================================================================
# Statistics Functions
# =============================================================================


def get_catalog_statistics() -> dict:
    """
    Get statistics about the SOC 2 catalog.

    Returns:
        Dictionary with catalog statistics.
    """
    index = get_soc2_catalog_index()

    # Count by category
    category_counts: dict[str, int] = {}
    for criterion in index.values():
        category = criterion.get("category", "unknown")
        category_counts[category] = category_counts.get(category, 0) + 1

    # Count by automation status
    automation_counts: dict[str, int] = {"automated": 0, "partial": 0, "manual": 0}
    for criterion_id in index.keys():
        status = get_criterion_automation_status(criterion_id)
        automation_counts[status] = automation_counts.get(status, 0) + 1

    # Count CC groups
    cc_group_counts: dict[str, int] = {}
    for criterion in index.values():
        if criterion.get("category") == "CC":
            group = criterion.get("group", "unknown")
            cc_group_counts[group] = cc_group_counts.get(group, 0) + 1

    # Verify integrity
    _, _, file_hash = verify_catalog_integrity()

    return {
        "total_criteria": len(index),
        "category_counts": category_counts,
        "cc_group_counts": cc_group_counts,
        "automation_status": automation_counts,
        "mandatory_criteria": category_counts.get("CC", 0),
        "optional_criteria": sum(
            count for cat, count in category_counts.items() if cat != "CC"
        ),
        "sha256": file_hash[:32] + "..." if file_hash else None,
    }


def get_catalog_metadata() -> dict:
    """
    Get metadata from the SOC 2 catalog.

    Returns:
        Dictionary with catalog metadata.
    """
    catalog = load_soc2_catalog()
    metadata = catalog.get("catalog", {}).get("metadata", {})

    return {
        "uuid": catalog.get("catalog", {}).get("uuid"),
        "title": metadata.get("title"),
        "version": metadata.get("version"),
        "oscal_version": metadata.get("oscal-version"),
        "published": metadata.get("published"),
        "last_modified": metadata.get("last-modified"),
        "source": next(
            (p.get("value") for p in metadata.get("props", []) if p.get("name") == "source"),
            None,
        ),
    }


# =============================================================================
# Search Functions
# =============================================================================


def search_criteria(query: str, fields: list[str] | None = None) -> list[dict]:
    """
    Search criteria by text query.

    Args:
        query: Text to search for (case-insensitive).
        fields: Fields to search in (default: ["id", "title"]).

    Returns:
        List of matching criteria.
    """
    if fields is None:
        fields = ["id", "title"]

    query_lower = query.lower()
    index = get_soc2_catalog_index()
    results = []

    for criterion in index.values():
        for field in fields:
            value = criterion.get(field, "")
            if isinstance(value, str) and query_lower in value.lower():
                results.append(criterion)
                break

        # Also search in statement
        if "statement" in fields or len(fields) == 0:
            criterion_id = criterion.get("id", "")
            statement = get_criterion_statement(criterion_id)
            if statement and query_lower in statement.lower():
                if criterion not in results:
                    results.append(criterion)

    return results


__all__ = [
    # Constants
    "SOC2_OSCAL_CATALOG_PATH",
    "SOC2_CATALOG_SHA256",
    "TSC_CATEGORIES",
    "CC_GROUPS",
    # Path functions
    "get_catalog_path",
    "verify_catalog_integrity",
    # Loading
    "load_soc2_catalog",
    "get_soc2_catalog_index",
    # Criterion access
    "get_oscal_criterion",
    "get_criterion_statement",
    "get_criterion_points_of_focus",
    "get_criterion_automation_status",
    # Category/group access
    "get_category_criteria",
    "get_group_criteria",
    "get_all_criteria_ids",
    "get_mandatory_criteria",
    "get_optional_categories",
    # Statistics
    "get_catalog_statistics",
    "get_catalog_metadata",
    # Search
    "search_criteria",
]
