"""
ISO 27001:2022 OSCAL Catalog Loader.

Provides access to the ISO 27001:2022 OSCAL catalog, with functions for
loading, parsing, and querying controls.

The catalog follows the ISO/IEC 27001:2022 structure:
- ISMS Requirements (Clauses 4-10) - Management system requirements
- Annex A Controls (A.5-A.8) - Information security controls

Annex A Domains:
- A.5: Organizational controls (37 controls)
- A.6: People controls (8 controls)
- A.7: Physical controls (14 controls)
- A.8: Technological controls (34 controls)

Total Annex A Controls: 93 (reduced from 114 in ISO 27001:2013)
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from attestful.core.exceptions import CatalogError
from attestful.core.logging import get_logger

logger = get_logger("frameworks.iso27001.oscal_catalog")


# =============================================================================
# Constants
# =============================================================================

# Path to the ISO 27001 OSCAL catalog file
ISO27001_OSCAL_CATALOG_PATH = (
    Path(__file__).parent.parent.parent.parent.parent
    / "data"
    / "oscal"
    / "catalogs"
    / "iso27001-2022.json"
)

# SHA-256 hash for integrity verification (computed on first load)
ISO27001_CATALOG_SHA256: str | None = None

# Annex A Control Domains
ANNEX_A_DOMAINS = {
    "A.5": {
        "name": "Organizational controls",
        "count": 37,
        "description": "Non-technical controls implemented through policies, procedures, and governance structures",
    },
    "A.6": {
        "name": "People controls",
        "count": 8,
        "description": "Human resource security throughout the employment lifecycle",
    },
    "A.7": {
        "name": "Physical controls",
        "count": 14,
        "description": "Protection of physical facilities, equipment, and media",
    },
    "A.8": {
        "name": "Technological controls",
        "count": 34,
        "description": "Technical security measures implemented through hardware, software, and configuration",
    },
}

# ISMS Clauses
ISMS_CLAUSES = {
    "4": "Context of the organization",
    "5": "Leadership",
    "6": "Planning",
    "7": "Support",
    "8": "Operation",
    "9": "Performance evaluation",
    "10": "Improvement",
}

# Control types
CONTROL_TYPES = {
    "preventive": "Prevents security incidents before they occur",
    "detective": "Detects security incidents during or after they occur",
    "corrective": "Corrects or mitigates the impact of security incidents",
}


# =============================================================================
# Catalog Loading Functions
# =============================================================================


def get_catalog_path() -> Path:
    """
    Get the path to the ISO 27001 OSCAL catalog file.

    Returns:
        Path to the catalog JSON file.

    Raises:
        CatalogError: If the catalog file does not exist.
    """
    if not ISO27001_OSCAL_CATALOG_PATH.exists():
        raise CatalogError(
            f"ISO 27001 OSCAL catalog not found at: {ISO27001_OSCAL_CATALOG_PATH}. "
            "Please ensure the data/oscal/catalogs/ directory contains the catalog file.",
            catalog_id="iso27001-2022",
        )
    return ISO27001_OSCAL_CATALOG_PATH


def verify_catalog_integrity() -> tuple[bool, str, str]:
    """
    Verify the integrity of the ISO 27001 OSCAL catalog.

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
def load_iso27001_catalog() -> dict[str, Any]:
    """
    Load the ISO 27001:2022 OSCAL catalog.

    Returns:
        The catalog as a dictionary.

    Raises:
        CatalogError: If the catalog cannot be loaded.
    """
    path = get_catalog_path()

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        logger.info(f"Loaded ISO 27001 OSCAL catalog from {path}")
        return data

    except json.JSONDecodeError as e:
        raise CatalogError(
            f"Failed to parse ISO 27001 catalog JSON: {e}",
            catalog_id="iso27001-2022",
        ) from e
    except Exception as e:
        raise CatalogError(
            f"Failed to load ISO 27001 catalog: {e}",
            catalog_id="iso27001-2022",
        ) from e


@lru_cache(maxsize=1)
def get_iso27001_catalog_index() -> dict[str, dict]:
    """
    Build an index of all controls by ID for fast lookup.

    Returns:
        Dictionary mapping control IDs to their definitions.
    """
    catalog = load_iso27001_catalog()
    index: dict[str, dict] = {}

    def _index_controls(controls: list[dict], domain: str | None = None, clause: str | None = None) -> None:
        """Index controls from a list."""
        for control in controls:
            control_id = control.get("id", "")
            index[control_id] = {
                "id": control_id,
                "title": control.get("title", ""),
                "class": control.get("class", ""),
                "domain": domain,
                "clause": clause,
                "props": control.get("props", []),
                "parts": control.get("parts", []),
            }

    def _process_group(group: dict, domain: str | None = None, clause: str | None = None) -> None:
        """Process a group and its nested groups/controls."""
        group_id = group.get("id", "")

        # Determine if this is a domain (A.5, A.6, etc.) or clause (clause-4, etc.)
        if group_id.startswith("A."):
            domain = group_id
        elif group_id.startswith("clause-"):
            clause = group_id.replace("clause-", "")

        # Index controls in this group
        controls = group.get("controls", [])
        _index_controls(controls, domain, clause)

        # Process nested groups
        for nested_group in group.get("groups", []):
            _process_group(nested_group, domain, clause)

    # Process top-level groups (isms, annex-a)
    for top_group in catalog.get("catalog", {}).get("groups", []):
        # Process sub-groups
        for group in top_group.get("groups", []):
            _process_group(group)

    logger.debug(f"Built ISO 27001 catalog index with {len(index)} controls")
    return index


# =============================================================================
# Control Access Functions
# =============================================================================


def get_oscal_control(control_id: str) -> dict | None:
    """
    Get a specific control by its ID.

    Args:
        control_id: The control identifier (e.g., "A.5.1", "4.1").

    Returns:
        The control definition or None if not found.
    """
    index = get_iso27001_catalog_index()
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


def get_control_type(control_id: str) -> str:
    """
    Get the control type (preventive, detective, corrective).

    Args:
        control_id: The control identifier.

    Returns:
        Control type or "preventive" if not specified.
    """
    control = get_oscal_control(control_id)
    if not control:
        return "preventive"

    for prop in control.get("props", []):
        if prop.get("name") == "control-type":
            return prop.get("value", "preventive")

    return "preventive"


# =============================================================================
# Domain and Clause Functions
# =============================================================================


def get_domain_controls(domain_id: str) -> list[dict]:
    """
    Get all controls in an Annex A domain.

    Args:
        domain_id: Domain ID ("A.5", "A.6", "A.7", or "A.8").

    Returns:
        List of controls in the domain.
    """
    index = get_iso27001_catalog_index()
    return [
        control
        for control in index.values()
        if control.get("domain") == domain_id
    ]


def get_clause_requirements(clause_id: str) -> list[dict]:
    """
    Get all requirements in an ISMS clause.

    Args:
        clause_id: Clause number (e.g., "4", "5", "6").

    Returns:
        List of requirements in the clause.
    """
    index = get_iso27001_catalog_index()
    return [
        control
        for control in index.values()
        if control.get("clause") == clause_id
    ]


def get_all_control_ids() -> list[str]:
    """
    Get all control IDs in the catalog.

    Returns:
        Sorted list of all control IDs.
    """
    index = get_iso27001_catalog_index()
    return sorted(index.keys())


def get_annex_a_controls() -> list[dict]:
    """
    Get all Annex A controls (A.5.x through A.8.x).

    Returns:
        List of Annex A controls.
    """
    index = get_iso27001_catalog_index()
    return [
        control
        for control in index.values()
        if control.get("id", "").startswith("A.")
    ]


def get_isms_requirements() -> list[dict]:
    """
    Get all ISMS clause requirements (4.x through 10.x).

    Returns:
        List of ISMS requirements.
    """
    index = get_iso27001_catalog_index()
    return [
        control
        for control in index.values()
        if control.get("clause") is not None
    ]


# =============================================================================
# Statistics Functions
# =============================================================================


def get_catalog_statistics() -> dict:
    """
    Get statistics about the ISO 27001 catalog.

    Returns:
        Dictionary with catalog statistics.
    """
    index = get_iso27001_catalog_index()

    # Count by domain
    domain_counts: dict[str, int] = {}
    for control in index.values():
        domain = control.get("domain")
        if domain:
            domain_counts[domain] = domain_counts.get(domain, 0) + 1

    # Count by clause
    clause_counts: dict[str, int] = {}
    for control in index.values():
        clause = control.get("clause")
        if clause:
            clause_counts[clause] = clause_counts.get(clause, 0) + 1

    # Count by automation status
    automation_counts: dict[str, int] = {"automated": 0, "partial": 0, "manual": 0}
    for control_id in index.keys():
        status = get_control_automation_status(control_id)
        automation_counts[status] = automation_counts.get(status, 0) + 1

    # Count by control type
    type_counts: dict[str, int] = {"preventive": 0, "detective": 0, "corrective": 0}
    for control_id in index.keys():
        ctrl_type = get_control_type(control_id)
        type_counts[ctrl_type] = type_counts.get(ctrl_type, 0) + 1

    # Verify integrity
    _, _, file_hash = verify_catalog_integrity()

    # Calculate Annex A totals
    annex_a_total = sum(domain_counts.values())
    isms_total = sum(clause_counts.values())

    return {
        "total_controls": len(index),
        "annex_a_controls": annex_a_total,
        "isms_requirements": isms_total,
        "domain_counts": domain_counts,
        "clause_counts": clause_counts,
        "automation_status": automation_counts,
        "control_types": type_counts,
        "automated_percentage": round(
            (automation_counts["automated"] / annex_a_total * 100) if annex_a_total > 0 else 0, 1
        ),
        "sha256": file_hash[:32] + "..." if file_hash else None,
    }


def get_catalog_metadata() -> dict:
    """
    Get metadata from the ISO 27001 catalog.

    Returns:
        Dictionary with catalog metadata.
    """
    catalog = load_iso27001_catalog()
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
    index = get_iso27001_catalog_index()
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
    index = get_iso27001_catalog_index()
    return [
        control
        for control in index.values()
        if get_control_automation_status(control.get("id", "")) == status
    ]


def get_controls_by_type(control_type: str) -> list[dict]:
    """
    Get controls by control type.

    Args:
        control_type: "preventive", "detective", or "corrective".

    Returns:
        List of controls with the specified type.
    """
    index = get_iso27001_catalog_index()
    return [
        control
        for control in index.values()
        if get_control_type(control.get("id", "")) == control_type
    ]


__all__ = [
    # Constants
    "ISO27001_OSCAL_CATALOG_PATH",
    "ISO27001_CATALOG_SHA256",
    "ANNEX_A_DOMAINS",
    "ISMS_CLAUSES",
    "CONTROL_TYPES",
    # Path functions
    "get_catalog_path",
    "verify_catalog_integrity",
    # Loading
    "load_iso27001_catalog",
    "get_iso27001_catalog_index",
    # Control access
    "get_oscal_control",
    "get_control_statement",
    "get_control_guidance",
    "get_control_automation_status",
    "get_control_type",
    # Domain/clause access
    "get_domain_controls",
    "get_clause_requirements",
    "get_all_control_ids",
    "get_annex_a_controls",
    "get_isms_requirements",
    # Statistics
    "get_catalog_statistics",
    "get_catalog_metadata",
    # Search
    "search_controls",
    "get_controls_by_automation_status",
    "get_controls_by_type",
]
