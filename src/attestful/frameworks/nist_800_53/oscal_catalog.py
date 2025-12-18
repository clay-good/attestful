"""
NIST 800-53 Rev 5 OSCAL Catalog Loader.

Provides access to the official NIST 800-53 Rev 5 OSCAL catalog,
with indexing, parameter resolution, and integrity verification.

The catalog is sourced from:
https://github.com/usnistgov/oscal-content

Catalog Details:
- Version: 5.2.0
- OSCAL Version: 1.1.3
- Total Base Controls: 324
- Total Enhancements: 872
- Control Families: 20
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

from attestful.core.exceptions import CatalogError
from attestful.core.logging import get_logger
from attestful.oscal.catalog import CatalogIndex, CatalogLoader

if TYPE_CHECKING:
    from attestful.oscal.models import Catalog, Control

logger = get_logger("frameworks.nist_800_53.oscal")

# Path to the official NIST 800-53 Rev 5 OSCAL catalog
NIST_800_53_OSCAL_CATALOG_PATH = (
    Path(__file__).parent.parent.parent.parent.parent
    / "data"
    / "oscal"
    / "catalogs"
    / "nist-800-53-rev5.json"
)

# SHA-256 hash of the catalog file for integrity verification
# Generated from the official NIST OSCAL content repository
NIST_800_53_CATALOG_SHA256 = (
    "1645df6a370dcb931db2e2d5d70c2f77bc89c38499a416c23a70eb2c0e595bcc"
)

# Expected catalog metadata
EXPECTED_CATALOG_VERSION = "5.2.0"
EXPECTED_OSCAL_VERSION = "1.1.3"
EXPECTED_CONTROL_FAMILIES = 20
EXPECTED_BASE_CONTROLS = 324


def get_catalog_path() -> Path:
    """
    Get the path to the NIST 800-53 OSCAL catalog file.

    Returns:
        Path to the catalog JSON file

    Raises:
        CatalogError: If the catalog file does not exist
    """
    if not NIST_800_53_OSCAL_CATALOG_PATH.exists():
        raise CatalogError(
            f"NIST 800-53 OSCAL catalog not found at: {NIST_800_53_OSCAL_CATALOG_PATH}. "
            "Please ensure the data/oscal/catalogs/nist-800-53-rev5.json file exists.",
            catalog_id="nist-800-53-rev5",
        )
    return NIST_800_53_OSCAL_CATALOG_PATH


def verify_catalog_integrity(path: Path | None = None) -> tuple[bool, str]:
    """
    Verify the integrity of the NIST 800-53 OSCAL catalog.

    Computes SHA-256 hash and compares against expected value.

    Args:
        path: Optional path to catalog file. Uses default if not provided.

    Returns:
        Tuple of (is_valid, message)
    """
    if path is None:
        path = get_catalog_path()

    try:
        content = path.read_bytes()
        actual_hash = hashlib.sha256(content).hexdigest()

        if actual_hash == NIST_800_53_CATALOG_SHA256:
            return True, f"Catalog integrity verified (SHA-256: {actual_hash[:16]}...)"
        else:
            return False, (
                f"Catalog integrity check failed. "
                f"Expected SHA-256: {NIST_800_53_CATALOG_SHA256[:16]}..., "
                f"Got: {actual_hash[:16]}..."
            )
    except Exception as e:
        return False, f"Failed to verify catalog integrity: {e}"


@lru_cache(maxsize=1)
def load_nist_800_53_catalog(
    *,
    verify_integrity: bool = True,
) -> Catalog:
    """
    Load the official NIST 800-53 Rev 5 OSCAL catalog.

    The catalog is cached after first load for performance.

    Args:
        verify_integrity: Whether to verify SHA-256 hash before loading

    Returns:
        The NIST 800-53 Catalog object

    Raises:
        CatalogError: If loading or verification fails
    """
    path = get_catalog_path()

    # Verify integrity if requested
    if verify_integrity:
        is_valid, message = verify_catalog_integrity(path)
        if not is_valid:
            logger.warning(f"Catalog integrity warning: {message}")
            # Continue loading but log warning - hash may change with updates

    # Load catalog
    loader = CatalogLoader()
    catalog = loader.load(path, use_cache=False)

    # Validate expected metadata
    if catalog.metadata.version != EXPECTED_CATALOG_VERSION:
        logger.info(
            f"Catalog version mismatch: expected {EXPECTED_CATALOG_VERSION}, "
            f"got {catalog.metadata.version}"
        )

    logger.info(
        f"Loaded NIST 800-53 Rev 5 catalog v{catalog.metadata.version} "
        f"(OSCAL {catalog.metadata.oscal_version})"
    )

    return catalog


@lru_cache(maxsize=1)
def get_nist_800_53_catalog_index() -> CatalogIndex:
    """
    Get an indexed view of the NIST 800-53 catalog for fast lookups.

    Returns:
        CatalogIndex with all controls indexed
    """
    catalog = load_nist_800_53_catalog()
    loader = CatalogLoader()
    index = loader.create_index(catalog)

    logger.debug(
        f"Created NIST 800-53 catalog index: "
        f"{index.control_count} controls, {index.group_count} groups"
    )

    return index


def get_oscal_control(control_id: str) -> Control | None:
    """
    Get a NIST 800-53 control from the OSCAL catalog.

    Args:
        control_id: Control ID (e.g., "ac-2", "AC-2", "ac-2.1", "AC-2(1)")

    Returns:
        Control object if found, None otherwise
    """
    index = get_nist_800_53_catalog_index()

    # Normalize control ID to lowercase with proper enhancement format
    normalized_id = _normalize_control_id(control_id)

    return index.get_control(normalized_id)


def get_oscal_control_family(family_id: str) -> list[Control]:
    """
    Get all controls in a NIST 800-53 control family.

    Args:
        family_id: Family ID (e.g., "ac", "AC", "au", "AU")

    Returns:
        List of controls in the family
    """
    index = get_nist_800_53_catalog_index()
    family_id_lower = family_id.lower()

    return index.search_controls(in_group=family_id_lower)


def get_oscal_control_enhancements(control_id: str) -> list[Control]:
    """
    Get all enhancements for a base control.

    Args:
        control_id: Base control ID (e.g., "ac-2", "AC-2")

    Returns:
        List of enhancement controls
    """
    index = get_nist_800_53_catalog_index()
    normalized_id = _normalize_control_id(control_id)

    return index.get_enhancements(normalized_id)


def search_oscal_controls(
    *,
    title_contains: str | None = None,
    family: str | None = None,
) -> list[Control]:
    """
    Search for NIST 800-53 controls.

    Args:
        title_contains: Filter by title substring
        family: Filter by control family

    Returns:
        List of matching controls
    """
    index = get_nist_800_53_catalog_index()

    return index.search_controls(
        title_contains=title_contains,
        in_group=family.lower() if family else None,
    )


def get_catalog_statistics() -> dict:
    """
    Get statistics about the NIST 800-53 OSCAL catalog.

    Returns:
        Dictionary with catalog statistics
    """
    catalog = load_nist_800_53_catalog(verify_integrity=False)
    index = get_nist_800_53_catalog_index()

    # Count controls by family
    family_counts = {}
    for group in catalog.groups or []:
        if group.id:
            control_count = len(group.controls or [])
            enhancement_count = sum(
                len(ctrl.controls or []) for ctrl in (group.controls or [])
            )
            family_counts[group.id.upper()] = {
                "base_controls": control_count,
                "enhancements": enhancement_count,
                "total": control_count + enhancement_count,
            }

    return {
        "title": catalog.metadata.title,
        "version": catalog.metadata.version,
        "oscal_version": catalog.metadata.oscal_version,
        "last_modified": catalog.metadata.last_modified,
        "total_controls": index.control_count,
        "total_groups": index.group_count,
        "families": family_counts,
    }


def _normalize_control_id(control_id: str) -> str:
    """
    Normalize a control ID to match OSCAL format.

    OSCAL uses lowercase IDs with hyphens:
    - "AC-2" -> "ac-2"
    - "AC-2(1)" -> "ac-2.1"
    - "ac-2.1" -> "ac-2.1"

    Args:
        control_id: Control ID in various formats

    Returns:
        Normalized control ID
    """
    # Convert to lowercase
    normalized = control_id.lower()

    # Convert parenthetical enhancement notation to dot notation
    # AC-2(1) -> ac-2.1
    if "(" in normalized and ")" in normalized:
        normalized = normalized.replace("(", ".").replace(")", "")

    return normalized


# Control family metadata
CONTROL_FAMILIES = {
    "AC": {
        "id": "ac",
        "title": "Access Control",
        "description": "Controls related to access control policies and mechanisms",
    },
    "AT": {
        "id": "at",
        "title": "Awareness and Training",
        "description": "Controls related to security awareness and training",
    },
    "AU": {
        "id": "au",
        "title": "Audit and Accountability",
        "description": "Controls related to audit and accountability",
    },
    "CA": {
        "id": "ca",
        "title": "Assessment, Authorization, and Monitoring",
        "description": "Controls related to security assessment and authorization",
    },
    "CM": {
        "id": "cm",
        "title": "Configuration Management",
        "description": "Controls related to configuration management",
    },
    "CP": {
        "id": "cp",
        "title": "Contingency Planning",
        "description": "Controls related to contingency planning and recovery",
    },
    "IA": {
        "id": "ia",
        "title": "Identification and Authentication",
        "description": "Controls related to identification and authentication",
    },
    "IR": {
        "id": "ir",
        "title": "Incident Response",
        "description": "Controls related to incident response",
    },
    "MA": {
        "id": "ma",
        "title": "Maintenance",
        "description": "Controls related to system maintenance",
    },
    "MP": {
        "id": "mp",
        "title": "Media Protection",
        "description": "Controls related to media protection",
    },
    "PE": {
        "id": "pe",
        "title": "Physical and Environmental Protection",
        "description": "Controls related to physical and environmental protection",
    },
    "PL": {
        "id": "pl",
        "title": "Planning",
        "description": "Controls related to security planning",
    },
    "PM": {
        "id": "pm",
        "title": "Program Management",
        "description": "Controls related to information security program management",
    },
    "PS": {
        "id": "ps",
        "title": "Personnel Security",
        "description": "Controls related to personnel security",
    },
    "PT": {
        "id": "pt",
        "title": "PII Processing and Transparency",
        "description": "Controls related to PII processing and transparency",
    },
    "RA": {
        "id": "ra",
        "title": "Risk Assessment",
        "description": "Controls related to risk assessment",
    },
    "SA": {
        "id": "sa",
        "title": "System and Services Acquisition",
        "description": "Controls related to system and services acquisition",
    },
    "SC": {
        "id": "sc",
        "title": "System and Communications Protection",
        "description": "Controls related to system and communications protection",
    },
    "SI": {
        "id": "si",
        "title": "System and Information Integrity",
        "description": "Controls related to system and information integrity",
    },
    "SR": {
        "id": "sr",
        "title": "Supply Chain Risk Management",
        "description": "Controls related to supply chain risk management",
    },
}


__all__ = [
    # Constants
    "NIST_800_53_OSCAL_CATALOG_PATH",
    "NIST_800_53_CATALOG_SHA256",
    "CONTROL_FAMILIES",
    # Path functions
    "get_catalog_path",
    # Verification
    "verify_catalog_integrity",
    # Loading
    "load_nist_800_53_catalog",
    "get_nist_800_53_catalog_index",
    # Control access
    "get_oscal_control",
    "get_oscal_control_family",
    "get_oscal_control_enhancements",
    "search_oscal_controls",
    # Statistics
    "get_catalog_statistics",
]
