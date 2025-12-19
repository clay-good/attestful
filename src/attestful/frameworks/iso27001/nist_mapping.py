"""
ISO 27001:2022 to NIST 800-53 Rev 5 Control Mappings.

Provides bidirectional mappings between ISO 27001:2022 Annex A controls
and NIST 800-53 Rev 5 controls based on established crosswalk documentation.

Key features:
- Bidirectional mappings (ISO→NIST and NIST→ISO)
- Mapping strength indicators (strong, moderate, partial)
- Coverage analysis and gap identification
- Support for automated check inheritance

Mapping Sources:
- NIST SP 800-53 Rev 5 to ISO 27001:2022 crosswalk
- ISO/IEC 27001:2022 Annex A mapping guidance
- CIS Controls to ISO 27001 mappings (supplementary)

Note: Mappings are approximate. ISO 27001 and NIST 800-53 have different
structures and objectives. Some controls have no direct equivalent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from attestful.core.logging import get_logger
from attestful.frameworks.iso27001.controls import (
    ISO_27001_CONTROLS,
    DOMAIN_ORGANIZATIONAL,
    DOMAIN_PEOPLE,
    DOMAIN_PHYSICAL,
    DOMAIN_TECHNOLOGICAL,
)

logger = get_logger("frameworks.iso27001.nist_mapping")


# =============================================================================
# Enums and Data Classes
# =============================================================================


class MappingStrength(str, Enum):
    """Strength of control mapping relationship."""

    STRONG = "strong"  # Controls are nearly equivalent
    MODERATE = "moderate"  # Controls address similar requirements
    PARTIAL = "partial"  # Controls partially overlap
    NONE = "none"  # No meaningful mapping


@dataclass
class ControlMapping:
    """
    Represents a mapping between ISO 27001 and NIST 800-53 controls.

    Attributes:
        iso_control_id: ISO 27001 control ID (e.g., "A.5.1").
        nist_control_id: NIST 800-53 control ID (e.g., "PL-1").
        strength: Mapping strength indicator.
        notes: Additional mapping notes.
    """

    iso_control_id: str
    nist_control_id: str
    strength: MappingStrength = MappingStrength.MODERATE
    notes: str = ""


@dataclass
class ISO27001MappingSummary:
    """
    Summary of mappings for an ISO 27001 control.

    Attributes:
        iso_control_id: ISO 27001 control ID.
        iso_title: ISO 27001 control title.
        domain: ISO 27001 domain.
        nist_mappings: List of mapped NIST control IDs.
        soc2_mappings: List of mapped SOC 2 criteria.
        mapping_count: Number of NIST mappings.
        has_automated_checks: Whether automated checks exist via mappings.
    """

    iso_control_id: str
    iso_title: str
    domain: str
    nist_mappings: list[str] = field(default_factory=list)
    soc2_mappings: list[str] = field(default_factory=list)
    mapping_count: int = 0
    has_automated_checks: bool = False


# =============================================================================
# NIST 800-53 Control Family Definitions
# =============================================================================

NIST_CONTROL_FAMILIES = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "PT": "Personally Identifiable Information Processing and Transparency",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}


# =============================================================================
# Mapping Strength Definitions
# =============================================================================

# Controls with strong NIST equivalents (nearly 1:1 mapping)
STRONG_MAPPINGS: dict[str, list[str]] = {
    # Access Control mappings
    "A.5.15": ["AC-1", "AC-2", "AC-3"],  # Access control
    "A.5.16": ["IA-1", "IA-4", "IA-5"],  # Identity management
    "A.5.17": ["IA-5", "IA-6"],  # Authentication information
    "A.5.18": ["AC-2", "AC-6"],  # Access rights
    "A.8.2": ["AC-2", "AC-6"],  # Privileged access rights
    "A.8.3": ["AC-3", "AC-4"],  # Information access restriction
    "A.8.5": ["IA-2", "IA-5", "IA-8"],  # Secure authentication
    # Logging and Monitoring
    "A.8.15": ["AU-2", "AU-3", "AU-6"],  # Logging
    "A.8.16": ["SI-4", "AU-6"],  # Monitoring activities
    # Incident Response
    "A.5.24": ["IR-1", "IR-8"],  # Incident management planning
    "A.5.25": ["IR-4", "IR-5"],  # Assessment of security events
    "A.5.26": ["IR-4", "IR-6"],  # Response to incidents
    # Configuration and Change Management
    "A.8.9": ["CM-2", "CM-6", "CM-7"],  # Configuration management
    "A.8.32": ["CM-3", "CM-4"],  # Change management
    # Backup and Recovery
    "A.8.13": ["CP-9", "CP-10"],  # Information backup
    "A.8.14": ["CP-7", "CP-8"],  # Redundancy
    # Network Security
    "A.8.20": ["SC-7", "SC-8"],  # Networks security
    "A.8.22": ["SC-7", "AC-4"],  # Segregation of networks
    "A.8.24": ["SC-8", "SC-12", "SC-13"],  # Use of cryptography
}

# Controls with partial or contextual mappings
PARTIAL_MAPPINGS: dict[str, list[str]] = {
    # Organizational controls with governance focus
    "A.5.1": ["PL-1", "PM-1"],  # Policies (broader in ISO)
    "A.5.2": ["PM-2", "PS-2"],  # Roles and responsibilities
    "A.5.4": ["PM-1", "PM-13"],  # Management responsibilities
    # Physical controls (different focus)
    "A.7.1": ["PE-1", "PE-3"],  # Physical perimeters
    "A.7.2": ["PE-2", "PE-3"],  # Physical entry
    "A.7.5": ["PE-9", "PE-10", "PE-11"],  # Environmental threats
    # People controls (HR-focused)
    "A.6.1": ["PS-3"],  # Screening
    "A.6.2": ["PS-6", "PL-4"],  # Employment terms
    "A.6.3": ["AT-1", "AT-2", "AT-3"],  # Security awareness
}

# ISO controls with no direct NIST equivalent
ISO_UNIQUE_CONTROLS: list[str] = [
    # These controls have mappings but address ISO-specific requirements
    # that go beyond typical NIST coverage
]


# =============================================================================
# Bidirectional Mapping Functions
# =============================================================================


def get_iso_to_nist_mappings() -> dict[str, list[str]]:
    """
    Get all ISO 27001 to NIST 800-53 mappings.

    Returns:
        Dictionary mapping ISO control IDs to lists of NIST control IDs.
    """
    mappings: dict[str, list[str]] = {}

    for control_id, control in ISO_27001_CONTROLS.items():
        if control.nist_mappings:
            mappings[control_id] = list(control.nist_mappings)

    return mappings


def get_nist_to_iso_mappings() -> dict[str, list[str]]:
    """
    Get all NIST 800-53 to ISO 27001 mappings (reverse lookup).

    Returns:
        Dictionary mapping NIST control IDs to lists of ISO control IDs.
    """
    nist_to_iso: dict[str, list[str]] = {}

    for control_id, control in ISO_27001_CONTROLS.items():
        for nist_id in control.nist_mappings:
            if nist_id not in nist_to_iso:
                nist_to_iso[nist_id] = []
            nist_to_iso[nist_id].append(control_id)

    # Sort ISO controls for consistent output
    for nist_id in nist_to_iso:
        nist_to_iso[nist_id].sort()

    return nist_to_iso


def get_nist_controls_for_iso(iso_control_id: str) -> list[str]:
    """
    Get NIST 800-53 controls mapped to an ISO 27001 control.

    Args:
        iso_control_id: ISO 27001 control ID (e.g., "A.5.1").

    Returns:
        List of mapped NIST control IDs.
    """
    control = ISO_27001_CONTROLS.get(iso_control_id)
    if control:
        return list(control.nist_mappings)
    return []


def get_iso_controls_for_nist(nist_control_id: str) -> list[str]:
    """
    Get ISO 27001 controls mapped to a NIST 800-53 control.

    Args:
        nist_control_id: NIST 800-53 control ID (e.g., "AC-2").

    Returns:
        List of mapped ISO control IDs.
    """
    nist_to_iso = get_nist_to_iso_mappings()
    return nist_to_iso.get(nist_control_id, [])


def get_mapping_strength(iso_control_id: str, nist_control_id: str) -> MappingStrength:
    """
    Get the strength of mapping between an ISO and NIST control.

    Args:
        iso_control_id: ISO 27001 control ID.
        nist_control_id: NIST 800-53 control ID.

    Returns:
        Mapping strength indicator.
    """
    # Check if this is a strong mapping
    if iso_control_id in STRONG_MAPPINGS:
        if nist_control_id in STRONG_MAPPINGS[iso_control_id]:
            return MappingStrength.STRONG

    # Check if this is a partial mapping
    if iso_control_id in PARTIAL_MAPPINGS:
        if nist_control_id in PARTIAL_MAPPINGS[iso_control_id]:
            return MappingStrength.PARTIAL

    # Check if mapping exists at all
    control = ISO_27001_CONTROLS.get(iso_control_id)
    if control and nist_control_id in control.nist_mappings:
        return MappingStrength.MODERATE

    return MappingStrength.NONE


# =============================================================================
# Mapping Analysis Functions
# =============================================================================


def get_mapping_summary(iso_control_id: str) -> ISO27001MappingSummary | None:
    """
    Get a comprehensive mapping summary for an ISO 27001 control.

    Args:
        iso_control_id: ISO 27001 control ID.

    Returns:
        Mapping summary or None if control not found.
    """
    control = ISO_27001_CONTROLS.get(iso_control_id)
    if not control:
        return None

    return ISO27001MappingSummary(
        iso_control_id=iso_control_id,
        iso_title=control.title,
        domain=control.domain,
        nist_mappings=list(control.nist_mappings),
        soc2_mappings=list(control.soc2_mappings),
        mapping_count=len(control.nist_mappings),
        has_automated_checks=len(control.nist_mappings) > 0,  # Will be refined in Step 6.4.4
    )


def get_unmapped_iso_controls() -> list[str]:
    """
    Get ISO 27001 controls that have no NIST 800-53 mappings.

    Returns:
        List of ISO control IDs without NIST mappings.
    """
    unmapped = []
    for control_id, control in ISO_27001_CONTROLS.items():
        if not control.nist_mappings:
            unmapped.append(control_id)
    return sorted(unmapped)


def get_unmapped_nist_families() -> list[str]:
    """
    Get NIST 800-53 control families not covered by ISO 27001 mappings.

    Returns:
        List of NIST family codes not represented in mappings.
    """
    nist_to_iso = get_nist_to_iso_mappings()
    covered_families = set()

    for nist_id in nist_to_iso.keys():
        # Extract family from control ID (e.g., "AC" from "AC-2")
        family = nist_id.split("-")[0]
        covered_families.add(family)

    all_families = set(NIST_CONTROL_FAMILIES.keys())
    uncovered = all_families - covered_families

    return sorted(list(uncovered))


def get_mapping_coverage_by_domain() -> dict[str, dict[str, Any]]:
    """
    Get mapping coverage statistics by ISO 27001 domain.

    Returns:
        Dictionary with coverage statistics per domain.
    """
    domains = {
        DOMAIN_ORGANIZATIONAL: {"total": 0, "mapped": 0, "unmapped": []},
        DOMAIN_PEOPLE: {"total": 0, "mapped": 0, "unmapped": []},
        DOMAIN_PHYSICAL: {"total": 0, "mapped": 0, "unmapped": []},
        DOMAIN_TECHNOLOGICAL: {"total": 0, "mapped": 0, "unmapped": []},
    }

    for control_id, control in ISO_27001_CONTROLS.items():
        domain = control.domain
        if domain in domains:
            domains[domain]["total"] += 1
            if control.nist_mappings:
                domains[domain]["mapped"] += 1
            else:
                domains[domain]["unmapped"].append(control_id)

    # Calculate percentages
    for domain in domains.values():
        total = domain["total"]
        mapped = domain["mapped"]
        domain["coverage_pct"] = round((mapped / total * 100) if total > 0 else 0, 1)

    return domains


def get_nist_family_coverage() -> dict[str, dict[str, Any]]:
    """
    Get coverage statistics by NIST 800-53 control family.

    Returns:
        Dictionary with ISO coverage per NIST family.
    """
    nist_to_iso = get_nist_to_iso_mappings()
    families: dict[str, dict[str, Any]] = {}

    for family_code, family_name in NIST_CONTROL_FAMILIES.items():
        families[family_code] = {
            "name": family_name,
            "controls": [],
            "iso_mappings": [],
        }

    for nist_id, iso_ids in nist_to_iso.items():
        family = nist_id.split("-")[0]
        if family in families:
            families[family]["controls"].append(nist_id)
            families[family]["iso_mappings"].extend(iso_ids)

    # Deduplicate and count
    for family in families.values():
        family["control_count"] = len(family["controls"])
        family["iso_mappings"] = sorted(list(set(family["iso_mappings"])))
        family["iso_mapping_count"] = len(family["iso_mappings"])

    return families


# =============================================================================
# Mapping Export Functions
# =============================================================================


def export_mapping_matrix() -> list[dict[str, Any]]:
    """
    Export the full ISO-to-NIST mapping matrix.

    Returns:
        List of mapping entries with full details.
    """
    matrix = []

    for control_id, control in sorted(ISO_27001_CONTROLS.items()):
        for nist_id in control.nist_mappings:
            strength = get_mapping_strength(control_id, nist_id)
            matrix.append({
                "iso_control_id": control_id,
                "iso_title": control.title,
                "iso_domain": control.domain,
                "nist_control_id": nist_id,
                "nist_family": nist_id.split("-")[0],
                "nist_family_name": NIST_CONTROL_FAMILIES.get(nist_id.split("-")[0], "Unknown"),
                "mapping_strength": strength.value,
            })

    return matrix


def export_reverse_mapping_matrix() -> list[dict[str, Any]]:
    """
    Export the NIST-to-ISO reverse mapping matrix.

    Returns:
        List of reverse mapping entries.
    """
    nist_to_iso = get_nist_to_iso_mappings()
    matrix = []

    for nist_id in sorted(nist_to_iso.keys()):
        iso_ids = nist_to_iso[nist_id]
        family = nist_id.split("-")[0]

        for iso_id in iso_ids:
            control = ISO_27001_CONTROLS.get(iso_id)
            if control:
                strength = get_mapping_strength(iso_id, nist_id)
                matrix.append({
                    "nist_control_id": nist_id,
                    "nist_family": family,
                    "nist_family_name": NIST_CONTROL_FAMILIES.get(family, "Unknown"),
                    "iso_control_id": iso_id,
                    "iso_title": control.title,
                    "iso_domain": control.domain,
                    "mapping_strength": strength.value,
                })

    return matrix


# =============================================================================
# Statistics Functions
# =============================================================================


def get_mapping_statistics() -> dict[str, Any]:
    """
    Get comprehensive mapping statistics.

    Returns:
        Dictionary with mapping statistics.
    """
    iso_to_nist = get_iso_to_nist_mappings()
    nist_to_iso = get_nist_to_iso_mappings()

    # Count by strength
    strength_counts = {
        MappingStrength.STRONG.value: 0,
        MappingStrength.MODERATE.value: 0,
        MappingStrength.PARTIAL.value: 0,
    }

    for iso_id, nist_ids in iso_to_nist.items():
        for nist_id in nist_ids:
            strength = get_mapping_strength(iso_id, nist_id)
            if strength != MappingStrength.NONE:
                strength_counts[strength.value] += 1

    # Count controls with mappings
    iso_with_mappings = sum(1 for mappings in iso_to_nist.values() if mappings)

    # Domain coverage
    domain_coverage = get_mapping_coverage_by_domain()

    return {
        "total_iso_controls": len(ISO_27001_CONTROLS),
        "iso_controls_with_mappings": iso_with_mappings,
        "iso_controls_without_mappings": len(ISO_27001_CONTROLS) - iso_with_mappings,
        "unique_nist_controls_mapped": len(nist_to_iso),
        "total_mapping_pairs": sum(len(m) for m in iso_to_nist.values()),
        "mapping_strength_distribution": strength_counts,
        "domain_coverage": {
            domain: {
                "total": stats["total"],
                "mapped": stats["mapped"],
                "coverage_pct": stats["coverage_pct"],
            }
            for domain, stats in domain_coverage.items()
        },
        "nist_families_covered": len([
            f for f, stats in get_nist_family_coverage().items()
            if stats["control_count"] > 0
        ]),
        "nist_families_total": len(NIST_CONTROL_FAMILIES),
    }


__all__ = [
    # Enums and data classes
    "MappingStrength",
    "ControlMapping",
    "ISO27001MappingSummary",
    # Constants
    "NIST_CONTROL_FAMILIES",
    "STRONG_MAPPINGS",
    "PARTIAL_MAPPINGS",
    "ISO_UNIQUE_CONTROLS",
    # Bidirectional mapping functions
    "get_iso_to_nist_mappings",
    "get_nist_to_iso_mappings",
    "get_nist_controls_for_iso",
    "get_iso_controls_for_nist",
    "get_mapping_strength",
    # Analysis functions
    "get_mapping_summary",
    "get_unmapped_iso_controls",
    "get_unmapped_nist_families",
    "get_mapping_coverage_by_domain",
    "get_nist_family_coverage",
    # Export functions
    "export_mapping_matrix",
    "export_reverse_mapping_matrix",
    # Statistics
    "get_mapping_statistics",
]
