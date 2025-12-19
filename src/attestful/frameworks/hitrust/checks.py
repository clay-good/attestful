"""
HITRUST CSF Automated Compliance Checks.

Provides automated checks for HITRUST CSF controls by inheriting checks
from SOC 2, NIST 800-53, and ISO 27001 through the framework mapping graph.

HITRUST Check Inheritance Strategy:
-----------------------------------
HITRUST inherits checks through multiple framework bridges:

1. HITRUST -> NIST 800-53 -> SOC 2 checks
   - Primary inheritance path for technical controls
   - Strong mappings inherit all applicable SOC 2 checks

2. HITRUST -> ISO 27001 -> NIST 800-53 -> SOC 2 checks
   - Secondary path for organizational controls
   - Provides broader coverage through ISO's control structure

3. HITRUST -> HIPAA -> Evidence-based checks
   - Healthcare-specific requirements
   - Privacy and security safeguard checks

4. HITRUST -> PCI DSS -> Security checks
   - Payment card security requirements
   - Data protection and network security checks

Coverage by HITRUST Category:
-----------------------------
- Category 01 (Access Control): High automation via NIST AC family
- Category 09 (Operations): High automation via SOC 2 operational checks
- Category 10 (SDLC): Moderate automation via SA/CM families
- Category 08 (Physical): Limited automation, requires facility integration
- Category 02 (HR Security): Limited automation, requires HR integration
- Category 13 (Privacy): Moderate automation via HIPAA bridge

Maturity-Based Coverage:
------------------------
Checks are associated with maturity levels:
- Level 3 (Implemented): Full automated checks
- Level 4 (Measured): Automated + metrics collection
- Level 5 (Managed): Automated + continuous monitoring
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from attestful.core.evaluator import CheckDefinition
from attestful.core.logging import get_logger
from attestful.frameworks.hitrust.controls import (
    HITRUST_CONTROLS,
    HITRUST_FRAMEWORK_ID,
    HITRUST_VERSION,
    CATEGORY_ACCESS_CONTROL,
    CATEGORY_OPERATIONS,
    CATEGORY_SDLC,
    CATEGORY_PHYSICAL,
    CATEGORY_HR_SECURITY,
    CATEGORY_PRIVACY,
    CATEGORY_NAMES,
    get_control,
)
from attestful.frameworks.hitrust.framework_mappings import (
    get_nist_controls_for_hitrust,
    get_iso_controls_for_hitrust,
    get_hipaa_requirements_for_hitrust,
    get_pci_requirements_for_hitrust,
    get_all_mappings_for_hitrust,
    MappingStrength,
)

logger = get_logger("frameworks.hitrust.checks")


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class InheritedCheck:
    """
    Represents a check inherited from another framework.

    Attributes:
        hitrust_control_id: HITRUST control ID this check applies to.
        source_check_id: Original check ID from source framework.
        source_framework: Source framework (e.g., "soc2", "nist-800-53").
        bridge_path: Framework path used to reach this check.
        mapping_strength: Strength of the mapping relationship.
        check_definition: The actual check definition.
    """

    hitrust_control_id: str
    source_check_id: str
    source_framework: str
    bridge_path: list[str] = field(default_factory=list)
    mapping_strength: str = "strong"
    check_definition: CheckDefinition | None = None


@dataclass
class CheckCoverageReport:
    """
    Report on check coverage for a HITRUST control.

    Attributes:
        hitrust_control_id: HITRUST control ID.
        hitrust_title: Control title.
        category: Control category code.
        category_name: Category display name.
        maturity_level: Required maturity level (1-5).
        has_automated_checks: Whether automated checks exist.
        inherited_check_count: Number of inherited checks.
        native_check_count: Number of HITRUST-specific checks.
        check_ids: List of applicable check IDs.
        coverage_status: Coverage status (full, partial, none).
        inheritance_sources: Frameworks contributing checks.
        notes: Additional notes about coverage.
    """

    hitrust_control_id: str
    hitrust_title: str
    category: str
    category_name: str
    maturity_level: int = 3
    has_automated_checks: bool = False
    inherited_check_count: int = 0
    native_check_count: int = 0
    check_ids: list[str] = field(default_factory=list)
    coverage_status: str = "none"
    inheritance_sources: list[str] = field(default_factory=list)
    notes: str = ""


# =============================================================================
# Check Lookup Functions (by Framework)
# =============================================================================


def get_soc2_checks_by_nist(nist_control_id: str) -> list[dict[str, Any]]:
    """
    Get SOC 2 checks that map to a specific NIST 800-53 control.

    Args:
        nist_control_id: NIST 800-53 control ID (e.g., "AC-2").

    Returns:
        List of check info dictionaries with id, title, and frameworks.
    """
    try:
        from attestful.frameworks.soc2.checks import (
            get_soc2_aws_checks,
            get_soc2_azure_checks,
            get_soc2_gcp_checks,
        )

        matching_checks = []

        # Collect all SOC 2 checks
        all_checks = (
            get_soc2_aws_checks() +
            get_soc2_azure_checks() +
            get_soc2_gcp_checks()
        )

        for check in all_checks:
            # Check if this check maps to the NIST control
            nist_mappings = check.frameworks.get("nist-800-53", [])
            if nist_control_id in nist_mappings:
                matching_checks.append({
                    "id": check.id,
                    "title": check.title,
                    "description": check.description,
                    "severity": check.severity,
                    "resource_types": check.resource_types,
                    "frameworks": check.frameworks,
                    "check_definition": check,
                    "source": "soc2",
                })

        return matching_checks

    except ImportError:
        logger.warning("SOC 2 checks module not available for inheritance")
        return []


def get_iso27001_checks_by_control(iso_control_id: str) -> list[dict[str, Any]]:
    """
    Get ISO 27001 checks for a specific control.

    Args:
        iso_control_id: ISO 27001 control ID (e.g., "A.8.5").

    Returns:
        List of check info dictionaries.
    """
    try:
        from attestful.frameworks.iso27001.checks import (
            get_iso27001_checks_for_control,
        )

        checks = get_iso27001_checks_for_control(iso_control_id)
        return [
            {
                "id": check.id,
                "title": check.title,
                "description": check.description,
                "severity": check.severity,
                "resource_types": check.resource_types,
                "frameworks": check.frameworks,
                "check_definition": check,
                "source": "iso27001",
            }
            for check in checks
        ]

    except ImportError:
        logger.warning("ISO 27001 checks module not available for inheritance")
        return []


# =============================================================================
# Check Inheritance Functions
# =============================================================================


def get_checks_via_nist_bridge(hitrust_control_id: str) -> list[InheritedCheck]:
    """
    Get checks inherited through the NIST 800-53 bridge.

    Path: HITRUST -> NIST 800-53 -> SOC 2 checks

    Args:
        hitrust_control_id: HITRUST control ID.

    Returns:
        List of inherited checks via NIST bridge.
    """
    inherited = []
    seen_check_ids: set[str] = set()

    # Get NIST controls mapped to this HITRUST control
    nist_controls = get_nist_controls_for_hitrust(hitrust_control_id)

    for nist_id in nist_controls:
        soc2_checks = get_soc2_checks_by_nist(nist_id)

        for check_info in soc2_checks:
            check_id = check_info["id"]

            if check_id in seen_check_ids:
                continue
            seen_check_ids.add(check_id)

            inherited.append(InheritedCheck(
                hitrust_control_id=hitrust_control_id,
                source_check_id=check_id,
                source_framework="soc2",
                bridge_path=["hitrust", "nist-800-53", "soc2"],
                mapping_strength="strong",
                check_definition=check_info.get("check_definition"),
            ))

    return inherited


def get_checks_via_iso_bridge(hitrust_control_id: str) -> list[InheritedCheck]:
    """
    Get checks inherited through the ISO 27001 bridge.

    Path: HITRUST -> ISO 27001 -> (inherited checks)

    Args:
        hitrust_control_id: HITRUST control ID.

    Returns:
        List of inherited checks via ISO bridge.
    """
    inherited = []
    seen_check_ids: set[str] = set()

    # Get ISO controls mapped to this HITRUST control
    iso_controls = get_iso_controls_for_hitrust(hitrust_control_id)

    for iso_id in iso_controls:
        iso_checks = get_iso27001_checks_by_control(iso_id)

        for check_info in iso_checks:
            check_id = check_info["id"]

            if check_id in seen_check_ids:
                continue
            seen_check_ids.add(check_id)

            inherited.append(InheritedCheck(
                hitrust_control_id=hitrust_control_id,
                source_check_id=check_id,
                source_framework="iso27001",
                bridge_path=["hitrust", "iso-27001", check_info.get("source", "soc2")],
                mapping_strength="moderate",
                check_definition=check_info.get("check_definition"),
            ))

    return inherited


def get_inherited_checks_for_hitrust_control(
    hitrust_control_id: str,
    include_iso_bridge: bool = True,
) -> list[InheritedCheck]:
    """
    Get all checks inherited from other frameworks for a HITRUST control.

    Traverses the framework mapping graph to find all applicable checks.

    Args:
        hitrust_control_id: HITRUST control ID (e.g., "01.a").
        include_iso_bridge: Whether to include ISO 27001 bridge path.

    Returns:
        List of inherited check objects.
    """
    inherited = []
    seen_check_ids: set[str] = set()

    # Primary path: HITRUST -> NIST 800-53 -> SOC 2
    nist_inherited = get_checks_via_nist_bridge(hitrust_control_id)
    for ic in nist_inherited:
        if ic.source_check_id not in seen_check_ids:
            seen_check_ids.add(ic.source_check_id)
            inherited.append(ic)

    # Secondary path: HITRUST -> ISO 27001 -> (inherited checks)
    if include_iso_bridge:
        iso_inherited = get_checks_via_iso_bridge(hitrust_control_id)
        for ic in iso_inherited:
            if ic.source_check_id not in seen_check_ids:
                seen_check_ids.add(ic.source_check_id)
                inherited.append(ic)

    return inherited


def get_all_inherited_checks() -> dict[str, list[InheritedCheck]]:
    """
    Get all inherited checks for all HITRUST controls.

    Returns:
        Dictionary mapping HITRUST control IDs to lists of inherited checks.
    """
    all_inherited: dict[str, list[InheritedCheck]] = {}

    for hitrust_control_id in HITRUST_CONTROLS.keys():
        inherited = get_inherited_checks_for_hitrust_control(hitrust_control_id)
        if inherited:
            all_inherited[hitrust_control_id] = inherited

    return all_inherited


# =============================================================================
# Coverage Analysis Functions
# =============================================================================


def get_check_coverage_report(hitrust_control_id: str) -> CheckCoverageReport | None:
    """
    Get a coverage report for a specific HITRUST control.

    Args:
        hitrust_control_id: HITRUST control ID.

    Returns:
        Coverage report or None if control not found.
    """
    control = get_control(hitrust_control_id)
    if not control:
        return None

    inherited = get_inherited_checks_for_hitrust_control(hitrust_control_id)
    inherited_count = len(inherited)
    check_ids = [ic.source_check_id for ic in inherited]

    # Determine inheritance sources
    sources = list(set(ic.source_framework for ic in inherited))

    # Determine coverage status based on maturity level expectations
    if inherited_count >= 5:
        coverage_status = "full"
    elif inherited_count >= 2:
        coverage_status = "partial"
    elif inherited_count > 0:
        coverage_status = "minimal"
    else:
        coverage_status = "none"

    # Add notes based on category
    notes = ""
    category = control.category
    if category == CATEGORY_ACCESS_CONTROL:
        if inherited_count == 0:
            notes = "Access control - should have high automation potential"
    elif category == CATEGORY_OPERATIONS:
        if inherited_count == 0:
            notes = "Operations control - should have high automation potential"
    elif category == CATEGORY_HR_SECURITY:
        notes = "HR control - requires HR system integration"
    elif category == CATEGORY_PHYSICAL:
        notes = "Physical control - requires facility system integration"
    elif category == CATEGORY_PRIVACY:
        notes = "Privacy control - may require HIPAA-specific checks"

    category_name = CATEGORY_NAMES.get(category, f"Category {category}")

    return CheckCoverageReport(
        hitrust_control_id=hitrust_control_id,
        hitrust_title=control.title,
        category=category,
        category_name=category_name,
        maturity_level=control.maturity_level,
        has_automated_checks=inherited_count > 0,
        inherited_check_count=inherited_count,
        native_check_count=0,  # To be updated when native checks are added
        check_ids=check_ids,
        coverage_status=coverage_status,
        inheritance_sources=sources,
        notes=notes,
    )


def get_controls_needing_checks() -> list[str]:
    """
    Get HITRUST controls that need new checks (no inherited coverage).

    Focuses on controls that should be automatable based on category.

    Returns:
        List of control IDs without automated check coverage.
    """
    automatable_categories = {
        CATEGORY_ACCESS_CONTROL,
        CATEGORY_OPERATIONS,
        CATEGORY_SDLC,
    }

    needing_checks = []

    for hitrust_control_id, control in HITRUST_CONTROLS.items():
        if control.category in automatable_categories:
            inherited = get_inherited_checks_for_hitrust_control(hitrust_control_id)
            if not inherited:
                needing_checks.append(hitrust_control_id)

    return sorted(needing_checks)


def get_controls_with_full_coverage() -> list[str]:
    """
    Get HITRUST controls with full automated check coverage.

    Returns:
        List of control IDs with 5+ inherited checks.
    """
    full_coverage = []

    for hitrust_control_id in HITRUST_CONTROLS.keys():
        inherited = get_inherited_checks_for_hitrust_control(hitrust_control_id)
        if len(inherited) >= 5:
            full_coverage.append(hitrust_control_id)

    return sorted(full_coverage)


def get_coverage_by_category() -> dict[str, dict[str, Any]]:
    """
    Get check coverage statistics by HITRUST category.

    Returns:
        Dictionary with coverage statistics per category.
    """
    categories: dict[str, dict[str, Any]] = {}

    # Initialize all categories
    for cat_code, cat_name in CATEGORY_NAMES.items():
        categories[cat_code] = {
            "name": cat_name,
            "total": 0,
            "with_checks": 0,
            "check_count": 0,
        }

    # Populate statistics
    for hitrust_control_id, control in HITRUST_CONTROLS.items():
        category = control.category
        if category in categories:
            categories[category]["total"] += 1

            inherited = get_inherited_checks_for_hitrust_control(hitrust_control_id)
            if inherited:
                categories[category]["with_checks"] += 1
                categories[category]["check_count"] += len(inherited)

    # Calculate percentages
    for cat_stats in categories.values():
        total = cat_stats["total"]
        with_checks = cat_stats["with_checks"]
        cat_stats["coverage_pct"] = round(
            (with_checks / total * 100) if total > 0 else 0, 1
        )
        cat_stats["avg_checks"] = round(
            (cat_stats["check_count"] / with_checks) if with_checks > 0 else 0, 1
        )

    return categories


def get_coverage_by_maturity_level() -> dict[int, dict[str, Any]]:
    """
    Get check coverage statistics by HITRUST maturity level.

    Returns:
        Dictionary with coverage statistics per maturity level (1-5).
    """
    levels: dict[int, dict[str, Any]] = {
        1: {"name": "Policy", "total": 0, "with_checks": 0, "check_count": 0},
        2: {"name": "Procedure", "total": 0, "with_checks": 0, "check_count": 0},
        3: {"name": "Implemented", "total": 0, "with_checks": 0, "check_count": 0},
        4: {"name": "Measured", "total": 0, "with_checks": 0, "check_count": 0},
        5: {"name": "Managed", "total": 0, "with_checks": 0, "check_count": 0},
    }

    for hitrust_control_id, control in HITRUST_CONTROLS.items():
        level = control.maturity_level
        if level in levels:
            levels[level]["total"] += 1

            inherited = get_inherited_checks_for_hitrust_control(hitrust_control_id)
            if inherited:
                levels[level]["with_checks"] += 1
                levels[level]["check_count"] += len(inherited)

    # Calculate percentages
    for level_stats in levels.values():
        total = level_stats["total"]
        with_checks = level_stats["with_checks"]
        level_stats["coverage_pct"] = round(
            (with_checks / total * 100) if total > 0 else 0, 1
        )
        level_stats["avg_checks"] = round(
            (level_stats["check_count"] / with_checks) if with_checks > 0 else 0, 1
        )

    return levels


# =============================================================================
# Check Retrieval Functions
# =============================================================================


def get_hitrust_checks_for_control(hitrust_control_id: str) -> list[CheckDefinition]:
    """
    Get all automated checks applicable to a HITRUST control.

    Combines inherited checks from other frameworks with any HITRUST-specific
    native checks.

    Args:
        hitrust_control_id: HITRUST control ID.

    Returns:
        List of check definitions.
    """
    checks = []

    # Get inherited checks
    inherited = get_inherited_checks_for_hitrust_control(hitrust_control_id)
    for ic in inherited:
        if ic.check_definition:
            checks.append(ic.check_definition)

    # Native HITRUST checks would be added here
    # (to be implemented for HITRUST-specific requirements)

    return checks


def get_all_hitrust_checks() -> list[CheckDefinition]:
    """
    Get all automated checks for HITRUST CSF compliance.

    Returns:
        List of all check definitions (inherited + native).
    """
    all_checks: list[CheckDefinition] = []
    seen_ids: set[str] = set()

    for hitrust_control_id in HITRUST_CONTROLS.keys():
        checks = get_hitrust_checks_for_control(hitrust_control_id)
        for check in checks:
            if check.id not in seen_ids:
                seen_ids.add(check.id)
                all_checks.append(check)

    return all_checks


def get_checks_by_category(category_code: str) -> list[CheckDefinition]:
    """
    Get all automated checks for a HITRUST category.

    Args:
        category_code: Category code (e.g., "01", "09").

    Returns:
        List of check definitions for the category.
    """
    all_checks: list[CheckDefinition] = []
    seen_ids: set[str] = set()

    for hitrust_control_id, control in HITRUST_CONTROLS.items():
        if control.category == category_code:
            checks = get_hitrust_checks_for_control(hitrust_control_id)
            for check in checks:
                if check.id not in seen_ids:
                    seen_ids.add(check.id)
                    all_checks.append(check)

    return all_checks


# =============================================================================
# Statistics Functions
# =============================================================================


def get_check_statistics() -> dict[str, Any]:
    """
    Get comprehensive statistics about HITRUST check coverage.

    Returns:
        Dictionary with check statistics.
    """
    all_inherited = get_all_inherited_checks()

    # Count unique checks
    unique_checks: set[str] = set()
    source_counts: dict[str, int] = {}

    for inherited_list in all_inherited.values():
        for ic in inherited_list:
            unique_checks.add(ic.source_check_id)
            source = ic.source_framework
            source_counts[source] = source_counts.get(source, 0) + 1

    # Category coverage
    category_coverage = get_coverage_by_category()

    # Maturity level coverage
    maturity_coverage = get_coverage_by_maturity_level()

    # Controls needing checks
    needing_checks = get_controls_needing_checks()

    # Full coverage controls
    full_coverage = get_controls_with_full_coverage()

    # Calculate overall coverage percentage
    total_controls = len(HITRUST_CONTROLS)
    controls_with_checks = len(all_inherited)
    overall_coverage_pct = round(
        (controls_with_checks / total_controls * 100) if total_controls > 0 else 0, 1
    )

    return {
        "total_hitrust_controls": total_controls,
        "controls_with_inherited_checks": controls_with_checks,
        "controls_without_checks": total_controls - controls_with_checks,
        "overall_coverage_pct": overall_coverage_pct,
        "unique_inherited_checks": len(unique_checks),
        "total_check_mappings": sum(len(v) for v in all_inherited.values()),
        "inheritance_sources": source_counts,
        "controls_needing_new_checks": len(needing_checks),
        "controls_with_full_coverage": len(full_coverage),
        "category_coverage": {
            code: {
                "name": stats["name"],
                "total": stats["total"],
                "with_checks": stats["with_checks"],
                "coverage_pct": stats["coverage_pct"],
                "avg_checks_per_control": stats["avg_checks"],
            }
            for code, stats in category_coverage.items()
        },
        "maturity_coverage": {
            level: {
                "name": stats["name"],
                "total": stats["total"],
                "with_checks": stats["with_checks"],
                "coverage_pct": stats["coverage_pct"],
            }
            for level, stats in maturity_coverage.items()
        },
        "framework_version": HITRUST_VERSION,
        "framework_id": HITRUST_FRAMEWORK_ID,
    }


def get_inheritance_summary() -> list[dict[str, Any]]:
    """
    Get a summary of all check inheritances.

    Returns:
        List of inheritance summary entries.
    """
    summary = []

    for hitrust_control_id, control in sorted(HITRUST_CONTROLS.items()):
        inherited = get_inherited_checks_for_hitrust_control(hitrust_control_id)

        # Get all framework mappings
        mappings = get_all_mappings_for_hitrust(hitrust_control_id)

        summary.append({
            "hitrust_control_id": hitrust_control_id,
            "hitrust_title": control.title,
            "category": control.category,
            "category_name": CATEGORY_NAMES.get(control.category, "Unknown"),
            "maturity_level": control.maturity_level,
            "framework_mappings": {
                "nist_800_53": list(control.nist_mappings),
                "iso_27001": list(control.iso_mappings),
                "hipaa": list(control.hipaa_mappings),
                "pci_dss": list(control.pci_mappings),
            },
            "inherited_checks": [
                {
                    "check_id": ic.source_check_id,
                    "source": ic.source_framework,
                    "bridge_path": ic.bridge_path,
                    "mapping_strength": ic.mapping_strength,
                }
                for ic in inherited
            ],
            "inherited_count": len(inherited),
            "has_coverage": len(inherited) > 0,
        })

    return summary


def export_coverage_matrix() -> list[dict[str, Any]]:
    """
    Export a coverage matrix for reporting.

    Returns:
        List of coverage entries suitable for CSV/Excel export.
    """
    matrix = []

    for hitrust_control_id, control in sorted(HITRUST_CONTROLS.items()):
        report = get_check_coverage_report(hitrust_control_id)
        if report:
            matrix.append({
                "control_id": hitrust_control_id,
                "title": control.title,
                "category_code": control.category,
                "category_name": report.category_name,
                "maturity_level": control.maturity_level,
                "has_automated_checks": report.has_automated_checks,
                "inherited_check_count": report.inherited_check_count,
                "coverage_status": report.coverage_status,
                "inheritance_sources": ", ".join(report.inheritance_sources),
                "check_ids": ", ".join(report.check_ids[:10]),  # First 10
                "notes": report.notes,
            })

    return matrix


__all__ = [
    # Data classes
    "InheritedCheck",
    "CheckCoverageReport",
    # Check lookup functions
    "get_soc2_checks_by_nist",
    "get_iso27001_checks_by_control",
    # Check inheritance functions
    "get_checks_via_nist_bridge",
    "get_checks_via_iso_bridge",
    "get_inherited_checks_for_hitrust_control",
    "get_all_inherited_checks",
    # Coverage analysis
    "get_check_coverage_report",
    "get_controls_needing_checks",
    "get_controls_with_full_coverage",
    "get_coverage_by_category",
    "get_coverage_by_maturity_level",
    # Check retrieval
    "get_hitrust_checks_for_control",
    "get_all_hitrust_checks",
    "get_checks_by_category",
    # Statistics
    "get_check_statistics",
    "get_inheritance_summary",
    "export_coverage_matrix",
]
