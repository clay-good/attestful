"""
ISO 27001:2022 Automated Compliance Checks.

Provides automated checks for ISO 27001:2022 controls by inheriting checks
from SOC 2 and mapping them through NIST 800-53 control relationships.

Approach:
1. ISO 27001 controls map to NIST 800-53 controls (via nist_mapping.py)
2. SOC 2 checks already map to NIST 800-53 controls (via frameworks field)
3. We inherit SOC 2 checks for ISO 27001 controls sharing NIST mappings
4. Additional ISO-specific checks are added where gaps exist

Check Inheritance Strategy:
- A.8.x (Technological controls): High automation potential via SOC 2 checks
- A.5.x (Organizational controls): Limited automation, evidence-based
- A.6.x (People controls): Mostly manual, HR system integration
- A.7.x (Physical controls): Limited automation, facility system integration

Coverage Statistics (via inheritance):
- Total ISO 27001 controls: 93
- Controls with inherited checks: ~45 (technological + some organizational)
- Controls requiring evidence: ~48 (people, physical, governance)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from attestful.core.evaluator import CheckDefinition
from attestful.core.logging import get_logger
from attestful.frameworks.iso27001.controls import (
    ISO_27001_CONTROLS,
    ISO_27001_FRAMEWORK_ID,
    ISO_27001_VERSION,
    DOMAIN_ORGANIZATIONAL,
    DOMAIN_PEOPLE,
    DOMAIN_PHYSICAL,
    DOMAIN_TECHNOLOGICAL,
)
from attestful.frameworks.iso27001.nist_mapping import (
    get_nist_controls_for_iso,
    get_iso_to_nist_mappings,
)

logger = get_logger("frameworks.iso27001.checks")


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class InheritedCheck:
    """
    Represents a check inherited from another framework.

    Attributes:
        iso_control_id: ISO 27001 control ID this check applies to.
        source_check_id: Original check ID from source framework.
        source_framework: Source framework (e.g., "soc2").
        nist_bridge: NIST 800-53 control(s) used to bridge the mapping.
        check_definition: The actual check definition.
    """

    iso_control_id: str
    source_check_id: str
    source_framework: str
    nist_bridge: list[str] = field(default_factory=list)
    check_definition: CheckDefinition | None = None


@dataclass
class CheckCoverageReport:
    """
    Report on check coverage for ISO 27001 controls.

    Attributes:
        iso_control_id: ISO 27001 control ID.
        iso_title: Control title.
        domain: Control domain.
        has_automated_checks: Whether automated checks exist.
        inherited_check_count: Number of inherited checks.
        native_check_count: Number of ISO-specific checks.
        check_ids: List of applicable check IDs.
        coverage_status: Coverage status (full, partial, none).
        notes: Additional notes about coverage.
    """

    iso_control_id: str
    iso_title: str
    domain: str
    has_automated_checks: bool = False
    inherited_check_count: int = 0
    native_check_count: int = 0
    check_ids: list[str] = field(default_factory=list)
    coverage_status: str = "none"
    notes: str = ""


# =============================================================================
# Check Inheritance Functions
# =============================================================================


def get_soc2_checks_by_nist(nist_control_id: str) -> list[dict[str, Any]]:
    """
    Get SOC 2 checks that map to a specific NIST 800-53 control.

    This function imports SOC 2 checks lazily to avoid circular imports
    and searches for checks that include the NIST control in their
    frameworks mapping.

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
                })

        return matching_checks

    except ImportError:
        logger.warning("SOC 2 checks module not available for inheritance")
        return []


def get_inherited_checks_for_iso_control(iso_control_id: str) -> list[InheritedCheck]:
    """
    Get all checks inherited from other frameworks for an ISO 27001 control.

    Uses NIST 800-53 mappings as a bridge to find applicable checks
    from SOC 2 and other frameworks.

    Args:
        iso_control_id: ISO 27001 control ID (e.g., "A.8.5").

    Returns:
        List of inherited check objects.
    """
    inherited = []

    # Get NIST mappings for this ISO control
    nist_controls = get_nist_controls_for_iso(iso_control_id)

    if not nist_controls:
        return inherited

    # For each NIST control, find SOC 2 checks
    seen_check_ids: set[str] = set()

    for nist_id in nist_controls:
        soc2_checks = get_soc2_checks_by_nist(nist_id)

        for check_info in soc2_checks:
            check_id = check_info["id"]

            # Avoid duplicates
            if check_id in seen_check_ids:
                continue
            seen_check_ids.add(check_id)

            inherited.append(InheritedCheck(
                iso_control_id=iso_control_id,
                source_check_id=check_id,
                source_framework="soc2",
                nist_bridge=[nist_id],
                check_definition=check_info.get("check_definition"),
            ))

    return inherited


def get_all_inherited_checks() -> dict[str, list[InheritedCheck]]:
    """
    Get all inherited checks for all ISO 27001 controls.

    Returns:
        Dictionary mapping ISO control IDs to lists of inherited checks.
    """
    all_inherited: dict[str, list[InheritedCheck]] = {}

    for iso_control_id in ISO_27001_CONTROLS.keys():
        inherited = get_inherited_checks_for_iso_control(iso_control_id)
        if inherited:
            all_inherited[iso_control_id] = inherited

    return all_inherited


# =============================================================================
# Coverage Analysis Functions
# =============================================================================


def get_check_coverage_report(iso_control_id: str) -> CheckCoverageReport | None:
    """
    Get a coverage report for a specific ISO 27001 control.

    Args:
        iso_control_id: ISO 27001 control ID.

    Returns:
        Coverage report or None if control not found.
    """
    control = ISO_27001_CONTROLS.get(iso_control_id)
    if not control:
        return None

    inherited = get_inherited_checks_for_iso_control(iso_control_id)
    inherited_count = len(inherited)
    check_ids = [ic.source_check_id for ic in inherited]

    # Determine coverage status
    if inherited_count >= 3:
        coverage_status = "full"
    elif inherited_count > 0:
        coverage_status = "partial"
    else:
        coverage_status = "none"

    # Add notes based on domain
    notes = ""
    if control.domain == DOMAIN_ORGANIZATIONAL:
        notes = "Organizational control - may require evidence collection"
    elif control.domain == DOMAIN_PEOPLE:
        notes = "People control - requires HR system integration"
    elif control.domain == DOMAIN_PHYSICAL:
        notes = "Physical control - requires facility system integration"
    elif control.domain == DOMAIN_TECHNOLOGICAL:
        if inherited_count == 0:
            notes = "Technological control - may need ISO-specific checks"

    return CheckCoverageReport(
        iso_control_id=iso_control_id,
        iso_title=control.title,
        domain=control.domain,
        has_automated_checks=inherited_count > 0,
        inherited_check_count=inherited_count,
        native_check_count=0,  # Will be updated when native checks are added
        check_ids=check_ids,
        coverage_status=coverage_status,
        notes=notes,
    )


def get_controls_needing_checks() -> list[str]:
    """
    Get ISO 27001 controls that need new checks (no inherited coverage).

    Returns:
        List of control IDs without automated check coverage.
    """
    needing_checks = []

    for iso_control_id, control in ISO_27001_CONTROLS.items():
        # Focus on technological controls as they should be automatable
        if control.domain == DOMAIN_TECHNOLOGICAL:
            inherited = get_inherited_checks_for_iso_control(iso_control_id)
            if not inherited:
                needing_checks.append(iso_control_id)

    return sorted(needing_checks)


def get_controls_with_full_coverage() -> list[str]:
    """
    Get ISO 27001 controls with full automated check coverage.

    Returns:
        List of control IDs with 3+ inherited checks.
    """
    full_coverage = []

    for iso_control_id in ISO_27001_CONTROLS.keys():
        inherited = get_inherited_checks_for_iso_control(iso_control_id)
        if len(inherited) >= 3:
            full_coverage.append(iso_control_id)

    return sorted(full_coverage)


def get_coverage_by_domain() -> dict[str, dict[str, Any]]:
    """
    Get check coverage statistics by ISO 27001 domain.

    Returns:
        Dictionary with coverage statistics per domain.
    """
    domains = {
        DOMAIN_ORGANIZATIONAL: {"total": 0, "with_checks": 0, "check_count": 0},
        DOMAIN_PEOPLE: {"total": 0, "with_checks": 0, "check_count": 0},
        DOMAIN_PHYSICAL: {"total": 0, "with_checks": 0, "check_count": 0},
        DOMAIN_TECHNOLOGICAL: {"total": 0, "with_checks": 0, "check_count": 0},
    }

    for iso_control_id, control in ISO_27001_CONTROLS.items():
        domain = control.domain
        if domain in domains:
            domains[domain]["total"] += 1

            inherited = get_inherited_checks_for_iso_control(iso_control_id)
            if inherited:
                domains[domain]["with_checks"] += 1
                domains[domain]["check_count"] += len(inherited)

    # Calculate percentages
    for domain_stats in domains.values():
        total = domain_stats["total"]
        with_checks = domain_stats["with_checks"]
        domain_stats["coverage_pct"] = round(
            (with_checks / total * 100) if total > 0 else 0, 1
        )
        domain_stats["avg_checks"] = round(
            (domain_stats["check_count"] / with_checks) if with_checks > 0 else 0, 1
        )

    return domains


# =============================================================================
# Check Retrieval Functions
# =============================================================================


def get_iso27001_checks_for_control(iso_control_id: str) -> list[CheckDefinition]:
    """
    Get all automated checks applicable to an ISO 27001 control.

    Combines inherited checks from other frameworks with any ISO-specific
    native checks.

    Args:
        iso_control_id: ISO 27001 control ID.

    Returns:
        List of check definitions.
    """
    checks = []

    # Get inherited checks
    inherited = get_inherited_checks_for_iso_control(iso_control_id)
    for ic in inherited:
        if ic.check_definition:
            checks.append(ic.check_definition)

    # Native ISO 27001 checks would be added here
    # (to be implemented in future iterations)

    return checks


def get_all_iso27001_checks() -> list[CheckDefinition]:
    """
    Get all automated checks for ISO 27001 compliance.

    Returns:
        List of all check definitions (inherited + native).
    """
    all_checks: list[CheckDefinition] = []
    seen_ids: set[str] = set()

    for iso_control_id in ISO_27001_CONTROLS.keys():
        checks = get_iso27001_checks_for_control(iso_control_id)
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
    Get comprehensive statistics about ISO 27001 check coverage.

    Returns:
        Dictionary with check statistics.
    """
    all_inherited = get_all_inherited_checks()

    # Count unique checks
    unique_checks: set[str] = set()
    for inherited_list in all_inherited.values():
        for ic in inherited_list:
            unique_checks.add(ic.source_check_id)

    # Domain coverage
    domain_coverage = get_coverage_by_domain()

    # Controls needing checks
    needing_checks = get_controls_needing_checks()

    # Full coverage controls
    full_coverage = get_controls_with_full_coverage()

    return {
        "total_iso_controls": len(ISO_27001_CONTROLS),
        "controls_with_inherited_checks": len(all_inherited),
        "controls_without_checks": len(ISO_27001_CONTROLS) - len(all_inherited),
        "unique_inherited_checks": len(unique_checks),
        "total_check_mappings": sum(len(v) for v in all_inherited.values()),
        "controls_needing_new_checks": len(needing_checks),
        "controls_with_full_coverage": len(full_coverage),
        "domain_coverage": {
            domain: {
                "total": stats["total"],
                "with_checks": stats["with_checks"],
                "coverage_pct": stats["coverage_pct"],
                "avg_checks_per_control": stats["avg_checks"],
            }
            for domain, stats in domain_coverage.items()
        },
        "framework_version": ISO_27001_VERSION,
        "framework_id": ISO_27001_FRAMEWORK_ID,
    }


def get_inheritance_summary() -> list[dict[str, Any]]:
    """
    Get a summary of all check inheritances.

    Returns:
        List of inheritance summary entries.
    """
    summary = []

    for iso_control_id, control in sorted(ISO_27001_CONTROLS.items()):
        inherited = get_inherited_checks_for_iso_control(iso_control_id)

        summary.append({
            "iso_control_id": iso_control_id,
            "iso_title": control.title,
            "domain": control.domain,
            "nist_mappings": list(control.nist_mappings),
            "inherited_checks": [
                {
                    "check_id": ic.source_check_id,
                    "source": ic.source_framework,
                    "nist_bridge": ic.nist_bridge,
                }
                for ic in inherited
            ],
            "inherited_count": len(inherited),
            "has_coverage": len(inherited) > 0,
        })

    return summary


__all__ = [
    # Data classes
    "InheritedCheck",
    "CheckCoverageReport",
    # Check inheritance functions
    "get_soc2_checks_by_nist",
    "get_inherited_checks_for_iso_control",
    "get_all_inherited_checks",
    # Coverage analysis
    "get_check_coverage_report",
    "get_controls_needing_checks",
    "get_controls_with_full_coverage",
    "get_coverage_by_domain",
    # Check retrieval
    "get_iso27001_checks_for_control",
    "get_all_iso27001_checks",
    # Statistics
    "get_check_statistics",
    "get_inheritance_summary",
]
