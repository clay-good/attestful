"""
HITRUST CSF Framework Mappings.

Provides bidirectional mappings between HITRUST CSF controls and underlying
frameworks including NIST 800-53, ISO 27001, HIPAA, and PCI DSS.

Key features:
- Bidirectional mappings (HITRUST→Framework and Framework→HITRUST)
- Mapping strength indicators
- Coverage analysis and gap identification
- Support for automated check inheritance

HITRUST CSF is based on multiple frameworks:
- ISO/IEC 27001/27002 (primary source)
- NIST 800-53 (federal/comprehensive)
- HIPAA Security Rule (healthcare)
- PCI DSS (payment card industry)
- NIST CSF (risk-based)
- FedRAMP (federal cloud)
- GDPR (privacy)

Note: HITRUST uses a harmonized approach where controls inherit from
multiple frameworks. This module focuses on the primary framework mappings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from attestful.core.logging import get_logger
from attestful.frameworks.hitrust.controls import (
    HITRUST_CONTROLS,
    CATEGORY_NAMES,
)

logger = get_logger("frameworks.hitrust.framework_mappings")


# =============================================================================
# Enums and Data Classes
# =============================================================================


class MappingStrength(str, Enum):
    """Strength of control mapping relationship."""

    STRONG = "strong"  # Controls are nearly equivalent
    MODERATE = "moderate"  # Controls address similar requirements
    PARTIAL = "partial"  # Controls partially overlap
    NONE = "none"  # No meaningful mapping


class FrameworkType(str, Enum):
    """Supported framework types for mapping."""

    NIST_800_53 = "nist-800-53"
    ISO_27001 = "iso-27001"
    HIPAA = "hipaa"
    PCI_DSS = "pci-dss"
    NIST_CSF = "nist-csf"


@dataclass
class FrameworkMapping:
    """
    Represents a mapping between HITRUST and another framework's control.

    Attributes:
        hitrust_control_id: HITRUST CSF control ID (e.g., "01.a").
        framework: Target framework type.
        framework_control_id: Control ID in the target framework.
        strength: Mapping strength indicator.
        notes: Additional mapping notes.
    """

    hitrust_control_id: str
    framework: FrameworkType
    framework_control_id: str
    strength: MappingStrength = MappingStrength.MODERATE
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hitrust_control_id": self.hitrust_control_id,
            "framework": self.framework.value,
            "framework_control_id": self.framework_control_id,
            "strength": self.strength.value,
            "notes": self.notes,
        }


@dataclass
class HITRUSTMappingSummary:
    """
    Summary of all framework mappings for a HITRUST control.

    Attributes:
        hitrust_control_id: HITRUST control ID.
        hitrust_title: HITRUST control title.
        category: HITRUST control category.
        nist_mappings: List of mapped NIST 800-53 control IDs.
        iso_mappings: List of mapped ISO 27001 control IDs.
        hipaa_mappings: List of mapped HIPAA requirements.
        pci_mappings: List of mapped PCI DSS requirements.
        total_mappings: Total number of mappings across all frameworks.
        has_automated_checks: Whether automated checks exist via mappings.
    """

    hitrust_control_id: str
    hitrust_title: str
    category: str
    nist_mappings: list[str] = field(default_factory=list)
    iso_mappings: list[str] = field(default_factory=list)
    hipaa_mappings: list[str] = field(default_factory=list)
    pci_mappings: list[str] = field(default_factory=list)
    total_mappings: int = 0
    has_automated_checks: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hitrust_control_id": self.hitrust_control_id,
            "hitrust_title": self.hitrust_title,
            "category": self.category,
            "category_name": CATEGORY_NAMES.get(self.category, "Unknown"),
            "nist_mappings": self.nist_mappings,
            "iso_mappings": self.iso_mappings,
            "hipaa_mappings": self.hipaa_mappings,
            "pci_mappings": self.pci_mappings,
            "total_mappings": self.total_mappings,
            "has_automated_checks": self.has_automated_checks,
        }


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
    "PT": "PII Processing and Transparency",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}


# =============================================================================
# HIPAA Regulation Reference
# =============================================================================

HIPAA_REQUIREMENTS = {
    "164.308(a)(1)": "Security Management Process",
    "164.308(a)(2)": "Assigned Security Responsibility",
    "164.308(a)(3)": "Workforce Security",
    "164.308(a)(4)": "Information Access Management",
    "164.308(a)(5)": "Security Awareness and Training",
    "164.308(a)(6)": "Security Incident Procedures",
    "164.308(a)(7)": "Contingency Plan",
    "164.308(a)(8)": "Evaluation",
    "164.308(b)": "Business Associate Contracts",
    "164.310(a)": "Facility Access Controls",
    "164.310(b)": "Workstation Use",
    "164.310(c)": "Workstation Security",
    "164.310(d)": "Device and Media Controls",
    "164.312(a)": "Access Control",
    "164.312(b)": "Audit Controls",
    "164.312(c)": "Integrity",
    "164.312(d)": "Person or Entity Authentication",
    "164.312(e)": "Transmission Security",
    "164.502": "Uses and Disclosures of PHI",
    "164.514": "Other Requirements Relating to Uses and Disclosures",
    "164.520": "Notice of Privacy Practices",
    "164.524": "Access of Individuals to PHI",
    "164.526": "Amendment of PHI",
    "164.528": "Accounting of Disclosures",
    "164.530": "Administrative Requirements",
}


# =============================================================================
# PCI DSS Requirements Reference
# =============================================================================

PCI_DSS_REQUIREMENTS = {
    "1.1": "Install and maintain firewall configuration",
    "1.2": "Build firewall and router configurations",
    "2.4": "Maintain inventory of system components",
    "3.1": "Keep cardholder data storage to minimum",
    "3.4": "Render PAN unreadable anywhere stored",
    "3.5": "Protect keys used to secure cardholder data",
    "3.6": "Document and implement key-management procedures",
    "4.1": "Use strong cryptography for transmission",
    "4.2": "Never send unprotected PANs via messaging",
    "5.1": "Deploy anti-virus on commonly affected systems",
    "5.2": "Ensure anti-virus is current and running",
    "6.1": "Establish process for identifying vulnerabilities",
    "6.2": "Protect systems with latest security patches",
    "6.3": "Develop applications based on secure coding guidelines",
    "6.4": "Follow change control processes",
    "6.5": "Address common coding vulnerabilities",
    "6.6": "Address web application threats",
    "7.1": "Limit access to system components",
    "7.2": "Establish access control system",
    "8.1": "Define and implement user identification policies",
    "8.2": "Employ proper user-authentication management",
    "8.3": "Implement multi-factor authentication",
    "9.1": "Use appropriate facility entry controls",
    "9.5": "Physically secure all media",
    "9.6": "Maintain strict control over media distribution",
    "9.7": "Maintain strict control over media storage",
    "9.8": "Destroy media when no longer needed",
    "9.9": "Protect devices that capture payment card data",
    "10.1": "Implement audit trails",
    "10.2": "Implement automated audit trails",
    "10.4": "Synchronize all system clocks",
    "10.5": "Secure audit trails",
    "10.6": "Review logs and security events",
    "10.7": "Retain audit trail history",
    "11.2": "Run vulnerability scans",
    "11.3": "Implement penetration testing",
    "12.1": "Establish security policy",
    "12.2": "Implement risk-assessment process",
    "12.3": "Develop usage policies",
    "12.4": "Define security responsibilities",
    "12.5": "Assign security management responsibility",
    "12.6": "Implement security awareness program",
    "12.7": "Screen personnel prior to hire",
    "12.8": "Manage service providers",
    "12.10": "Implement incident response plan",
    "12.11": "Perform reviews to confirm policies are followed",
}


# =============================================================================
# Strong Mapping Definitions (High Confidence)
# =============================================================================

# HITRUST to NIST 800-53 Strong Mappings
HITRUST_TO_NIST_STRONG: dict[str, list[str]] = {
    # Access Control (01.x)
    "01.a": ["AC-1", "AC-2"],
    "01.b": ["AC-2", "IA-4"],
    "01.c": ["AC-6", "AC-2(7)"],
    "01.d": ["IA-5", "IA-5(1)"],
    "01.e": ["AC-2(3)", "AC-6(7)"],
    "01.f": ["IA-5(1)"],
    "01.g": ["AC-11", "AC-11(1)"],
    "01.h": ["AC-4", "SC-7"],
    "01.i": ["IA-2", "IA-2(1)", "IA-2(2)"],
    "01.j": ["IA-3"],
    # Human Resources Security (02.x)
    "02.a": ["PS-1", "PS-7"],
    "02.b": ["PS-3"],
    "02.c": ["PS-6", "PS-7"],
    "02.d": ["AT-1", "AT-2", "AT-3"],
    "02.e": ["PS-8"],
    "02.f": ["PS-4", "PS-5"],
    "02.g": ["PS-4"],
    "02.h": ["PS-4", "PS-5"],
    # Risk Management (03.x)
    "03.a": ["RA-1", "RA-2", "RA-3"],
    "03.b": ["RA-3", "RA-5"],
    "03.c": ["RA-7", "PM-9"],
    # Security Policy (04.x)
    "04.a": ["PL-1", "PM-1"],
    "04.b": ["PL-1", "PM-1"],
    # Organization of Information Security (05.x)
    "05.a": ["PM-1", "PM-2"],
    "05.b": ["PM-2", "PM-10"],
    "05.c": ["CA-6", "CM-3"],
    "05.d": ["PS-6"],
    "05.e": ["IR-6", "PM-15"],
    "05.f": ["PM-15", "PM-16"],
    "05.g": ["CA-7", "PM-14"],
    "05.h": ["SA-9", "SR-6"],
    "05.i": ["SA-9", "SC-14"],
    "05.j": ["SA-9", "SR-3"],
    # Compliance (06.x)
    "06.a": ["PM-8", "SA-12"],
    "06.b": ["PM-8"],
    "06.c": ["AU-9", "AU-11"],
    "06.d": ["PT-1", "PT-2"],
    "06.e": ["AC-8", "PL-4"],
    "06.f": ["SC-13"],
    "06.g": ["CA-2", "PM-14"],
    "06.h": ["CA-2", "RA-5"],
    "06.i": ["AU-1", "AU-2"],
    # Asset Management (07.x)
    "07.a": ["CM-8", "PM-5"],
    "07.b": ["CM-8"],
    "07.c": ["PL-4", "AC-8"],
    "07.d": ["RA-2", "SC-16"],
    "07.e": ["MP-3", "SC-16"],
    # Physical and Environmental Security (08.x)
    "08.a": ["PE-3", "PE-4"],
    "08.b": ["PE-2", "PE-3"],
    "08.c": ["PE-3", "PE-5"],
    "08.d": ["PE-13", "PE-15"],
    "08.e": ["PE-3"],
    "08.f": ["PE-16"],
    "08.g": ["PE-9", "PE-14"],
    "08.h": ["PE-9", "PE-11"],
    "08.i": ["PE-4", "PE-9"],
    "08.j": ["MA-2", "MA-4"],
    "08.k": ["PE-17"],
    "08.l": ["MP-6", "PE-16"],
    "08.m": ["PE-16", "MP-5"],
    # Communications and Operations Management (09.x)
    "09.a": ["CM-1", "SA-5"],
    "09.b": ["CM-3", "CM-4"],
    "09.c": ["AC-5"],
    "09.d": ["CM-4", "SA-11"],
    "09.e": ["SA-9", "SR-1"],
    "09.f": ["SA-2", "CP-2"],
    "09.g": ["SA-11", "CA-2"],
    "09.h": ["SI-3", "SI-8"],
    "09.i": ["SC-18"],
    "09.j": ["CP-9", "CP-10"],
    "09.k": ["SC-7", "AC-4"],
    "09.l": ["SC-7", "SA-9"],
    "09.m": ["MP-2", "MP-4"],
    "09.n": ["MP-6"],
    "09.o": ["MP-2", "MP-4"],
    "09.p": ["SA-5", "AC-3"],
    "09.q": ["SC-8", "SC-13"],
    "09.r": ["SC-8", "SC-23"],
    "09.s": ["AC-22", "SC-14"],
    "09.t": ["AU-2", "AU-3", "AU-12"],
    "09.u": ["AU-6", "SI-4"],
    "09.v": ["AU-9"],
    "09.w": ["AU-2", "AU-12"],
    "09.x": ["SI-4", "AU-6"],
    "09.y": ["AU-8"],
    # Systems Development (10.x)
    "10.a": ["SA-3", "SA-4"],
    "10.b": ["SI-10"],
    "10.c": ["SI-7"],
    "10.d": ["SC-8", "SC-13"],
    "10.e": ["SI-7"],
    "10.f": ["SC-13"],
    "10.g": ["SC-12"],
    "10.h": ["CM-7", "CM-11"],
    "10.i": ["SA-15"],
    "10.j": ["CM-5", "AC-6"],
    "10.k": ["CM-3", "SA-10"],
    "10.l": ["CM-4", "SA-11"],
    "10.m": ["CM-5", "CM-6"],
    "10.n": ["SC-7", "SI-4"],
    "10.o": ["SA-9", "SA-11"],
    "10.p": ["RA-5", "SI-2"],
    # Incident Management (11.x)
    "11.a": ["IR-6", "SI-5"],
    "11.b": ["IR-6", "PM-16"],
    "11.c": ["IR-1", "IR-8"],
    "11.d": ["IR-4", "IR-8"],
    "11.e": ["IR-4", "AU-9"],
    # Business Continuity (12.x)
    "12.a": ["CP-1", "CP-2"],
    "12.b": ["CP-2", "RA-3"],
    "12.c": ["CP-2", "CP-7"],
    "12.d": ["CP-2"],
    "12.e": ["CP-4", "CP-3"],
    # Privacy (13.x)
    "13.a": ["PT-1", "PT-2"],
    "13.b": ["PT-5", "PT-5(2)"],
    "13.c": ["PT-2"],
    "13.d": ["PT-2", "PT-3"],
    "13.e": ["PT-5", "PT-6"],
    "13.f": ["PT-2", "PT-4"],
    "13.g": ["PT-3", "SC-28"],
    "13.h": ["PT-2"],
    "13.i": ["PT-1", "PM-14"],
}


# HITRUST to ISO 27001 Strong Mappings
HITRUST_TO_ISO_STRONG: dict[str, list[str]] = {
    # Access Control (01.x)
    "01.a": ["A.5.15", "A.5.18"],
    "01.b": ["A.5.16", "A.5.18"],
    "01.c": ["A.8.2"],
    "01.d": ["A.5.17"],
    "01.e": ["A.5.18"],
    "01.f": ["A.5.17"],
    "01.g": ["A.8.1"],
    "01.h": ["A.8.20", "A.8.21"],
    "01.i": ["A.8.5"],
    "01.j": ["A.8.20"],
    # Human Resources Security (02.x)
    "02.a": ["A.5.2", "A.6.1"],
    "02.b": ["A.6.1"],
    "02.c": ["A.6.2"],
    "02.d": ["A.6.3"],
    "02.e": ["A.6.4"],
    "02.f": ["A.6.5"],
    "02.g": ["A.6.5"],
    "02.h": ["A.6.5"],
    # Risk Management (03.x)
    "03.a": ["A.5.7", "A.5.8"],
    "03.b": ["A.5.7"],
    "03.c": ["A.5.8"],
    # Security Policy (04.x)
    "04.a": ["A.5.1"],
    "04.b": ["A.5.1"],
    # Organization of Information Security (05.x)
    "05.a": ["A.5.1", "A.5.2"],
    "05.b": ["A.5.2"],
    "05.c": ["A.5.9"],
    "05.d": ["A.6.6"],
    "05.e": ["A.5.5"],
    "05.f": ["A.5.6"],
    "05.g": ["A.5.35"],
    "05.h": ["A.5.19", "A.5.20"],
    "05.i": ["A.5.21"],
    "05.j": ["A.5.20"],
    # Compliance (06.x)
    "06.a": ["A.5.31"],
    "06.b": ["A.5.32"],
    "06.c": ["A.5.33"],
    "06.d": ["A.5.34"],
    "06.e": ["A.5.10"],
    "06.f": ["A.8.24"],
    "06.g": ["A.5.36"],
    "06.h": ["A.5.36", "A.8.8"],
    "06.i": ["A.5.35"],
    # Asset Management (07.x)
    "07.a": ["A.5.9"],
    "07.b": ["A.5.9"],
    "07.c": ["A.5.10"],
    "07.d": ["A.5.12"],
    "07.e": ["A.5.13"],
    # Physical Security (08.x)
    "08.a": ["A.7.1"],
    "08.b": ["A.7.2"],
    "08.c": ["A.7.3"],
    "08.d": ["A.7.5"],
    "08.e": ["A.7.6"],
    "08.f": ["A.7.2"],
    "08.g": ["A.7.8"],
    "08.h": ["A.7.11"],
    "08.i": ["A.7.12"],
    "08.j": ["A.7.13"],
    "08.k": ["A.7.9"],
    "08.l": ["A.7.14"],
    "08.m": ["A.7.10"],
    # Operations (09.x)
    "09.a": ["A.5.37"],
    "09.b": ["A.8.32"],
    "09.c": ["A.5.3"],
    "09.d": ["A.8.31"],
    "09.e": ["A.5.21", "A.5.22"],
    "09.f": ["A.8.6"],
    "09.g": ["A.8.29"],
    "09.h": ["A.8.7"],
    "09.i": ["A.8.7"],
    "09.j": ["A.8.13"],
    "09.k": ["A.8.20"],
    "09.l": ["A.8.21"],
    "09.m": ["A.7.10"],
    "09.n": ["A.7.14"],
    "09.o": ["A.5.13"],
    "09.p": ["A.5.37"],
    "09.q": ["A.8.24"],
    "09.r": ["A.8.24"],
    "09.s": ["A.8.26"],
    "09.t": ["A.8.15"],
    "09.u": ["A.8.16"],
    "09.v": ["A.8.15"],
    "09.w": ["A.8.15"],
    "09.x": ["A.8.15"],
    "09.y": ["A.8.17"],
    # Development (10.x)
    "10.a": ["A.8.25"],
    "10.b": ["A.8.28"],
    "10.c": ["A.8.28"],
    "10.d": ["A.8.24"],
    "10.e": ["A.8.28"],
    "10.f": ["A.8.24"],
    "10.g": ["A.8.24"],
    "10.h": ["A.8.19"],
    "10.i": ["A.8.33"],
    "10.j": ["A.8.4"],
    "10.k": ["A.8.32"],
    "10.l": ["A.8.32"],
    "10.m": ["A.8.32"],
    "10.n": ["A.8.12"],
    "10.o": ["A.8.30"],
    "10.p": ["A.8.8"],
    # Incident Management (11.x)
    "11.a": ["A.5.24", "A.6.8"],
    "11.b": ["A.6.8"],
    "11.c": ["A.5.24"],
    "11.d": ["A.5.27"],
    "11.e": ["A.5.28"],
    # Business Continuity (12.x)
    "12.a": ["A.5.29"],
    "12.b": ["A.5.29"],
    "12.c": ["A.5.30"],
    "12.d": ["A.5.29"],
    "12.e": ["A.5.30"],
    # Privacy (13.x)
    "13.a": ["A.5.34"],
    "13.b": ["A.5.34"],
    "13.c": ["A.5.34"],
    "13.d": ["A.5.34"],
    "13.e": ["A.5.34"],
    "13.f": ["A.5.34"],
    "13.g": ["A.5.34", "A.8.24"],
    "13.h": ["A.5.34"],
    "13.i": ["A.5.35", "A.5.36"],
}


# =============================================================================
# HITRUST → Framework Mapping Functions
# =============================================================================


def get_nist_controls_for_hitrust(hitrust_control_id: str) -> list[str]:
    """
    Get NIST 800-53 controls that map to a HITRUST control.

    Args:
        hitrust_control_id: HITRUST control ID (e.g., "01.a").

    Returns:
        List of NIST 800-53 control IDs.
    """
    control = HITRUST_CONTROLS.get(hitrust_control_id)
    if control:
        return list(control.nist_mappings)

    # Fallback to strong mappings
    return HITRUST_TO_NIST_STRONG.get(hitrust_control_id, [])


def get_iso_controls_for_hitrust(hitrust_control_id: str) -> list[str]:
    """
    Get ISO 27001 controls that map to a HITRUST control.

    Args:
        hitrust_control_id: HITRUST control ID (e.g., "01.a").

    Returns:
        List of ISO 27001 control IDs.
    """
    control = HITRUST_CONTROLS.get(hitrust_control_id)
    if control:
        return list(control.iso_mappings)

    # Fallback to strong mappings
    return HITRUST_TO_ISO_STRONG.get(hitrust_control_id, [])


def get_hipaa_requirements_for_hitrust(hitrust_control_id: str) -> list[str]:
    """
    Get HIPAA requirements that map to a HITRUST control.

    Args:
        hitrust_control_id: HITRUST control ID (e.g., "01.a").

    Returns:
        List of HIPAA requirement references.
    """
    control = HITRUST_CONTROLS.get(hitrust_control_id)
    if control:
        return list(control.hipaa_mappings)
    return []


def get_pci_requirements_for_hitrust(hitrust_control_id: str) -> list[str]:
    """
    Get PCI DSS requirements that map to a HITRUST control.

    Args:
        hitrust_control_id: HITRUST control ID (e.g., "01.a").

    Returns:
        List of PCI DSS requirement references.
    """
    control = HITRUST_CONTROLS.get(hitrust_control_id)
    if control:
        return list(control.pci_mappings)
    return []


def get_all_mappings_for_hitrust(hitrust_control_id: str) -> HITRUSTMappingSummary | None:
    """
    Get all framework mappings for a HITRUST control.

    Args:
        hitrust_control_id: HITRUST control ID.

    Returns:
        HITRUSTMappingSummary or None if control not found.
    """
    control = HITRUST_CONTROLS.get(hitrust_control_id)
    if not control:
        return None

    nist_mappings = list(control.nist_mappings)
    iso_mappings = list(control.iso_mappings)
    hipaa_mappings = list(control.hipaa_mappings)
    pci_mappings = list(control.pci_mappings)

    total = len(nist_mappings) + len(iso_mappings) + len(hipaa_mappings) + len(pci_mappings)

    return HITRUSTMappingSummary(
        hitrust_control_id=hitrust_control_id,
        hitrust_title=control.title,
        category=control.category,
        nist_mappings=nist_mappings,
        iso_mappings=iso_mappings,
        hipaa_mappings=hipaa_mappings,
        pci_mappings=pci_mappings,
        total_mappings=total,
        has_automated_checks=len(nist_mappings) > 0,  # NIST mappings enable check inheritance
    )


# =============================================================================
# Framework → HITRUST Mapping Functions (Reverse Mappings)
# =============================================================================


def get_hitrust_controls_for_nist(nist_control_id: str) -> list[str]:
    """
    Get HITRUST controls that map to a NIST 800-53 control.

    Args:
        nist_control_id: NIST 800-53 control ID (e.g., "AC-2").

    Returns:
        List of HITRUST control IDs.
    """
    hitrust_controls = []
    for control_id, control in HITRUST_CONTROLS.items():
        if nist_control_id in control.nist_mappings:
            hitrust_controls.append(control_id)
    return sorted(hitrust_controls)


def get_hitrust_controls_for_iso(iso_control_id: str) -> list[str]:
    """
    Get HITRUST controls that map to an ISO 27001 control.

    Args:
        iso_control_id: ISO 27001 control ID (e.g., "A.5.1").

    Returns:
        List of HITRUST control IDs.
    """
    hitrust_controls = []
    for control_id, control in HITRUST_CONTROLS.items():
        if iso_control_id in control.iso_mappings:
            hitrust_controls.append(control_id)
    return sorted(hitrust_controls)


def get_hitrust_controls_for_hipaa(hipaa_reference: str) -> list[str]:
    """
    Get HITRUST controls that map to a HIPAA requirement.

    Args:
        hipaa_reference: HIPAA reference (e.g., "164.312(a)(1)").

    Returns:
        List of HITRUST control IDs.
    """
    hitrust_controls = []
    for control_id, control in HITRUST_CONTROLS.items():
        if any(hipaa_reference in h for h in control.hipaa_mappings):
            hitrust_controls.append(control_id)
    return sorted(hitrust_controls)


def get_hitrust_controls_for_pci(pci_requirement: str) -> list[str]:
    """
    Get HITRUST controls that map to a PCI DSS requirement.

    Args:
        pci_requirement: PCI DSS requirement (e.g., "8.3").

    Returns:
        List of HITRUST control IDs.
    """
    hitrust_controls = []
    for control_id, control in HITRUST_CONTROLS.items():
        if pci_requirement in control.pci_mappings:
            hitrust_controls.append(control_id)
    return sorted(hitrust_controls)


# =============================================================================
# Coverage Analysis Functions
# =============================================================================


def get_mapping_coverage_by_category() -> dict[str, dict[str, Any]]:
    """
    Get mapping coverage statistics by HITRUST category.

    Returns:
        Dictionary with coverage stats per category.
    """
    coverage: dict[str, dict[str, Any]] = {}

    for category_code, category_name in CATEGORY_NAMES.items():
        coverage[category_code] = {
            "category_name": category_name,
            "total_controls": 0,
            "controls_with_nist_mapping": 0,
            "controls_with_iso_mapping": 0,
            "controls_with_hipaa_mapping": 0,
            "controls_with_pci_mapping": 0,
            "nist_coverage_pct": 0.0,
            "iso_coverage_pct": 0.0,
        }

    for control in HITRUST_CONTROLS.values():
        cat = control.category
        if cat not in coverage:
            continue

        coverage[cat]["total_controls"] += 1
        if control.nist_mappings:
            coverage[cat]["controls_with_nist_mapping"] += 1
        if control.iso_mappings:
            coverage[cat]["controls_with_iso_mapping"] += 1
        if control.hipaa_mappings:
            coverage[cat]["controls_with_hipaa_mapping"] += 1
        if control.pci_mappings:
            coverage[cat]["controls_with_pci_mapping"] += 1

    # Calculate percentages
    for cat_data in coverage.values():
        total = cat_data["total_controls"]
        if total > 0:
            cat_data["nist_coverage_pct"] = round(
                cat_data["controls_with_nist_mapping"] / total * 100, 1
            )
            cat_data["iso_coverage_pct"] = round(
                cat_data["controls_with_iso_mapping"] / total * 100, 1
            )

    return coverage


def get_unmapped_hitrust_controls(framework: FrameworkType) -> list[str]:
    """
    Get HITRUST controls that have no mapping to a specific framework.

    Args:
        framework: Target framework type.

    Returns:
        List of HITRUST control IDs without mappings.
    """
    unmapped = []

    for control_id, control in HITRUST_CONTROLS.items():
        if framework == FrameworkType.NIST_800_53:
            if not control.nist_mappings:
                unmapped.append(control_id)
        elif framework == FrameworkType.ISO_27001:
            if not control.iso_mappings:
                unmapped.append(control_id)
        elif framework == FrameworkType.HIPAA:
            if not control.hipaa_mappings:
                unmapped.append(control_id)
        elif framework == FrameworkType.PCI_DSS:
            if not control.pci_mappings:
                unmapped.append(control_id)

    return sorted(unmapped)


def get_nist_family_coverage() -> dict[str, dict[str, Any]]:
    """
    Get HITRUST coverage of NIST 800-53 control families.

    Returns:
        Dictionary with NIST family coverage statistics.
    """
    family_coverage: dict[str, dict[str, Any]] = {}

    for family_code, family_name in NIST_CONTROL_FAMILIES.items():
        family_coverage[family_code] = {
            "family_name": family_name,
            "hitrust_controls_mapped": 0,
            "unique_nist_controls": set(),
            "hitrust_control_ids": [],
        }

    for control_id, control in HITRUST_CONTROLS.items():
        for nist_id in control.nist_mappings:
            family_code = nist_id.split("-")[0]
            if family_code in family_coverage:
                family_coverage[family_code]["hitrust_controls_mapped"] += 1
                family_coverage[family_code]["unique_nist_controls"].add(nist_id)
                family_coverage[family_code]["hitrust_control_ids"].append(control_id)

    # Convert sets to counts
    for family_data in family_coverage.values():
        family_data["unique_nist_control_count"] = len(family_data["unique_nist_controls"])
        family_data["unique_nist_controls"] = sorted(family_data["unique_nist_controls"])
        family_data["hitrust_control_ids"] = sorted(set(family_data["hitrust_control_ids"]))

    return family_coverage


# =============================================================================
# Export Functions
# =============================================================================


def export_mapping_matrix(framework: FrameworkType) -> list[dict[str, Any]]:
    """
    Export HITRUST to framework mapping matrix.

    Args:
        framework: Target framework type.

    Returns:
        List of mapping entries.
    """
    mappings = []

    for control_id, control in sorted(HITRUST_CONTROLS.items()):
        if framework == FrameworkType.NIST_800_53:
            framework_controls = control.nist_mappings
        elif framework == FrameworkType.ISO_27001:
            framework_controls = control.iso_mappings
        elif framework == FrameworkType.HIPAA:
            framework_controls = control.hipaa_mappings
        elif framework == FrameworkType.PCI_DSS:
            framework_controls = control.pci_mappings
        else:
            framework_controls = []

        mappings.append({
            "hitrust_control_id": control_id,
            "hitrust_title": control.title,
            "hitrust_category": control.category,
            "framework": framework.value,
            "framework_controls": list(framework_controls),
            "mapping_count": len(framework_controls),
        })

    return mappings


# =============================================================================
# Statistics Functions
# =============================================================================


def get_mapping_statistics() -> dict[str, Any]:
    """
    Get comprehensive mapping statistics.

    Returns:
        Dictionary with mapping statistics.
    """
    total_controls = len(HITRUST_CONTROLS)
    controls_with_nist = sum(1 for c in HITRUST_CONTROLS.values() if c.nist_mappings)
    controls_with_iso = sum(1 for c in HITRUST_CONTROLS.values() if c.iso_mappings)
    controls_with_hipaa = sum(1 for c in HITRUST_CONTROLS.values() if c.hipaa_mappings)
    controls_with_pci = sum(1 for c in HITRUST_CONTROLS.values() if c.pci_mappings)

    # Count unique framework control IDs
    unique_nist: set[str] = set()
    unique_iso: set[str] = set()
    unique_hipaa: set[str] = set()
    unique_pci: set[str] = set()

    for control in HITRUST_CONTROLS.values():
        unique_nist.update(control.nist_mappings)
        unique_iso.update(control.iso_mappings)
        unique_hipaa.update(control.hipaa_mappings)
        unique_pci.update(control.pci_mappings)

    return {
        "total_hitrust_controls": total_controls,
        "nist_800_53": {
            "controls_with_mappings": controls_with_nist,
            "coverage_percentage": round(controls_with_nist / total_controls * 100, 1),
            "unique_nist_controls": len(unique_nist),
            "nist_families_covered": len(set(c.split("-")[0] for c in unique_nist)),
        },
        "iso_27001": {
            "controls_with_mappings": controls_with_iso,
            "coverage_percentage": round(controls_with_iso / total_controls * 100, 1),
            "unique_iso_controls": len(unique_iso),
        },
        "hipaa": {
            "controls_with_mappings": controls_with_hipaa,
            "coverage_percentage": round(controls_with_hipaa / total_controls * 100, 1),
            "unique_hipaa_requirements": len(unique_hipaa),
        },
        "pci_dss": {
            "controls_with_mappings": controls_with_pci,
            "coverage_percentage": round(controls_with_pci / total_controls * 100, 1),
            "unique_pci_requirements": len(unique_pci),
        },
        "fully_mapped_controls": sum(
            1 for c in HITRUST_CONTROLS.values()
            if c.nist_mappings and c.iso_mappings and c.hipaa_mappings and c.pci_mappings
        ),
    }


__all__ = [
    # Enums
    "MappingStrength",
    "FrameworkType",
    # Data classes
    "FrameworkMapping",
    "HITRUSTMappingSummary",
    # Reference constants
    "NIST_CONTROL_FAMILIES",
    "HIPAA_REQUIREMENTS",
    "PCI_DSS_REQUIREMENTS",
    # Mapping constants
    "HITRUST_TO_NIST_STRONG",
    "HITRUST_TO_ISO_STRONG",
    # HITRUST → Framework functions
    "get_nist_controls_for_hitrust",
    "get_iso_controls_for_hitrust",
    "get_hipaa_requirements_for_hitrust",
    "get_pci_requirements_for_hitrust",
    "get_all_mappings_for_hitrust",
    # Framework → HITRUST functions
    "get_hitrust_controls_for_nist",
    "get_hitrust_controls_for_iso",
    "get_hitrust_controls_for_hipaa",
    "get_hitrust_controls_for_pci",
    # Coverage analysis
    "get_mapping_coverage_by_category",
    "get_unmapped_hitrust_controls",
    "get_nist_family_coverage",
    # Export
    "export_mapping_matrix",
    # Statistics
    "get_mapping_statistics",
]
