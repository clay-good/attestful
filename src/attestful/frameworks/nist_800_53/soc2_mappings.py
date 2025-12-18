"""
SOC 2 Trust Services Criteria to NIST 800-53 Control Mappings.

Provides crosswalk mappings from SOC 2 TSC controls to NIST 800-53 Rev 5 controls.
These mappings enable inheriting compliance evidence from SOC 2 assessments for
NIST 800-53 compliance.

Mapping sources:
- AICPA SOC 2 Trust Services Criteria to NIST 800-53 crosswalk
- AICPA Cybersecurity Risk Management Reporting Framework mappings
- Professional judgment based on control requirements

SOC 2 Trust Services Categories:
- Security (Common Criteria CC1-CC9) - Mandatory for all SOC 2 reports
- Availability (A1) - Optional
- Processing Integrity (PI1) - Optional
- Confidentiality (C1) - Optional
- Privacy (P1-P8) - Optional
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from attestful.core.logging import get_logger

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


@dataclass
class SOC2Mapping:
    """Mapping from a SOC 2 criterion to NIST 800-53 controls."""

    soc2_criterion_id: str
    soc2_criterion_name: str
    nist_controls: list[str]
    mapping_rationale: str = ""
    coverage: str = "full"  # full, partial


# =============================================================================
# SOC 2 Common Criteria (Security) to NIST 800-53 Mappings
# =============================================================================

SOC2_CC_TO_NIST_800_53: dict[str, SOC2Mapping] = {
    # CC1: Control Environment
    "CC1.1": SOC2Mapping(
        soc2_criterion_id="CC1.1",
        soc2_criterion_name="COSO Principle 1: Demonstrates commitment to integrity and ethical values",
        nist_controls=["AT-1", "PL-4", "PS-6", "SA-8"],
        mapping_rationale="Organizational ethics and integrity programs",
        coverage="partial",
    ),
    "CC1.2": SOC2Mapping(
        soc2_criterion_id="CC1.2",
        soc2_criterion_name="COSO Principle 2: Exercises oversight responsibility",
        nist_controls=["PM-1", "PM-2", "PM-9", "CA-7"],
        mapping_rationale="Board and management oversight",
        coverage="partial",
    ),
    "CC1.3": SOC2Mapping(
        soc2_criterion_id="CC1.3",
        soc2_criterion_name="COSO Principle 3: Establishes structure, authority, and responsibility",
        nist_controls=["PM-2", "PS-1", "PS-2", "PL-2"],
        mapping_rationale="Organizational structure and roles",
        coverage="partial",
    ),
    "CC1.4": SOC2Mapping(
        soc2_criterion_id="CC1.4",
        soc2_criterion_name="COSO Principle 4: Demonstrates commitment to competence",
        nist_controls=["AT-2", "AT-3", "PS-2", "PS-7"],
        mapping_rationale="Personnel competence and training",
    ),
    "CC1.5": SOC2Mapping(
        soc2_criterion_id="CC1.5",
        soc2_criterion_name="COSO Principle 5: Enforces accountability",
        nist_controls=["PS-1", "PS-4", "PS-8", "AU-1"],
        mapping_rationale="Personnel accountability",
    ),

    # CC2: Communication and Information
    "CC2.1": SOC2Mapping(
        soc2_criterion_id="CC2.1",
        soc2_criterion_name="COSO Principle 13: Uses relevant information",
        nist_controls=["PM-6", "RA-3", "CA-7", "SI-4"],
        mapping_rationale="Information quality and security monitoring",
    ),
    "CC2.2": SOC2Mapping(
        soc2_criterion_id="CC2.2",
        soc2_criterion_name="COSO Principle 14: Communicates internally",
        nist_controls=["AT-1", "IR-1", "PL-4", "PM-15"],
        mapping_rationale="Internal communication of policies",
    ),
    "CC2.3": SOC2Mapping(
        soc2_criterion_id="CC2.3",
        soc2_criterion_name="COSO Principle 15: Communicates externally",
        nist_controls=["IR-6", "IR-7", "PM-15", "SC-42"],
        mapping_rationale="External communication and reporting",
    ),

    # CC3: Risk Assessment
    "CC3.1": SOC2Mapping(
        soc2_criterion_id="CC3.1",
        soc2_criterion_name="COSO Principle 6: Specifies suitable objectives",
        nist_controls=["RA-1", "RA-3", "PM-9"],
        mapping_rationale="Risk management objectives",
    ),
    "CC3.2": SOC2Mapping(
        soc2_criterion_id="CC3.2",
        soc2_criterion_name="COSO Principle 7: Identifies and analyzes risk",
        nist_controls=["RA-3", "RA-5", "PM-9", "PM-28"],
        mapping_rationale="Risk identification and analysis",
    ),
    "CC3.3": SOC2Mapping(
        soc2_criterion_id="CC3.3",
        soc2_criterion_name="COSO Principle 8: Assesses fraud risk",
        nist_controls=["RA-3", "SI-4", "AU-6"],
        mapping_rationale="Fraud risk assessment",
        coverage="partial",
    ),
    "CC3.4": SOC2Mapping(
        soc2_criterion_id="CC3.4",
        soc2_criterion_name="COSO Principle 9: Identifies and analyzes significant change",
        nist_controls=["RA-3", "CM-3", "CM-4", "PM-28"],
        mapping_rationale="Change-related risk assessment",
    ),

    # CC4: Monitoring Activities
    "CC4.1": SOC2Mapping(
        soc2_criterion_id="CC4.1",
        soc2_criterion_name="COSO Principle 16: Conducts ongoing and/or separate evaluations",
        nist_controls=["CA-2", "CA-5", "CA-7", "PM-14"],
        mapping_rationale="Ongoing security assessments",
    ),
    "CC4.2": SOC2Mapping(
        soc2_criterion_id="CC4.2",
        soc2_criterion_name="COSO Principle 17: Evaluates and communicates deficiencies",
        nist_controls=["CA-5", "CA-7", "PM-4", "PM-6"],
        mapping_rationale="Deficiency tracking and remediation",
    ),

    # CC5: Control Activities
    "CC5.1": SOC2Mapping(
        soc2_criterion_id="CC5.1",
        soc2_criterion_name="COSO Principle 10: Selects and develops control activities",
        nist_controls=["PL-2", "SA-3", "SA-8", "PM-1"],
        mapping_rationale="Control selection and development",
    ),
    "CC5.2": SOC2Mapping(
        soc2_criterion_id="CC5.2",
        soc2_criterion_name="COSO Principle 11: Selects and develops general controls over technology",
        nist_controls=["CM-1", "CM-6", "SA-10", "SI-2"],
        mapping_rationale="Technology general controls",
    ),
    "CC5.3": SOC2Mapping(
        soc2_criterion_id="CC5.3",
        soc2_criterion_name="COSO Principle 12: Deploys through policies and procedures",
        nist_controls=["PL-1", "PL-2", "AC-1", "AT-1"],
        mapping_rationale="Policy and procedure deployment",
    ),

    # CC6: Logical and Physical Access Controls
    "CC6.1": SOC2Mapping(
        soc2_criterion_id="CC6.1",
        soc2_criterion_name="Logical access security software, infrastructure, and architectures",
        nist_controls=["AC-1", "AC-2", "AC-3", "AC-5", "AC-6", "SC-7"],
        mapping_rationale="Access control policies and mechanisms",
    ),
    "CC6.2": SOC2Mapping(
        soc2_criterion_id="CC6.2",
        soc2_criterion_name="New access registration and authentication for users",
        nist_controls=["AC-2", "IA-1", "IA-2", "IA-4", "IA-5"],
        mapping_rationale="User registration and authentication",
    ),
    "CC6.3": SOC2Mapping(
        soc2_criterion_id="CC6.3",
        soc2_criterion_name="Access removal and modification for terminated and transferred users",
        nist_controls=["AC-2", "AC-2(3)", "PS-4", "PS-5"],
        mapping_rationale="Access revocation and transfer",
    ),
    "CC6.4": SOC2Mapping(
        soc2_criterion_id="CC6.4",
        soc2_criterion_name="Physical access restrictions",
        nist_controls=["PE-2", "PE-3", "PE-6", "PE-8"],
        mapping_rationale="Physical access controls",
    ),
    "CC6.5": SOC2Mapping(
        soc2_criterion_id="CC6.5",
        soc2_criterion_name="Logical access restrictions for data at rest",
        nist_controls=["AC-3", "AC-4", "SC-28", "MP-4"],
        mapping_rationale="Data protection at rest",
    ),
    "CC6.6": SOC2Mapping(
        soc2_criterion_id="CC6.6",
        soc2_criterion_name="Encryption for data in transit",
        nist_controls=["SC-8", "SC-8(1)", "SC-13", "SC-23"],
        mapping_rationale="Transmission confidentiality",
    ),
    "CC6.7": SOC2Mapping(
        soc2_criterion_id="CC6.7",
        soc2_criterion_name="Data transmission endpoints protection",
        nist_controls=["SC-7", "SC-7(4)", "SC-7(5)", "SC-8"],
        mapping_rationale="Boundary protection for data transmission",
    ),
    "CC6.8": SOC2Mapping(
        soc2_criterion_id="CC6.8",
        soc2_criterion_name="Intrusion detection and prevention",
        nist_controls=["SI-4", "SI-4(4)", "SI-4(5)", "SC-7"],
        mapping_rationale="Malicious activity detection",
    ),

    # CC7: System Operations
    "CC7.1": SOC2Mapping(
        soc2_criterion_id="CC7.1",
        soc2_criterion_name="Detection and monitoring of security events",
        nist_controls=["AU-1", "AU-2", "AU-3", "AU-6", "SI-4"],
        mapping_rationale="Security event monitoring",
    ),
    "CC7.2": SOC2Mapping(
        soc2_criterion_id="CC7.2",
        soc2_criterion_name="Incident response and recovery procedures",
        nist_controls=["IR-1", "IR-4", "IR-5", "IR-6", "IR-8"],
        mapping_rationale="Incident handling",
    ),
    "CC7.3": SOC2Mapping(
        soc2_criterion_id="CC7.3",
        soc2_criterion_name="Incident eradication and containment",
        nist_controls=["IR-4", "IR-4(1)", "SI-7", "SC-18"],
        mapping_rationale="Incident containment and eradication",
    ),
    "CC7.4": SOC2Mapping(
        soc2_criterion_id="CC7.4",
        soc2_criterion_name="Business continuity and disaster recovery",
        nist_controls=["CP-1", "CP-2", "CP-4", "CP-9", "CP-10"],
        mapping_rationale="Continuity and recovery",
    ),
    "CC7.5": SOC2Mapping(
        soc2_criterion_id="CC7.5",
        soc2_criterion_name="Backup and restoration testing",
        nist_controls=["CP-4", "CP-9", "CP-9(1)", "CP-10"],
        mapping_rationale="Backup and recovery testing",
    ),

    # CC8: Change Management
    "CC8.1": SOC2Mapping(
        soc2_criterion_id="CC8.1",
        soc2_criterion_name="Infrastructure, data, software, and procedure changes",
        nist_controls=["CM-1", "CM-2", "CM-3", "CM-4", "SA-10"],
        mapping_rationale="Configuration and change management",
    ),

    # CC9: Risk Mitigation
    "CC9.1": SOC2Mapping(
        soc2_criterion_id="CC9.1",
        soc2_criterion_name="Vendor and business partner risk identification",
        nist_controls=["SA-9", "SA-12", "SR-1", "SR-3", "SR-6"],
        mapping_rationale="Supply chain risk management",
    ),
    "CC9.2": SOC2Mapping(
        soc2_criterion_id="CC9.2",
        soc2_criterion_name="Vendor and business partner risk assessment",
        nist_controls=["SA-9", "RA-3", "SR-3", "SR-5", "SR-6"],
        mapping_rationale="Third-party risk assessment",
    ),
}


# =============================================================================
# SOC 2 Availability to NIST 800-53 Mappings
# =============================================================================

SOC2_AVAILABILITY_TO_NIST_800_53: dict[str, SOC2Mapping] = {
    "A1.1": SOC2Mapping(
        soc2_criterion_id="A1.1",
        soc2_criterion_name="System availability commitments and performance monitoring",
        nist_controls=["CA-7", "SI-4", "CP-2", "PM-5"],
        mapping_rationale="Availability monitoring and commitments",
    ),
    "A1.2": SOC2Mapping(
        soc2_criterion_id="A1.2",
        soc2_criterion_name="Environmental protections and disaster recovery",
        nist_controls=["PE-1", "PE-9", "PE-10", "PE-13", "CP-6", "CP-7"],
        mapping_rationale="Environmental and recovery controls",
    ),
    "A1.3": SOC2Mapping(
        soc2_criterion_id="A1.3",
        soc2_criterion_name="Recovery testing and business continuity",
        nist_controls=["CP-4", "CP-10", "IR-4"],
        mapping_rationale="Recovery and continuity testing",
    ),
}


# =============================================================================
# SOC 2 Processing Integrity to NIST 800-53 Mappings
# =============================================================================

SOC2_PROCESSING_INTEGRITY_TO_NIST_800_53: dict[str, SOC2Mapping] = {
    "PI1.1": SOC2Mapping(
        soc2_criterion_id="PI1.1",
        soc2_criterion_name="Processing inputs are complete, accurate, timely, and authorized",
        nist_controls=["SI-9", "SI-10", "AU-10"],
        mapping_rationale="Input validation and authorization",
    ),
    "PI1.2": SOC2Mapping(
        soc2_criterion_id="PI1.2",
        soc2_criterion_name="System processing is complete, accurate, timely, and authorized",
        nist_controls=["SI-7", "SI-10", "AU-10"],
        mapping_rationale="Processing integrity controls",
    ),
    "PI1.3": SOC2Mapping(
        soc2_criterion_id="PI1.3",
        soc2_criterion_name="Processing outputs are complete, accurate, timely, and authorized",
        nist_controls=["SI-10", "AU-10", "SI-12"],
        mapping_rationale="Output integrity controls",
    ),
}


# =============================================================================
# SOC 2 Confidentiality to NIST 800-53 Mappings
# =============================================================================

SOC2_CONFIDENTIALITY_TO_NIST_800_53: dict[str, SOC2Mapping] = {
    "C1.1": SOC2Mapping(
        soc2_criterion_id="C1.1",
        soc2_criterion_name="Confidential information identification",
        nist_controls=["RA-2", "PM-11", "SC-16"],
        mapping_rationale="Information classification",
    ),
    "C1.2": SOC2Mapping(
        soc2_criterion_id="C1.2",
        soc2_criterion_name="Confidential information disposal",
        nist_controls=["MP-6", "SR-12", "SI-12"],
        mapping_rationale="Secure disposal",
    ),
}


# =============================================================================
# SOC 2 Privacy to NIST 800-53 Mappings
# =============================================================================

SOC2_PRIVACY_TO_NIST_800_53: dict[str, SOC2Mapping] = {
    "P1.1": SOC2Mapping(
        soc2_criterion_id="P1.1",
        soc2_criterion_name="Privacy notice and consent",
        nist_controls=["PT-5", "PT-6", "SI-18"],
        mapping_rationale="Privacy notice and transparency",
    ),
    "P2.1": SOC2Mapping(
        soc2_criterion_id="P2.1",
        soc2_criterion_name="Lawful and fair collection of personal information",
        nist_controls=["PT-2", "PT-3"],
        mapping_rationale="Collection limitations",
    ),
    "P3.1": SOC2Mapping(
        soc2_criterion_id="P3.1",
        soc2_criterion_name="Use and retention of personal information",
        nist_controls=["PT-3", "SI-12"],
        mapping_rationale="Use and retention limitations",
    ),
    "P4.1": SOC2Mapping(
        soc2_criterion_id="P4.1",
        soc2_criterion_name="Access to personal information",
        nist_controls=["PT-4", "PT-6"],
        mapping_rationale="Individual access rights",
    ),
    "P5.1": SOC2Mapping(
        soc2_criterion_id="P5.1",
        soc2_criterion_name="Personal information disclosure",
        nist_controls=["PT-2", "PT-6"],
        mapping_rationale="Disclosure limitations",
    ),
    "P6.1": SOC2Mapping(
        soc2_criterion_id="P6.1",
        soc2_criterion_name="Personal information quality",
        nist_controls=["PT-4", "SI-18"],
        mapping_rationale="Data quality",
    ),
    "P7.1": SOC2Mapping(
        soc2_criterion_id="P7.1",
        soc2_criterion_name="Privacy complaints and inquiries",
        nist_controls=["PT-7", "PT-8"],
        mapping_rationale="Complaint handling",
    ),
    "P8.1": SOC2Mapping(
        soc2_criterion_id="P8.1",
        soc2_criterion_name="Privacy monitoring and enforcement",
        nist_controls=["PT-1", "CA-7", "PM-20"],
        mapping_rationale="Privacy monitoring",
    ),
}


# =============================================================================
# Combined Mappings
# =============================================================================


def get_all_soc2_mappings() -> dict[str, SOC2Mapping]:
    """Get all SOC 2 to NIST 800-53 mappings combined."""
    all_mappings = {}
    all_mappings.update(SOC2_CC_TO_NIST_800_53)
    all_mappings.update(SOC2_AVAILABILITY_TO_NIST_800_53)
    all_mappings.update(SOC2_PROCESSING_INTEGRITY_TO_NIST_800_53)
    all_mappings.update(SOC2_CONFIDENTIALITY_TO_NIST_800_53)
    all_mappings.update(SOC2_PRIVACY_TO_NIST_800_53)
    return all_mappings


# =============================================================================
# Utility Functions
# =============================================================================


def get_soc2_to_nist_mapping(soc2_criterion_id: str) -> SOC2Mapping | None:
    """
    Get NIST 800-53 controls mapped to a SOC 2 criterion.

    Args:
        soc2_criterion_id: SOC 2 criterion ID (e.g., "CC6.1")

    Returns:
        SOC2Mapping if found, None otherwise
    """
    all_mappings = get_all_soc2_mappings()
    return all_mappings.get(soc2_criterion_id)


def get_nist_controls_for_soc2(soc2_criterion_id: str) -> list[str]:
    """
    Get NIST 800-53 control IDs mapped to a SOC 2 criterion.

    Args:
        soc2_criterion_id: SOC 2 criterion ID (e.g., "CC6.1")

    Returns:
        List of NIST 800-53 control IDs
    """
    mapping = get_soc2_to_nist_mapping(soc2_criterion_id)
    return mapping.nist_controls if mapping else []


def get_soc2_criteria_for_nist(nist_control_id: str) -> list[SOC2Mapping]:
    """
    Get all SOC 2 criteria mapped to a NIST 800-53 control.

    Args:
        nist_control_id: NIST 800-53 control ID (e.g., "AC-2")

    Returns:
        List of SOC2Mapping objects
    """
    results: list[SOC2Mapping] = []
    nist_id_upper = nist_control_id.upper()
    all_mappings = get_all_soc2_mappings()

    for mapping in all_mappings.values():
        if nist_id_upper in [c.upper() for c in mapping.nist_controls]:
            results.append(mapping)

    return results


def get_all_mapped_nist_controls_from_soc2() -> set[str]:
    """
    Get all NIST 800-53 controls that have SOC 2 mappings.

    Returns:
        Set of NIST 800-53 control IDs
    """
    controls: set[str] = set()
    all_mappings = get_all_soc2_mappings()

    for mapping in all_mappings.values():
        controls.update(mapping.nist_controls)

    return controls


def get_soc2_mapping_statistics() -> dict:
    """
    Get statistics about SOC 2 to NIST 800-53 mappings.

    Returns:
        Dictionary with mapping statistics
    """
    all_controls = get_all_mapped_nist_controls_from_soc2()

    return {
        "total_soc2_criteria_mapped": len(get_all_soc2_mappings()),
        "common_criteria_mapped": len(SOC2_CC_TO_NIST_800_53),
        "availability_criteria_mapped": len(SOC2_AVAILABILITY_TO_NIST_800_53),
        "processing_integrity_mapped": len(SOC2_PROCESSING_INTEGRITY_TO_NIST_800_53),
        "confidentiality_mapped": len(SOC2_CONFIDENTIALITY_TO_NIST_800_53),
        "privacy_mapped": len(SOC2_PRIVACY_TO_NIST_800_53),
        "unique_nist_controls_covered": len(all_controls),
    }


def get_soc2_category_coverage() -> dict[str, list[str]]:
    """
    Get NIST control coverage by SOC 2 category.

    Returns:
        Dictionary mapping SOC 2 category to list of NIST controls
    """
    return {
        "common_criteria": sorted(
            set().union(*[set(m.nist_controls) for m in SOC2_CC_TO_NIST_800_53.values()])
        ),
        "availability": sorted(
            set().union(*[set(m.nist_controls) for m in SOC2_AVAILABILITY_TO_NIST_800_53.values()])
        ),
        "processing_integrity": sorted(
            set().union(*[set(m.nist_controls) for m in SOC2_PROCESSING_INTEGRITY_TO_NIST_800_53.values()])
        ),
        "confidentiality": sorted(
            set().union(*[set(m.nist_controls) for m in SOC2_CONFIDENTIALITY_TO_NIST_800_53.values()])
        ),
        "privacy": sorted(
            set().union(*[set(m.nist_controls) for m in SOC2_PRIVACY_TO_NIST_800_53.values()])
        ),
    }


__all__ = [
    # Data classes
    "SOC2Mapping",
    # Mapping tables
    "SOC2_CC_TO_NIST_800_53",
    "SOC2_AVAILABILITY_TO_NIST_800_53",
    "SOC2_PROCESSING_INTEGRITY_TO_NIST_800_53",
    "SOC2_CONFIDENTIALITY_TO_NIST_800_53",
    "SOC2_PRIVACY_TO_NIST_800_53",
    # Functions
    "get_all_soc2_mappings",
    "get_soc2_to_nist_mapping",
    "get_nist_controls_for_soc2",
    "get_soc2_criteria_for_nist",
    "get_all_mapped_nist_controls_from_soc2",
    "get_soc2_mapping_statistics",
    "get_soc2_category_coverage",
]
