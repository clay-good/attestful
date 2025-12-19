"""
HITRUST CSF Control Definitions.

Provides control definitions for HITRUST CSF (Common Security Framework) controls,
organized by domain with mappings to underlying frameworks.

HITRUST CSF Control Categories (Domains):
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

HITRUST Maturity Levels:
- Level 1 (Policy): Policy exists
- Level 2 (Procedure): Procedure exists and is implemented
- Level 3 (Implemented): Control is implemented
- Level 4 (Measured): Control is measured
- Level 5 (Managed): Control is managed and optimized

Note: HITRUST CSF is based on ISO 27001/27002, NIST 800-53, HIPAA, PCI DSS,
and other frameworks. This implementation focuses on commonly assessed controls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from attestful.core.logging import get_logger

logger = get_logger("frameworks.hitrust.controls")


# =============================================================================
# Constants
# =============================================================================

HITRUST_FRAMEWORK_ID = "hitrust-csf"
HITRUST_VERSION = "11.0"  # Current major version

# Control category (domain) constants
CATEGORY_ISMP = "00"  # Information Security Management Program
CATEGORY_ACCESS_CONTROL = "01"  # Access Control
CATEGORY_HR_SECURITY = "02"  # Human Resources Security
CATEGORY_RISK_MANAGEMENT = "03"  # Risk Management
CATEGORY_SECURITY_POLICY = "04"  # Security Policy
CATEGORY_ORG_SECURITY = "05"  # Organization of Information Security
CATEGORY_COMPLIANCE = "06"  # Compliance
CATEGORY_ASSET_MGMT = "07"  # Asset Management
CATEGORY_PHYSICAL = "08"  # Physical and Environmental Security
CATEGORY_OPERATIONS = "09"  # Communications and Operations Management
CATEGORY_SDLC = "10"  # Information Systems Acquisition, Development, Maintenance
CATEGORY_INCIDENT = "11"  # Information Security Incident Management
CATEGORY_BCM = "12"  # Business Continuity Management
CATEGORY_PRIVACY = "13"  # Privacy Practices

# Domain names
CATEGORY_NAMES = {
    CATEGORY_ISMP: "Information Security Management Program",
    CATEGORY_ACCESS_CONTROL: "Access Control",
    CATEGORY_HR_SECURITY: "Human Resources Security",
    CATEGORY_RISK_MANAGEMENT: "Risk Management",
    CATEGORY_SECURITY_POLICY: "Security Policy",
    CATEGORY_ORG_SECURITY: "Organization of Information Security",
    CATEGORY_COMPLIANCE: "Compliance",
    CATEGORY_ASSET_MGMT: "Asset Management",
    CATEGORY_PHYSICAL: "Physical and Environmental Security",
    CATEGORY_OPERATIONS: "Communications and Operations Management",
    CATEGORY_SDLC: "Information Systems Acquisition, Development, and Maintenance",
    CATEGORY_INCIDENT: "Information Security Incident Management",
    CATEGORY_BCM: "Business Continuity Management",
    CATEGORY_PRIVACY: "Privacy Practices",
}

# Maturity levels
MATURITY_POLICY = 1
MATURITY_PROCEDURE = 2
MATURITY_IMPLEMENTED = 3
MATURITY_MEASURED = 4
MATURITY_MANAGED = 5

MATURITY_LEVEL_NAMES = {
    MATURITY_POLICY: "Policy",
    MATURITY_PROCEDURE: "Procedure",
    MATURITY_IMPLEMENTED: "Implemented",
    MATURITY_MEASURED: "Measured",
    MATURITY_MANAGED: "Managed",
}


# =============================================================================
# Data Models
# =============================================================================


@dataclass
class HITRUSTControl:
    """
    Represents a HITRUST CSF control requirement.

    Attributes:
        id: Control identifier (e.g., "01.a").
        title: Control title.
        description: Control description/requirement statement.
        category: Control category (domain) code.
        control_reference: Reference number within HITRUST.
        implementation_requirement: Specific implementation requirement.
        maturity_level: Required maturity level (1-5).
        nist_mappings: Mapped NIST 800-53 control IDs.
        iso_mappings: Mapped ISO 27001 control IDs.
        hipaa_mappings: Mapped HIPAA requirements.
        pci_mappings: Mapped PCI DSS requirements.
        assessment_factors: Factors used in assessment.
    """

    id: str
    title: str
    description: str
    category: str
    control_reference: str = ""
    implementation_requirement: str = ""
    maturity_level: int = MATURITY_IMPLEMENTED
    nist_mappings: list[str] = field(default_factory=list)
    iso_mappings: list[str] = field(default_factory=list)
    hipaa_mappings: list[str] = field(default_factory=list)
    pci_mappings: list[str] = field(default_factory=list)
    assessment_factors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "category_name": CATEGORY_NAMES.get(self.category, "Unknown"),
            "control_reference": self.control_reference,
            "implementation_requirement": self.implementation_requirement,
            "maturity_level": self.maturity_level,
            "maturity_level_name": MATURITY_LEVEL_NAMES.get(self.maturity_level, "Unknown"),
            "nist_mappings": self.nist_mappings,
            "iso_mappings": self.iso_mappings,
            "hipaa_mappings": self.hipaa_mappings,
            "pci_mappings": self.pci_mappings,
            "assessment_factors": self.assessment_factors,
        }


@dataclass
class HITRUSTFramework:
    """
    HITRUST CSF framework implementation.

    Attributes:
        version: Framework version.
        controls: Dictionary of controls by ID.
        check_mappings: Mapping of control IDs to automated check IDs.
    """

    version: str = HITRUST_VERSION
    controls: dict[str, HITRUSTControl] = field(default_factory=dict)
    check_mappings: dict[str, list[str]] = field(default_factory=dict)

    def get_control(self, control_id: str) -> HITRUSTControl | None:
        """Get a control by ID."""
        return self.controls.get(control_id)

    def get_checks_for_control(self, control_id: str) -> list[str]:
        """Get check IDs mapped to a control."""
        return self.check_mappings.get(control_id, [])

    def get_controls_by_category(self, category: str) -> list[HITRUSTControl]:
        """Get all controls in a category."""
        return [c for c in self.controls.values() if c.category == category]

    def get_controls_by_maturity_level(self, level: int) -> list[HITRUSTControl]:
        """Get all controls at or below a maturity level."""
        return [c for c in self.controls.values() if c.maturity_level <= level]


# =============================================================================
# HITRUST CSF Control Definitions
# =============================================================================

# Note: HITRUST CSF contains hundreds of controls. This implementation includes
# the most commonly assessed controls from each category. The full control set
# would be loaded from the OSCAL catalog.

HITRUST_CONTROLS: dict[str, HITRUSTControl] = {
    # =========================================================================
    # 00: Information Security Management Program
    # =========================================================================
    "00.a": HITRUSTControl(
        id="00.a",
        title="Information Security Management Program",
        description="The organization shall establish and maintain an information security management program (ISMP) that includes the development and maintenance of security policies, assignment of responsibilities, and ongoing monitoring and improvement.",
        category=CATEGORY_ISMP,
        control_reference="00.a",
        implementation_requirement="Establish and maintain an ISMP that addresses all aspects of information security.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PM-1", "PM-2", "PM-3"],
        iso_mappings=["A.5.1"],
        hipaa_mappings=["164.308(a)(1)"],
        pci_mappings=["12.1"],
    ),

    # =========================================================================
    # 01: Access Control
    # =========================================================================
    "01.a": HITRUSTControl(
        id="01.a",
        title="Access Control Policy",
        description="Access control policies shall be established, documented, and reviewed based on business and information security requirements.",
        category=CATEGORY_ACCESS_CONTROL,
        control_reference="01.a",
        implementation_requirement="Document and implement access control policy.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["AC-1", "AC-2"],
        iso_mappings=["A.5.15", "A.5.18"],
        hipaa_mappings=["164.312(a)(1)"],
        pci_mappings=["7.1", "7.2"],
    ),
    "01.b": HITRUSTControl(
        id="01.b",
        title="User Registration and De-registration",
        description="A formal user registration and de-registration procedure shall be implemented to enable assignment and revocation of access rights.",
        category=CATEGORY_ACCESS_CONTROL,
        control_reference="01.b",
        implementation_requirement="Implement formal user provisioning and deprovisioning processes.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["AC-2", "IA-4"],
        iso_mappings=["A.5.16", "A.5.18"],
        hipaa_mappings=["164.308(a)(4)(ii)(B)"],
        pci_mappings=["8.1.1", "8.1.3"],
    ),
    "01.c": HITRUSTControl(
        id="01.c",
        title="Privilege Management",
        description="The allocation and use of privileged access rights shall be restricted and controlled.",
        category=CATEGORY_ACCESS_CONTROL,
        control_reference="01.c",
        implementation_requirement="Restrict and control privileged access.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["AC-6", "AC-2(7)"],
        iso_mappings=["A.8.2"],
        hipaa_mappings=["164.308(a)(4)(ii)(B)"],
        pci_mappings=["7.1.2", "7.2.2"],
    ),
    "01.d": HITRUSTControl(
        id="01.d",
        title="User Password Management",
        description="The allocation of secret authentication information shall be controlled through a formal management process.",
        category=CATEGORY_ACCESS_CONTROL,
        control_reference="01.d",
        implementation_requirement="Implement password management controls.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["IA-5", "IA-5(1)"],
        iso_mappings=["A.5.17"],
        hipaa_mappings=["164.308(a)(5)(ii)(D)"],
        pci_mappings=["8.2.1", "8.2.3"],
    ),
    "01.e": HITRUSTControl(
        id="01.e",
        title="Review of User Access Rights",
        description="Asset owners shall review users access rights at regular intervals.",
        category=CATEGORY_ACCESS_CONTROL,
        control_reference="01.e",
        implementation_requirement="Conduct regular access reviews.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["AC-2(3)", "AC-6(7)"],
        iso_mappings=["A.5.18"],
        hipaa_mappings=["164.308(a)(4)(ii)(C)"],
        pci_mappings=["7.1.3"],
    ),
    "01.f": HITRUSTControl(
        id="01.f",
        title="Password Use",
        description="Users shall be required to follow good security practices in the selection and use of passwords.",
        category=CATEGORY_ACCESS_CONTROL,
        control_reference="01.f",
        implementation_requirement="Implement password complexity requirements.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["IA-5(1)"],
        iso_mappings=["A.5.17"],
        hipaa_mappings=["164.308(a)(5)(ii)(D)"],
        pci_mappings=["8.2.3", "8.2.4"],
    ),
    "01.g": HITRUSTControl(
        id="01.g",
        title="Unattended User Equipment",
        description="Users shall ensure that unattended equipment has appropriate protection.",
        category=CATEGORY_ACCESS_CONTROL,
        control_reference="01.g",
        implementation_requirement="Implement screen locking and session timeout.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["AC-11", "AC-11(1)"],
        iso_mappings=["A.8.1"],
        hipaa_mappings=["164.310(b)"],
        pci_mappings=["8.1.8"],
    ),
    "01.h": HITRUSTControl(
        id="01.h",
        title="Network Access Control",
        description="Users shall only be provided access to internal and external network services for which they have been specifically authorized.",
        category=CATEGORY_ACCESS_CONTROL,
        control_reference="01.h",
        implementation_requirement="Implement network segmentation and access controls.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["AC-4", "SC-7"],
        iso_mappings=["A.8.20", "A.8.21"],
        hipaa_mappings=["164.312(a)(1)"],
        pci_mappings=["1.1", "1.2"],
    ),
    "01.i": HITRUSTControl(
        id="01.i",
        title="User Authentication for External Connections",
        description="Appropriate authentication methods shall be used to control access by remote users.",
        category=CATEGORY_ACCESS_CONTROL,
        control_reference="01.i",
        implementation_requirement="Implement multi-factor authentication for remote access.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["IA-2", "IA-2(1)", "IA-2(2)"],
        iso_mappings=["A.8.5"],
        hipaa_mappings=["164.312(d)"],
        pci_mappings=["8.3"],
    ),
    "01.j": HITRUSTControl(
        id="01.j",
        title="Equipment Identification in Networks",
        description="Automatic equipment identification shall be considered as a means to authenticate connections from specific locations and equipment.",
        category=CATEGORY_ACCESS_CONTROL,
        control_reference="01.j",
        implementation_requirement="Implement device authentication where appropriate.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["IA-3"],
        iso_mappings=["A.8.20"],
        hipaa_mappings=["164.312(d)"],
        pci_mappings=["1.1.6"],
    ),

    # =========================================================================
    # 02: Human Resources Security
    # =========================================================================
    "02.a": HITRUSTControl(
        id="02.a",
        title="Roles and Responsibilities",
        description="Security roles and responsibilities of employees, contractors, and third-party users shall be defined and documented.",
        category=CATEGORY_HR_SECURITY,
        control_reference="02.a",
        implementation_requirement="Document security roles and responsibilities.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PS-1", "PS-7"],
        iso_mappings=["A.5.2", "A.6.1"],
        hipaa_mappings=["164.308(a)(2)"],
        pci_mappings=["12.4"],
    ),
    "02.b": HITRUSTControl(
        id="02.b",
        title="Screening",
        description="Background verification checks on all candidates for employment, contractors, and third-party users shall be carried out in accordance with relevant laws, regulations, and ethics.",
        category=CATEGORY_HR_SECURITY,
        control_reference="02.b",
        implementation_requirement="Implement background screening program.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PS-3"],
        iso_mappings=["A.6.1"],
        hipaa_mappings=["164.308(a)(3)(ii)(B)"],
        pci_mappings=["12.7"],
    ),
    "02.c": HITRUSTControl(
        id="02.c",
        title="Terms and Conditions of Employment",
        description="As part of their contractual obligation, employees, contractors, and third-party users shall agree and sign the terms and conditions of their employment contract.",
        category=CATEGORY_HR_SECURITY,
        control_reference="02.c",
        implementation_requirement="Include security requirements in employment agreements.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PS-6", "PS-7"],
        iso_mappings=["A.6.2"],
        hipaa_mappings=["164.308(a)(3)(ii)(A)"],
        pci_mappings=["12.8.2"],
    ),
    "02.d": HITRUSTControl(
        id="02.d",
        title="Information Security Awareness, Education, and Training",
        description="All employees and relevant third parties shall receive appropriate awareness training and regular updates in organizational policies and procedures.",
        category=CATEGORY_HR_SECURITY,
        control_reference="02.d",
        implementation_requirement="Implement security awareness training program.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["AT-1", "AT-2", "AT-3"],
        iso_mappings=["A.6.3"],
        hipaa_mappings=["164.308(a)(5)(i)"],
        pci_mappings=["12.6"],
    ),
    "02.e": HITRUSTControl(
        id="02.e",
        title="Disciplinary Process",
        description="There shall be a formal disciplinary process for employees who have committed a security breach.",
        category=CATEGORY_HR_SECURITY,
        control_reference="02.e",
        implementation_requirement="Implement disciplinary process for security violations.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PS-8"],
        iso_mappings=["A.6.4"],
        hipaa_mappings=["164.308(a)(1)(ii)(C)"],
        pci_mappings=["12.3"],
    ),
    "02.f": HITRUSTControl(
        id="02.f",
        title="Termination or Change Responsibilities",
        description="Responsibilities for performing employment termination or change of employment shall be clearly defined and assigned.",
        category=CATEGORY_HR_SECURITY,
        control_reference="02.f",
        implementation_requirement="Implement termination and job change procedures.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PS-4", "PS-5"],
        iso_mappings=["A.6.5"],
        hipaa_mappings=["164.308(a)(3)(ii)(C)"],
        pci_mappings=["8.1.3"],
    ),
    "02.g": HITRUSTControl(
        id="02.g",
        title="Return of Assets",
        description="All employees, contractors, and third-party users shall return all organizational assets in their possession upon termination.",
        category=CATEGORY_HR_SECURITY,
        control_reference="02.g",
        implementation_requirement="Implement asset return process for offboarding.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PS-4"],
        iso_mappings=["A.6.5"],
        hipaa_mappings=["164.308(a)(3)(ii)(C)"],
        pci_mappings=["9.9.3"],
    ),
    "02.h": HITRUSTControl(
        id="02.h",
        title="Removal of Access Rights",
        description="The access rights of all employees, contractors, and third-party users shall be removed upon termination or adjusted upon change.",
        category=CATEGORY_HR_SECURITY,
        control_reference="02.h",
        implementation_requirement="Implement access removal upon termination.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PS-4", "PS-5"],
        iso_mappings=["A.6.5"],
        hipaa_mappings=["164.308(a)(3)(ii)(C)"],
        pci_mappings=["8.1.3"],
    ),

    # =========================================================================
    # 03: Risk Management
    # =========================================================================
    "03.a": HITRUSTControl(
        id="03.a",
        title="Risk Management Program",
        description="A comprehensive risk management program shall be developed and maintained.",
        category=CATEGORY_RISK_MANAGEMENT,
        control_reference="03.a",
        implementation_requirement="Establish a formal risk management program.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["RA-1", "RA-2", "RA-3"],
        iso_mappings=["A.5.7", "A.5.8"],
        hipaa_mappings=["164.308(a)(1)(ii)(A)"],
        pci_mappings=["12.2"],
    ),
    "03.b": HITRUSTControl(
        id="03.b",
        title="Risk Assessment",
        description="Risk assessments shall identify, quantify, and prioritize risks against criteria for risk acceptance.",
        category=CATEGORY_RISK_MANAGEMENT,
        control_reference="03.b",
        implementation_requirement="Conduct regular risk assessments.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["RA-3", "RA-5"],
        iso_mappings=["A.5.7"],
        hipaa_mappings=["164.308(a)(1)(ii)(A)"],
        pci_mappings=["12.2"],
    ),
    "03.c": HITRUSTControl(
        id="03.c",
        title="Risk Treatment",
        description="Appropriate controls shall be selected and implemented to mitigate identified risks.",
        category=CATEGORY_RISK_MANAGEMENT,
        control_reference="03.c",
        implementation_requirement="Implement risk treatment plans.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["RA-7", "PM-9"],
        iso_mappings=["A.5.8"],
        hipaa_mappings=["164.308(a)(1)(ii)(B)"],
        pci_mappings=["12.2"],
    ),

    # =========================================================================
    # 04: Security Policy
    # =========================================================================
    "04.a": HITRUSTControl(
        id="04.a",
        title="Information Security Policy Document",
        description="An information security policy shall be approved by management, published, and communicated to all employees and relevant external parties.",
        category=CATEGORY_SECURITY_POLICY,
        control_reference="04.a",
        implementation_requirement="Develop and publish information security policy.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PL-1", "PM-1"],
        iso_mappings=["A.5.1"],
        hipaa_mappings=["164.308(a)(1)"],
        pci_mappings=["12.1"],
    ),
    "04.b": HITRUSTControl(
        id="04.b",
        title="Review of the Information Security Policy",
        description="The information security policy shall be reviewed at planned intervals or when significant changes occur to ensure its continuing suitability, adequacy, and effectiveness.",
        category=CATEGORY_SECURITY_POLICY,
        control_reference="04.b",
        implementation_requirement="Review and update security policy regularly.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PL-1", "PM-1"],
        iso_mappings=["A.5.1"],
        hipaa_mappings=["164.308(a)(8)"],
        pci_mappings=["12.1.1"],
    ),

    # =========================================================================
    # 05: Organization of Information Security
    # =========================================================================
    "05.a": HITRUSTControl(
        id="05.a",
        title="Management Commitment to Information Security",
        description="Management shall actively support security within the organization through clear direction, demonstrated commitment, explicit assignment, and acknowledgment of information security responsibilities.",
        category=CATEGORY_ORG_SECURITY,
        control_reference="05.a",
        implementation_requirement="Demonstrate management commitment to security.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PM-1", "PM-2"],
        iso_mappings=["A.5.1", "A.5.2"],
        hipaa_mappings=["164.308(a)(2)"],
        pci_mappings=["12.1", "12.4"],
    ),
    "05.b": HITRUSTControl(
        id="05.b",
        title="Information Security Coordination",
        description="Information security activities shall be coordinated by representatives from different parts of the organization.",
        category=CATEGORY_ORG_SECURITY,
        control_reference="05.b",
        implementation_requirement="Establish security coordination mechanisms.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PM-2", "PM-10"],
        iso_mappings=["A.5.2"],
        hipaa_mappings=["164.308(a)(2)"],
        pci_mappings=["12.5"],
    ),
    "05.c": HITRUSTControl(
        id="05.c",
        title="Authorization Process for Information Processing Facilities",
        description="A management authorization process for new information processing facilities shall be defined and implemented.",
        category=CATEGORY_ORG_SECURITY,
        control_reference="05.c",
        implementation_requirement="Implement change authorization process.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CA-6", "CM-3"],
        iso_mappings=["A.5.9"],
        hipaa_mappings=["164.308(a)(1)(ii)(B)"],
        pci_mappings=["6.4.2"],
    ),
    "05.d": HITRUSTControl(
        id="05.d",
        title="Confidentiality Agreements",
        description="Requirements for confidentiality or non-disclosure agreements reflecting the organization's needs shall be identified and regularly reviewed.",
        category=CATEGORY_ORG_SECURITY,
        control_reference="05.d",
        implementation_requirement="Implement confidentiality agreements.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PS-6"],
        iso_mappings=["A.6.6"],
        hipaa_mappings=["164.308(b)(1)"],
        pci_mappings=["12.8.2"],
    ),
    "05.e": HITRUSTControl(
        id="05.e",
        title="Contact with Authorities",
        description="Appropriate contacts with relevant authorities shall be maintained.",
        category=CATEGORY_ORG_SECURITY,
        control_reference="05.e",
        implementation_requirement="Maintain contact with authorities.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["IR-6", "PM-15"],
        iso_mappings=["A.5.5"],
        hipaa_mappings=["164.308(a)(6)(ii)"],
        pci_mappings=["12.10.1"],
    ),
    "05.f": HITRUSTControl(
        id="05.f",
        title="Contact with Special Interest Groups",
        description="Appropriate contacts with special interest groups, forums, and professional associations shall be maintained.",
        category=CATEGORY_ORG_SECURITY,
        control_reference="05.f",
        implementation_requirement="Maintain security community contacts.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PM-15", "PM-16"],
        iso_mappings=["A.5.6"],
        hipaa_mappings=["164.308(a)(1)"],
        pci_mappings=["12.10.1"],
    ),
    "05.g": HITRUSTControl(
        id="05.g",
        title="Independent Review of Information Security",
        description="The organization's approach to managing information security shall be reviewed independently at planned intervals.",
        category=CATEGORY_ORG_SECURITY,
        control_reference="05.g",
        implementation_requirement="Conduct independent security reviews.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CA-7", "PM-14"],
        iso_mappings=["A.5.35"],
        hipaa_mappings=["164.308(a)(8)"],
        pci_mappings=["11.3", "12.11"],
    ),
    "05.h": HITRUSTControl(
        id="05.h",
        title="Identification of Risks Related to External Parties",
        description="Risks to the organization's information from business processes involving external parties shall be identified and appropriate controls implemented.",
        category=CATEGORY_ORG_SECURITY,
        control_reference="05.h",
        implementation_requirement="Assess risks from third parties.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SA-9", "SR-6"],
        iso_mappings=["A.5.19", "A.5.20"],
        hipaa_mappings=["164.308(b)(1)"],
        pci_mappings=["12.8"],
    ),
    "05.i": HITRUSTControl(
        id="05.i",
        title="Addressing Security When Dealing with Customers",
        description="All identified security requirements shall be addressed before giving customers access to the organization's information or assets.",
        category=CATEGORY_ORG_SECURITY,
        control_reference="05.i",
        implementation_requirement="Address security in customer agreements.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SA-9", "SC-14"],
        iso_mappings=["A.5.21"],
        hipaa_mappings=["164.308(b)(3)"],
        pci_mappings=["12.8.2"],
    ),
    "05.j": HITRUSTControl(
        id="05.j",
        title="Addressing Security in Third-Party Agreements",
        description="Agreements with third parties involving accessing, processing, communicating, or managing the organization's information shall cover all relevant security requirements.",
        category=CATEGORY_ORG_SECURITY,
        control_reference="05.j",
        implementation_requirement="Include security in third-party contracts.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SA-9", "SR-3"],
        iso_mappings=["A.5.20"],
        hipaa_mappings=["164.308(b)(1)"],
        pci_mappings=["12.8.2"],
    ),

    # =========================================================================
    # 06: Compliance
    # =========================================================================
    "06.a": HITRUSTControl(
        id="06.a",
        title="Identification of Applicable Legislation",
        description="All relevant legislative, regulatory, and contractual requirements shall be explicitly defined, documented, and kept up to date.",
        category=CATEGORY_COMPLIANCE,
        control_reference="06.a",
        implementation_requirement="Identify applicable legal requirements.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PM-8", "SA-12"],
        iso_mappings=["A.5.31"],
        hipaa_mappings=["164.308(a)(1)"],
        pci_mappings=["12.1.1"],
    ),
    "06.b": HITRUSTControl(
        id="06.b",
        title="Intellectual Property Rights",
        description="Appropriate procedures shall be implemented to ensure compliance with legislative, regulatory, and contractual requirements on intellectual property rights.",
        category=CATEGORY_COMPLIANCE,
        control_reference="06.b",
        implementation_requirement="Protect intellectual property rights.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PM-8"],
        iso_mappings=["A.5.32"],
        hipaa_mappings=["164.530(c)"],
        pci_mappings=["12.1.1"],
    ),
    "06.c": HITRUSTControl(
        id="06.c",
        title="Protection of Organizational Records",
        description="Records shall be protected from loss, destruction, falsification, unauthorized access, and unauthorized release.",
        category=CATEGORY_COMPLIANCE,
        control_reference="06.c",
        implementation_requirement="Protect organizational records.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["AU-9", "AU-11"],
        iso_mappings=["A.5.33"],
        hipaa_mappings=["164.530(j)"],
        pci_mappings=["10.7"],
    ),
    "06.d": HITRUSTControl(
        id="06.d",
        title="Data Protection and Privacy of Personal Information",
        description="Data protection and privacy shall be ensured as required by relevant legislation, regulations, and contractual clauses.",
        category=CATEGORY_COMPLIANCE,
        control_reference="06.d",
        implementation_requirement="Implement data protection controls.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PT-1", "PT-2"],
        iso_mappings=["A.5.34"],
        hipaa_mappings=["164.502", "164.514"],
        pci_mappings=["3.1", "3.4"],
    ),
    "06.e": HITRUSTControl(
        id="06.e",
        title="Prevention of Misuse of Information Processing Facilities",
        description="Users shall be deterred from using information processing facilities for unauthorized purposes.",
        category=CATEGORY_COMPLIANCE,
        control_reference="06.e",
        implementation_requirement="Prevent misuse of systems.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["AC-8", "PL-4"],
        iso_mappings=["A.5.10"],
        hipaa_mappings=["164.308(a)(3)(ii)(A)"],
        pci_mappings=["12.3"],
    ),
    "06.f": HITRUSTControl(
        id="06.f",
        title="Regulation of Cryptographic Controls",
        description="Cryptographic controls shall be used in compliance with all relevant agreements, laws, and regulations.",
        category=CATEGORY_COMPLIANCE,
        control_reference="06.f",
        implementation_requirement="Ensure compliant use of cryptography.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SC-13"],
        iso_mappings=["A.8.24"],
        hipaa_mappings=["164.312(a)(2)(iv)"],
        pci_mappings=["3.5", "4.1"],
    ),
    "06.g": HITRUSTControl(
        id="06.g",
        title="Compliance with Security Policies and Standards",
        description="Managers shall ensure that all security procedures within their area of responsibility are carried out correctly.",
        category=CATEGORY_COMPLIANCE,
        control_reference="06.g",
        implementation_requirement="Ensure compliance with security policies.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CA-2", "PM-14"],
        iso_mappings=["A.5.36"],
        hipaa_mappings=["164.308(a)(8)"],
        pci_mappings=["12.11"],
    ),
    "06.h": HITRUSTControl(
        id="06.h",
        title="Technical Compliance Checking",
        description="Information systems shall be regularly checked for compliance with security implementation standards.",
        category=CATEGORY_COMPLIANCE,
        control_reference="06.h",
        implementation_requirement="Conduct technical compliance assessments.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CA-2", "RA-5"],
        iso_mappings=["A.5.36", "A.8.8"],
        hipaa_mappings=["164.308(a)(8)"],
        pci_mappings=["11.2", "11.3"],
    ),
    "06.i": HITRUSTControl(
        id="06.i",
        title="Information Systems Audit Controls",
        description="Audit requirements and activities involving checks on operational systems shall be planned and agreed to minimize disruptions.",
        category=CATEGORY_COMPLIANCE,
        control_reference="06.i",
        implementation_requirement="Plan and control audit activities.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["AU-1", "AU-2"],
        iso_mappings=["A.5.35"],
        hipaa_mappings=["164.312(b)"],
        pci_mappings=["10.1", "10.2"],
    ),

    # =========================================================================
    # 07: Asset Management
    # =========================================================================
    "07.a": HITRUSTControl(
        id="07.a",
        title="Inventory of Assets",
        description="All assets shall be clearly identified and an inventory of all important assets drawn up and maintained.",
        category=CATEGORY_ASSET_MGMT,
        control_reference="07.a",
        implementation_requirement="Maintain asset inventory.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CM-8", "PM-5"],
        iso_mappings=["A.5.9"],
        hipaa_mappings=["164.310(d)(1)"],
        pci_mappings=["2.4", "9.9.1"],
    ),
    "07.b": HITRUSTControl(
        id="07.b",
        title="Ownership of Assets",
        description="All information and assets associated with information processing facilities shall be owned by a designated part of the organization.",
        category=CATEGORY_ASSET_MGMT,
        control_reference="07.b",
        implementation_requirement="Assign asset ownership.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CM-8"],
        iso_mappings=["A.5.9"],
        hipaa_mappings=["164.310(d)(1)"],
        pci_mappings=["9.9.1"],
    ),
    "07.c": HITRUSTControl(
        id="07.c",
        title="Acceptable Use of Assets",
        description="Rules for the acceptable use of information and assets associated with information processing facilities shall be identified, documented, and implemented.",
        category=CATEGORY_ASSET_MGMT,
        control_reference="07.c",
        implementation_requirement="Define acceptable use policies.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PL-4", "AC-8"],
        iso_mappings=["A.5.10"],
        hipaa_mappings=["164.310(b)"],
        pci_mappings=["12.3"],
    ),
    "07.d": HITRUSTControl(
        id="07.d",
        title="Classification Guidelines",
        description="Information shall be classified in terms of its value, legal requirements, sensitivity, and criticality to the organization.",
        category=CATEGORY_ASSET_MGMT,
        control_reference="07.d",
        implementation_requirement="Implement data classification scheme.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["RA-2", "SC-16"],
        iso_mappings=["A.5.12"],
        hipaa_mappings=["164.312(a)(1)"],
        pci_mappings=["9.6.1"],
    ),
    "07.e": HITRUSTControl(
        id="07.e",
        title="Labeling and Handling of Information",
        description="An appropriate set of procedures for information labeling and handling shall be developed and implemented.",
        category=CATEGORY_ASSET_MGMT,
        control_reference="07.e",
        implementation_requirement="Implement data labeling procedures.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["MP-3", "SC-16"],
        iso_mappings=["A.5.13"],
        hipaa_mappings=["164.312(c)(1)"],
        pci_mappings=["9.6.1"],
    ),

    # =========================================================================
    # 08: Physical and Environmental Security
    # =========================================================================
    "08.a": HITRUSTControl(
        id="08.a",
        title="Physical Security Perimeter",
        description="Security perimeters shall be used to protect areas that contain information and information processing facilities.",
        category=CATEGORY_PHYSICAL,
        control_reference="08.a",
        implementation_requirement="Implement physical security perimeter.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PE-3", "PE-4"],
        iso_mappings=["A.7.1"],
        hipaa_mappings=["164.310(a)(1)"],
        pci_mappings=["9.1"],
    ),
    "08.b": HITRUSTControl(
        id="08.b",
        title="Physical Entry Controls",
        description="Secure areas shall be protected by appropriate entry controls to ensure only authorized personnel are allowed access.",
        category=CATEGORY_PHYSICAL,
        control_reference="08.b",
        implementation_requirement="Implement physical access controls.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PE-2", "PE-3"],
        iso_mappings=["A.7.2"],
        hipaa_mappings=["164.310(a)(2)(iii)"],
        pci_mappings=["9.1", "9.2"],
    ),
    "08.c": HITRUSTControl(
        id="08.c",
        title="Securing Offices, Rooms, and Facilities",
        description="Physical security for offices, rooms, and facilities shall be designed and applied.",
        category=CATEGORY_PHYSICAL,
        control_reference="08.c",
        implementation_requirement="Secure work areas.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PE-3", "PE-5"],
        iso_mappings=["A.7.3"],
        hipaa_mappings=["164.310(a)(1)"],
        pci_mappings=["9.1"],
    ),
    "08.d": HITRUSTControl(
        id="08.d",
        title="Protecting Against External and Environmental Threats",
        description="Physical protection against damage from fire, flood, earthquake, explosion, civil unrest, and other forms of natural or man-made disaster shall be designed and applied.",
        category=CATEGORY_PHYSICAL,
        control_reference="08.d",
        implementation_requirement="Implement environmental controls.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PE-13", "PE-15"],
        iso_mappings=["A.7.5"],
        hipaa_mappings=["164.310(a)(2)(ii)"],
        pci_mappings=["9.1.3"],
    ),
    "08.e": HITRUSTControl(
        id="08.e",
        title="Working in Secure Areas",
        description="Physical protection and guidelines for working in secure areas shall be designed and applied.",
        category=CATEGORY_PHYSICAL,
        control_reference="08.e",
        implementation_requirement="Control access to secure areas.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PE-3"],
        iso_mappings=["A.7.6"],
        hipaa_mappings=["164.310(a)(1)"],
        pci_mappings=["9.1"],
    ),
    "08.f": HITRUSTControl(
        id="08.f",
        title="Delivery and Loading Areas",
        description="Access points such as delivery and loading areas shall be controlled and isolated from information processing facilities.",
        category=CATEGORY_PHYSICAL,
        control_reference="08.f",
        implementation_requirement="Secure delivery areas.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PE-16"],
        iso_mappings=["A.7.2"],
        hipaa_mappings=["164.310(a)(2)(iii)"],
        pci_mappings=["9.1.2"],
    ),
    "08.g": HITRUSTControl(
        id="08.g",
        title="Equipment Siting and Protection",
        description="Equipment shall be sited and protected to reduce the risks from environmental threats and hazards.",
        category=CATEGORY_PHYSICAL,
        control_reference="08.g",
        implementation_requirement="Protect equipment from environmental threats.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PE-9", "PE-14"],
        iso_mappings=["A.7.8"],
        hipaa_mappings=["164.310(c)"],
        pci_mappings=["9.1.3"],
    ),
    "08.h": HITRUSTControl(
        id="08.h",
        title="Supporting Utilities",
        description="Equipment shall be protected from power failures and other disruptions caused by failures in supporting utilities.",
        category=CATEGORY_PHYSICAL,
        control_reference="08.h",
        implementation_requirement="Implement utility protection (UPS, backup power).",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PE-9", "PE-11"],
        iso_mappings=["A.7.11"],
        hipaa_mappings=["164.310(a)(2)(ii)"],
        pci_mappings=["9.1.3"],
    ),
    "08.i": HITRUSTControl(
        id="08.i",
        title="Cabling Security",
        description="Power and telecommunications cabling carrying data or supporting information services shall be protected from interception or damage.",
        category=CATEGORY_PHYSICAL,
        control_reference="08.i",
        implementation_requirement="Secure cabling infrastructure.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PE-4", "PE-9"],
        iso_mappings=["A.7.12"],
        hipaa_mappings=["164.310(c)"],
        pci_mappings=["9.1.3"],
    ),
    "08.j": HITRUSTControl(
        id="08.j",
        title="Equipment Maintenance",
        description="Equipment shall be correctly maintained to ensure its continued availability and integrity.",
        category=CATEGORY_PHYSICAL,
        control_reference="08.j",
        implementation_requirement="Implement equipment maintenance program.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["MA-2", "MA-4"],
        iso_mappings=["A.7.13"],
        hipaa_mappings=["164.310(a)(2)(iv)"],
        pci_mappings=["9.9.2"],
    ),
    "08.k": HITRUSTControl(
        id="08.k",
        title="Security of Equipment Off-Premises",
        description="Security shall be applied to equipment off-premises taking into account the different risks of working outside the organization's premises.",
        category=CATEGORY_PHYSICAL,
        control_reference="08.k",
        implementation_requirement="Secure off-site equipment.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PE-17"],
        iso_mappings=["A.7.9"],
        hipaa_mappings=["164.310(d)(1)"],
        pci_mappings=["9.5"],
    ),
    "08.l": HITRUSTControl(
        id="08.l",
        title="Secure Disposal or Reuse of Equipment",
        description="All items of equipment containing storage media shall be checked to ensure sensitive data has been removed or overwritten prior to disposal or reuse.",
        category=CATEGORY_PHYSICAL,
        control_reference="08.l",
        implementation_requirement="Implement secure disposal procedures.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["MP-6", "PE-16"],
        iso_mappings=["A.7.14"],
        hipaa_mappings=["164.310(d)(2)(i)"],
        pci_mappings=["9.8"],
    ),
    "08.m": HITRUSTControl(
        id="08.m",
        title="Removal of Property",
        description="Equipment, information, or software shall not be taken off-site without prior authorization.",
        category=CATEGORY_PHYSICAL,
        control_reference="08.m",
        implementation_requirement="Control removal of assets.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PE-16", "MP-5"],
        iso_mappings=["A.7.10"],
        hipaa_mappings=["164.310(d)(1)"],
        pci_mappings=["9.6"],
    ),

    # =========================================================================
    # 09: Communications and Operations Management
    # =========================================================================
    "09.a": HITRUSTControl(
        id="09.a",
        title="Documented Operating Procedures",
        description="Operating procedures shall be documented, maintained, and made available to all users who need them.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.a",
        implementation_requirement="Document operational procedures.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CM-1", "SA-5"],
        iso_mappings=["A.5.37"],
        hipaa_mappings=["164.308(a)(3)(ii)"],
        pci_mappings=["12.1"],
    ),
    "09.b": HITRUSTControl(
        id="09.b",
        title="Change Management",
        description="Changes to information processing facilities and systems shall be controlled.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.b",
        implementation_requirement="Implement change management process.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CM-3", "CM-4"],
        iso_mappings=["A.8.32"],
        hipaa_mappings=["164.308(a)(1)(ii)(B)"],
        pci_mappings=["6.4"],
    ),
    "09.c": HITRUSTControl(
        id="09.c",
        title="Segregation of Duties",
        description="Duties and areas of responsibility shall be segregated to reduce opportunities for unauthorized or unintentional modification or misuse of assets.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.c",
        implementation_requirement="Implement segregation of duties.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["AC-5"],
        iso_mappings=["A.5.3"],
        hipaa_mappings=["164.308(a)(3)(ii)(A)"],
        pci_mappings=["6.4.2"],
    ),
    "09.d": HITRUSTControl(
        id="09.d",
        title="Separation of Development, Test, and Operational Environments",
        description="Development, testing, and operational environments shall be separated to reduce unauthorized access or changes.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.d",
        implementation_requirement="Separate dev/test/prod environments.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CM-4", "SA-11"],
        iso_mappings=["A.8.31"],
        hipaa_mappings=["164.308(a)(1)(ii)(B)"],
        pci_mappings=["6.4.1"],
    ),
    "09.e": HITRUSTControl(
        id="09.e",
        title="External Facilities Management",
        description="Risks from external service delivery shall be identified and appropriate controls implemented.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.e",
        implementation_requirement="Manage third-party service risks.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SA-9", "SR-1"],
        iso_mappings=["A.5.21", "A.5.22"],
        hipaa_mappings=["164.308(b)(1)"],
        pci_mappings=["12.8"],
    ),
    "09.f": HITRUSTControl(
        id="09.f",
        title="Capacity Management",
        description="The use of resources shall be monitored and projections made of future capacity requirements.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.f",
        implementation_requirement="Monitor and plan capacity.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SA-2", "CP-2"],
        iso_mappings=["A.8.6"],
        hipaa_mappings=["164.308(a)(7)(ii)(B)"],
        pci_mappings=["12.10.2"],
    ),
    "09.g": HITRUSTControl(
        id="09.g",
        title="System Acceptance",
        description="Acceptance criteria for new information systems, upgrades, and new versions shall be established and suitable tests carried out.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.g",
        implementation_requirement="Implement system acceptance testing.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SA-11", "CA-2"],
        iso_mappings=["A.8.29"],
        hipaa_mappings=["164.308(a)(1)(ii)(B)"],
        pci_mappings=["6.4.4"],
    ),
    "09.h": HITRUSTControl(
        id="09.h",
        title="Controls Against Malicious Code",
        description="Detection, prevention, and recovery controls to protect against malicious code shall be implemented.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.h",
        implementation_requirement="Implement malware protection.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SI-3", "SI-8"],
        iso_mappings=["A.8.7"],
        hipaa_mappings=["164.308(a)(5)(ii)(B)"],
        pci_mappings=["5.1", "5.2"],
    ),
    "09.i": HITRUSTControl(
        id="09.i",
        title="Controls Against Mobile Code",
        description="Where the use of mobile code is authorized, the configuration shall ensure it operates within a clearly defined security policy.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.i",
        implementation_requirement="Control mobile code execution.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SC-18"],
        iso_mappings=["A.8.7"],
        hipaa_mappings=["164.308(a)(5)(ii)(B)"],
        pci_mappings=["5.1"],
    ),
    "09.j": HITRUSTControl(
        id="09.j",
        title="Information Backup",
        description="Backup copies of information and software shall be taken and tested regularly.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.j",
        implementation_requirement="Implement backup and recovery procedures.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CP-9", "CP-10"],
        iso_mappings=["A.8.13"],
        hipaa_mappings=["164.308(a)(7)(ii)(A)"],
        pci_mappings=["9.5.1"],
    ),
    "09.k": HITRUSTControl(
        id="09.k",
        title="Network Controls",
        description="Networks shall be adequately managed and controlled to protect information in systems and applications.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.k",
        implementation_requirement="Implement network security controls.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SC-7", "AC-4"],
        iso_mappings=["A.8.20"],
        hipaa_mappings=["164.312(e)(1)"],
        pci_mappings=["1.1", "1.2"],
    ),
    "09.l": HITRUSTControl(
        id="09.l",
        title="Security of Network Services",
        description="Security features, service levels, and management requirements of network services shall be identified and included in agreements.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.l",
        implementation_requirement="Secure network services.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SC-7", "SA-9"],
        iso_mappings=["A.8.21"],
        hipaa_mappings=["164.312(e)(1)"],
        pci_mappings=["1.1.6"],
    ),
    "09.m": HITRUSTControl(
        id="09.m",
        title="Management of Removable Media",
        description="There shall be procedures in place for the management of removable media.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.m",
        implementation_requirement="Control removable media.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["MP-2", "MP-4"],
        iso_mappings=["A.7.10"],
        hipaa_mappings=["164.310(d)(1)"],
        pci_mappings=["9.7"],
    ),
    "09.n": HITRUSTControl(
        id="09.n",
        title="Disposal of Media",
        description="Media shall be disposed of securely when no longer required.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.n",
        implementation_requirement="Securely dispose of media.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["MP-6"],
        iso_mappings=["A.7.14"],
        hipaa_mappings=["164.310(d)(2)(i)"],
        pci_mappings=["9.8"],
    ),
    "09.o": HITRUSTControl(
        id="09.o",
        title="Information Handling Procedures",
        description="Procedures for the handling and storage of information shall be established to protect from unauthorized disclosure or misuse.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.o",
        implementation_requirement="Implement information handling procedures.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["MP-2", "MP-4"],
        iso_mappings=["A.5.13"],
        hipaa_mappings=["164.310(d)(1)"],
        pci_mappings=["9.6"],
    ),
    "09.p": HITRUSTControl(
        id="09.p",
        title="Security of System Documentation",
        description="System documentation shall be protected against unauthorized access.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.p",
        implementation_requirement="Protect system documentation.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SA-5", "AC-3"],
        iso_mappings=["A.5.37"],
        hipaa_mappings=["164.312(c)(1)"],
        pci_mappings=["6.3.1"],
    ),
    "09.q": HITRUSTControl(
        id="09.q",
        title="Electronic Commerce Services",
        description="Information involved in electronic commerce passing over public networks shall be protected from fraudulent activity, contract dispute, and unauthorized disclosure.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.q",
        implementation_requirement="Secure electronic commerce.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SC-8", "SC-13"],
        iso_mappings=["A.8.24"],
        hipaa_mappings=["164.312(e)(2)(ii)"],
        pci_mappings=["4.1"],
    ),
    "09.r": HITRUSTControl(
        id="09.r",
        title="Online Transactions",
        description="Information involved in online transactions shall be protected to prevent incomplete transmission, mis-routing, unauthorized message alteration, or unauthorized disclosure.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.r",
        implementation_requirement="Secure online transactions.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SC-8", "SC-23"],
        iso_mappings=["A.8.24"],
        hipaa_mappings=["164.312(e)(2)(ii)"],
        pci_mappings=["4.1"],
    ),
    "09.s": HITRUSTControl(
        id="09.s",
        title="Publicly Available Information",
        description="The integrity of information made available on publicly accessible systems shall be protected.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.s",
        implementation_requirement="Protect public-facing systems.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["AC-22", "SC-14"],
        iso_mappings=["A.8.26"],
        hipaa_mappings=["164.312(e)(1)"],
        pci_mappings=["6.6"],
    ),
    "09.t": HITRUSTControl(
        id="09.t",
        title="Audit Logging",
        description="Audit logs recording user activities, exceptions, and information security events shall be produced and kept for an agreed period.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.t",
        implementation_requirement="Implement audit logging.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["AU-2", "AU-3", "AU-12"],
        iso_mappings=["A.8.15"],
        hipaa_mappings=["164.312(b)"],
        pci_mappings=["10.1", "10.2"],
    ),
    "09.u": HITRUSTControl(
        id="09.u",
        title="Monitoring System Use",
        description="Procedures for monitoring use of information processing facilities shall be established.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.u",
        implementation_requirement="Monitor system usage.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["AU-6", "SI-4"],
        iso_mappings=["A.8.16"],
        hipaa_mappings=["164.308(a)(1)(ii)(D)"],
        pci_mappings=["10.6"],
    ),
    "09.v": HITRUSTControl(
        id="09.v",
        title="Protection of Log Information",
        description="Logging facilities and log information shall be protected against tampering and unauthorized access.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.v",
        implementation_requirement="Protect log integrity.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["AU-9"],
        iso_mappings=["A.8.15"],
        hipaa_mappings=["164.312(b)"],
        pci_mappings=["10.5"],
    ),
    "09.w": HITRUSTControl(
        id="09.w",
        title="Administrator and Operator Logs",
        description="System administrator and system operator activities shall be logged.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.w",
        implementation_requirement="Log administrator activities.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["AU-2", "AU-12"],
        iso_mappings=["A.8.15"],
        hipaa_mappings=["164.312(b)"],
        pci_mappings=["10.2.2"],
    ),
    "09.x": HITRUSTControl(
        id="09.x",
        title="Fault Logging",
        description="Faults shall be logged, analyzed, and appropriate action taken.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.x",
        implementation_requirement="Implement fault logging.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SI-4", "AU-6"],
        iso_mappings=["A.8.15"],
        hipaa_mappings=["164.312(b)"],
        pci_mappings=["10.6"],
    ),
    "09.y": HITRUSTControl(
        id="09.y",
        title="Clock Synchronization",
        description="The clocks of all relevant information processing systems shall be synchronized with an agreed accurate time source.",
        category=CATEGORY_OPERATIONS,
        control_reference="09.y",
        implementation_requirement="Synchronize system clocks.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["AU-8"],
        iso_mappings=["A.8.17"],
        hipaa_mappings=["164.312(b)"],
        pci_mappings=["10.4"],
    ),

    # =========================================================================
    # 10: Information Systems Acquisition, Development, and Maintenance
    # =========================================================================
    "10.a": HITRUSTControl(
        id="10.a",
        title="Security Requirements Analysis and Specification",
        description="Statements of business requirements for new information systems shall specify requirements for security controls.",
        category=CATEGORY_SDLC,
        control_reference="10.a",
        implementation_requirement="Include security in requirements.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SA-3", "SA-4"],
        iso_mappings=["A.8.25"],
        hipaa_mappings=["164.308(a)(1)(ii)(B)"],
        pci_mappings=["6.3"],
    ),
    "10.b": HITRUSTControl(
        id="10.b",
        title="Input Data Validation",
        description="Data input to applications shall be validated to ensure it is correct and appropriate.",
        category=CATEGORY_SDLC,
        control_reference="10.b",
        implementation_requirement="Validate input data.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SI-10"],
        iso_mappings=["A.8.28"],
        hipaa_mappings=["164.312(c)(2)"],
        pci_mappings=["6.5.1"],
    ),
    "10.c": HITRUSTControl(
        id="10.c",
        title="Control of Internal Processing",
        description="Validation checks shall be incorporated into applications to detect any corruption of information.",
        category=CATEGORY_SDLC,
        control_reference="10.c",
        implementation_requirement="Implement processing controls.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SI-7"],
        iso_mappings=["A.8.28"],
        hipaa_mappings=["164.312(c)(2)"],
        pci_mappings=["6.5.1"],
    ),
    "10.d": HITRUSTControl(
        id="10.d",
        title="Message Integrity",
        description="Requirements for ensuring authenticity and protecting message integrity shall be identified and appropriate controls implemented.",
        category=CATEGORY_SDLC,
        control_reference="10.d",
        implementation_requirement="Protect message integrity.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SC-8", "SC-13"],
        iso_mappings=["A.8.24"],
        hipaa_mappings=["164.312(e)(2)(ii)"],
        pci_mappings=["4.1"],
    ),
    "10.e": HITRUSTControl(
        id="10.e",
        title="Output Data Validation",
        description="Data output from an application shall be validated to ensure the processing of stored information is correct.",
        category=CATEGORY_SDLC,
        control_reference="10.e",
        implementation_requirement="Validate output data.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SI-7"],
        iso_mappings=["A.8.28"],
        hipaa_mappings=["164.312(c)(2)"],
        pci_mappings=["6.5.1"],
    ),
    "10.f": HITRUSTControl(
        id="10.f",
        title="Policy on the Use of Cryptographic Controls",
        description="A policy on the use of cryptographic controls for protection of information shall be developed and implemented.",
        category=CATEGORY_SDLC,
        control_reference="10.f",
        implementation_requirement="Develop cryptographic policy.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SC-13"],
        iso_mappings=["A.8.24"],
        hipaa_mappings=["164.312(a)(2)(iv)"],
        pci_mappings=["3.5", "4.1"],
    ),
    "10.g": HITRUSTControl(
        id="10.g",
        title="Key Management",
        description="Key management shall be in place to support the organization's use of cryptographic techniques.",
        category=CATEGORY_SDLC,
        control_reference="10.g",
        implementation_requirement="Implement key management.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SC-12"],
        iso_mappings=["A.8.24"],
        hipaa_mappings=["164.312(a)(2)(iv)"],
        pci_mappings=["3.5", "3.6"],
    ),
    "10.h": HITRUSTControl(
        id="10.h",
        title="Control of Operational Software",
        description="There shall be procedures in place to control the installation of software on operational systems.",
        category=CATEGORY_SDLC,
        control_reference="10.h",
        implementation_requirement="Control software installation.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CM-7", "CM-11"],
        iso_mappings=["A.8.19"],
        hipaa_mappings=["164.308(a)(1)(ii)(B)"],
        pci_mappings=["6.4"],
    ),
    "10.i": HITRUSTControl(
        id="10.i",
        title="Protection of System Test Data",
        description="Test data shall be selected carefully, protected, and controlled.",
        category=CATEGORY_SDLC,
        control_reference="10.i",
        implementation_requirement="Protect test data.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SA-15"],
        iso_mappings=["A.8.33"],
        hipaa_mappings=["164.308(a)(1)(ii)(B)"],
        pci_mappings=["6.4.3"],
    ),
    "10.j": HITRUSTControl(
        id="10.j",
        title="Access Control to Program Source Code",
        description="Access to program source code shall be restricted.",
        category=CATEGORY_SDLC,
        control_reference="10.j",
        implementation_requirement="Restrict access to source code.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CM-5", "AC-6"],
        iso_mappings=["A.8.4"],
        hipaa_mappings=["164.312(a)(1)"],
        pci_mappings=["6.3.2"],
    ),
    "10.k": HITRUSTControl(
        id="10.k",
        title="Change Control Procedures",
        description="The implementation of changes shall be controlled by the use of formal change control procedures.",
        category=CATEGORY_SDLC,
        control_reference="10.k",
        implementation_requirement="Implement change control procedures.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CM-3", "SA-10"],
        iso_mappings=["A.8.32"],
        hipaa_mappings=["164.308(a)(1)(ii)(B)"],
        pci_mappings=["6.4.5"],
    ),
    "10.l": HITRUSTControl(
        id="10.l",
        title="Technical Review of Applications After Operating System Changes",
        description="When operating systems are changed, business critical applications shall be reviewed and tested.",
        category=CATEGORY_SDLC,
        control_reference="10.l",
        implementation_requirement="Review applications after OS changes.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CM-4", "SA-11"],
        iso_mappings=["A.8.32"],
        hipaa_mappings=["164.308(a)(1)(ii)(B)"],
        pci_mappings=["6.4.5"],
    ),
    "10.m": HITRUSTControl(
        id="10.m",
        title="Restrictions on Changes to Software Packages",
        description="Modifications to software packages shall be discouraged, limited to necessary changes, and all changes strictly controlled.",
        category=CATEGORY_SDLC,
        control_reference="10.m",
        implementation_requirement="Control software package modifications.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CM-5", "CM-6"],
        iso_mappings=["A.8.32"],
        hipaa_mappings=["164.308(a)(1)(ii)(B)"],
        pci_mappings=["6.4"],
    ),
    "10.n": HITRUSTControl(
        id="10.n",
        title="Information Leakage",
        description="Opportunities for information leakage shall be prevented.",
        category=CATEGORY_SDLC,
        control_reference="10.n",
        implementation_requirement="Prevent data leakage.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SC-7", "SI-4"],
        iso_mappings=["A.8.12"],
        hipaa_mappings=["164.312(e)(1)"],
        pci_mappings=["3.4", "4.2"],
    ),
    "10.o": HITRUSTControl(
        id="10.o",
        title="Outsourced Software Development",
        description="Outsourced software development shall be supervised and monitored by the organization.",
        category=CATEGORY_SDLC,
        control_reference="10.o",
        implementation_requirement="Oversee outsourced development.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["SA-9", "SA-11"],
        iso_mappings=["A.8.30"],
        hipaa_mappings=["164.308(b)(1)"],
        pci_mappings=["6.3", "12.8"],
    ),
    "10.p": HITRUSTControl(
        id="10.p",
        title="Control of Technical Vulnerabilities",
        description="Timely information about technical vulnerabilities of information systems shall be obtained, the exposure evaluated, and appropriate measures taken.",
        category=CATEGORY_SDLC,
        control_reference="10.p",
        implementation_requirement="Manage technical vulnerabilities.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["RA-5", "SI-2"],
        iso_mappings=["A.8.8"],
        hipaa_mappings=["164.308(a)(1)(ii)(B)"],
        pci_mappings=["6.1", "6.2"],
    ),

    # =========================================================================
    # 11: Information Security Incident Management
    # =========================================================================
    "11.a": HITRUSTControl(
        id="11.a",
        title="Reporting Information Security Events",
        description="Information security events shall be reported through appropriate management channels as quickly as possible.",
        category=CATEGORY_INCIDENT,
        control_reference="11.a",
        implementation_requirement="Establish incident reporting procedures.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["IR-6", "SI-5"],
        iso_mappings=["A.5.24", "A.6.8"],
        hipaa_mappings=["164.308(a)(6)(ii)"],
        pci_mappings=["12.10.2"],
    ),
    "11.b": HITRUSTControl(
        id="11.b",
        title="Reporting Security Weaknesses",
        description="All employees, contractors, and third-party users shall be required to note and report any observed or suspected security weaknesses.",
        category=CATEGORY_INCIDENT,
        control_reference="11.b",
        implementation_requirement="Report security weaknesses.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["IR-6", "PM-16"],
        iso_mappings=["A.6.8"],
        hipaa_mappings=["164.308(a)(6)(ii)"],
        pci_mappings=["12.10.4"],
    ),
    "11.c": HITRUSTControl(
        id="11.c",
        title="Responsibilities and Procedures",
        description="Management responsibilities and procedures shall be established to ensure a quick, effective, and orderly response to information security incidents.",
        category=CATEGORY_INCIDENT,
        control_reference="11.c",
        implementation_requirement="Define incident response procedures.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["IR-1", "IR-8"],
        iso_mappings=["A.5.24"],
        hipaa_mappings=["164.308(a)(6)(i)"],
        pci_mappings=["12.10.1"],
    ),
    "11.d": HITRUSTControl(
        id="11.d",
        title="Learning from Information Security Incidents",
        description="There shall be mechanisms in place to enable the types, volumes, and costs of information security incidents to be quantified and monitored.",
        category=CATEGORY_INCIDENT,
        control_reference="11.d",
        implementation_requirement="Learn from security incidents.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["IR-4", "IR-8"],
        iso_mappings=["A.5.27"],
        hipaa_mappings=["164.308(a)(6)(ii)"],
        pci_mappings=["12.10.6"],
    ),
    "11.e": HITRUSTControl(
        id="11.e",
        title="Collection of Evidence",
        description="Where a follow-up action against a person or organization involves legal action, evidence shall be collected, retained, and presented to conform to rules for evidence.",
        category=CATEGORY_INCIDENT,
        control_reference="11.e",
        implementation_requirement="Collect and preserve evidence.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["IR-4", "AU-9"],
        iso_mappings=["A.5.28"],
        hipaa_mappings=["164.530(j)"],
        pci_mappings=["12.10.5"],
    ),

    # =========================================================================
    # 12: Business Continuity Management
    # =========================================================================
    "12.a": HITRUSTControl(
        id="12.a",
        title="Including Information Security in the Business Continuity Management Process",
        description="A managed process shall be developed and maintained for business continuity that addresses information security requirements.",
        category=CATEGORY_BCM,
        control_reference="12.a",
        implementation_requirement="Include security in BCM process.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CP-1", "CP-2"],
        iso_mappings=["A.5.29"],
        hipaa_mappings=["164.308(a)(7)(i)"],
        pci_mappings=["12.10.1"],
    ),
    "12.b": HITRUSTControl(
        id="12.b",
        title="Business Continuity and Risk Assessment",
        description="Events that can cause interruptions to business processes shall be identified along with their probability and impact.",
        category=CATEGORY_BCM,
        control_reference="12.b",
        implementation_requirement="Conduct BC risk assessment.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CP-2", "RA-3"],
        iso_mappings=["A.5.29"],
        hipaa_mappings=["164.308(a)(7)(ii)(E)"],
        pci_mappings=["12.10.1"],
    ),
    "12.c": HITRUSTControl(
        id="12.c",
        title="Developing and Implementing Continuity Plans Including Information Security",
        description="Plans shall be developed and implemented to maintain or restore operations and ensure availability of information following interruption.",
        category=CATEGORY_BCM,
        control_reference="12.c",
        implementation_requirement="Develop business continuity plans.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CP-2", "CP-7"],
        iso_mappings=["A.5.30"],
        hipaa_mappings=["164.308(a)(7)(ii)(B)"],
        pci_mappings=["12.10.1"],
    ),
    "12.d": HITRUSTControl(
        id="12.d",
        title="Business Continuity Planning Framework",
        description="A single framework of business continuity plans shall be maintained to ensure all plans are consistent.",
        category=CATEGORY_BCM,
        control_reference="12.d",
        implementation_requirement="Maintain BC planning framework.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CP-2"],
        iso_mappings=["A.5.29"],
        hipaa_mappings=["164.308(a)(7)(ii)(C)"],
        pci_mappings=["12.10.1"],
    ),
    "12.e": HITRUSTControl(
        id="12.e",
        title="Testing, Maintaining, and Re-assessing Business Continuity Plans",
        description="Business continuity plans shall be tested and updated regularly to ensure they are up to date and effective.",
        category=CATEGORY_BCM,
        control_reference="12.e",
        implementation_requirement="Test and update BC plans.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["CP-4", "CP-3"],
        iso_mappings=["A.5.30"],
        hipaa_mappings=["164.308(a)(7)(ii)(D)"],
        pci_mappings=["12.10.2"],
    ),

    # =========================================================================
    # 13: Privacy Practices
    # =========================================================================
    "13.a": HITRUSTControl(
        id="13.a",
        title="Privacy Governance",
        description="The organization shall establish a privacy governance structure with defined roles, responsibilities, and accountability for protecting personal information.",
        category=CATEGORY_PRIVACY,
        control_reference="13.a",
        implementation_requirement="Establish privacy governance.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PT-1", "PT-2"],
        iso_mappings=["A.5.34"],
        hipaa_mappings=["164.530(a)"],
        pci_mappings=["12.1"],
    ),
    "13.b": HITRUSTControl(
        id="13.b",
        title="Notice and Choice",
        description="Individuals shall be provided with notice about the organization's privacy practices and choices about how their personal information is used.",
        category=CATEGORY_PRIVACY,
        control_reference="13.b",
        implementation_requirement="Provide privacy notices.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PT-5", "PT-5(2)"],
        iso_mappings=["A.5.34"],
        hipaa_mappings=["164.520"],
        pci_mappings=["12.8.2"],
    ),
    "13.c": HITRUSTControl(
        id="13.c",
        title="Collection Limitation",
        description="The collection of personal information shall be limited to what is necessary for the identified purposes.",
        category=CATEGORY_PRIVACY,
        control_reference="13.c",
        implementation_requirement="Limit data collection.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PT-2"],
        iso_mappings=["A.5.34"],
        hipaa_mappings=["164.502(b)"],
        pci_mappings=["3.1"],
    ),
    "13.d": HITRUSTControl(
        id="13.d",
        title="Use, Retention, and Disposal",
        description="Personal information shall only be used for the purposes identified, retained only as long as necessary, and disposed of securely.",
        category=CATEGORY_PRIVACY,
        control_reference="13.d",
        implementation_requirement="Control data use and retention.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PT-2", "PT-3"],
        iso_mappings=["A.5.34"],
        hipaa_mappings=["164.502(b)", "164.530(j)"],
        pci_mappings=["3.1", "9.8"],
    ),
    "13.e": HITRUSTControl(
        id="13.e",
        title="Access",
        description="Individuals shall be provided with access to their personal information and mechanisms to update, correct, or request deletion.",
        category=CATEGORY_PRIVACY,
        control_reference="13.e",
        implementation_requirement="Provide data access rights.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PT-5", "PT-6"],
        iso_mappings=["A.5.34"],
        hipaa_mappings=["164.524"],
        pci_mappings=["12.3"],
    ),
    "13.f": HITRUSTControl(
        id="13.f",
        title="Disclosure to Third Parties",
        description="Personal information shall only be disclosed to third parties with appropriate authorization and safeguards.",
        category=CATEGORY_PRIVACY,
        control_reference="13.f",
        implementation_requirement="Control third-party disclosures.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PT-2", "PT-4"],
        iso_mappings=["A.5.34"],
        hipaa_mappings=["164.502(e)", "164.504(e)"],
        pci_mappings=["12.8"],
    ),
    "13.g": HITRUSTControl(
        id="13.g",
        title="Security for Privacy",
        description="Personal information shall be protected by appropriate security safeguards against unauthorized access, use, or disclosure.",
        category=CATEGORY_PRIVACY,
        control_reference="13.g",
        implementation_requirement="Implement security for privacy.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PT-3", "SC-28"],
        iso_mappings=["A.5.34", "A.8.24"],
        hipaa_mappings=["164.312"],
        pci_mappings=["3.4", "4.1"],
    ),
    "13.h": HITRUSTControl(
        id="13.h",
        title="Quality",
        description="Personal information shall be accurate, complete, and kept up to date.",
        category=CATEGORY_PRIVACY,
        control_reference="13.h",
        implementation_requirement="Maintain data quality.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PT-2"],
        iso_mappings=["A.5.34"],
        hipaa_mappings=["164.526"],
        pci_mappings=["3.1"],
    ),
    "13.i": HITRUSTControl(
        id="13.i",
        title="Monitoring and Enforcement",
        description="The organization shall monitor compliance with privacy policies and procedures and enforce adherence.",
        category=CATEGORY_PRIVACY,
        control_reference="13.i",
        implementation_requirement="Monitor privacy compliance.",
        maturity_level=MATURITY_IMPLEMENTED,
        nist_mappings=["PT-1", "PM-14"],
        iso_mappings=["A.5.35", "A.5.36"],
        hipaa_mappings=["164.530(a)(1)"],
        pci_mappings=["12.11"],
    ),
}


# =============================================================================
# Lookup Functions
# =============================================================================


def get_control(control_id: str) -> HITRUSTControl | None:
    """
    Get a HITRUST control by ID.

    Args:
        control_id: Control identifier (e.g., "01.a").

    Returns:
        HITRUSTControl or None if not found.
    """
    return HITRUST_CONTROLS.get(control_id)


def get_controls_by_category(category: str) -> list[HITRUSTControl]:
    """
    Get all controls in a category.

    Args:
        category: Category code (e.g., "01", "09").

    Returns:
        List of controls in the category.
    """
    return [c for c in HITRUST_CONTROLS.values() if c.category == category]


def get_all_controls() -> list[HITRUSTControl]:
    """
    Get all HITRUST controls.

    Returns:
        List of all controls.
    """
    return list(HITRUST_CONTROLS.values())


def get_all_categories() -> list[str]:
    """
    Get all control categories.

    Returns:
        List of category codes.
    """
    return list(CATEGORY_NAMES.keys())


def get_control_count_by_category() -> dict[str, int]:
    """
    Get control count by category.

    Returns:
        Dictionary mapping category codes to control counts.
    """
    counts: dict[str, int] = {}
    for control in HITRUST_CONTROLS.values():
        counts[control.category] = counts.get(control.category, 0) + 1
    return counts


def get_controls_by_nist_mapping(nist_control_id: str) -> list[HITRUSTControl]:
    """
    Get HITRUST controls that map to a NIST 800-53 control.

    Args:
        nist_control_id: NIST 800-53 control ID (e.g., "AC-2").

    Returns:
        List of HITRUST controls mapping to the NIST control.
    """
    return [
        c for c in HITRUST_CONTROLS.values()
        if nist_control_id in c.nist_mappings
    ]


def get_controls_by_iso_mapping(iso_control_id: str) -> list[HITRUSTControl]:
    """
    Get HITRUST controls that map to an ISO 27001 control.

    Args:
        iso_control_id: ISO 27001 control ID (e.g., "A.5.1").

    Returns:
        List of HITRUST controls mapping to the ISO control.
    """
    return [
        c for c in HITRUST_CONTROLS.values()
        if iso_control_id in c.iso_mappings
    ]


def get_controls_by_hipaa_mapping(hipaa_reference: str) -> list[HITRUSTControl]:
    """
    Get HITRUST controls that map to a HIPAA requirement.

    Args:
        hipaa_reference: HIPAA reference (e.g., "164.308(a)(1)").

    Returns:
        List of HITRUST controls mapping to the HIPAA requirement.
    """
    return [
        c for c in HITRUST_CONTROLS.values()
        if any(hipaa_reference in h for h in c.hipaa_mappings)
    ]


def get_controls_by_maturity_level(level: int) -> list[HITRUSTControl]:
    """
    Get controls at or below a maturity level.

    Args:
        level: Maturity level (1-5).

    Returns:
        List of controls at or below the specified level.
    """
    return [c for c in HITRUST_CONTROLS.values() if c.maturity_level <= level]


def get_control_statistics() -> dict[str, Any]:
    """
    Get statistics about HITRUST controls.

    Returns:
        Dictionary with control statistics.
    """
    controls = list(HITRUST_CONTROLS.values())
    category_counts = get_control_count_by_category()

    # Count mappings
    nist_mapped = sum(1 for c in controls if c.nist_mappings)
    iso_mapped = sum(1 for c in controls if c.iso_mappings)
    hipaa_mapped = sum(1 for c in controls if c.hipaa_mappings)
    pci_mapped = sum(1 for c in controls if c.pci_mappings)

    return {
        "framework_id": HITRUST_FRAMEWORK_ID,
        "framework_version": HITRUST_VERSION,
        "total_controls": len(controls),
        "categories": len(CATEGORY_NAMES),
        "category_counts": category_counts,
        "controls_with_nist_mappings": nist_mapped,
        "controls_with_iso_mappings": iso_mapped,
        "controls_with_hipaa_mappings": hipaa_mapped,
        "controls_with_pci_mappings": pci_mapped,
        "maturity_levels": MATURITY_LEVEL_NAMES,
    }


__all__ = [
    # Constants
    "HITRUST_FRAMEWORK_ID",
    "HITRUST_VERSION",
    # Category constants
    "CATEGORY_ISMP",
    "CATEGORY_ACCESS_CONTROL",
    "CATEGORY_HR_SECURITY",
    "CATEGORY_RISK_MANAGEMENT",
    "CATEGORY_SECURITY_POLICY",
    "CATEGORY_ORG_SECURITY",
    "CATEGORY_COMPLIANCE",
    "CATEGORY_ASSET_MGMT",
    "CATEGORY_PHYSICAL",
    "CATEGORY_OPERATIONS",
    "CATEGORY_SDLC",
    "CATEGORY_INCIDENT",
    "CATEGORY_BCM",
    "CATEGORY_PRIVACY",
    "CATEGORY_NAMES",
    # Maturity constants
    "MATURITY_POLICY",
    "MATURITY_PROCEDURE",
    "MATURITY_IMPLEMENTED",
    "MATURITY_MEASURED",
    "MATURITY_MANAGED",
    "MATURITY_LEVEL_NAMES",
    # Data classes
    "HITRUSTControl",
    "HITRUSTFramework",
    # Control definitions
    "HITRUST_CONTROLS",
    # Lookup functions
    "get_control",
    "get_controls_by_category",
    "get_all_controls",
    "get_all_categories",
    "get_control_count_by_category",
    "get_controls_by_nist_mapping",
    "get_controls_by_iso_mapping",
    "get_controls_by_hipaa_mapping",
    "get_controls_by_maturity_level",
    "get_control_statistics",
]
