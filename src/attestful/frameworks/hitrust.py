"""
HITRUST CSF Framework Implementation for Attestful.

Provides HITRUST CSF control definitions and AWS compliance checks
mapped to HITRUST controls. Supports HITRUST maturity scoring.

HITRUST CSF Control Categories:
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

The HITRUST CSF maps to multiple underlying frameworks:
- HIPAA Security Rule
- NIST 800-53
- ISO 27001/27002
- PCI DSS
- COBIT
- FedRAMP
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from attestful.core.evaluator import (
    CheckDefinition,
    Condition,
    ConditionGroup,
    Evaluator,
    LogicOperator,
    Operator,
)
from attestful.core.logging import get_logger

logger = get_logger(__name__)


# =============================================================================
# Constants
# =============================================================================

HITRUST_FRAMEWORK_ID = "hitrust"
HITRUST_VERSION = "11.0"

# Control categories
CATEGORY_ISMP = "00"  # Information Security Management Program
CATEGORY_ACCESS_CONTROL = "01"
CATEGORY_HR_SECURITY = "02"
CATEGORY_RISK_MANAGEMENT = "03"
CATEGORY_SECURITY_POLICY = "04"
CATEGORY_ORG_SECURITY = "05"
CATEGORY_COMPLIANCE = "06"
CATEGORY_ASSET_MANAGEMENT = "07"
CATEGORY_PHYSICAL_SECURITY = "08"
CATEGORY_OPERATIONS = "09"
CATEGORY_SDLC = "10"
CATEGORY_INCIDENT_MANAGEMENT = "11"
CATEGORY_BCM = "12"
CATEGORY_PRIVACY = "13"

# Maturity levels
MATURITY_POLICY = 1
MATURITY_PROCEDURE = 2
MATURITY_IMPLEMENTED = 3
MATURITY_MEASURED = 4
MATURITY_MANAGED = 5


# =============================================================================
# Data Models
# =============================================================================


@dataclass
class HITRUSTControl:
    """
    Represents a HITRUST CSF control.

    Attributes:
        id: Control identifier (e.g., "01.a").
        title: Control title.
        description: Control description/requirement.
        category: Control category (00-13).
        objective: Control objective.
        implementation_requirement: Specific implementation guidance.
        nist_mappings: Mapped NIST 800-53 control IDs.
        iso_mappings: Mapped ISO 27001 control IDs.
        hipaa_mappings: Mapped HIPAA requirements.
        pci_mappings: Mapped PCI DSS requirements.
    """

    id: str
    title: str
    description: str
    category: str
    objective: str = ""
    implementation_requirement: str = ""
    nist_mappings: list[str] = field(default_factory=list)
    iso_mappings: list[str] = field(default_factory=list)
    hipaa_mappings: list[str] = field(default_factory=list)
    pci_mappings: list[str] = field(default_factory=list)


@dataclass
class HITRUSTMaturityScore:
    """
    HITRUST maturity score for a control.

    Attributes:
        control_id: Control identifier.
        policy_score: Score for policy level (0-100).
        procedure_score: Score for procedure level (0-100).
        implemented_score: Score for implementation level (0-100).
        measured_score: Score for measurement level (0-100).
        managed_score: Score for management level (0-100).
        overall_level: Overall maturity level (1-5).
    """

    control_id: str
    policy_score: int = 0
    procedure_score: int = 0
    implemented_score: int = 0
    measured_score: int = 0
    managed_score: int = 0

    @property
    def overall_level(self) -> int:
        """Calculate overall maturity level based on scores."""
        if self.managed_score >= 80 and all(
            s >= 80 for s in [self.policy_score, self.procedure_score,
                             self.implemented_score, self.measured_score]
        ):
            return 5
        if self.measured_score >= 80 and all(
            s >= 80 for s in [self.policy_score, self.procedure_score,
                             self.implemented_score]
        ):
            return 4
        if self.implemented_score >= 80 and all(
            s >= 80 for s in [self.policy_score, self.procedure_score]
        ):
            return 3
        if self.procedure_score >= 80 and self.policy_score >= 80:
            return 2
        if self.policy_score >= 80:
            return 1
        return 0


@dataclass
class HITRUSTFramework:
    """
    HITRUST CSF framework implementation.

    Attributes:
        version: Framework version.
        controls: Dictionary of controls by ID.
        check_mappings: Mapping of control IDs to check IDs.
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

    def get_controls_mapped_to_hipaa(self) -> list[HITRUSTControl]:
        """Get controls that map to HIPAA requirements."""
        return [c for c in self.controls.values() if c.hipaa_mappings]

    def calculate_category_score(
        self, category: str, maturity_scores: dict[str, HITRUSTMaturityScore]
    ) -> float:
        """
        Calculate average maturity score for a category.

        Args:
            category: Category identifier.
            maturity_scores: Dictionary of maturity scores by control ID.

        Returns:
            Average maturity level for the category.
        """
        category_controls = self.get_controls_by_category(category)
        if not category_controls:
            return 0.0

        total = 0
        count = 0
        for control in category_controls:
            if control.id in maturity_scores:
                total += maturity_scores[control.id].overall_level
                count += 1

        return total / count if count > 0 else 0.0


# =============================================================================
# HITRUST CSF Control Definitions
# =============================================================================

HITRUST_CONTROLS: dict[str, HITRUSTControl] = {
    # =========================================================================
    # Category 01: Access Control
    # =========================================================================
    "01.a": HITRUSTControl(
        id="01.a",
        title="Access Control Policy",
        description="An access control policy shall be established, documented, and reviewed based on business and security requirements for access.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Establish access control policy aligned with business needs.",
        nist_mappings=["AC-1"],
        iso_mappings=["A.5.15"],
        hipaa_mappings=["164.312(a)(1)"],
        pci_mappings=["7.1"],
    ),
    "01.b": HITRUSTControl(
        id="01.b",
        title="User Registration",
        description="A formal user registration and de-registration process shall be implemented to enable assignment of access rights.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Control user registration and access assignment.",
        nist_mappings=["AC-2"],
        iso_mappings=["A.5.16"],
        hipaa_mappings=["164.312(a)(2)(i)"],
        pci_mappings=["7.1.1"],
    ),
    "01.c": HITRUSTControl(
        id="01.c",
        title="Privilege Management",
        description="The allocation and use of privileges shall be restricted and controlled.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Manage privileged access appropriately.",
        nist_mappings=["AC-6"],
        iso_mappings=["A.8.2"],
        hipaa_mappings=["164.312(a)(1)"],
        pci_mappings=["7.1.2"],
    ),
    "01.d": HITRUSTControl(
        id="01.d",
        title="User Password Management",
        description="The allocation of passwords shall be controlled through a formal management process.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Control password allocation and management.",
        nist_mappings=["IA-5"],
        iso_mappings=["A.5.17"],
        hipaa_mappings=["164.312(d)"],
        pci_mappings=["8.2.3"],
    ),
    "01.e": HITRUSTControl(
        id="01.e",
        title="Review of User Access Rights",
        description="Management shall review users' access rights at regular intervals using a formal process.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Regularly review access rights.",
        nist_mappings=["AC-2"],
        iso_mappings=["A.5.18"],
        hipaa_mappings=["164.312(a)(2)(i)"],
        pci_mappings=["7.1.4"],
    ),
    "01.f": HITRUSTControl(
        id="01.f",
        title="Password Use",
        description="Users shall be required to follow good security practices in the selection and use of passwords.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Ensure strong password practices.",
        nist_mappings=["IA-5"],
        iso_mappings=["A.5.17"],
        hipaa_mappings=["164.312(d)"],
        pci_mappings=["8.2"],
    ),
    "01.g": HITRUSTControl(
        id="01.g",
        title="Unattended User Equipment",
        description="Users shall ensure that unattended equipment has appropriate protection.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Protect unattended equipment.",
        nist_mappings=["AC-11"],
        iso_mappings=["A.7.7"],
        hipaa_mappings=["164.312(a)(2)(iii)"],
        pci_mappings=["8.1.8"],
    ),
    "01.h": HITRUSTControl(
        id="01.h",
        title="Clear Desk and Clear Screen Policy",
        description="A clear desk policy for papers and removable storage media and a clear screen policy for information processing facilities shall be adopted.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Implement clear desk and screen policies.",
        nist_mappings=["MP-4", "AC-11"],
        iso_mappings=["A.7.7"],
        hipaa_mappings=["164.312(a)(2)(iii)"],
    ),
    "01.i": HITRUSTControl(
        id="01.i",
        title="Policy on Use of Network Services",
        description="Users shall only be provided with access to the network and network services that they have been specifically authorized to use.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Control network service access.",
        nist_mappings=["AC-4", "SC-7"],
        iso_mappings=["A.8.20"],
        hipaa_mappings=["164.312(a)(1)"],
        pci_mappings=["1.2"],
    ),
    "01.j": HITRUSTControl(
        id="01.j",
        title="User Authentication for External Connections",
        description="Appropriate authentication methods shall be used to control access by remote users.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Authenticate remote access.",
        nist_mappings=["AC-17", "IA-2"],
        iso_mappings=["A.8.5"],
        hipaa_mappings=["164.312(d)"],
        pci_mappings=["8.3"],
    ),
    "01.k": HITRUSTControl(
        id="01.k",
        title="Equipment Identification in Networks",
        description="Automatic equipment identification shall be considered as a means to authenticate connections from specific locations and equipment.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Identify equipment on networks.",
        nist_mappings=["IA-3"],
        iso_mappings=["A.8.20"],
        hipaa_mappings=["164.312(d)"],
    ),
    "01.l": HITRUSTControl(
        id="01.l",
        title="Remote Diagnostic and Configuration Port Protection",
        description="Physical and logical access to diagnostic and configuration ports shall be controlled.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Protect diagnostic ports.",
        nist_mappings=["CM-7"],
        iso_mappings=["A.8.9"],
        hipaa_mappings=["164.312(a)(1)"],
    ),
    "01.m": HITRUSTControl(
        id="01.m",
        title="Segregation in Networks",
        description="Groups of information services, users, and information systems shall be segregated on networks.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Segment networks appropriately.",
        nist_mappings=["SC-7", "AC-4"],
        iso_mappings=["A.8.22"],
        hipaa_mappings=["164.312(a)(1)"],
        pci_mappings=["1.2.1"],
    ),
    "01.n": HITRUSTControl(
        id="01.n",
        title="Network Connection Control",
        description="The capability of users to connect to the network shall be restricted, in accordance with the access control policy.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Control network connections.",
        nist_mappings=["AC-17", "SC-7"],
        iso_mappings=["A.8.20"],
        hipaa_mappings=["164.312(a)(1)"],
        pci_mappings=["1.3"],
    ),
    "01.o": HITRUSTControl(
        id="01.o",
        title="Network Routing Control",
        description="Routing controls shall be implemented for networks to ensure that computer connections and information flows do not breach the access control policy.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Control network routing.",
        nist_mappings=["SC-7", "AC-4"],
        iso_mappings=["A.8.22"],
        hipaa_mappings=["164.312(e)(1)"],
    ),
    "01.p": HITRUSTControl(
        id="01.p",
        title="Secure Log-on Procedures",
        description="Access to operating systems shall be controlled by a secure log-on procedure.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Implement secure logon.",
        nist_mappings=["AC-7", "IA-2"],
        iso_mappings=["A.8.5"],
        hipaa_mappings=["164.312(d)"],
        pci_mappings=["8.1.6"],
    ),
    "01.q": HITRUSTControl(
        id="01.q",
        title="User Identification and Authentication",
        description="All users shall have a unique identifier for their personal use only, and a suitable authentication technique shall be chosen to substantiate the claimed identity of a user.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Uniquely identify and authenticate users.",
        nist_mappings=["IA-2", "IA-4"],
        iso_mappings=["A.5.16", "A.8.5"],
        hipaa_mappings=["164.312(d)"],
        pci_mappings=["8.1"],
    ),
    "01.r": HITRUSTControl(
        id="01.r",
        title="Password Management System",
        description="Systems for managing passwords shall be interactive and shall ensure quality passwords.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Implement password management systems.",
        nist_mappings=["IA-5"],
        iso_mappings=["A.5.17"],
        hipaa_mappings=["164.312(d)"],
        pci_mappings=["8.2.3"],
    ),
    "01.s": HITRUSTControl(
        id="01.s",
        title="Use of System Utilities",
        description="The use of utility programs that might be capable of overriding system and application controls shall be restricted and tightly controlled.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Control system utility use.",
        nist_mappings=["AC-6", "CM-7"],
        iso_mappings=["A.8.18"],
        hipaa_mappings=["164.312(a)(1)"],
    ),
    "01.t": HITRUSTControl(
        id="01.t",
        title="Session Time-out",
        description="Inactive sessions shall shut down after a defined period of inactivity.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Implement session timeouts.",
        nist_mappings=["AC-11", "AC-12"],
        iso_mappings=["A.8.5"],
        hipaa_mappings=["164.312(a)(2)(iii)"],
        pci_mappings=["8.1.8"],
    ),
    "01.u": HITRUSTControl(
        id="01.u",
        title="Limitation of Connection Time",
        description="Restrictions on connection times shall be used to provide additional security for high-risk applications.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Limit connection times for high-risk systems.",
        nist_mappings=["AC-12"],
        iso_mappings=["A.8.5"],
        hipaa_mappings=["164.312(a)(1)"],
    ),
    "01.v": HITRUSTControl(
        id="01.v",
        title="Information Access Restriction",
        description="Access to information and application system functions by users and support personnel shall be restricted in accordance with the defined access control policy.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Restrict information access.",
        nist_mappings=["AC-3", "AC-6"],
        iso_mappings=["A.8.3"],
        hipaa_mappings=["164.312(a)(1)"],
        pci_mappings=["7.1"],
    ),
    "01.w": HITRUSTControl(
        id="01.w",
        title="Sensitive System Isolation",
        description="Sensitive systems shall have a dedicated computing environment.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Isolate sensitive systems.",
        nist_mappings=["SC-7", "SC-3"],
        iso_mappings=["A.8.22"],
        hipaa_mappings=["164.312(a)(1)"],
        pci_mappings=["2.2.1"],
    ),
    "01.x": HITRUSTControl(
        id="01.x",
        title="Mobile Computing and Communications",
        description="A formal policy shall be in place and appropriate security measures shall be adopted to protect against the risks of using mobile computing and communication facilities.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Secure mobile computing.",
        nist_mappings=["AC-19", "SC-7"],
        iso_mappings=["A.8.1"],
        hipaa_mappings=["164.312(a)(1)"],
        pci_mappings=["12.3.8"],
    ),
    "01.y": HITRUSTControl(
        id="01.y",
        title="Teleworking",
        description="A policy, operational plans, and procedures shall be developed and implemented for teleworking activities.",
        category=CATEGORY_ACCESS_CONTROL,
        objective="Secure telework activities.",
        nist_mappings=["AC-17", "PE-17"],
        iso_mappings=["A.6.7"],
        hipaa_mappings=["164.312(a)(1)"],
    ),
    # =========================================================================
    # Category 09: Communications and Operations Management
    # =========================================================================
    "09.a": HITRUSTControl(
        id="09.a",
        title="Documented Operating Procedures",
        description="Operating procedures shall be documented, maintained, and made available to all users who need them.",
        category=CATEGORY_OPERATIONS,
        objective="Document operating procedures.",
        nist_mappings=["SA-5", "CM-3"],
        iso_mappings=["A.5.37"],
        hipaa_mappings=["164.308(a)(3)(ii)(A)"],
    ),
    "09.b": HITRUSTControl(
        id="09.b",
        title="Change Management",
        description="Changes to information processing facilities and systems shall be controlled.",
        category=CATEGORY_OPERATIONS,
        objective="Manage changes to systems.",
        nist_mappings=["CM-3", "CM-4"],
        iso_mappings=["A.8.32"],
        hipaa_mappings=["164.308(a)(8)"],
        pci_mappings=["6.4.5"],
    ),
    "09.c": HITRUSTControl(
        id="09.c",
        title="Segregation of Duties",
        description="Duties and areas of responsibility shall be segregated to reduce opportunities for unauthorized or unintentional modification or misuse of the organization's assets.",
        category=CATEGORY_OPERATIONS,
        objective="Segregate duties.",
        nist_mappings=["AC-5"],
        iso_mappings=["A.5.3"],
        hipaa_mappings=["164.312(a)(1)"],
        pci_mappings=["6.4.2"],
    ),
    "09.d": HITRUSTControl(
        id="09.d",
        title="Separation of Development, Test, and Operational Facilities",
        description="Development, test, and operational facilities shall be separated to reduce the risks of unauthorized access or changes to the operational system.",
        category=CATEGORY_OPERATIONS,
        objective="Separate environments.",
        nist_mappings=["CM-4", "SA-11"],
        iso_mappings=["A.8.31"],
        hipaa_mappings=["164.308(a)(4)"],
        pci_mappings=["6.4.1"],
    ),
    "09.e": HITRUSTControl(
        id="09.e",
        title="External Parties",
        description="The security of the organization's information and information processing facilities shall not be reduced by the introduction of external party products or services.",
        category=CATEGORY_OPERATIONS,
        objective="Manage external party access.",
        nist_mappings=["SA-9", "PS-7"],
        iso_mappings=["A.5.19"],
        hipaa_mappings=["164.308(b)(1)"],
        pci_mappings=["12.8"],
    ),
    "09.f": HITRUSTControl(
        id="09.f",
        title="Service Delivery",
        description="It shall be ensured that the security controls, service definitions, and delivery levels included in the third party service delivery agreement are implemented, operated, and maintained by the third party.",
        category=CATEGORY_OPERATIONS,
        objective="Ensure third party service delivery.",
        nist_mappings=["SA-9"],
        iso_mappings=["A.5.22"],
        hipaa_mappings=["164.308(b)(3)"],
        pci_mappings=["12.8.2"],
    ),
    "09.g": HITRUSTControl(
        id="09.g",
        title="Monitoring and Review of Third Party Services",
        description="The services, reports, and records provided by the third party shall be regularly monitored and reviewed.",
        category=CATEGORY_OPERATIONS,
        objective="Monitor third party services.",
        nist_mappings=["SA-9", "CA-7"],
        iso_mappings=["A.5.22"],
        hipaa_mappings=["164.308(b)(4)"],
        pci_mappings=["12.8.4"],
    ),
    "09.h": HITRUSTControl(
        id="09.h",
        title="Managing Changes to Third Party Services",
        description="Changes to the provision of services, including maintaining and improving existing information security policies, procedures, and controls, shall be managed.",
        category=CATEGORY_OPERATIONS,
        objective="Manage third party service changes.",
        nist_mappings=["SA-9", "CM-3"],
        iso_mappings=["A.5.22"],
        hipaa_mappings=["164.308(b)(3)"],
    ),
    "09.i": HITRUSTControl(
        id="09.i",
        title="Capacity Management",
        description="The use of resources shall be monitored, tuned, and projections made of future capacity requirements to ensure the required system performance.",
        category=CATEGORY_OPERATIONS,
        objective="Manage system capacity.",
        nist_mappings=["CP-2", "SA-17"],
        iso_mappings=["A.8.6"],
        hipaa_mappings=["164.308(a)(7)(ii)(D)"],
    ),
    "09.j": HITRUSTControl(
        id="09.j",
        title="System Acceptance",
        description="Acceptance criteria for new information systems, upgrades, and new versions shall be established and suitable tests of the system(s) shall be carried out during development and prior to acceptance.",
        category=CATEGORY_OPERATIONS,
        objective="Establish system acceptance criteria.",
        nist_mappings=["SA-11", "CA-2"],
        iso_mappings=["A.8.29"],
        hipaa_mappings=["164.308(a)(8)"],
        pci_mappings=["6.3.2"],
    ),
    "09.k": HITRUSTControl(
        id="09.k",
        title="Controls Against Malicious Code",
        description="Detection, prevention, and recovery controls to protect against malicious code and appropriate user awareness procedures shall be implemented.",
        category=CATEGORY_OPERATIONS,
        objective="Protect against malware.",
        nist_mappings=["SI-3", "SI-8"],
        iso_mappings=["A.8.7"],
        hipaa_mappings=["164.308(a)(5)(ii)(B)"],
        pci_mappings=["5.1"],
    ),
    "09.l": HITRUSTControl(
        id="09.l",
        title="Controls Against Mobile Code",
        description="Where the use of mobile code is authorized, the configuration shall ensure that the authorized mobile code operates according to a clearly defined security policy.",
        category=CATEGORY_OPERATIONS,
        objective="Control mobile code.",
        nist_mappings=["SC-18"],
        iso_mappings=["A.8.7"],
        hipaa_mappings=["164.312(e)(1)"],
    ),
    "09.m": HITRUSTControl(
        id="09.m",
        title="Information Back-up",
        description="Back-up copies of information and software shall be taken and tested regularly in accordance with the agreed backup policy.",
        category=CATEGORY_OPERATIONS,
        objective="Backup information regularly.",
        nist_mappings=["CP-9", "CP-10"],
        iso_mappings=["A.8.13"],
        hipaa_mappings=["164.308(a)(7)(ii)(A)"],
        pci_mappings=["9.5.1"],
    ),
    "09.n": HITRUSTControl(
        id="09.n",
        title="Network Controls",
        description="Networks shall be adequately managed and controlled, in order to be protected from threats, and to maintain security for the systems and applications using the network, including information in transit.",
        category=CATEGORY_OPERATIONS,
        objective="Secure networks.",
        nist_mappings=["SC-7", "SC-8"],
        iso_mappings=["A.8.20"],
        hipaa_mappings=["164.312(e)(1)"],
        pci_mappings=["1.1"],
    ),
    "09.o": HITRUSTControl(
        id="09.o",
        title="Security of Network Services",
        description="Security features, service levels, and management requirements of all network services shall be identified and included in any network services agreement.",
        category=CATEGORY_OPERATIONS,
        objective="Define network service security.",
        nist_mappings=["SC-7", "SC-8"],
        iso_mappings=["A.8.21"],
        hipaa_mappings=["164.312(e)(1)"],
    ),
    "09.p": HITRUSTControl(
        id="09.p",
        title="Management of Removable Media",
        description="There shall be procedures in place for the management of removable media.",
        category=CATEGORY_OPERATIONS,
        objective="Manage removable media.",
        nist_mappings=["MP-2", "MP-4"],
        iso_mappings=["A.7.10"],
        hipaa_mappings=["164.310(d)(1)"],
        pci_mappings=["9.6"],
    ),
    "09.q": HITRUSTControl(
        id="09.q",
        title="Disposal of Media",
        description="Media shall be disposed of securely and safely when no longer required, using formal procedures.",
        category=CATEGORY_OPERATIONS,
        objective="Securely dispose of media.",
        nist_mappings=["MP-6"],
        iso_mappings=["A.7.10", "A.7.14"],
        hipaa_mappings=["164.310(d)(2)(i)"],
        pci_mappings=["9.8"],
    ),
    "09.r": HITRUSTControl(
        id="09.r",
        title="Information Handling Procedures",
        description="Procedures for the handling and storage of information shall be established to protect this information from unauthorized disclosure or misuse.",
        category=CATEGORY_OPERATIONS,
        objective="Handle information securely.",
        nist_mappings=["MP-2", "MP-4"],
        iso_mappings=["A.5.10"],
        hipaa_mappings=["164.312(c)(1)"],
    ),
    "09.s": HITRUSTControl(
        id="09.s",
        title="Security of System Documentation",
        description="System documentation shall be protected against unauthorized access.",
        category=CATEGORY_OPERATIONS,
        objective="Protect system documentation.",
        nist_mappings=["SA-5", "AC-3"],
        iso_mappings=["A.5.37"],
        hipaa_mappings=["164.312(a)(1)"],
    ),
    "09.t": HITRUSTControl(
        id="09.t",
        title="Information Exchange Policies and Procedures",
        description="Formal exchange policies, procedures, and controls shall be in place to protect the exchange of information through the use of all types of communication facilities.",
        category=CATEGORY_OPERATIONS,
        objective="Secure information exchange.",
        nist_mappings=["SC-8", "AC-20"],
        iso_mappings=["A.5.14"],
        hipaa_mappings=["164.312(e)(1)"],
    ),
    "09.u": HITRUSTControl(
        id="09.u",
        title="Exchange Agreements",
        description="Agreements shall be established for the exchange of information and software between the organization and external parties.",
        category=CATEGORY_OPERATIONS,
        objective="Establish exchange agreements.",
        nist_mappings=["CA-3", "SA-9"],
        iso_mappings=["A.5.14"],
        hipaa_mappings=["164.308(b)(1)"],
    ),
    "09.v": HITRUSTControl(
        id="09.v",
        title="Physical Media in Transit",
        description="Media containing information shall be protected against unauthorized access, misuse, or corruption during transportation beyond an organization's physical boundaries.",
        category=CATEGORY_OPERATIONS,
        objective="Protect media in transit.",
        nist_mappings=["MP-5"],
        iso_mappings=["A.7.9"],
        hipaa_mappings=["164.310(d)(2)(iii)"],
        pci_mappings=["9.7"],
    ),
    "09.w": HITRUSTControl(
        id="09.w",
        title="Electronic Messaging",
        description="Information involved in electronic messaging shall be appropriately protected.",
        category=CATEGORY_OPERATIONS,
        objective="Secure electronic messaging.",
        nist_mappings=["SC-8"],
        iso_mappings=["A.5.14"],
        hipaa_mappings=["164.312(e)(2)(ii)"],
    ),
    "09.x": HITRUSTControl(
        id="09.x",
        title="Business Information Systems",
        description="Policies and procedures shall be developed and implemented to protect information associated with the interconnection of business information systems.",
        category=CATEGORY_OPERATIONS,
        objective="Protect business system interconnections.",
        nist_mappings=["CA-3", "SC-7"],
        iso_mappings=["A.8.20"],
        hipaa_mappings=["164.312(a)(1)"],
    ),
    "09.y": HITRUSTControl(
        id="09.y",
        title="On-line Transactions",
        description="Information involved in on-line transactions shall be protected to prevent incomplete transmission, mis-routing, unauthorized message alteration, unauthorized disclosure, unauthorized message duplication, or replay.",
        category=CATEGORY_OPERATIONS,
        objective="Protect online transactions.",
        nist_mappings=["SC-8", "SC-23"],
        iso_mappings=["A.8.24"],
        hipaa_mappings=["164.312(e)(1)"],
        pci_mappings=["4.1"],
    ),
    "09.z": HITRUSTControl(
        id="09.z",
        title="Publicly Available Information",
        description="The integrity of information being made available on a publicly available system shall be protected to prevent unauthorized modification.",
        category=CATEGORY_OPERATIONS,
        objective="Protect publicly available information.",
        nist_mappings=["SC-8", "SI-10"],
        iso_mappings=["A.8.24"],
        hipaa_mappings=["164.312(c)(1)"],
    ),
    "09.aa": HITRUSTControl(
        id="09.aa",
        title="Audit Logging",
        description="Audit logs recording user activities, exceptions, and information security events shall be produced and kept for an agreed period to assist in future investigations and access control monitoring.",
        category=CATEGORY_OPERATIONS,
        objective="Maintain audit logs.",
        nist_mappings=["AU-2", "AU-3", "AU-6"],
        iso_mappings=["A.8.15"],
        hipaa_mappings=["164.312(b)"],
        pci_mappings=["10.1"],
    ),
    "09.ab": HITRUSTControl(
        id="09.ab",
        title="Monitoring System Use",
        description="Procedures for monitoring use of information processing facilities shall be established and the results of the monitoring activities reviewed regularly.",
        category=CATEGORY_OPERATIONS,
        objective="Monitor system use.",
        nist_mappings=["SI-4", "AU-6"],
        iso_mappings=["A.8.16"],
        hipaa_mappings=["164.308(a)(1)(ii)(D)"],
        pci_mappings=["10.6"],
    ),
    "09.ac": HITRUSTControl(
        id="09.ac",
        title="Protection of Log Information",
        description="Logging facilities and log information shall be protected against tampering and unauthorized access.",
        category=CATEGORY_OPERATIONS,
        objective="Protect log information.",
        nist_mappings=["AU-9"],
        iso_mappings=["A.8.15"],
        hipaa_mappings=["164.312(b)"],
        pci_mappings=["10.5"],
    ),
    "09.ad": HITRUSTControl(
        id="09.ad",
        title="Administrator and Operator Logs",
        description="System administrator and system operator activities shall be logged and the logs protected and regularly reviewed.",
        category=CATEGORY_OPERATIONS,
        objective="Log administrator activities.",
        nist_mappings=["AU-2", "AU-12"],
        iso_mappings=["A.8.15"],
        hipaa_mappings=["164.312(b)"],
        pci_mappings=["10.2.2"],
    ),
    "09.ae": HITRUSTControl(
        id="09.ae",
        title="Fault Logging",
        description="Faults shall be logged, analyzed, and appropriate action taken.",
        category=CATEGORY_OPERATIONS,
        objective="Log and analyze faults.",
        nist_mappings=["SI-2", "AU-6"],
        iso_mappings=["A.8.15"],
        hipaa_mappings=["164.308(a)(1)(ii)(D)"],
    ),
    "09.af": HITRUSTControl(
        id="09.af",
        title="Clock Synchronization",
        description="The clocks of all relevant information processing systems within an organization or security domain shall be synchronized with an agreed accurate time source.",
        category=CATEGORY_OPERATIONS,
        objective="Synchronize system clocks.",
        nist_mappings=["AU-8"],
        iso_mappings=["A.8.17"],
        hipaa_mappings=["164.312(b)"],
        pci_mappings=["10.4"],
    ),
    # =========================================================================
    # Category 10: Information Systems Acquisition, Development, and Maintenance
    # =========================================================================
    "10.a": HITRUSTControl(
        id="10.a",
        title="Security Requirements Analysis and Specification",
        description="Statements of business requirements for new information systems, or enhancements to existing information systems shall specify the requirements for security controls.",
        category=CATEGORY_SDLC,
        objective="Specify security requirements.",
        nist_mappings=["SA-4", "SA-8"],
        iso_mappings=["A.8.26"],
        hipaa_mappings=["164.308(a)(1)"],
        pci_mappings=["6.3"],
    ),
    "10.b": HITRUSTControl(
        id="10.b",
        title="Input Data Validation",
        description="Data input to applications shall be validated to ensure that this data is correct and appropriate.",
        category=CATEGORY_SDLC,
        objective="Validate input data.",
        nist_mappings=["SI-10"],
        iso_mappings=["A.8.28"],
        hipaa_mappings=["164.312(c)(1)"],
        pci_mappings=["6.5.1"],
    ),
    "10.c": HITRUSTControl(
        id="10.c",
        title="Control of Internal Processing",
        description="Validation checks shall be incorporated into applications to detect any corruption of information through processing errors or deliberate acts.",
        category=CATEGORY_SDLC,
        objective="Control internal processing.",
        nist_mappings=["SI-10"],
        iso_mappings=["A.8.28"],
        hipaa_mappings=["164.312(c)(1)"],
    ),
    "10.d": HITRUSTControl(
        id="10.d",
        title="Message Integrity",
        description="Requirements for ensuring authenticity and protecting message integrity in applications shall be identified and appropriate controls identified and implemented.",
        category=CATEGORY_SDLC,
        objective="Ensure message integrity.",
        nist_mappings=["SC-8", "SC-13"],
        iso_mappings=["A.8.24"],
        hipaa_mappings=["164.312(c)(1)"],
    ),
    "10.e": HITRUSTControl(
        id="10.e",
        title="Output Data Validation",
        description="The data output of an application shall be validated to ensure that the processing of stored information is correct and appropriate to the circumstances.",
        category=CATEGORY_SDLC,
        objective="Validate output data.",
        nist_mappings=["SI-10"],
        iso_mappings=["A.8.28"],
        hipaa_mappings=["164.312(c)(1)"],
    ),
    "10.f": HITRUSTControl(
        id="10.f",
        title="Policy on the Use of Cryptographic Controls",
        description="A policy on the use of cryptographic controls for protection of information shall be developed and implemented.",
        category=CATEGORY_SDLC,
        objective="Implement cryptographic controls.",
        nist_mappings=["SC-12", "SC-13"],
        iso_mappings=["A.8.24"],
        hipaa_mappings=["164.312(a)(2)(iv)"],
        pci_mappings=["3.5"],
    ),
    "10.g": HITRUSTControl(
        id="10.g",
        title="Key Management",
        description="Key management shall be in place to support the organization's use of cryptographic techniques.",
        category=CATEGORY_SDLC,
        objective="Manage cryptographic keys.",
        nist_mappings=["SC-12"],
        iso_mappings=["A.8.24"],
        hipaa_mappings=["164.312(a)(2)(iv)"],
        pci_mappings=["3.6"],
    ),
    "10.h": HITRUSTControl(
        id="10.h",
        title="Control of Operational Software",
        description="There shall be procedures in place to control the installation of software on operational systems.",
        category=CATEGORY_SDLC,
        objective="Control software installation.",
        nist_mappings=["CM-5", "CM-11"],
        iso_mappings=["A.8.19"],
        hipaa_mappings=["164.312(a)(1)"],
        pci_mappings=["6.4"],
    ),
    "10.i": HITRUSTControl(
        id="10.i",
        title="Protection of System Test Data",
        description="Test data shall be selected carefully, and protected and controlled.",
        category=CATEGORY_SDLC,
        objective="Protect test data.",
        nist_mappings=["SA-11"],
        iso_mappings=["A.8.33"],
        hipaa_mappings=["164.308(a)(4)"],
        pci_mappings=["6.4.3"],
    ),
    "10.j": HITRUSTControl(
        id="10.j",
        title="Access Control to Program Source Code",
        description="Access to program source code shall be restricted.",
        category=CATEGORY_SDLC,
        objective="Restrict source code access.",
        nist_mappings=["CM-5", "AC-3"],
        iso_mappings=["A.8.4"],
        hipaa_mappings=["164.312(a)(1)"],
        pci_mappings=["6.4.2"],
    ),
    "10.k": HITRUSTControl(
        id="10.k",
        title="Change Control Procedures",
        description="The implementation of changes shall be controlled by the use of formal change control procedures.",
        category=CATEGORY_SDLC,
        objective="Control changes formally.",
        nist_mappings=["CM-3", "CM-4"],
        iso_mappings=["A.8.32"],
        hipaa_mappings=["164.308(a)(8)"],
        pci_mappings=["6.4.5"],
    ),
    "10.l": HITRUSTControl(
        id="10.l",
        title="Technical Review of Applications After Operating Platform Changes",
        description="When operating platforms are changed, business critical applications shall be reviewed and tested to ensure there is no adverse impact on organizational operations or security.",
        category=CATEGORY_SDLC,
        objective="Review applications after platform changes.",
        nist_mappings=["CM-4", "SA-11"],
        iso_mappings=["A.8.32"],
        hipaa_mappings=["164.308(a)(8)"],
    ),
    "10.m": HITRUSTControl(
        id="10.m",
        title="Restrictions on Changes to Software Packages",
        description="Modifications to software packages shall be discouraged, limited to necessary changes, and all changes shall be strictly controlled.",
        category=CATEGORY_SDLC,
        objective="Control software package changes.",
        nist_mappings=["CM-3", "CM-5"],
        iso_mappings=["A.8.32"],
        hipaa_mappings=["164.308(a)(8)"],
    ),
    "10.n": HITRUSTControl(
        id="10.n",
        title="Information Leakage",
        description="Opportunities for information leakage shall be prevented.",
        category=CATEGORY_SDLC,
        objective="Prevent information leakage.",
        nist_mappings=["SC-7", "AC-4"],
        iso_mappings=["A.8.12"],
        hipaa_mappings=["164.312(e)(1)"],
    ),
    "10.o": HITRUSTControl(
        id="10.o",
        title="Outsourced Software Development",
        description="Outsourced software development shall be supervised and monitored by the organization.",
        category=CATEGORY_SDLC,
        objective="Monitor outsourced development.",
        nist_mappings=["SA-9", "SA-11"],
        iso_mappings=["A.8.30"],
        hipaa_mappings=["164.308(b)(1)"],
        pci_mappings=["6.3.2"],
    ),
    "10.p": HITRUSTControl(
        id="10.p",
        title="Control of Technical Vulnerabilities",
        description="Timely information about technical vulnerabilities of information systems being used shall be obtained, the organization's exposure to such vulnerabilities evaluated, and appropriate measures taken to address the associated risk.",
        category=CATEGORY_SDLC,
        objective="Manage technical vulnerabilities.",
        nist_mappings=["RA-5", "SI-2"],
        iso_mappings=["A.8.8"],
        hipaa_mappings=["164.308(a)(1)(ii)(A)"],
        pci_mappings=["6.1"],
    ),
    # =========================================================================
    # Category 11: Information Security Incident Management
    # =========================================================================
    "11.a": HITRUSTControl(
        id="11.a",
        title="Reporting Information Security Events",
        description="Information security events shall be reported through appropriate management channels as quickly as possible.",
        category=CATEGORY_INCIDENT_MANAGEMENT,
        objective="Report security events promptly.",
        nist_mappings=["IR-6", "IR-7"],
        iso_mappings=["A.6.8"],
        hipaa_mappings=["164.308(a)(6)(ii)"],
        pci_mappings=["12.10.2"],
    ),
    "11.b": HITRUSTControl(
        id="11.b",
        title="Reporting Security Weaknesses",
        description="All employees, contractors, and third party users of information systems and services shall be required to note and report any observed or suspected security weaknesses in systems or services.",
        category=CATEGORY_INCIDENT_MANAGEMENT,
        objective="Report security weaknesses.",
        nist_mappings=["IR-6", "SI-5"],
        iso_mappings=["A.6.8"],
        hipaa_mappings=["164.308(a)(6)(ii)"],
    ),
    "11.c": HITRUSTControl(
        id="11.c",
        title="Responsibilities and Procedures",
        description="Management responsibilities and procedures shall be established to ensure a quick, effective, and orderly response to information security incidents.",
        category=CATEGORY_INCIDENT_MANAGEMENT,
        objective="Establish incident response procedures.",
        nist_mappings=["IR-1", "IR-8"],
        iso_mappings=["A.5.24"],
        hipaa_mappings=["164.308(a)(6)(i)"],
        pci_mappings=["12.10.1"],
    ),
    "11.d": HITRUSTControl(
        id="11.d",
        title="Learning from Information Security Incidents",
        description="There shall be mechanisms in place to enable the types, volumes, and costs of information security incidents to be quantified and monitored.",
        category=CATEGORY_INCIDENT_MANAGEMENT,
        objective="Learn from incidents.",
        nist_mappings=["IR-4", "IR-6"],
        iso_mappings=["A.5.27"],
        hipaa_mappings=["164.308(a)(6)(ii)"],
    ),
    "11.e": HITRUSTControl(
        id="11.e",
        title="Collection of Evidence",
        description="Where a follow-up action against a person or organization after an information security incident involves legal action, evidence shall be collected, retained, and presented to conform to the rules for evidence laid down in the relevant jurisdiction(s).",
        category=CATEGORY_INCIDENT_MANAGEMENT,
        objective="Collect and preserve evidence.",
        nist_mappings=["AU-9", "IR-4"],
        iso_mappings=["A.5.28"],
        hipaa_mappings=["164.308(a)(6)(ii)"],
    ),
}


# =============================================================================
# AWS Compliance Checks for HITRUST
# =============================================================================


def get_hitrust_aws_checks() -> list[CheckDefinition]:
    """
    Get AWS compliance checks mapped to HITRUST controls.

    Returns:
        List of CheckDefinition objects for AWS resources.
    """
    return [
        # ---------------------------------------------------------------------------
        # 01.q/01.j: User Authentication
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="hitrust-aws-01q-1",
            title="IAM users should have MFA enabled",
            description="Multi-factor authentication adds an extra layer of protection for user accounts.",
            severity="high",
            resource_types=["iam_user"],
            condition=Condition(
                path="raw_data.MFADevices",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Enable MFA for all IAM users.",
            frameworks={"hitrust": ["01.q", "01.j"]},
        ),
        CheckDefinition(
            id="hitrust-aws-01c-1",
            title="IAM root user should not have access keys",
            description="Root account access keys provide unrestricted access to all AWS resources.",
            severity="critical",
            resource_types=["iam_account_summary"],
            condition=Condition(
                path="raw_data.AccountAccessKeysPresent",
                operator=Operator.EQUALS,
                value=0,
            ),
            remediation="Delete root account access keys and use IAM users for programmatic access.",
            frameworks={"hitrust": ["01.c", "01.v"]},
        ),
        CheckDefinition(
            id="hitrust-aws-01d-1",
            title="IAM password policy should be strong",
            description="Strong password policies help prevent unauthorized access.",
            severity="medium",
            resource_types=["iam_password_policy"],
            condition=ConditionGroup(
                logic=LogicOperator.AND,
                conditions=[
                    Condition(
                        path="raw_data.MinimumPasswordLength",
                        operator=Operator.GREATER_THAN_OR_EQUAL,
                        value=14,
                    ),
                    Condition(
                        path="raw_data.RequireSymbols",
                        operator=Operator.IS_TRUE,
                    ),
                ],
            ),
            remediation="Configure IAM password policy with minimum length 14 and require symbols.",
            frameworks={"hitrust": ["01.d", "01.f", "01.r"]},
        ),
        # ---------------------------------------------------------------------------
        # 09.aa/09.ab: Audit Logging and Monitoring
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="hitrust-aws-09aa-1",
            title="CloudTrail should be enabled and logging",
            description="CloudTrail provides audit logs for API calls across AWS services.",
            severity="high",
            resource_types=["cloudtrail"],
            condition=Condition(
                path="raw_data.IsLogging",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable CloudTrail logging.",
            frameworks={"hitrust": ["09.aa", "09.ab"]},
        ),
        CheckDefinition(
            id="hitrust-aws-09aa-2",
            title="CloudTrail should be multi-region",
            description="Multi-region trails capture API activity across all AWS regions.",
            severity="high",
            resource_types=["cloudtrail"],
            condition=Condition(
                path="raw_data.IsMultiRegionTrail",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable multi-region CloudTrail trail.",
            frameworks={"hitrust": ["09.aa"]},
        ),
        CheckDefinition(
            id="hitrust-aws-09ac-1",
            title="CloudTrail logs should be encrypted",
            description="Encrypting CloudTrail logs protects sensitive audit information.",
            severity="medium",
            resource_types=["cloudtrail"],
            condition=Condition(
                path="raw_data.KMSKeyId",
                operator=Operator.IS_NOT_EMPTY,
            ),
            remediation="Enable KMS encryption for CloudTrail logs.",
            frameworks={"hitrust": ["09.ac", "10.f"]},
        ),
        CheckDefinition(
            id="hitrust-aws-09ac-2",
            title="CloudTrail log file validation should be enabled",
            description="Log file validation ensures audit logs have not been tampered with.",
            severity="medium",
            resource_types=["cloudtrail"],
            condition=Condition(
                path="raw_data.LogFileValidationEnabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable log file validation for CloudTrail.",
            frameworks={"hitrust": ["09.ac"]},
        ),
        CheckDefinition(
            id="hitrust-aws-09ab-1",
            title="GuardDuty should be enabled",
            description="GuardDuty provides intelligent threat detection for AWS accounts.",
            severity="high",
            resource_types=["guardduty_detector"],
            condition=Condition(
                path="raw_data.Status",
                operator=Operator.EQUALS,
                value="ENABLED",
            ),
            remediation="Enable GuardDuty in all AWS regions.",
            frameworks={"hitrust": ["09.ab", "11.a"]},
        ),
        # ---------------------------------------------------------------------------
        # 01.m/01.n: Network Security
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="hitrust-aws-01m-1",
            title="Security groups should not allow unrestricted SSH access",
            description="Unrestricted SSH access from the internet poses a security risk.",
            severity="high",
            resource_types=["security_group"],
            condition=Condition(
                path="raw_data.AllowsSSHFromInternet",
                operator=Operator.IS_FALSE,
            ),
            remediation="Restrict SSH access to specific IP ranges.",
            frameworks={"hitrust": ["01.m", "01.n", "09.n"]},
        ),
        CheckDefinition(
            id="hitrust-aws-01m-2",
            title="Security groups should not allow unrestricted RDP access",
            description="Unrestricted RDP access from the internet poses a security risk.",
            severity="high",
            resource_types=["security_group"],
            condition=Condition(
                path="raw_data.AllowsRDPFromInternet",
                operator=Operator.IS_FALSE,
            ),
            remediation="Restrict RDP access to specific IP ranges.",
            frameworks={"hitrust": ["01.m", "01.n", "09.n"]},
        ),
        CheckDefinition(
            id="hitrust-aws-01m-3",
            title="VPCs should have flow logs enabled",
            description="VPC flow logs capture information about IP traffic for security analysis.",
            severity="medium",
            resource_types=["vpc"],
            condition=Condition(
                path="raw_data.FlowLogsEnabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable VPC flow logs for all VPCs.",
            frameworks={"hitrust": ["01.m", "09.ab"]},
        ),
        # ---------------------------------------------------------------------------
        # 10.f: Cryptographic Controls
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="hitrust-aws-10f-1",
            title="S3 buckets should have server-side encryption enabled",
            description="Server-side encryption protects data at rest in S3 buckets.",
            severity="high",
            resource_types=["s3_bucket"],
            condition=Condition(
                path="raw_data.ServerSideEncryptionEnabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable default encryption on S3 buckets.",
            frameworks={"hitrust": ["10.f", "09.r"]},
        ),
        CheckDefinition(
            id="hitrust-aws-10f-2",
            title="EBS volumes should be encrypted",
            description="EBS encryption protects data at rest on EC2 volumes.",
            severity="high",
            resource_types=["ebs_volume"],
            condition=Condition(
                path="raw_data.Encrypted",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable encryption for EBS volumes.",
            frameworks={"hitrust": ["10.f"]},
        ),
        CheckDefinition(
            id="hitrust-aws-10f-3",
            title="RDS instances should be encrypted",
            description="RDS encryption protects data at rest in databases.",
            severity="high",
            resource_types=["rds_instance"],
            condition=Condition(
                path="raw_data.StorageEncrypted",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable encryption for RDS instances.",
            frameworks={"hitrust": ["10.f"]},
        ),
        CheckDefinition(
            id="hitrust-aws-10g-1",
            title="KMS keys should have automatic rotation enabled",
            description="Key rotation limits the amount of data encrypted with a single key.",
            severity="medium",
            resource_types=["kms_key"],
            condition=Condition(
                path="raw_data.KeyRotationEnabled",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable automatic key rotation for KMS keys.",
            frameworks={"hitrust": ["10.g"]},
        ),
        # ---------------------------------------------------------------------------
        # 09.m: Information Backup
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="hitrust-aws-09m-1",
            title="S3 buckets should have versioning enabled",
            description="Versioning protects against accidental deletion or modification.",
            severity="medium",
            resource_types=["s3_bucket"],
            condition=Condition(
                path="raw_data.Versioning.Status",
                operator=Operator.EQUALS,
                value="Enabled",
            ),
            remediation="Enable versioning on S3 buckets.",
            frameworks={"hitrust": ["09.m"]},
        ),
        CheckDefinition(
            id="hitrust-aws-09m-2",
            title="RDS instances should have automated backups enabled",
            description="Automated backups enable point-in-time recovery.",
            severity="medium",
            resource_types=["rds_instance"],
            condition=Condition(
                path="raw_data.BackupRetentionPeriod",
                operator=Operator.GREATER_THAN,
                value=0,
            ),
            remediation="Enable automated backups for RDS instances.",
            frameworks={"hitrust": ["09.m"]},
        ),
        CheckDefinition(
            id="hitrust-aws-09m-3",
            title="RDS instances should be Multi-AZ",
            description="Multi-AZ provides high availability for database instances.",
            severity="medium",
            resource_types=["rds_instance"],
            condition=Condition(
                path="raw_data.MultiAZ",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable Multi-AZ for RDS instances.",
            frameworks={"hitrust": ["09.m", "09.i"]},
        ),
        # ---------------------------------------------------------------------------
        # 09.k: Malware Protection
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="hitrust-aws-09k-1",
            title="EC2 instances should use IMDSv2",
            description="IMDSv2 provides enhanced protection against SSRF attacks.",
            severity="medium",
            resource_types=["ec2_instance"],
            condition=Condition(
                path="raw_data.MetadataOptions.HttpTokens",
                operator=Operator.EQUALS,
                value="required",
            ),
            remediation="Configure EC2 instances to require IMDSv2.",
            frameworks={"hitrust": ["09.k", "01.l"]},
        ),
        # ---------------------------------------------------------------------------
        # 09.b: Change Management / 10.p: Vulnerability Management
        # ---------------------------------------------------------------------------
        CheckDefinition(
            id="hitrust-aws-09b-1",
            title="AWS Config should be enabled",
            description="AWS Config tracks resource configuration changes.",
            severity="medium",
            resource_types=["config_recorder"],
            condition=Condition(
                path="raw_data.Recording",
                operator=Operator.IS_TRUE,
            ),
            remediation="Enable AWS Config in all regions.",
            frameworks={"hitrust": ["09.b", "10.p"]},
        ),
    ]


# =============================================================================
# Framework Factory Functions
# =============================================================================


def create_hitrust_evaluator() -> Evaluator:
    """
    Create an evaluator pre-configured with HITRUST checks.

    Returns:
        Evaluator configured with HITRUST checks.
    """
    evaluator = Evaluator()

    for check in get_hitrust_aws_checks():
        evaluator.register_check(check)

    logger.info(
        f"Created HITRUST evaluator with {len(evaluator.list_checks())} checks"
    )
    return evaluator


def get_hitrust_framework() -> HITRUSTFramework:
    """
    Get the HITRUST CSF framework with controls and check mappings.

    Returns:
        HITRUSTFramework with controls and check mappings.
    """
    framework = HITRUSTFramework(
        version=HITRUST_VERSION,
        controls=HITRUST_CONTROLS,
    )

    # Build check mappings from all checks
    all_checks = get_hitrust_aws_checks()

    for check in all_checks:
        if "hitrust" in check.frameworks:
            for control_id in check.frameworks["hitrust"]:
                if control_id not in framework.check_mappings:
                    framework.check_mappings[control_id] = []
                framework.check_mappings[control_id].append(check.id)

    logger.info(
        f"Built HITRUST framework with {len(framework.controls)} controls, "
        f"{len(framework.check_mappings)} mapped to checks"
    )
    return framework


def get_controls_by_category(category: str) -> list[HITRUSTControl]:
    """
    Get all HITRUST controls in a specific category.

    Args:
        category: Category identifier (00-13).

    Returns:
        List of controls in the specified category.
    """
    return [c for c in HITRUST_CONTROLS.values() if c.category == category]


def get_hipaa_mapped_controls() -> list[HITRUSTControl]:
    """
    Get all HITRUST controls that map to HIPAA requirements.

    Returns:
        List of controls with HIPAA mappings.
    """
    return [c for c in HITRUST_CONTROLS.values() if c.hipaa_mappings]


def get_control_count_by_category() -> dict[str, int]:
    """
    Get the count of controls in each category.

    Returns:
        Dictionary mapping category to control count.
    """
    counts: dict[str, int] = {}
    for control in HITRUST_CONTROLS.values():
        counts[control.category] = counts.get(control.category, 0) + 1
    return counts
