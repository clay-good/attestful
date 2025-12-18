"""
NIST 800-53 Rev 5 control definitions.

Contains the complete control family definitions and individual controls
from NIST Special Publication 800-53 Revision 5.

This module provides:
- Control family constants
- Control dataclass definitions
- All 1000+ control definitions (key controls included, full set loaded from OSCAL)
- Lookup functions for controls and families
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from attestful.core.logging import get_logger

logger = get_logger(__name__)


# =============================================================================
# Framework Constants
# =============================================================================

NIST_800_53_FRAMEWORK_ID = "nist-800-53"
NIST_800_53_VERSION = "5.1.1"  # Rev 5, Update 1

# Control Families
FAMILY_AC = "AC"  # Access Control
FAMILY_AU = "AU"  # Audit and Accountability
FAMILY_AT = "AT"  # Awareness and Training
FAMILY_CM = "CM"  # Configuration Management
FAMILY_CP = "CP"  # Contingency Planning
FAMILY_IA = "IA"  # Identification and Authentication
FAMILY_IR = "IR"  # Incident Response
FAMILY_MA = "MA"  # Maintenance
FAMILY_MP = "MP"  # Media Protection
FAMILY_PE = "PE"  # Physical and Environmental Protection
FAMILY_PL = "PL"  # Planning
FAMILY_PM = "PM"  # Program Management
FAMILY_PS = "PS"  # Personnel Security
FAMILY_PT = "PT"  # PII Processing and Transparency
FAMILY_RA = "RA"  # Risk Assessment
FAMILY_SA = "SA"  # System and Services Acquisition
FAMILY_SC = "SC"  # System and Communications Protection
FAMILY_SI = "SI"  # System and Information Integrity
FAMILY_SR = "SR"  # Supply Chain Risk Management

# Family metadata
FAMILY_NAMES = {
    FAMILY_AC: "Access Control",
    FAMILY_AU: "Audit and Accountability",
    FAMILY_AT: "Awareness and Training",
    FAMILY_CM: "Configuration Management",
    FAMILY_CP: "Contingency Planning",
    FAMILY_IA: "Identification and Authentication",
    FAMILY_IR: "Incident Response",
    FAMILY_MA: "Maintenance",
    FAMILY_MP: "Media Protection",
    FAMILY_PE: "Physical and Environmental Protection",
    FAMILY_PL: "Planning",
    FAMILY_PM: "Program Management",
    FAMILY_PS: "Personnel Security",
    FAMILY_PT: "PII Processing and Transparency",
    FAMILY_RA: "Risk Assessment",
    FAMILY_SA: "System and Services Acquisition",
    FAMILY_SC: "System and Communications Protection",
    FAMILY_SI: "System and Information Integrity",
    FAMILY_SR: "Supply Chain Risk Management",
}


# =============================================================================
# Control Data Classes
# =============================================================================


@dataclass
class NIST80053Control:
    """
    A NIST 800-53 security control.

    Attributes:
        id: Control identifier (e.g., "AC-2", "AC-2(1)" for enhancements).
        title: Control title.
        description: Control description/requirement text.
        family: Control family (e.g., "AC").
        priority: Control priority (P0, P1, P2, P3 - P0 is not selected).
        baseline_impact: Impact levels where control is required (low, moderate, high).
        enhancements: List of control enhancement IDs.
        parent: Parent control ID for enhancements (e.g., "AC-2" for "AC-2(1)").
        withdrawn: Whether the control has been withdrawn.
        incorporated_into: Control ID this was incorporated into if withdrawn.
        related_controls: List of related control IDs.
        references: External references (NIST SPs, OMB circulars, etc.).
    """

    id: str
    title: str
    description: str
    family: str
    priority: str = "P1"
    baseline_impact: list[str] = field(default_factory=lambda: ["low", "moderate", "high"])
    enhancements: list[str] = field(default_factory=list)
    parent: str | None = None
    withdrawn: bool = False
    incorporated_into: str | None = None
    related_controls: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    @property
    def is_enhancement(self) -> bool:
        """Check if this is a control enhancement."""
        return "(" in self.id and ")" in self.id

    @property
    def base_control_id(self) -> str:
        """Get the base control ID (without enhancement number)."""
        if self.is_enhancement:
            return self.id.split("(")[0]
        return self.id

    @property
    def enhancement_number(self) -> int | None:
        """Get the enhancement number if this is an enhancement."""
        if not self.is_enhancement:
            return None
        try:
            return int(self.id.split("(")[1].rstrip(")"))
        except (IndexError, ValueError):
            return None


@dataclass
class NIST80053Framework:
    """
    NIST 800-53 Rev 5 compliance framework definition.

    Contains security controls and their mappings to automated checks.
    """

    version: str = NIST_800_53_VERSION
    controls: dict[str, NIST80053Control] = field(default_factory=dict)
    check_mappings: dict[str, list[str]] = field(default_factory=dict)  # control_id -> check_ids

    def get_control(self, control_id: str) -> NIST80053Control | None:
        """Get a control by ID."""
        return self.controls.get(control_id)

    def get_checks_for_control(self, control_id: str) -> list[str]:
        """Get check IDs mapped to a control."""
        return self.check_mappings.get(control_id, [])

    def get_controls_for_baseline(self, baseline: str) -> list[NIST80053Control]:
        """Get all controls required for a FedRAMP baseline."""
        impact = baseline.replace("fedramp-", "")
        return [
            ctrl for ctrl in self.controls.values()
            if impact in ctrl.baseline_impact and not ctrl.withdrawn
        ]

    def get_controls_by_family(self, family: str) -> list[NIST80053Control]:
        """Get all controls in a family."""
        return [
            ctrl for ctrl in self.controls.values()
            if ctrl.family == family and not ctrl.withdrawn
        ]

    def get_enhancements(self, control_id: str) -> list[NIST80053Control]:
        """Get all enhancements for a base control."""
        control = self.controls.get(control_id)
        if not control:
            return []
        return [
            self.controls[enh_id]
            for enh_id in control.enhancements
            if enh_id in self.controls
        ]


# =============================================================================
# Control Definitions
# =============================================================================

# This contains key controls. The full set of 1000+ controls is loaded
# from the official NIST OSCAL catalog when available.

NIST_800_53_CONTROLS: dict[str, NIST80053Control] = {
    # ==========================================================================
    # AC - Access Control Family
    # ==========================================================================
    "AC-1": NIST80053Control(
        id="AC-1",
        title="Policy and Procedures",
        description=(
            "a. Develop, document, and disseminate to [Assignment: organization-defined "
            "personnel or roles]: 1. [Selection (one or more): Organization-level; "
            "Mission/business process-level; System-level] access control policy that: "
            "(a) Addresses purpose, scope, roles, responsibilities, management commitment, "
            "coordination among organizational entities, and compliance; and (b) Is "
            "consistent with applicable laws, executive orders, directives, regulations, "
            "policies, standards, and guidelines; and 2. Procedures to facilitate the "
            "implementation of the access control policy and the associated access controls;\n"
            "b. Designate an [Assignment: organization-defined official] to manage the "
            "development, documentation, and dissemination of the access control policy "
            "and procedures; and\n"
            "c. Review and update the current access control: 1. Policy [Assignment: "
            "organization-defined frequency] and following [Assignment: organization-defined "
            "events]; and 2. Procedures [Assignment: organization-defined frequency] and "
            "following [Assignment: organization-defined events]."
        ),
        family=FAMILY_AC,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        related_controls=["PM-9", "PS-8", "SI-12"],
    ),
    "AC-2": NIST80053Control(
        id="AC-2",
        title="Account Management",
        description=(
            "a. Define and document the types of accounts allowed and specifically prohibited "
            "for use within the system;\n"
            "b. Assign account managers;\n"
            "c. Require [Assignment: organization-defined prerequisites and criteria] for "
            "group and role membership;\n"
            "d. Specify: 1. Authorized users of the system; 2. Group and role membership; "
            "and 3. Access authorizations (i.e., privileges) and [Assignment: organization-defined "
            "attributes (as required)] for each account;\n"
            "e. Require approvals by [Assignment: organization-defined personnel or roles] "
            "for requests to create accounts;\n"
            "f. Create, enable, modify, disable, and remove accounts in accordance with "
            "[Assignment: organization-defined policy, procedures, prerequisites, and criteria];\n"
            "g. Monitor the use of accounts;\n"
            "h. Notify account managers and [Assignment: organization-defined personnel or roles] "
            "within: 1. [Assignment: organization-defined time period] when accounts are no "
            "longer required; 2. [Assignment: organization-defined time period] when users are "
            "terminated or transferred; and 3. [Assignment: organization-defined time period] "
            "when system usage or need-to-know changes for an individual;\n"
            "i. Authorize access to the system based on: 1. A valid access authorization; "
            "2. Intended system usage; and 3. [Assignment: organization-defined attributes "
            "(as required)];\n"
            "j. Review accounts for compliance with account management requirements "
            "[Assignment: organization-defined frequency];\n"
            "k. Establish and implement a process for changing shared or group account "
            "authenticators (if deployed) when individuals are removed from the group; and\n"
            "l. Align account management processes with personnel termination and transfer processes."
        ),
        family=FAMILY_AC,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=[
            "AC-2(1)", "AC-2(2)", "AC-2(3)", "AC-2(4)", "AC-2(5)",
            "AC-2(6)", "AC-2(7)", "AC-2(8)", "AC-2(9)", "AC-2(10)",
            "AC-2(11)", "AC-2(12)", "AC-2(13)",
        ],
        related_controls=[
            "AC-3", "AC-5", "AC-6", "AC-17", "AC-18", "AC-19", "AC-20",
            "AU-2", "AU-12", "CM-5", "IA-2", "IA-4", "IA-5", "IA-8",
            "MA-3", "MA-5", "PE-2", "PL-4", "PS-2", "PS-4", "PS-5",
            "PS-7", "PT-2", "PT-3", "SC-7", "SC-12", "SC-13", "SC-37",
        ],
    ),
    "AC-2(1)": NIST80053Control(
        id="AC-2(1)",
        title="Account Management | Automated System Account Management",
        description=(
            "Support the management of system accounts using [Assignment: "
            "organization-defined automated mechanisms]."
        ),
        family=FAMILY_AC,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="AC-2",
        related_controls=["CA-7", "SI-4"],
    ),
    "AC-2(2)": NIST80053Control(
        id="AC-2(2)",
        title="Account Management | Automated Temporary and Emergency Account Management",
        description=(
            "Automatically [Selection: remove; disable] temporary and emergency accounts "
            "after [Assignment: organization-defined time period for each type of account]."
        ),
        family=FAMILY_AC,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="AC-2",
    ),
    "AC-2(3)": NIST80053Control(
        id="AC-2(3)",
        title="Account Management | Disable Accounts",
        description=(
            "Disable accounts within [Assignment: organization-defined time period] when "
            "the accounts: (a) Have expired; (b) Are no longer associated with a user or "
            "individual; (c) Are in violation of organizational policy; or (d) Have been "
            "inactive for [Assignment: organization-defined time period]."
        ),
        family=FAMILY_AC,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="AC-2",
    ),
    "AC-2(4)": NIST80053Control(
        id="AC-2(4)",
        title="Account Management | Automated Audit Actions",
        description=(
            "Automatically audit account creation, modification, enabling, disabling, "
            "and removal actions."
        ),
        family=FAMILY_AC,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="AC-2",
        related_controls=["AU-2", "AU-6"],
    ),
    "AC-2(5)": NIST80053Control(
        id="AC-2(5)",
        title="Account Management | Inactivity Logout",
        description=(
            "Require that users log out when [Assignment: organization-defined "
            "time period of expected inactivity or description of when to log out]."
        ),
        family=FAMILY_AC,
        priority="P2",
        baseline_impact=["high"],
        parent="AC-2",
    ),
    "AC-3": NIST80053Control(
        id="AC-3",
        title="Access Enforcement",
        description=(
            "Enforce approved authorizations for logical access to information and "
            "system resources in accordance with applicable access control policies."
        ),
        family=FAMILY_AC,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=[
            "AC-3(1)", "AC-3(2)", "AC-3(3)", "AC-3(4)", "AC-3(5)",
            "AC-3(7)", "AC-3(8)", "AC-3(9)", "AC-3(10)", "AC-3(11)",
            "AC-3(12)", "AC-3(13)", "AC-3(14)", "AC-3(15)",
        ],
        related_controls=[
            "AC-2", "AC-4", "AC-5", "AC-6", "AC-16", "AC-17", "AC-18",
            "AC-19", "AC-20", "AC-21", "AC-22", "AC-24", "AC-25",
            "AT-2", "AT-3", "AU-9", "CA-9", "CM-5", "CM-11", "IA-2",
            "IA-5", "IA-6", "IA-7", "IA-11", "MA-3", "MA-4", "MA-5",
            "MP-4", "PM-2", "PS-3", "PT-2", "PT-3", "SA-17", "SC-2",
            "SC-3", "SC-4", "SC-12", "SC-13", "SC-28", "SC-31", "SC-34",
            "SI-4", "SI-8",
        ],
    ),
    "AC-4": NIST80053Control(
        id="AC-4",
        title="Information Flow Enforcement",
        description=(
            "Enforce approved authorizations for controlling the flow of information "
            "within the system and between connected systems based on [Assignment: "
            "organization-defined information flow control policies]."
        ),
        family=FAMILY_AC,
        priority="P1",
        baseline_impact=["moderate", "high"],
        enhancements=[
            "AC-4(1)", "AC-4(2)", "AC-4(3)", "AC-4(4)", "AC-4(5)",
            "AC-4(6)", "AC-4(7)", "AC-4(8)", "AC-4(9)", "AC-4(10)",
            "AC-4(11)", "AC-4(12)", "AC-4(13)", "AC-4(14)", "AC-4(15)",
            "AC-4(17)", "AC-4(19)", "AC-4(20)", "AC-4(21)", "AC-4(22)",
            "AC-4(23)", "AC-4(24)", "AC-4(25)", "AC-4(26)", "AC-4(27)",
            "AC-4(28)", "AC-4(29)", "AC-4(30)", "AC-4(31)", "AC-4(32)",
        ],
        related_controls=[
            "AC-3", "AC-6", "AC-16", "AC-17", "AC-19", "AC-21", "AU-10",
            "CA-3", "CA-9", "CM-6", "CM-7", "PM-24", "SA-17", "SC-4",
            "SC-7", "SC-16", "SC-31",
        ],
    ),
    "AC-5": NIST80053Control(
        id="AC-5",
        title="Separation of Duties",
        description=(
            "a. Identify and document [Assignment: organization-defined duties of "
            "individuals requiring separation]; and\n"
            "b. Define system access authorizations to support separation of duties."
        ),
        family=FAMILY_AC,
        priority="P1",
        baseline_impact=["moderate", "high"],
        related_controls=[
            "AC-2", "AC-3", "AC-6", "AU-9", "CM-5", "CM-11", "CP-9",
            "IA-2", "IA-4", "IA-5", "IA-12", "MA-3", "MA-5", "PS-2",
            "SA-8", "SA-17",
        ],
    ),
    "AC-6": NIST80053Control(
        id="AC-6",
        title="Least Privilege",
        description=(
            "Employ the principle of least privilege, allowing only authorized accesses "
            "for users (or processes acting on behalf of users) that are necessary to "
            "accomplish assigned organizational tasks."
        ),
        family=FAMILY_AC,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=[
            "AC-6(1)", "AC-6(2)", "AC-6(3)", "AC-6(4)", "AC-6(5)",
            "AC-6(6)", "AC-6(7)", "AC-6(8)", "AC-6(9)", "AC-6(10)",
        ],
        related_controls=[
            "AC-2", "AC-3", "AC-5", "AC-16", "CM-5", "CM-11", "PL-2",
            "PM-12", "SA-8", "SA-15", "SA-17", "SC-38",
        ],
    ),
    "AC-6(1)": NIST80053Control(
        id="AC-6(1)",
        title="Least Privilege | Authorize Access to Security Functions",
        description=(
            "Authorize access for [Assignment: organization-defined individuals or roles] "
            "to: (a) [Assignment: organization-defined security functions (deployed in "
            "hardware, software, and firmware)]; and (b) [Assignment: organization-defined "
            "security-relevant information]."
        ),
        family=FAMILY_AC,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="AC-6",
        related_controls=["AC-17", "AC-18", "AC-19", "AU-9", "PE-3"],
    ),
    "AC-6(2)": NIST80053Control(
        id="AC-6(2)",
        title="Least Privilege | Non-privileged Access for Nonsecurity Functions",
        description=(
            "Require that users of system accounts (or roles) with access to "
            "[Assignment: organization-defined security functions or security-relevant "
            "information] use non-privileged accounts or roles, when accessing "
            "nonsecurity functions."
        ),
        family=FAMILY_AC,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="AC-6",
        related_controls=["AC-17", "AC-18", "AC-19", "PL-4"],
    ),
    "AC-6(5)": NIST80053Control(
        id="AC-6(5)",
        title="Least Privilege | Privileged Accounts",
        description=(
            "Restrict privileged accounts on the system to [Assignment: "
            "organization-defined personnel or roles]."
        ),
        family=FAMILY_AC,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="AC-6",
        related_controls=["IA-2", "MA-3", "MA-4"],
    ),
    "AC-6(9)": NIST80053Control(
        id="AC-6(9)",
        title="Least Privilege | Log Use of Privileged Functions",
        description="Log the execution of privileged functions.",
        family=FAMILY_AC,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="AC-6",
        related_controls=["AU-2", "AU-3", "AU-12"],
    ),
    "AC-6(10)": NIST80053Control(
        id="AC-6(10)",
        title="Least Privilege | Prohibit Non-privileged Users from Executing Privileged Functions",
        description=(
            "Prevent non-privileged users from executing privileged functions."
        ),
        family=FAMILY_AC,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="AC-6",
    ),
    "AC-7": NIST80053Control(
        id="AC-7",
        title="Unsuccessful Logon Attempts",
        description=(
            "a. Enforce a limit of [Assignment: organization-defined number] consecutive "
            "invalid logon attempts by a user during a [Assignment: organization-defined "
            "time period]; and\n"
            "b. Automatically [Selection (one or more): lock the account or node for an "
            "[Assignment: organization-defined time period]; lock the account or node "
            "until released by an administrator; delay next logon prompt per [Assignment: "
            "organization-defined delay algorithm]; notify system administrator; take other "
            "[Assignment: organization-defined action]] when the maximum number of "
            "unsuccessful attempts is exceeded."
        ),
        family=FAMILY_AC,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=["AC-7(1)", "AC-7(2)", "AC-7(3)", "AC-7(4)"],
        related_controls=["AC-2", "AC-9", "AU-2", "AU-6", "IA-5"],
    ),
    "AC-17": NIST80053Control(
        id="AC-17",
        title="Remote Access",
        description=(
            "a. Establish and document usage restrictions, configuration/connection "
            "requirements, and implementation guidance for each type of remote access "
            "allowed; and\n"
            "b. Authorize each type of remote access to the system prior to allowing "
            "such connections."
        ),
        family=FAMILY_AC,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=[
            "AC-17(1)", "AC-17(2)", "AC-17(3)", "AC-17(4)", "AC-17(5)",
            "AC-17(6)", "AC-17(7)", "AC-17(8)", "AC-17(9)", "AC-17(10)",
        ],
        related_controls=[
            "AC-2", "AC-3", "AC-4", "AC-6", "AC-18", "AC-19", "AC-20",
            "CA-3", "CM-10", "IA-2", "IA-3", "IA-8", "MA-4", "PE-17",
            "PL-2", "PL-4", "SC-10", "SC-12", "SC-13", "SI-4",
        ],
    ),

    # ==========================================================================
    # AU - Audit and Accountability Family
    # ==========================================================================
    "AU-1": NIST80053Control(
        id="AU-1",
        title="Policy and Procedures",
        description=(
            "a. Develop, document, and disseminate to [Assignment: organization-defined "
            "personnel or roles]: 1. [Selection (one or more): Organization-level; "
            "Mission/business process-level; System-level] audit and accountability "
            "policy that: (a) Addresses purpose, scope, roles, responsibilities, "
            "management commitment, coordination among organizational entities, and "
            "compliance; and (b) Is consistent with applicable laws, executive orders, "
            "directives, regulations, policies, standards, and guidelines; and "
            "2. Procedures to facilitate the implementation of the audit and accountability "
            "policy and the associated audit and accountability controls;\n"
            "b. Designate an [Assignment: organization-defined official] to manage the "
            "development, documentation, and dissemination of the audit and accountability "
            "policy and procedures; and\n"
            "c. Review and update the current audit and accountability: 1. Policy "
            "[Assignment: organization-defined frequency] and following [Assignment: "
            "organization-defined events]; and 2. Procedures [Assignment: organization-defined "
            "frequency] and following [Assignment: organization-defined events]."
        ),
        family=FAMILY_AU,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        related_controls=["PM-9", "PS-8", "SI-12"],
    ),
    "AU-2": NIST80053Control(
        id="AU-2",
        title="Event Logging",
        description=(
            "a. Identify the types of events that the system is capable of logging in "
            "support of the audit function: [Assignment: organization-defined event types "
            "that the system is capable of logging];\n"
            "b. Coordinate the event logging function with other organizational entities "
            "requiring audit-related information to guide and inform the selection criteria "
            "for events to be logged;\n"
            "c. Specify the following event types for logging within the system: "
            "[Assignment: organization-defined event types (subset of the event types "
            "defined in AU-2a.) along with the frequency of (or situation requiring) "
            "logging for each identified event type];\n"
            "d. Provide a rationale for why the event types selected for logging are "
            "deemed to be adequate to support after-the-fact investigations of incidents; and\n"
            "e. Review and update the event types selected for logging [Assignment: "
            "organization-defined frequency]."
        ),
        family=FAMILY_AU,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=["AU-2(1)", "AU-2(2)", "AU-2(3)", "AU-2(4)"],
        related_controls=[
            "AC-2", "AC-3", "AC-6", "AC-7", "AC-8", "AC-16", "AC-17",
            "AU-3", "AU-4", "AU-5", "AU-6", "AU-7", "AU-11", "AU-12",
            "CM-3", "CM-5", "CM-6", "CM-13", "IA-3", "MA-4", "MP-2",
            "MP-4", "PE-3", "PM-21", "PT-7", "RA-8", "SA-8", "SC-7",
            "SC-18", "SI-3", "SI-4", "SI-7", "SI-10", "SI-11",
        ],
    ),
    "AU-3": NIST80053Control(
        id="AU-3",
        title="Content of Audit Records",
        description=(
            "Ensure that audit records contain information that establishes the following:\n"
            "a. What type of event occurred;\n"
            "b. When the event occurred;\n"
            "c. Where the event occurred;\n"
            "d. Source of the event;\n"
            "e. Outcome of the event; and\n"
            "f. Identity of any individuals, subjects, or objects/entities associated "
            "with the event."
        ),
        family=FAMILY_AU,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=["AU-3(1)", "AU-3(2)", "AU-3(3)"],
        related_controls=[
            "AU-2", "AU-8", "AU-12", "AU-14", "MA-4", "PL-9", "PM-12",
            "SA-8", "SI-7", "SI-11",
        ],
    ),
    "AU-6": NIST80053Control(
        id="AU-6",
        title="Audit Record Review, Analysis, and Reporting",
        description=(
            "a. Review and analyze system audit records [Assignment: organization-defined "
            "frequency] for indications of [Assignment: organization-defined inappropriate "
            "or unusual activity] and the potential impact of the inappropriate or "
            "unusual activity;\n"
            "b. Report findings to [Assignment: organization-defined personnel or roles]; and\n"
            "c. Adjust the level of audit record review, analysis, and reporting within "
            "the system when there is a change in risk based on law enforcement information, "
            "intelligence information, or other credible sources of information."
        ),
        family=FAMILY_AU,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=[
            "AU-6(1)", "AU-6(2)", "AU-6(3)", "AU-6(4)", "AU-6(5)",
            "AU-6(6)", "AU-6(7)", "AU-6(8)", "AU-6(9)", "AU-6(10)",
        ],
        related_controls=[
            "AC-2", "AC-3", "AC-5", "AC-6", "AC-7", "AC-17", "AT-3",
            "AU-7", "AU-16", "CA-2", "CA-7", "CM-2", "CM-5", "CM-6",
            "CM-10", "CM-11", "IA-2", "IA-3", "IA-5", "IA-8", "IR-4",
            "IR-5", "IR-6", "MA-4", "MP-4", "PE-3", "PE-6", "PE-14",
            "PE-16", "RA-5", "SC-7", "SC-18", "SC-38", "SI-3", "SI-4",
            "SI-7",
        ],
    ),
    "AU-9": NIST80053Control(
        id="AU-9",
        title="Protection of Audit Information",
        description=(
            "a. Protect audit information and audit logging tools from unauthorized access, "
            "modification, and deletion; and\n"
            "b. Alert [Assignment: organization-defined personnel or roles] upon detection "
            "of unauthorized access, modification, or deletion of audit information."
        ),
        family=FAMILY_AU,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=["AU-9(1)", "AU-9(2)", "AU-9(3)", "AU-9(4)", "AU-9(5)", "AU-9(6)", "AU-9(7)"],
        related_controls=[
            "AC-3", "AC-6", "AU-6", "AU-11", "AU-14", "AU-15", "MP-2",
            "MP-4", "PE-2", "PE-3", "PE-6", "SA-8", "SC-8", "SI-4",
        ],
    ),
    "AU-11": NIST80053Control(
        id="AU-11",
        title="Audit Record Retention",
        description=(
            "Retain audit records for [Assignment: organization-defined time period "
            "consistent with records retention policy] to provide support for after-the-fact "
            "investigations of incidents and to meet regulatory and organizational "
            "information retention requirements."
        ),
        family=FAMILY_AU,
        priority="P3",
        baseline_impact=["low", "moderate", "high"],
        enhancements=["AU-11(1)"],
        related_controls=["AU-2", "AU-4", "AU-5", "AU-6", "AU-9", "AU-14", "MP-6", "RA-5", "SI-12"],
    ),
    "AU-12": NIST80053Control(
        id="AU-12",
        title="Audit Record Generation",
        description=(
            "a. Provide audit record generation capability for the event types the system "
            "is capable of auditing as defined in AU-2a on [Assignment: organization-defined "
            "system components];\n"
            "b. Allow [Assignment: organization-defined personnel or roles] to select the "
            "event types that are to be logged by specific components of the system; and\n"
            "c. Generate audit records for the event types defined in AU-2c that include "
            "the audit record content defined in AU-3."
        ),
        family=FAMILY_AU,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=["AU-12(1)", "AU-12(2)", "AU-12(3)", "AU-12(4)"],
        related_controls=[
            "AC-6", "AC-17", "AU-2", "AU-3", "AU-4", "AU-5", "AU-6",
            "AU-7", "AU-14", "CM-5", "MA-4", "MP-4", "PM-12", "SA-8",
            "SC-18", "SI-3", "SI-4", "SI-7", "SI-10",
        ],
    ),

    # ==========================================================================
    # CM - Configuration Management Family
    # ==========================================================================
    "CM-1": NIST80053Control(
        id="CM-1",
        title="Policy and Procedures",
        description=(
            "a. Develop, document, and disseminate to [Assignment: organization-defined "
            "personnel or roles]: 1. [Selection (one or more): Organization-level; "
            "Mission/business process-level; System-level] configuration management "
            "policy that: (a) Addresses purpose, scope, roles, responsibilities, management "
            "commitment, coordination among organizational entities, and compliance; and "
            "(b) Is consistent with applicable laws, executive orders, directives, regulations, "
            "policies, standards, and guidelines; and 2. Procedures to facilitate the "
            "implementation of the configuration management policy and the associated "
            "configuration management controls;\n"
            "b. Designate an [Assignment: organization-defined official] to manage the "
            "development, documentation, and dissemination of the configuration management "
            "policy and procedures; and\n"
            "c. Review and update the current configuration management: 1. Policy "
            "[Assignment: organization-defined frequency] and following [Assignment: "
            "organization-defined events]; and 2. Procedures [Assignment: organization-defined "
            "frequency] and following [Assignment: organization-defined events]."
        ),
        family=FAMILY_CM,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        related_controls=["PM-9", "PS-8", "SI-12"],
    ),
    "CM-2": NIST80053Control(
        id="CM-2",
        title="Baseline Configuration",
        description=(
            "a. Develop, document, and maintain under configuration control, a current "
            "baseline configuration of the system; and\n"
            "b. Review and update the baseline configuration of the system: 1. [Assignment: "
            "organization-defined frequency]; 2. When required due to [Assignment: "
            "organization-defined circumstances]; and 3. When system components are "
            "installed or upgraded."
        ),
        family=FAMILY_CM,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=["CM-2(1)", "CM-2(2)", "CM-2(3)", "CM-2(4)", "CM-2(5)", "CM-2(6)", "CM-2(7)"],
        related_controls=[
            "AC-19", "AU-6", "CA-9", "CM-1", "CM-3", "CM-5", "CM-6",
            "CM-8", "CM-9", "CP-9", "CP-10", "CP-12", "MA-2", "PL-8",
            "PM-5", "SA-8", "SA-10", "SA-15", "SC-18",
        ],
    ),
    "CM-6": NIST80053Control(
        id="CM-6",
        title="Configuration Settings",
        description=(
            "a. Establish and document configuration settings for components employed "
            "within the system that reflect the most restrictive mode consistent with "
            "operational requirements using [Assignment: organization-defined common "
            "secure configurations];\n"
            "b. Implement the configuration settings;\n"
            "c. Identify, document, and approve any deviations from established configuration "
            "settings for [Assignment: organization-defined system components] based on "
            "[Assignment: organization-defined operational requirements]; and\n"
            "d. Monitor and control changes to the configuration settings in accordance "
            "with organizational policies and procedures."
        ),
        family=FAMILY_CM,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=["CM-6(1)", "CM-6(2)"],
        related_controls=[
            "AC-3", "AC-19", "AU-2", "AU-6", "CA-7", "CA-9", "CM-2",
            "CM-3", "CM-5", "CM-7", "CM-11", "CP-7", "CP-9", "CP-10",
            "IA-5", "PL-8", "PL-9", "RA-5", "SA-4", "SA-5", "SA-8",
            "SA-9", "SC-18", "SC-28", "SC-43", "SI-2", "SI-4", "SI-6",
        ],
    ),
    "CM-7": NIST80053Control(
        id="CM-7",
        title="Least Functionality",
        description=(
            "a. Configure the system to provide only [Assignment: organization-defined "
            "mission essential capabilities]; and\n"
            "b. Prohibit or restrict the use of the following functions, ports, protocols, "
            "software, and/or services: [Assignment: organization-defined prohibited or "
            "restricted functions, system ports, protocols, software, and/or services]."
        ),
        family=FAMILY_CM,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=["CM-7(1)", "CM-7(2)", "CM-7(3)", "CM-7(4)", "CM-7(5)", "CM-7(6)", "CM-7(7)", "CM-7(8)", "CM-7(9)"],
        related_controls=[
            "AC-3", "AC-4", "AC-6", "CM-2", "CM-5", "CM-6", "CM-11",
            "RA-5", "SA-4", "SA-5", "SA-8", "SA-9", "SC-2", "SC-3",
            "SC-7", "SC-37", "SI-4",
        ],
    ),
    "CM-8": NIST80053Control(
        id="CM-8",
        title="System Component Inventory",
        description=(
            "a. Develop and document an inventory of system components that: "
            "1. Accurately reflects the system; 2. Includes all components within the "
            "system; 3. Does not include duplicate accounting of components or components "
            "assigned to any other system; 4. Is at the level of granularity deemed "
            "necessary for tracking and reporting; and 5. Includes the following "
            "information to achieve system component accountability: [Assignment: "
            "organization-defined information deemed necessary to achieve effective "
            "system component accountability]; and\n"
            "b. Review and update the system component inventory [Assignment: "
            "organization-defined frequency]."
        ),
        family=FAMILY_CM,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=["CM-8(1)", "CM-8(2)", "CM-8(3)", "CM-8(4)", "CM-8(5)", "CM-8(6)", "CM-8(7)", "CM-8(8)", "CM-8(9)"],
        related_controls=[
            "CM-2", "CM-7", "CM-9", "CM-10", "CM-11", "CM-13", "CP-2",
            "CP-9", "MA-2", "MA-6", "PE-20", "PL-9", "PM-5", "SA-4",
            "SA-5", "SI-2", "SR-4",
        ],
    ),

    # ==========================================================================
    # IA - Identification and Authentication Family
    # ==========================================================================
    "IA-1": NIST80053Control(
        id="IA-1",
        title="Policy and Procedures",
        description=(
            "a. Develop, document, and disseminate to [Assignment: organization-defined "
            "personnel or roles]: 1. [Selection (one or more): Organization-level; "
            "Mission/business process-level; System-level] identification and authentication "
            "policy that: (a) Addresses purpose, scope, roles, responsibilities, management "
            "commitment, coordination among organizational entities, and compliance; and "
            "(b) Is consistent with applicable laws, executive orders, directives, regulations, "
            "policies, standards, and guidelines; and 2. Procedures to facilitate the "
            "implementation of the identification and authentication policy and the "
            "associated identification and authentication controls;\n"
            "b. Designate an [Assignment: organization-defined official] to manage the "
            "development, documentation, and dissemination of the identification and "
            "authentication policy and procedures; and\n"
            "c. Review and update the current identification and authentication: 1. Policy "
            "[Assignment: organization-defined frequency] and following [Assignment: "
            "organization-defined events]; and 2. Procedures [Assignment: organization-defined "
            "frequency] and following [Assignment: organization-defined events]."
        ),
        family=FAMILY_IA,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        related_controls=["PM-9", "PS-8", "SI-12"],
    ),
    "IA-2": NIST80053Control(
        id="IA-2",
        title="Identification and Authentication (Organizational Users)",
        description=(
            "Uniquely identify and authenticate organizational users and associate that "
            "unique identification with processes acting on behalf of those users."
        ),
        family=FAMILY_IA,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=[
            "IA-2(1)", "IA-2(2)", "IA-2(3)", "IA-2(4)", "IA-2(5)",
            "IA-2(6)", "IA-2(7)", "IA-2(8)", "IA-2(9)", "IA-2(10)",
            "IA-2(11)", "IA-2(12)", "IA-2(13)",
        ],
        related_controls=[
            "AC-2", "AC-3", "AC-4", "AC-14", "AC-17", "AC-18", "AU-1",
            "AU-6", "IA-4", "IA-5", "IA-8", "IA-11", "MA-4", "MA-5",
            "PE-2", "PL-4", "SA-4", "SA-8",
        ],
    ),
    "IA-2(1)": NIST80053Control(
        id="IA-2(1)",
        title="Identification and Authentication | Multi-Factor Authentication to Privileged Accounts",
        description=(
            "Implement multi-factor authentication for access to privileged accounts."
        ),
        family=FAMILY_IA,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        parent="IA-2",
        related_controls=["AC-5", "AC-6"],
    ),
    "IA-2(2)": NIST80053Control(
        id="IA-2(2)",
        title="Identification and Authentication | Multi-Factor Authentication to Non-Privileged Accounts",
        description=(
            "Implement multi-factor authentication for access to non-privileged accounts."
        ),
        family=FAMILY_IA,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="IA-2",
    ),
    "IA-2(8)": NIST80053Control(
        id="IA-2(8)",
        title="Identification and Authentication | Access to Accounts — Replay Resistant",
        description=(
            "Implement replay-resistant authentication mechanisms for access to "
            "[Selection (one or more): privileged accounts; non-privileged accounts]."
        ),
        family=FAMILY_IA,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="IA-2",
    ),
    "IA-2(12)": NIST80053Control(
        id="IA-2(12)",
        title="Identification and Authentication | Acceptance of PIV Credentials",
        description=(
            "Accept and electronically verify Personal Identity Verification-compliant "
            "credentials."
        ),
        family=FAMILY_IA,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="IA-2",
        related_controls=["PE-6", "PM-12"],
    ),
    "IA-4": NIST80053Control(
        id="IA-4",
        title="Identifier Management",
        description=(
            "Manage system identifiers by: a. Receiving authorization from [Assignment: "
            "organization-defined personnel or roles] to assign an individual, group, role, "
            "service, or device identifier; b. Selecting an identifier that identifies an "
            "individual, group, role, service, or device; c. Assigning the identifier to "
            "the intended individual, group, role, service, or device; and d. Preventing "
            "reuse of identifiers for [Assignment: organization-defined time period]."
        ),
        family=FAMILY_IA,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=["IA-4(1)", "IA-4(4)", "IA-4(5)", "IA-4(6)", "IA-4(8)", "IA-4(9)"],
        related_controls=[
            "AC-5", "IA-2", "IA-3", "IA-5", "IA-8", "IA-9", "IA-12",
            "MA-4", "PE-2", "PE-3", "PE-4", "PL-4", "PM-12", "PS-3",
            "PS-4", "PS-5", "SC-37",
        ],
    ),
    "IA-5": NIST80053Control(
        id="IA-5",
        title="Authenticator Management",
        description=(
            "Manage system authenticators by: a. Verifying, as part of the initial "
            "authenticator distribution, the identity of the individual, group, role, "
            "service, or device receiving the authenticator; b. Establishing initial "
            "authenticator content for any authenticators issued by the organization; "
            "c. Ensuring that authenticators have sufficient strength of mechanism for "
            "their intended use; d. Establishing and implementing administrative procedures "
            "for initial authenticator distribution, for lost or compromised or damaged "
            "authenticators, and for revoking authenticators; e. Changing default "
            "authenticators prior to first use; f. Changing or refreshing authenticators "
            "[Assignment: organization-defined time period by authenticator type] or when "
            "[Assignment: organization-defined events] occur; g. Protecting authenticator "
            "content from unauthorized disclosure and modification; h. Requiring individuals "
            "to take, and having devices implement, specific controls to protect "
            "authenticators; and i. Changing authenticators for group or role accounts "
            "when membership to those accounts changes."
        ),
        family=FAMILY_IA,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=[
            "IA-5(1)", "IA-5(2)", "IA-5(3)", "IA-5(4)", "IA-5(5)",
            "IA-5(6)", "IA-5(7)", "IA-5(8)", "IA-5(9)", "IA-5(10)",
            "IA-5(12)", "IA-5(13)", "IA-5(14)", "IA-5(15)", "IA-5(16)",
            "IA-5(17)", "IA-5(18)",
        ],
        related_controls=[
            "AC-3", "AC-6", "CM-6", "IA-2", "IA-4", "IA-7", "IA-8",
            "IA-9", "MA-4", "PE-2", "PL-4", "SC-12", "SC-13",
        ],
    ),
    "IA-5(1)": NIST80053Control(
        id="IA-5(1)",
        title="Authenticator Management | Password-Based Authentication",
        description=(
            "For password-based authentication: (a) Maintain a list of commonly-used, "
            "expected, or compromised passwords and update the list [Assignment: "
            "organization-defined frequency] and when organizational passwords are "
            "suspected to have been compromised directly or indirectly; (b) Verify, "
            "when users create or update passwords, that the passwords are not found "
            "on the list of commonly-used, expected, or compromised passwords in (a); "
            "(c) Transmit passwords only over cryptographically-protected channels; "
            "(d) Store passwords using an approved salted key derivation function, "
            "preferably using a keyed hash; (e) Require immediate selection of a new "
            "password upon account recovery; (f) Allow user selection of long passwords "
            "and passphrases, including spaces and all printable characters; "
            "(g) Employ automated tools to assist the user in selecting strong password "
            "authenticators; and (h) Enforce the following composition and complexity "
            "rules: [Assignment: organization-defined composition and complexity rules]."
        ),
        family=FAMILY_IA,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        parent="IA-5",
        related_controls=["IA-6"],
    ),
    "IA-5(2)": NIST80053Control(
        id="IA-5(2)",
        title="Authenticator Management | Public Key-Based Authentication",
        description=(
            "For public key-based authentication: (a) Enforce authorized access to the "
            "corresponding private key; and (b) Map the authenticated identity to the "
            "account of the individual or group."
        ),
        family=FAMILY_IA,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="IA-5",
    ),
    "IA-5(6)": NIST80053Control(
        id="IA-5(6)",
        title="Authenticator Management | Protection of Authenticators",
        description=(
            "Protect authenticators commensurate with the security category of the "
            "information to which use of the authenticator permits access."
        ),
        family=FAMILY_IA,
        priority="P1",
        baseline_impact=["high"],
        parent="IA-5",
    ),
    "IA-6": NIST80053Control(
        id="IA-6",
        title="Authentication Feedback",
        description=(
            "Obscure feedback of authentication information during the authentication "
            "process to protect the information from possible exploitation/use by "
            "unauthorized individuals."
        ),
        family=FAMILY_IA,
        priority="P2",
        baseline_impact=["low", "moderate", "high"],
        related_controls=["AC-3", "IA-5"],
    ),
    "IA-8": NIST80053Control(
        id="IA-8",
        title="Identification and Authentication (Non-Organizational Users)",
        description=(
            "Uniquely identify and authenticate non-organizational users or processes "
            "acting on behalf of non-organizational users."
        ),
        family=FAMILY_IA,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=["IA-8(1)", "IA-8(2)", "IA-8(3)", "IA-8(4)", "IA-8(5)", "IA-8(6)"],
        related_controls=["AC-2", "AC-6", "AC-14", "AC-17", "AC-18", "AU-6", "IA-2", "IA-4", "IA-5", "IA-10", "IA-11", "MA-4", "RA-3", "SA-4", "SC-8"],
    ),

    # ==========================================================================
    # SC - System and Communications Protection Family
    # ==========================================================================
    "SC-1": NIST80053Control(
        id="SC-1",
        title="Policy and Procedures",
        description=(
            "a. Develop, document, and disseminate to [Assignment: organization-defined "
            "personnel or roles]: 1. [Selection (one or more): Organization-level; "
            "Mission/business process-level; System-level] system and communications "
            "protection policy that: (a) Addresses purpose, scope, roles, responsibilities, "
            "management commitment, coordination among organizational entities, and "
            "compliance; and (b) Is consistent with applicable laws, executive orders, "
            "directives, regulations, policies, standards, and guidelines; and 2. Procedures "
            "to facilitate the implementation of the system and communications protection "
            "policy and the associated system and communications protection controls;\n"
            "b. Designate an [Assignment: organization-defined official] to manage the "
            "development, documentation, and dissemination of the system and communications "
            "protection policy and procedures; and\n"
            "c. Review and update the current system and communications protection: "
            "1. Policy [Assignment: organization-defined frequency] and following "
            "[Assignment: organization-defined events]; and 2. Procedures [Assignment: "
            "organization-defined frequency] and following [Assignment: organization-defined events]."
        ),
        family=FAMILY_SC,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        related_controls=["PM-9", "PS-8", "SI-12"],
    ),
    "SC-5": NIST80053Control(
        id="SC-5",
        title="Denial-of-Service Protection",
        description=(
            "a. [Selection: Protect against; Limit] the effects of the following types "
            "of denial-of-service events: [Assignment: organization-defined types of "
            "denial-of-service events]; and\n"
            "b. Employ the following controls to achieve the denial-of-service objective: "
            "[Assignment: organization-defined controls by type of denial-of-service event]."
        ),
        family=FAMILY_SC,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=["SC-5(1)", "SC-5(2)", "SC-5(3)"],
        related_controls=["CP-2", "IR-4", "SC-6", "SC-7", "SC-40"],
    ),
    "SC-7": NIST80053Control(
        id="SC-7",
        title="Boundary Protection",
        description=(
            "a. Monitor and control communications at the external managed interfaces "
            "to the system and at key internal managed interfaces within the system;\n"
            "b. Implement subnetworks for publicly accessible system components that "
            "are [Selection: physically; logically] separated from internal organizational "
            "networks; and\n"
            "c. Connect to external networks or systems only through managed interfaces "
            "consisting of boundary protection devices arranged in accordance with an "
            "organizational security and privacy architecture."
        ),
        family=FAMILY_SC,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=[
            "SC-7(3)", "SC-7(4)", "SC-7(5)", "SC-7(7)", "SC-7(8)",
            "SC-7(9)", "SC-7(10)", "SC-7(11)", "SC-7(12)", "SC-7(13)",
            "SC-7(14)", "SC-7(15)", "SC-7(16)", "SC-7(17)", "SC-7(18)",
            "SC-7(19)", "SC-7(20)", "SC-7(21)", "SC-7(22)", "SC-7(23)",
            "SC-7(24)", "SC-7(25)", "SC-7(26)", "SC-7(27)", "SC-7(28)",
            "SC-7(29)",
        ],
        related_controls=[
            "AC-4", "AC-17", "AC-18", "AC-19", "AC-20", "AU-13",
            "CA-3", "CM-6", "CM-7", "CP-6", "CP-7", "IR-4", "MA-4",
            "PE-4", "PL-8", "PM-12", "SA-8", "SA-17", "SC-5", "SC-8",
            "SC-18", "SC-32", "SC-35", "SC-43",
        ],
    ),
    "SC-7(3)": NIST80053Control(
        id="SC-7(3)",
        title="Boundary Protection | Access Points",
        description=(
            "Limit the number of external network connections to the system."
        ),
        family=FAMILY_SC,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="SC-7",
    ),
    "SC-7(4)": NIST80053Control(
        id="SC-7(4)",
        title="Boundary Protection | External Telecommunications Services",
        description=(
            "a. Implement a managed interface for each external telecommunication service;\n"
            "b. Establish a traffic flow policy for each managed interface;\n"
            "c. Protect the confidentiality and integrity of the information being "
            "transmitted across each interface;\n"
            "d. Document each exception to the traffic flow policy with a supporting "
            "mission or business need and duration of that need;\n"
            "e. Review exceptions to the traffic flow policy [Assignment: organization-defined "
            "frequency] and remove exceptions that are no longer supported by an explicit "
            "mission or business need;\n"
            "f. Prevent unauthorized exchange of control plane traffic with external networks;\n"
            "g. Publish information to enable remote networks to detect unauthorized control "
            "plane traffic from internal networks; and\n"
            "h. Filter unauthorized control plane traffic from external networks."
        ),
        family=FAMILY_SC,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="SC-7",
        related_controls=["SC-8"],
    ),
    "SC-7(5)": NIST80053Control(
        id="SC-7(5)",
        title="Boundary Protection | Deny by Default — Allow by Exception",
        description=(
            "Deny network communications traffic by default and allow network communications "
            "traffic by exception [Selection (one or more): at managed interfaces; for "
            "[Assignment: organization-defined systems]]."
        ),
        family=FAMILY_SC,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="SC-7",
    ),
    "SC-7(7)": NIST80053Control(
        id="SC-7(7)",
        title="Boundary Protection | Split Tunneling for Remote Devices",
        description=(
            "Prevent split tunneling for remote devices connecting to organizational "
            "systems unless the split tunnel is securely provisioned using [Assignment: "
            "organization-defined safeguards]."
        ),
        family=FAMILY_SC,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="SC-7",
    ),
    "SC-8": NIST80053Control(
        id="SC-8",
        title="Transmission Confidentiality and Integrity",
        description=(
            "Protect the [Selection (one or more): confidentiality; integrity] of "
            "transmitted information."
        ),
        family=FAMILY_SC,
        priority="P1",
        baseline_impact=["moderate", "high"],
        enhancements=["SC-8(1)", "SC-8(2)", "SC-8(3)", "SC-8(4)", "SC-8(5)"],
        related_controls=["AC-17", "IA-3", "MA-4", "PE-4", "SA-4", "SA-8", "SC-7", "SC-12", "SC-13", "SC-16", "SC-20", "SC-23", "SC-28"],
    ),
    "SC-8(1)": NIST80053Control(
        id="SC-8(1)",
        title="Transmission Confidentiality and Integrity | Cryptographic Protection",
        description=(
            "Implement cryptographic mechanisms to [Selection (one or more): prevent "
            "unauthorized disclosure of information; detect changes to information] "
            "during transmission."
        ),
        family=FAMILY_SC,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="SC-8",
        related_controls=["SC-12", "SC-13"],
    ),
    "SC-12": NIST80053Control(
        id="SC-12",
        title="Cryptographic Key Establishment and Management",
        description=(
            "Establish and manage cryptographic keys when cryptography is employed within "
            "the system in accordance with the following key management requirements: "
            "[Assignment: organization-defined requirements for key generation, distribution, "
            "storage, access, and destruction]."
        ),
        family=FAMILY_SC,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=["SC-12(1)", "SC-12(2)", "SC-12(3)", "SC-12(6)"],
        related_controls=["AC-17", "AU-9", "AU-10", "CM-3", "IA-3", "IA-7", "SA-4", "SA-8", "SA-9", "SC-8", "SC-11", "SC-13", "SC-17", "SC-28", "SI-3", "SI-7"],
    ),
    "SC-13": NIST80053Control(
        id="SC-13",
        title="Cryptographic Protection",
        description=(
            "a. Determine the [Assignment: organization-defined cryptographic uses]; and\n"
            "b. Implement the following types of cryptography required for each specified "
            "cryptographic use: [Assignment: organization-defined types of cryptography "
            "for each specified cryptographic use]."
        ),
        family=FAMILY_SC,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=["SC-13(1)", "SC-13(2)", "SC-13(3)", "SC-13(4)"],
        related_controls=["AC-2", "AC-3", "AC-7", "AC-17", "AC-18", "AC-19", "AU-9", "AU-10", "CM-11", "CP-9", "IA-3", "IA-5", "IA-7", "MA-4", "MP-2", "MP-4", "MP-5", "SA-4", "SA-8", "SA-9", "SC-8", "SC-12", "SC-23", "SC-28", "SC-40", "SI-3", "SI-7"],
    ),
    "SC-28": NIST80053Control(
        id="SC-28",
        title="Protection of Information at Rest",
        description=(
            "Protect the [Selection (one or more): confidentiality; integrity] of the "
            "following information at rest: [Assignment: organization-defined information "
            "at rest]."
        ),
        family=FAMILY_SC,
        priority="P1",
        baseline_impact=["moderate", "high"],
        enhancements=["SC-28(1)", "SC-28(2)", "SC-28(3)"],
        related_controls=["AC-3", "AC-6", "CA-7", "CM-3", "CM-5", "CM-6", "CP-9", "MP-4", "MP-5", "PE-3", "SC-8", "SC-12", "SC-13", "SI-3", "SI-7", "SI-16"],
    ),
    "SC-28(1)": NIST80053Control(
        id="SC-28(1)",
        title="Protection of Information at Rest | Cryptographic Protection",
        description=(
            "Implement cryptographic mechanisms to prevent unauthorized disclosure and "
            "modification of the following information at rest on [Assignment: "
            "organization-defined system components or media]: [Assignment: "
            "organization-defined information]."
        ),
        family=FAMILY_SC,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="SC-28",
        related_controls=["AC-19", "SC-12", "SC-13"],
    ),

    # ==========================================================================
    # SI - System and Information Integrity Family
    # ==========================================================================
    "SI-1": NIST80053Control(
        id="SI-1",
        title="Policy and Procedures",
        description=(
            "a. Develop, document, and disseminate to [Assignment: organization-defined "
            "personnel or roles]: 1. [Selection (one or more): Organization-level; "
            "Mission/business process-level; System-level] system and information integrity "
            "policy that: (a) Addresses purpose, scope, roles, responsibilities, management "
            "commitment, coordination among organizational entities, and compliance; and "
            "(b) Is consistent with applicable laws, executive orders, directives, regulations, "
            "policies, standards, and guidelines; and 2. Procedures to facilitate the "
            "implementation of the system and information integrity policy and the "
            "associated system and information integrity controls;\n"
            "b. Designate an [Assignment: organization-defined official] to manage the "
            "development, documentation, and dissemination of the system and information "
            "integrity policy and procedures; and\n"
            "c. Review and update the current system and information integrity: 1. Policy "
            "[Assignment: organization-defined frequency] and following [Assignment: "
            "organization-defined events]; and 2. Procedures [Assignment: organization-defined "
            "frequency] and following [Assignment: organization-defined events]."
        ),
        family=FAMILY_SI,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        related_controls=["PM-9", "PS-8", "SI-12"],
    ),
    "SI-2": NIST80053Control(
        id="SI-2",
        title="Flaw Remediation",
        description=(
            "a. Identify, report, and correct system flaws;\n"
            "b. Test software and firmware updates related to flaw remediation for "
            "effectiveness and potential side effects before installation;\n"
            "c. Install security-relevant software and firmware updates within "
            "[Assignment: organization-defined time period] of the release of the updates; and\n"
            "d. Incorporate flaw remediation into the organizational configuration "
            "management process."
        ),
        family=FAMILY_SI,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=["SI-2(1)", "SI-2(2)", "SI-2(3)", "SI-2(4)", "SI-2(5)", "SI-2(6)"],
        related_controls=["CA-5", "CM-3", "CM-4", "CM-5", "CM-6", "CM-8", "IR-4", "MA-2", "RA-5", "SA-8", "SA-10", "SA-11", "SI-3", "SI-5", "SI-7", "SI-11"],
    ),
    "SI-3": NIST80053Control(
        id="SI-3",
        title="Malicious Code Protection",
        description=(
            "a. Implement [Selection (one or more): signature based; non-signature based] "
            "malicious code protection mechanisms at system entry and exit points to detect "
            "and eradicate malicious code;\n"
            "b. Automatically update malicious code protection mechanisms as new releases "
            "are available in accordance with organizational configuration management "
            "policy and procedures;\n"
            "c. Configure malicious code protection mechanisms to: 1. Perform periodic "
            "scans of the system [Assignment: organization-defined frequency] and real-time "
            "scans of files from external sources at [Selection (one or more): endpoint; "
            "network entry and exit points] as the files are downloaded, opened, or "
            "executed in accordance with organizational policy; and 2. [Selection (one or "
            "more): block malicious code; quarantine malicious code; take [Assignment: "
            "organization-defined action]]; and send alert to [Assignment: organization-defined "
            "personnel or roles] in response to malicious code detection; and\n"
            "d. Address the receipt of false positives during malicious code detection "
            "and eradication and the resulting potential impact on the availability of "
            "the system."
        ),
        family=FAMILY_SI,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=["SI-3(1)", "SI-3(2)", "SI-3(3)", "SI-3(4)", "SI-3(6)", "SI-3(8)", "SI-3(10)"],
        related_controls=["AC-4", "AC-19", "CM-3", "CM-8", "IR-4", "MA-3", "MA-4", "PL-9", "RA-5", "SC-7", "SC-26", "SC-28", "SC-44", "SI-2", "SI-4", "SI-7", "SI-8", "SI-15"],
    ),
    "SI-4": NIST80053Control(
        id="SI-4",
        title="System Monitoring",
        description=(
            "a. Monitor the system to detect: 1. Attacks and indicators of potential "
            "attacks in accordance with the following monitoring objectives: [Assignment: "
            "organization-defined monitoring objectives]; and 2. Unauthorized local, "
            "network, and remote connections;\n"
            "b. Identify unauthorized use of the system through the following techniques "
            "and methods: [Assignment: organization-defined techniques and methods];\n"
            "c. Invoke internal monitoring capabilities or deploy monitoring devices: "
            "1. Strategically within the system to collect organization-determined essential "
            "information; and 2. At ad hoc locations within the system to track specific "
            "types of transactions of interest to the organization;\n"
            "d. Analyze detected events and anomalies;\n"
            "e. Adjust the level of system monitoring activity when there is a change in "
            "risk to organizational operations and assets, individuals, other organizations, "
            "or the Nation;\n"
            "f. Obtain legal opinion regarding system monitoring activities; and\n"
            "g. Provide [Assignment: organization-defined system monitoring information] "
            "to [Assignment: organization-defined personnel or roles] [Selection (one or "
            "more): as needed; [Assignment: organization-defined frequency]]."
        ),
        family=FAMILY_SI,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=[
            "SI-4(1)", "SI-4(2)", "SI-4(3)", "SI-4(4)", "SI-4(5)",
            "SI-4(6)", "SI-4(7)", "SI-4(8)", "SI-4(9)", "SI-4(10)",
            "SI-4(11)", "SI-4(12)", "SI-4(13)", "SI-4(14)", "SI-4(15)",
            "SI-4(16)", "SI-4(17)", "SI-4(18)", "SI-4(19)", "SI-4(20)",
            "SI-4(21)", "SI-4(22)", "SI-4(23)", "SI-4(24)", "SI-4(25)",
        ],
        related_controls=[
            "AC-2", "AC-3", "AC-4", "AC-8", "AC-17", "AU-2", "AU-6",
            "AU-7", "AU-9", "AU-12", "AU-13", "AU-14", "CA-7", "CM-3",
            "CM-8", "IA-10", "IR-4", "MA-4", "PE-3", "PE-6", "PE-14",
            "PM-12", "PS-6", "RA-5", "RA-10", "SC-5", "SC-7", "SC-18",
            "SC-26", "SC-31", "SC-35", "SC-36", "SC-37", "SC-45", "SI-3",
            "SI-7", "SR-9", "SR-10",
        ],
    ),
    "SI-4(2)": NIST80053Control(
        id="SI-4(2)",
        title="System Monitoring | Automated Tools and Mechanisms for Real-Time Analysis",
        description=(
            "Employ automated tools and mechanisms to support near real-time analysis "
            "of events."
        ),
        family=FAMILY_SI,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="SI-4",
        related_controls=["PM-23", "PM-25"],
    ),
    "SI-4(4)": NIST80053Control(
        id="SI-4(4)",
        title="System Monitoring | Inbound and Outbound Communications Traffic",
        description=(
            "a. Determine criteria for unusual or unauthorized activities or conditions "
            "for inbound and outbound communications traffic;\n"
            "b. Monitor inbound and outbound communications traffic [Assignment: "
            "organization-defined frequency] for [Assignment: organization-defined unusual "
            "or unauthorized activities or conditions]."
        ),
        family=FAMILY_SI,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="SI-4",
    ),
    "SI-4(5)": NIST80053Control(
        id="SI-4(5)",
        title="System Monitoring | System-Generated Alerts",
        description=(
            "Alert [Assignment: organization-defined personnel or roles] when the following "
            "system-generated indications of compromise or potential compromise occur: "
            "[Assignment: organization-defined compromise indicators]."
        ),
        family=FAMILY_SI,
        priority="P1",
        baseline_impact=["moderate", "high"],
        parent="SI-4",
        related_controls=["AU-4", "PE-6"],
    ),
    "SI-5": NIST80053Control(
        id="SI-5",
        title="Security Alerts, Advisories, and Directives",
        description=(
            "a. Receive system security alerts, advisories, and directives from "
            "[Assignment: organization-defined external organizations] on an ongoing basis;\n"
            "b. Generate internal security alerts, advisories, and directives as deemed "
            "necessary;\n"
            "c. Disseminate security alerts, advisories, and directives to: [Selection "
            "(one or more): [Assignment: organization-defined personnel or roles]; "
            "[Assignment: organization-defined elements within the organization]; "
            "[Assignment: organization-defined external organizations]]; and\n"
            "d. Implement security directives in accordance with established time frames, "
            "or notify the issuing organization of the degree of noncompliance."
        ),
        family=FAMILY_SI,
        priority="P1",
        baseline_impact=["low", "moderate", "high"],
        enhancements=["SI-5(1)"],
        related_controls=["PM-15", "RA-5", "SI-2"],
    ),
}


# =============================================================================
# Lookup Functions
# =============================================================================


def get_control(control_id: str) -> NIST80053Control | None:
    """
    Get a control by ID.

    Args:
        control_id: Control identifier (e.g., "AC-2", "AC-2(1)").

    Returns:
        The control if found, None otherwise.
    """
    return NIST_800_53_CONTROLS.get(control_id)


def get_controls_by_family(family: str) -> list[NIST80053Control]:
    """
    Get all controls in a family.

    Args:
        family: Family code (e.g., "AC", "AU", "CM").

    Returns:
        List of controls in the family.
    """
    return [
        ctrl for ctrl in NIST_800_53_CONTROLS.values()
        if ctrl.family == family and not ctrl.withdrawn
    ]


def get_all_controls() -> list[NIST80053Control]:
    """Get all controls (excluding withdrawn)."""
    return [ctrl for ctrl in NIST_800_53_CONTROLS.values() if not ctrl.withdrawn]


def get_all_families() -> list[tuple[str, str]]:
    """
    Get all control families.

    Returns:
        List of (family_code, family_name) tuples.
    """
    return list(FAMILY_NAMES.items())
